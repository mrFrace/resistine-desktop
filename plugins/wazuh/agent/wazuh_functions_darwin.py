"""
Wazuh Agent Functions for macOS
Handles download, install, start/stop of the Wazuh SIEM agent via osascript
privilege escalation.
Author: Resistine Team
Copyright (c) Resistine 2025
Licensed under the GNU General Public License v2 or later
"""

import json
import os
import platform
import shlex
import socket
import subprocess
import tempfile
import time

from utils import settings
from utils.logger import logger

from plugins.wazuh.config import (
    WAZUH_BASE_URL,
    WAZUH_ENV_FILE,
    WAZUH_INSTALL_DIR,
    WAZUH_LAUNCHD_PLIST,
    WAZUH_MANAGER,
    WAZUH_MANAGER_PORT,
    WAZUH_PKG_ARCH_MAP,
    WAZUH_PROTOCOL,
    WAZUH_REGISTRATION_PORT,
    WAZUH_VERSION,
)

_WAZUH_CONTROL = f"{WAZUH_INSTALL_DIR}/bin/wazuh-control"


def _get_hardware_uuid():
    """Return the macOS hardware UUID, or None on failure.

    The hardware UUID is stable across OS reinstalls and unique per physical
    machine, making it suitable as a stable disambiguator for agent names.
    """
    try:
        result = subprocess.run(
            ["ioreg", "-rd1", "-c", "IOPlatformExpertDevice"],
            capture_output=True, text=True, timeout=5,
        )
        for line in result.stdout.splitlines():
            if "IOPlatformUUID" in line:
                # Line format: "IOPlatformUUID" = "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX"
                return line.split('"')[-2]
    except Exception as e:
        logger.warning(f"Could not read hardware UUID: {e}")
    return None


def get_agent_name():
    """Return a stable, org-unique agent name: hostname + last 8 chars of hardware UUID.

    Using hostname alone causes collisions when multiple machines share a
    default name (e.g. 'MacBook-Air.local').  Appending a short hardware UUID
    suffix makes the name unique per physical device while keeping it
    human-readable on the Wazuh dashboard.

    The result is restricted to alphanumerics, hyphens, and dots to prevent
    shell injection when the name is interpolated into privileged scripts.
    """
    import re
    hostname = socket.gethostname()
    hw_uuid = _get_hardware_uuid()
    if hw_uuid:
        suffix = hw_uuid.replace("-", "")[-12:].upper()
        name = f"{hostname}-{suffix}"
    else:
        name = hostname
    # Strip any character that isn't safe in a shell argument or Wazuh agent
    # name.  Wazuh allows: alphanumerics, hyphens, underscores, dots.
    name = re.sub(r"[^A-Za-z0-9.\-_]", "", name)
    if not name:
        raise ValueError(f"Agent name is empty after sanitizing hostname: {hostname!r}")
    return name


def get_agent_group():
    """Return the user's email (sanitized) as the agent group.

    Replaces '@' with '-' to match the canonical group name created by
    the /verify-otp backend.  Falls back to 'default' if no email is
    stored.
    """
    import re

    email = settings.get("auth", "email", "default")
    if email and email != "default":
        raw = email.replace("@", "-")
        return re.sub(r"[^A-Za-z0-9.\-_]", "", raw) or "default"
    return "default"


def needs_reenrollment():
    """Return True if the agent was enrolled under a different email than the current user.

    This covers: new login with different email, org change, etc.
    Returns False if no prior enrollment is recorded (safe to proceed normally).
    """
    enrolled = settings.get("wazuh", "enrolled_email", "")
    current = settings.get("auth", "email", "")
    if enrolled and current and enrolled != current:
        logger.info(f"[WAZUH] Enrollment mismatch: enrolled={enrolled!r} current={current!r}")
        return True
    return False


_RESISTINE_API_BASE = "https://validate.resistine.work"


def get_package_url():
    """Build the full .pkg download URL from config constants + architecture."""
    arch = platform.machine()
    arch_suffix = WAZUH_PKG_ARCH_MAP.get(arch, "arm64")
    filename = f"wazuh-agent-{WAZUH_VERSION}.{arch_suffix}.pkg"
    return f"{WAZUH_BASE_URL}/{filename}"


def is_agent_installed():
    """Check whether the Wazuh agent is installed.

    The agent's /Library/Ossec/ directory is root-owned and not readable by
    normal users, so checking for files inside it returns False even when
    they exist.  Instead we check for the directory itself (os.path.isdir
    succeeds without read permission) or the launchd plist which is
    world-readable.
    """
    return os.path.isdir(WAZUH_INSTALL_DIR) or os.path.exists(WAZUH_LAUNCHD_PLIST)


def get_agent_status():
    """Return 'Running', 'Stopped', or 'Not Installed'.

    Checks launchd first, then falls back to checking for running
    wazuh-agentd processes (covers the case where the agent was started
    via wazuh-control instead of launchd).
    """
    if not is_agent_installed():
        return "Not Installed"

    # Check launchd service first
    try:
        result = subprocess.run(
            ["launchctl", "print", "system/com.wazuh.agent"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode == 0 and "state = running" in result.stdout:
            return "Running"
    except Exception as e:
        logger.warning(f"Could not query launchd for Wazuh agent: {e}")

    # Fallback: check if wazuh-agentd process is running (covers
    # agents started via wazuh-control instead of launchd)
    try:
        result = subprocess.run(
            ["pgrep", "-x", "wazuh-agentd"],
            capture_output=True,
            timeout=5,
        )
        if result.returncode == 0:
            return "Running"
    except Exception as e:
        logger.warning(f"Could not check wazuh-agentd process: {e}")

    return "Stopped"


def _run_privileged(script, timeout=120):
    """Execute a shell script with admin privileges via osascript.

    Shows the native macOS password dialog. Returns (success, output).
    """
    try:
        escaped = script.replace("\\", "\\\\").replace('"', '\\"')
        cmd = [
            "osascript", "-e",
            f'do shell script "{escaped}" with administrator privileges',
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        output = result.stdout.strip() or result.stderr.strip()
        logger.info(f"_run_privileged: rc={result.returncode} output={output!r}")
        return (result.returncode == 0, output)
    except subprocess.TimeoutExpired:
        logger.error("Privileged command timed out")
        return (False, "Command timed out")
    except Exception as e:
        logger.error(f"Privileged command error: {e}")
        return (False, str(e))


def download_package(progress_callback=None, output_path=None):
    """Download the Wazuh .pkg using curl.

    If output_path is given, downloads directly to that location (creating
    parent dirs as needed).  Otherwise uses a temporary directory.

    Returns the local path on success, or None on failure.
    """
    url = get_package_url()
    if output_path:
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        pkg_path = output_path
    else:
        tmp_dir = tempfile.mkdtemp(prefix="wazuh_")
        pkg_path = os.path.join(tmp_dir, "wazuh-agent.pkg")

    if progress_callback:
        progress_callback("Downloading Wazuh agent...")

    logger.info(f"Downloading Wazuh package from {url}")
    try:
        result = subprocess.run(
            ["/usr/bin/curl", "-fSL", "-o", pkg_path, url],
            capture_output=True,
            text=True,
            timeout=300,
        )
        if result.returncode != 0:
            logger.error(f"curl failed: {result.stderr}")
            return None
        logger.info(f"Downloaded to {pkg_path}")
        return pkg_path
    except Exception as e:
        logger.error(f"Download error: {e}")
        return None


def write_env_file(agent_name, agent_group):
    """Write the Wazuh environment file used during package installation."""
    content = (
        f"WAZUH_MANAGER='{WAZUH_MANAGER}'\n"
        f"WAZUH_MANAGER_PORT='{WAZUH_MANAGER_PORT}'\n"
        f"WAZUH_PROTOCOL='{WAZUH_PROTOCOL}'\n"
        f"WAZUH_REGISTRATION_SERVER='{WAZUH_MANAGER}'\n"
        f"WAZUH_REGISTRATION_PORT='{WAZUH_REGISTRATION_PORT}'\n"
        f"WAZUH_AGENT_NAME='{agent_name}'\n"
        f"WAZUH_AGENT_GROUP='{agent_group}'\n"
    )
    try:
        with open(WAZUH_ENV_FILE, "w") as f:
            f.write(content)
        logger.info(f"Wrote env file to {WAZUH_ENV_FILE}")
        return True
    except Exception as e:
        logger.error(f"Failed to write env file: {e}")
        return False


def _is_service_loaded():
    """Check whether the Wazuh launchd service is already bootstrapped."""
    try:
        result = subprocess.run(
            ["launchctl", "print", "system/com.wazuh.agent"],
            capture_output=True, text=True, timeout=5,
        )
        return result.returncode == 0
    except Exception:
        return False


def start_agent():
    """Start the Wazuh agent via launchd.

    Uses ``launchctl bootstrap`` to load the plist and let launchd
    manage all child processes.  This ensures that ``bootout`` can
    cleanly terminate the entire process tree later, avoiding orphans.

    We intentionally do NOT call ``wazuh-control start`` because it
    spawns processes outside launchd's supervision, which causes
    orphaned processes when ``bootout`` is used to stop the agent.

    If a client.keys backup exists but client.keys is missing (e.g.
    after the app was reinstalled), the key is restored in the same
    privileged call to avoid a second password prompt.
    """
    if _is_service_loaded():
        logger.info("Wazuh launchd service already loaded, nothing to do")
        return True

    parts = []
    # Restore client.keys from backup if it's missing — checked unprivileged
    # first (backup lives outside /Library/Ossec/ so is always readable).
    if os.path.exists(_KEY_BACKUP):
        parts.append(
            f"if [ ! -s '{_CLIENT_KEYS}' ]; then "
            # Try Keychain first (encrypted at rest), fall back to file.
            f"KC=$(security find-generic-password -k '{_KEYCHAIN}' -s '{_KC_SERVICE}' -a '{_KC_ACCOUNT}' -w 2>/dev/null); "
            f"if [ -n \"$KC\" ]; then "
            f"echo \"$KC\" > '{_CLIENT_KEYS}'; "
            f"elif [ -s '{_KEY_BACKUP}' ]; then "
            f"cp '{_KEY_BACKUP}' '{_CLIENT_KEYS}'; "
            f"fi; "
            f"if [ -s '{_CLIENT_KEYS}' ]; then "
            f"chmod 640 '{_CLIENT_KEYS}' && chown root:wazuh '{_CLIENT_KEYS}' && echo KEY_RESTORED; "
            f"fi; "
            f"fi"
        )
    # Re-enable in case the prior uninstall path disabled this label (it does,
    # to dodge Wazuh's anti-tampering kernel retaliation). Without this,
    # bootstrap returns "5: Input/output error" on a previously-disabled
    # service even when the plist + binary are healthy.
    parts.append("launchctl enable system/com.wazuh.agent 2>/dev/null || true")
    parts.append(f"launchctl bootstrap system '{WAZUH_LAUNCHD_PLIST}'")

    script = "; ".join(parts)
    success, output = _run_privileged(script)
    if success:
        if "KEY_RESTORED" in output:
            logger.info("Restored client.keys from backup before starting agent")
        logger.info("Wazuh agent started via launchd")
    else:
        logger.error(f"Failed to start agent: {output}")
    return success


def restore_client_key_if_needed():
    """Restore client.keys from backup if it is missing, then restart the agent.

    Called when Wazuh is already installed (e.g. after a Resistine app
    reinstall) but client.keys was lost.  Returns True if the key was
    already present or was successfully restored; False on failure.

    Returns False without touching anything if the current user's email
    differs from the enrolled email — restoring a stale key from a
    different account would connect the agent to the wrong group.
    The caller (UI) is responsible for prompting a reinstall in that case.
    """
    if needs_reenrollment():
        logger.info("[WAZUH] Skipping key restore — enrolled under different email, reinstall required")
        return False

    if not os.path.exists(_KEY_BACKUP):
        logger.info("No client.keys backup found, nothing to restore")
        return True

    # Only restore and restart if client.keys is actually missing/empty.
    # Do not touch a running agent if the key is already in place.
    # Keychain is tried first (encrypted at rest); file backup is the fallback.
    script = (
        f"if [ ! -s '{_CLIENT_KEYS}' ]; then "
        f"  KC=$(security find-generic-password -k '{_KEYCHAIN}' -s '{_KC_SERVICE}' -a '{_KC_ACCOUNT}' -w 2>/dev/null); "
        f"  if [ -n \"$KC\" ]; then "
        f"    echo \"$KC\" > '{_CLIENT_KEYS}'; "
        f"  elif [ -s '{_KEY_BACKUP}' ]; then "
        f"    cp '{_KEY_BACKUP}' '{_CLIENT_KEYS}'; "
        f"  fi; "
        f"  if [ -s '{_CLIENT_KEYS}' ]; then "
        f"    chmod 640 '{_CLIENT_KEYS}' && chown root:wazuh '{_CLIENT_KEYS}' && "
        f"    launchctl bootout system '{WAZUH_LAUNCHD_PLIST}' 2>/dev/null; "
        f"    launchctl enable system/com.wazuh.agent 2>/dev/null; "
        f"    launchctl bootstrap system '{WAZUH_LAUNCHD_PLIST}' 2>/dev/null; "
        f"    echo KEY_RESTORED; "
        f"  fi; "
        f"else "
        f"  echo KEY_OK; "
        f"fi"
    )
    success, output = _run_privileged(script)
    if success:
        if "KEY_RESTORED" in output:
            logger.info("Restored client.keys from backup and restarted agent")
        else:
            logger.info("client.keys already present, agent untouched")
        return True
    logger.error(f"Failed to restore client.keys: {output}")
    return False


def _has_running_processes():
    """Return True if any wazuh-* daemon processes are running."""
    try:
        result = subprocess.run(
            ["pgrep", "-x", "wazuh-agentd"],
            capture_output=True, timeout=5,
        )
        return result.returncode == 0
    except Exception:
        return False


def stop_agent():
    """Stop the Wazuh agent completely.

    Uses a two-phase approach:
      1. ``launchctl bootout`` to unload the launchd service (if loaded).
      2. ``wazuh-control stop`` to terminate any daemon processes that
         were spawned outside launchd (e.g. by a previous install or
         manual ``wazuh-control start``).

    ``launchctl bootstrap`` does NOT adopt already-running processes,
    so bootout alone cannot kill orphaned daemons.  ``wazuh-control stop``
    reads the PID files in /Library/Ossec/var/run/ and sends SIGTERM
    directly to each daemon, which handles both cases reliably.
    """
    if not is_agent_installed():
        logger.info("Wazuh agent not installed, nothing to stop")
        return True

    # Phase 1: unload launchd service (prevents auto-restart)
    parts = []
    if _is_service_loaded():
        parts.append(f"launchctl bootout system '{WAZUH_LAUNCHD_PLIST}' 2>/dev/null")

    # Phase 2: wazuh-control stop kills daemons via their PID files,
    # then wait briefly for processes to exit after SIGTERM
    parts.append(f"'{_WAZUH_CONTROL}' stop 2>/dev/null")
    parts.append("sleep 2")
    # Ensure the script always exits 0 — we verify via _has_running_processes
    parts.append("true")

    script = "; ".join(parts)
    success, output = _run_privileged(script)
    logger.info(f"stop_agent: privileged script returned success={success} output={output!r}")

    # Verify processes are actually gone
    if _has_running_processes():
        logger.warning("Wazuh processes still running after stop, force-killing")
        kill_script = "pkill -9 -f '/Library/Ossec/bin/wazuh-' 2>/dev/null; true"
        _run_privileged(kill_script)

    stopped = not _has_running_processes()
    if stopped:
        logger.info("Wazuh agent stopped successfully")
    else:
        logger.error("Failed to stop all Wazuh processes")
    return stopped


_KEY_BACKUP = "/Library/Application Support/Resistine/wazuh_client.keys"
_CLIENT_KEYS = f"{WAZUH_INSTALL_DIR}/etc/client.keys"

# macOS System Keychain — primary secure storage for the agent key.
# The file backup (_KEY_BACKUP) is kept as a fallback and as an unprivileged
# sentinel so Python can cheaply decide whether to attempt a privileged restore.
_KEYCHAIN = "/Library/Keychains/System.keychain"
_KC_SERVICE = "com.resistine.wazuh.agent"
_KC_ACCOUNT = "client_key"


def remove_agent(wipe_keys: bool = False):
    """Stop the Wazuh agent and remove /Library/Ossec/ with admin privileges.

    By default, the agent's client.keys is backed up to a persistent location
    outside /Library/Ossec/ before the install directory is wiped, so a later
    reinstall can restore the manager-issued key and skip re-enrollment.

    When ``wipe_keys=True`` (used on user logout) the backup file and System
    Keychain entry are deleted in the same privileged call, so the next user
    cannot inherit the previous account's enrollment.

    Returns True on success.
    """
    if not is_agent_installed() and not _is_service_loaded() and not (wipe_keys and (os.path.exists(_KEY_BACKUP) or _has_keychain_entry())):
        logger.info("Wazuh agent not installed and no key material to wipe")
        return True

    backup_dir = os.path.dirname(_KEY_BACKUP)
    if wipe_keys:
        # Tear everything down and wipe identity: no key backup written, and
        # any existing backup file + Keychain entry are deleted.
        key_phase = (
            f"rm -f '{_KEY_BACKUP}'; "
            f"security delete-generic-password "
            f"-s '{_KC_SERVICE}' -a '{_KC_ACCOUNT}' '{_KEYCHAIN}' 2>/dev/null; "
        )
    else:
        # Preserve the key in two places so reinstall can reconnect without
        # re-enrolling.  Keychain is the primary (encrypted at rest); the file
        # backup is a fallback and unprivileged sentinel for Python checks.
        key_phase = (
            f"mkdir -p '{backup_dir}' && "
            f"cp '{_CLIENT_KEYS}' '{_KEY_BACKUP}' 2>/dev/null && "
            f"security add-generic-password -U "
            f"-k '{_KEYCHAIN}' -s '{_KC_SERVICE}' -a '{_KC_ACCOUNT}' "
            f"-w \"$(cat '{_CLIENT_KEYS}')\" 2>/dev/null; "
        )

    script = (
        f"launchctl bootout system '{WAZUH_LAUNCHD_PLIST}' 2>/dev/null; "
        f"'{_WAZUH_CONTROL}' stop 2>/dev/null; "
        f"pkill -9 -f '/Library/Ossec/bin/wazuh-' 2>/dev/null; "
        f"{key_phase}"
        f"rm -rf '{WAZUH_INSTALL_DIR}'; "
        f"rm -f '{WAZUH_LAUNCHD_PLIST}'"
    )
    success, output = _run_privileged(script)
    if success:
        logger.info(f"Wazuh agent removed successfully (wipe_keys={wipe_keys})")
    else:
        logger.error(f"Failed to remove Wazuh agent: {output}")
    return success


def _has_keychain_entry() -> bool:
    """Return True if the agent's client.keys is present in the System Keychain."""
    try:
        result = subprocess.run(
            ["security", "find-generic-password",
             "-s", _KC_SERVICE, "-a", _KC_ACCOUNT, _KEYCHAIN],
            capture_output=True,
            timeout=5,
        )
        return result.returncode == 0
    except Exception:
        return False


def _get_script_path():
    """Return the absolute path to the postinstall shell script."""
    import sys

    if getattr(sys, "frozen", False):
        # PyInstaller bundle: scripts/ is in the _MEIPASS resource dir
        return os.path.join(sys._MEIPASS, "scripts", "wazuh-postinstall-darwin.sh")
    # Dev mode: project root is 3 levels up from this file
    project_root = os.path.dirname(
        os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    )
    return os.path.join(project_root, "scripts", "wazuh-postinstall-darwin.sh")


def _launch_postinstall(pkg_path, agent_name, agent_group, restore_keys):
    """Launch the postinstall script with admin privileges via osascript.

    Copies the script to /tmp/ before execution because macOS Sequoia's
    com.apple.provenance extended attribute blocks both execution AND
    reading of files created by non-trusted apps (git, editors, etc.)
    when running in a privileged context.  The copy in /tmp/ does not
    inherit the provenance attribute.

    In a signed .app bundle this isn't needed (the bundle signature
    satisfies Gatekeeper), but the copy approach works in both dev and
    production.

    Uses subprocess.Popen so Python doesn't block waiting for the script
    to finish.  start_new_session=True keeps osascript alive if the app
    quits mid-install.

    Returns (launched_ok, status_file_path).
    """
    import shutil
    import uuid

    unique_id = uuid.uuid4().hex[:12]
    status_file = f"/tmp/resistine-wazuh-install-{unique_id}.status"
    log_file = f"/tmp/resistine-wazuh-install-{unique_id}.log"
    script_path = _get_script_path()

    # Copy script to /tmp/ to strip com.apple.provenance xattr
    tmp_script = f"/tmp/resistine-wazuh-postinstall-{unique_id}.sh"
    shutil.copy2(script_path, tmp_script)
    os.chmod(tmp_script, 0o755)

    # Build the argument list for the script
    args = [
        f"--pkg-path {shlex.quote(pkg_path)}",
        f"--agent-name {shlex.quote(agent_name)}",
        f"--agent-group {shlex.quote(agent_group)}",
        f"--manager {shlex.quote(WAZUH_MANAGER)}",
        f"--status-file {shlex.quote(status_file)}",
        f"--log-file {shlex.quote(log_file)}",
    ]
    if restore_keys:
        args.append("--restore-keys")

    shell_cmd = f"{shlex.quote(tmp_script)} {' '.join(args)}"
    escaped = shell_cmd.replace("\\", "\\\\").replace('"', '\\"')

    try:
        proc = subprocess.Popen(
            [
                "osascript", "-e",
                f'do shell script "{escaped}" with administrator privileges',
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            stdin=subprocess.DEVNULL,
            start_new_session=True,
        )
        # Wait briefly to catch immediate failures (user cancelled password)
        try:
            proc.wait(timeout=2)
            # If it returned in <2s, user likely cancelled
            if proc.returncode != 0:
                stderr = proc.stderr.read().decode() if proc.stderr else ""
                logger.error(f"osascript failed immediately: rc={proc.returncode} {stderr}")
                return False, status_file
        except subprocess.TimeoutExpired:
            # Still running = admin prompt accepted, script executing
            pass
        logger.info(f"Postinstall launched (pid={proc.pid}), status_file={status_file}")
        return True, status_file
    except Exception as e:
        logger.error(f"Failed to launch postinstall: {e}")
        return False, status_file


def _poll_install_status(status_file):
    """Read the JSON status file. Returns (finished, success, details_dict)."""
    try:
        with open(status_file) as f:
            data = json.load(f)
        status = data.get("status", "")
        if status == "running":
            return False, False, data
        if status == "success":
            return True, True, data
        return True, False, data  # "failed"
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return False, False, {}


def full_install(progress_callback=None):
    """Orchestrate the complete install flow: download, write env, install, start.

    Launches a standalone shell script with admin privileges that runs
    detached from this process — survives app quit.  Python polls a
    status file to track progress.
    """
    # 1. Download
    if progress_callback:
        progress_callback("Downloading Wazuh agent...")
    pkg_path = download_package(progress_callback)
    if not pkg_path:
        if progress_callback:
            progress_callback("Download failed")
        return False

    # 2. Resolve agent name/group (group is auto-created server-side on enroll).
    agent_name = get_agent_name()
    agent_group = get_agent_group()

    if not write_env_file(agent_name, agent_group):
        if progress_callback:
            progress_callback("Failed to write environment file")
        return False

    # 3. Launch the standalone postinstall script with admin privileges.
    #    Runs via osascript Popen (start_new_session) so it survives app quit.
    if progress_callback:
        progress_callback("Installing Wazuh agent (admin password required)...")

    # Always re-enroll so the manager receives the group in the registration
    # request.  Server-side groups are auto-created on enroll; restoring a
    # stale client.keys would skip that.
    launched, status_file = _launch_postinstall(
        pkg_path, agent_name, agent_group, restore_keys=False
    )
    if not launched:
        logger.error("Failed to launch postinstall script (user cancelled or osascript error)")
        if progress_callback:
            progress_callback("Installation failed")
        return False

    # Poll the status file until the script finishes.  full_install() is
    # called from a background thread (_start_installation), so sleeping is OK.
    _STEP_LABELS = {
        "install_pkg": "Installing package...",
        "patch_config": "Configuring agent...",
        "enrollment": "Enrolling agent...",
        "key_backup": "Backing up keys...",
        "launchd": "Starting agent service...",
        "done": "Finishing up...",
    }
    deadline = time.monotonic() + 300  # 5-minute timeout
    success = False
    details = {}
    while time.monotonic() < deadline:
        time.sleep(3)
        finished, success, details = _poll_install_status(status_file)
        step = details.get("step", "")
        if progress_callback and step:
            progress_callback(_STEP_LABELS.get(step, f"Installing... ({step})"))
        if finished:
            try:
                os.unlink(status_file)
            except OSError:
                pass
            break
    else:
        # Timeout — clean up status file and check if agent installed anyway
        try:
            os.unlink(status_file)
        except OSError:
            pass
        success = is_agent_installed()
        if not success:
            logger.error("Postinstall script timed out")
            if progress_callback:
                progress_callback("Installation timed out")
            return False
        logger.warning("Poll timed out but agent is installed on disk")

    if not success:
        error = details.get("error", "unknown error")
        logger.error(f"Postinstall script failed: {error}")
        if progress_callback:
            progress_callback(f"Installation failed: {error}")
        return False

    # Log enrollment outcome for diagnostics
    enrollment = details.get("enrollment", "")
    if enrollment == "restored":
        logger.info("[WAZUH] Existing enrollment key restored — agent will reconnect as same agent")
    elif enrollment == "enrolled":
        logger.info("[WAZUH] Fresh enrollment succeeded — new agent registered on manager")
    elif enrollment == "enroll_failed":
        logger.warning("[WAZUH] agent-auth enrollment failed — agent may connect via auto-enrollment")

    # Verify the agent is actually running via launchd
    if get_agent_status() == "Running":
        logger.info("Wazuh agent installed and running via launchd")
        if progress_callback:
            progress_callback("Wazuh agent installed and running")
    else:
        logger.warning("Agent installed but not yet running")
        if progress_callback:
            progress_callback("Wazuh agent installed (agent may need manual start)")

    # Record which email this enrollment belongs to so we can detect
    # account changes (different user / org) on future startups.
    settings.set("wazuh", "enrolled_email", settings.get("auth", "email", ""))

    logger.info("Wazuh full install completed successfully")
    return True

"""
sudo /Library/Ossec/bin/wazuh-control restart
Check status:


sudo /Library/Ossec/bin/wazuh-control status
Check logs for the actual error:


sudo tail -50 /Library/Ossec/logs/ossec.log
Run the log command first — paste the output here and I can tell you exactly what's wrong.
"""