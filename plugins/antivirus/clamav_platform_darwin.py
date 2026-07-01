"""ClamAV platform module — macOS (Darwin).

Binary discovery, daemon registration (SMAppService / launchd),
Full Disk Access checks, and library path setup for macOS.

Author: Resistine Team
Copyright (c) Resistine 2025
Licensed under the GNU General Public License v2 or later
"""
from __future__ import annotations

import os
import shlex
import shutil
import subprocess
import sys
import time

from utils.logger import logger


def _applescript_quote(s: str) -> str:
    """Quote a string for AppleScript (double-quote delimited)."""
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


# ── macOS-specific paths ──────────────────────────────────

_SYSTEM_CLAMAV_DIR = "/Library/Application Support/Resistine/clamav"
_SYSTEM_CLAMD_SOCKET = os.path.join(_SYSTEM_CLAMAV_DIR, "run", "clamd.sock")
_SYSTEM_CLAMD_CONF = os.path.join(_SYSTEM_CLAMAV_DIR, "clamd.conf")
_SYSTEM_FRESHCLAM_CONF = os.path.join(_SYSTEM_CLAMAV_DIR, "freshclam.conf")
_SYSTEM_DB_DIR = os.path.join(_SYSTEM_CLAMAV_DIR, "db")
_SYSTEM_LOG_DIR = os.path.join(_SYSTEM_CLAMAV_DIR, "log")
_SYSTEM_RUN_DIR = os.path.join(_SYSTEM_CLAMAV_DIR, "run")

# SMAppService daemon plists (in Contents/Library/LaunchDaemons/).
# Order matters: clamd must be registered before clamonacc. freshclam (the
# signature auto-updater) is independent and registered last.
_DAEMON_PLISTS = [
    "com.resistine.desktop.clamd.plist",
    "com.resistine.desktop.clamonacc.plist",
    "com.resistine.desktop.freshclam.plist",
]

# Label of the freshclam auto-update daemon, used by
# set_freshclam_daemon_enabled() to bootout just this one daemon without
# touching clamd/clamonacc real-time protection.
_FRESHCLAM_DAEMON_LABEL = "com.resistine.desktop.freshclam"

# Legacy plist paths from pre-SMAppService installs
_LEGACY_PLIST_PATHS = [
    "/Library/LaunchDaemons/com.resistine.clamd.plist",
    "/Library/LaunchDaemons/com.resistine.clamonacc.plist",
]

# Legacy SMAppService labels from ≤4.12 — these were renamed to
# com.resistine.desktop.* in 2026-04-14 (commit 57aa3dd). Users updating
# from 4.12 still have the old labels registered in launchd, which fight
# the new labels over the same Unix socket and cause clamd crash loops.
# Bootout cleans them out regardless of plist file presence.
_LEGACY_DAEMON_LABELS = [
    "com.resistine.clamd",
    "com.resistine.clamonacc",
]

# Paths derived from the project source tree (relative to this file).
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
_DEV_ARTIFACTS = os.path.join(
    _PROJECT_ROOT, "scripts", "build", "clamav-artifacts",
)


def _installed_app_contents() -> str | None:
    """Find an installed Resistine.app's Contents/ directory.

    Checks standard macOS application directories rather than assuming
    a single hardcoded path, so it works on any machine.
    """
    for app_dir in ("/Applications", os.path.expanduser("~/Applications")):
        contents = os.path.join(app_dir, "Resistine.app", "Contents")
        if os.path.isdir(contents):
            return contents
    return None


# ── Platform interface ────────────────────────────────────


def system_clamd_socket_path() -> str:
    """Return the system-level clamd socket path."""
    return _SYSTEM_CLAMD_SOCKET


def system_clamd_conf_path() -> str:
    """Return the system-level clamd.conf location."""
    return _SYSTEM_CLAMD_CONF


def system_db_dir() -> str | None:
    """Return system DB dir path if it exists, else None."""
    if os.path.isdir(_SYSTEM_DB_DIR):
        return _SYSTEM_DB_DIR
    return None


def system_db_dir_writable() -> str | None:
    """Return system DB dir if writable by the current user, else None."""
    if os.path.isdir(_SYSTEM_DB_DIR) and os.access(_SYSTEM_DB_DIR, os.W_OK):
        return _SYSTEM_DB_DIR
    return None


def find_binary(name: str) -> str | None:
    """Find a ClamAV binary: running bundle -> installed app -> dev artifacts -> PATH."""
    candidates = []

    # 1. Running app bundle (frozen build — works regardless of install location)
    contents = _app_bundle_contents()
    if contents:
        candidates.append(os.path.join(contents, "Helpers", name))

    # 2. Installed app bundle (for dev mode using signed binaries)
    installed = _installed_app_contents()
    if installed:
        candidates.append(os.path.join(installed, "Helpers", name))

    # 3. Dev build artifacts
    candidates.append(os.path.join(_DEV_ARTIFACTS, "binaries", name))

    for path in candidates:
        resolved = os.path.realpath(path)
        if os.path.isfile(resolved) and os.access(resolved, os.X_OK):
            return resolved

    # 4. System PATH
    return shutil.which(name)


def find_certs_dir() -> str | None:
    """Locate the ClamAV CVD signature-verification certs directory."""
    candidates = []

    # 1. Running app bundle (frozen build — works regardless of install location)
    contents = _app_bundle_contents()
    if contents:
        candidates.append(os.path.join(contents, "certs"))

    # 2. Installed app bundle
    installed = _installed_app_contents()
    if installed:
        candidates.append(os.path.join(installed, "certs"))

    # 3. Dev build artifacts
    candidates.append(os.path.join(_DEV_ARTIFACTS, "certs"))

    # 4. ClamAV-Mac sibling repo (dev convenience — checked out alongside)
    clamav_sibling = os.path.join(_PROJECT_ROOT, "..", "ClamAV-Mac")
    candidates.append(os.path.join(clamav_sibling, "install", "etc", "certs"))
    candidates.append(os.path.join(clamav_sibling, "certs"))

    for path in candidates:
        resolved = os.path.realpath(path)
        if os.path.isdir(resolved) and os.path.isfile(
            os.path.join(resolved, "clamav.crt"),
        ):
            return resolved
    return None


def clamav_env() -> dict[str, str]:
    """Return env dict with library paths, SSL certs, and CVD certs for ClamAV."""
    env = os.environ.copy()

    # Override the CVD signature-verification certs directory.
    if "CVD_CERTS_DIR" not in env:
        certs_dir = find_certs_dir()
        if certs_dir:
            env["CVD_CERTS_DIR"] = certs_dir

    # Point OpenSSL at the system CA bundle so freshclam can verify TLS.
    if "SSL_CERT_FILE" not in env:
        for ca_path in (
            "/etc/ssl/cert.pem",                           # macOS
            "/etc/ssl/certs/ca-certificates.crt",          # Debian/Ubuntu
            "/etc/pki/tls/certs/ca-bundle.crt",            # RHEL/Fedora
        ):
            if os.path.isfile(ca_path):
                env["SSL_CERT_FILE"] = ca_path
                break

    if not getattr(sys, "frozen", False):
        lib_dirs = []
        # Installed app bundle frameworks
        installed = _installed_app_contents()
        if installed:
            fw = os.path.join(installed, "Frameworks")
            if os.path.isdir(fw):
                lib_dirs.append(fw)
        # Dev build artifacts
        lib_dir = os.path.join(_DEV_ARTIFACTS, "lib")
        if os.path.isdir(lib_dir):
            lib_dirs.append(lib_dir)
        if lib_dirs:
            existing = env.get("DYLD_LIBRARY_PATH", "")
            combined = ":".join(lib_dirs)
            env["DYLD_LIBRARY_PATH"] = (
                f"{combined}:{existing}" if existing else combined
            )
    return env


def is_app_bundle() -> bool:
    """Return True if running inside a .app bundle."""
    return (
        ".app/Contents/MacOS" in sys.executable
        or ".app/Contents/MacOS" in os.path.abspath(sys.argv[0])
    )


def daemons_approved() -> bool:
    """Check if ClamAV daemons are approved in Login Items via SMAppService."""
    if not is_app_bundle():
        return False
    try:
        from ServiceManagement import SMAppService

        for plist_name in _DAEMON_PLISTS:
            try:
                service = SMAppService.daemonServiceWithPlistName_(plist_name)
                status = int(service.status())
                if status != 1:  # 1 = enabled
                    return False
            except Exception:
                return False
        return True
    except ImportError:
        return False


def has_full_disk_access() -> bool:
    """Check whether clamonacc has Full Disk Access.

    clamonacc requires FDA for the Endpoint Security Framework.
    Rather than probing TCC-protected paths (which checks *our* process,
    not clamonacc's), we check clamonacc's actual runtime state:

    - If clamonacc is running → FDA is granted (it would crash without it).
    - If the system daemon is loaded but clamonacc isn't running → it's
      crash-looping, which means FDA (or ESF entitlement) is missing.
    - If the daemon isn't loaded yet → we can't tell, so fall back to a
      TCC directory probe as a best-effort hint.
    """
    # Direct check: if clamonacc is alive, it has FDA.
    if is_clamonacc_running():
        return True

    # If the launchd job is loaded AND the system config exists (meaning
    # the postinstall script has been run), a crash-looping clamonacc
    # indicates missing FDA. Without the config, clamonacc crashes because
    # it can't find its config file — not because of FDA.
    #
    # IMPORTANT: only blame FDA if system clamd is actually running.
    # clamonacc depends on clamd's socket — if clamd is still loading its
    # 500 MB+ signature DB, clamonacc will restart repeatedly trying to
    # connect. That's a transient startup issue, not an FDA denial.
    if os.path.exists(_SYSTEM_CLAMD_CONF):
        from plugins.antivirus.clamav_common import _ping_socket

        try:
            result = subprocess.run(
                ["launchctl", "print",
                 "system/com.resistine.desktop.clamonacc"],
                capture_output=True, text=True, timeout=5,
            )
            if result.returncode == 0:
                output = result.stdout
                for line in output.splitlines():
                    stripped = line.strip()
                    if stripped.startswith("runs = "):
                        try:
                            runs = int(stripped.split("=")[1].strip())
                            if runs > 3:
                                if _ping_socket(_SYSTEM_CLAMD_SOCKET):
                                    # clamd is ready but clamonacc has
                                    # crashed multiple times. Could be a
                                    # genuine FDA issue OR a transient
                                    # startup race (clamonacc couldn't
                                    # connect while clamd was loading
                                    # signatures). Poll for up to ~4s
                                    # (reduced from 12s to avoid blocking
                                    # plugin init on every status check;
                                    # the launchd ThrottleInterval is 10s
                                    # but 4s covers most transient races).
                                    for _retry in range(8):
                                        time.sleep(0.5)
                                        if is_clamonacc_running():
                                            logger.debug(
                                                "FDA check: clamonacc "
                                                "recovered — FDA is OK",
                                            )
                                            return True
                                    logger.debug(
                                        f"FDA check: clamonacc crash-looping "
                                        f"({runs} runs) with clamd running"
                                        f" — likely missing FDA",
                                    )
                                    return False
                                logger.debug(
                                    f"FDA check: clamonacc restarting "
                                    f"({runs} runs) but clamd not ready "
                                    f"— not an FDA issue",
                                )
                        except ValueError:
                            pass
        except Exception:
            pass

    # Final check: clamonacc may have started between the early-return
    # check and the crash-loop analysis above.
    if is_clamonacc_running():
        return True

    # Fallback: probe a TCC-protected directory as a hint.
    # This checks *our* process, not clamonacc, but is a reasonable
    # proxy when the daemon hasn't been loaded yet.
    probes = [
        os.path.expanduser("~/Library/Mail"),
        os.path.expanduser("~/Library/Safari"),
        os.path.expanduser("~/Library/Cookies"),
    ]
    for probe in probes:
        try:
            os.listdir(probe)
            return True
        except PermissionError:
            return False
        except FileNotFoundError:
            continue

    # When we can't determine FDA status (no TCC-protected dirs found),
    # assume it's available. If clamonacc actually lacks FDA, the
    # crash-loop check will catch it definitively once daemons are loaded.
    # Defaulting to False here causes a premature "FDA Required" screen
    # before the user has even started protection.
    logger.debug("FDA check: cannot determine status, assuming granted")
    return True


def open_fda_settings():
    """Open System Settings to the Full Disk Access pane."""
    try:
        subprocess.Popen(
            ["open", "x-apple.systempreferences:"
             "com.apple.preference.security?Privacy_AllFiles"],
        )
        logger.info("Opened System Settings — Full Disk Access")
    except Exception as exc:
        logger.error(f"Could not open FDA settings: {exc}")


def open_login_items_settings():
    """Open System Settings to the Login Items pane."""
    try:
        from ServiceManagement import SMAppService

        svc = SMAppService.daemonServiceWithPlistName_(_DAEMON_PLISTS[0])
        svc.openSystemSettingsLoginItems()
        logger.info("Opened System Settings — Login Items")
    except Exception:
        try:
            subprocess.Popen(
                ["open", "x-apple.systempreferences:"
                 "com.apple.LoginItems-Settings.extension"],
            )
            logger.info("Opened System Settings — Login Items (fallback)")
        except Exception as exc:
            logger.error(f"Could not open Login Items settings: {exc}")


def is_clamonacc_running() -> bool:
    """Check if clamonacc is running (by process name)."""
    try:
        result = subprocess.run(
            ["pgrep", "-x", "clamonacc"],
            capture_output=True, timeout=5,
        )
        return result.returncode == 0
    except Exception:
        return False


# ── SMAppService daemon registration (macOS 13+) ────────


def _daemon_loaded(label: str) -> bool:
    """Return True if *label* is loaded in the launchd system domain."""
    try:
        result = subprocess.run(
            ["launchctl", "print", f"system/{label}"],
            capture_output=True, timeout=5,
        )
        return result.returncode == 0
    except Exception:
        return False


def ensure_daemons_registered():
    """Register ClamAV LaunchDaemons via SMAppService.

    Called from the plugin init on a background thread. Follows the same
    pattern as the VPN helper registration in vpn_functions_darwin.py.

    After registration, verifies that each daemon is actually loaded in
    launchd. SMAppService status == 1 ("enabled") only means the user
    approved the daemon in Login Items — launchd may not have loaded it
    (e.g. after an update, crash-loop, or first registration). When this
    is detected, we unregister and re-register to trigger a fresh load.
    """
    if not (
        ".app/Contents/MacOS" in sys.executable
        or ".app/Contents/MacOS" in os.path.abspath(sys.argv[0])
    ):
        logger.debug("Skipping ClamAV daemon registration (not an app bundle)")
        return

    try:
        from ServiceManagement import SMAppService
    except ImportError:
        logger.warning("ServiceManagement framework not available")
        return

    needs_approval = False

    for plist_name in _DAEMON_PLISTS:
        try:
            service = SMAppService.daemonServiceWithPlistName_(plist_name)
        except Exception:
            try:
                service = SMAppService.daemonWithPlistName_(plist_name)
            except Exception:
                logger.warning(f"Could not create SMAppService for {plist_name}")
                continue

        status = int(service.status())
        status_map = {
            0: "notRegistered",
            1: "enabled",
            2: "requiresApproval",
            3: "notFound",
        }
        label = plist_name.replace(".plist", "")
        logger.info(
            f"ClamAV daemon {plist_name}: {status_map.get(status, 'unknown')}",
        )

        if status == 2:
            needs_approval = True
            continue

        if status == 1:
            # Enabled in Login Items — verify it's actually loaded in
            # launchd. If not, unregister and re-register to trigger a
            # fresh bootstrap.
            if _daemon_loaded(label):
                continue
            logger.warning(
                f"ClamAV daemon {label} is enabled but not loaded "
                f"in launchd — re-registering",
            )
            try:
                service.unregisterAndReturnError_(None)
            except Exception as exc:
                logger.debug(f"Unregister {label} failed: {exc}")
            # Small delay so BTM processes the unregister before we
            # re-register — avoids a "already registered" no-op.
            time.sleep(0.5)
            # Fall through to the register path below

        # Not registered (0), not found (3), or re-registering after
        # an enabled-but-not-loaded state.
        success, err = service.registerAndReturnError_(None)
        if not success:
            logger.error(f"ClamAV daemon registration error ({plist_name}): {err}")
            if int(service.status()) == 2:
                needs_approval = True
        else:
            logger.info(f"ClamAV daemon {plist_name} registered successfully")

    if needs_approval:
        logger.warning("ClamAV daemons require user approval in Login Items")


# ── System daemon activation ─────────────────────────────


def activate_system_daemons() -> tuple[bool, str]:
    """Start the system-level ClamAV daemons (clamd + clamonacc).

    Symmetric counterpart to deactivate_system_daemons(). The daemons are
    SMAppService-managed and provisioned by the installer flow
    (trigger_system_setup / the postinstall script), so "starting" an
    already-registered-but-offline daemon just means (re)loading it in launchd.
    ensure_daemons_registered() re-bootstraps any daemon that's
    enabled-but-not-loaded (e.g. after a bootout/stop, or a crash that KeepAlive
    didn't recover) without a second admin prompt. We then poll launchd to
    confirm the protection daemons actually came up.

    Returns (ok, message). Backs the "Start Protection" banner action when the
    app bundle is installed but the daemons aren't running.
    """
    if not is_app_bundle():
        return False, "Real-time protection requires the installed app."

    try:
        ensure_daemons_registered()
    except Exception as exc:
        logger.error(f"ClamAV: activating system daemons failed: {exc}")
        return False, str(exc)

    # freshclam is auto-update, not real-time protection — only clamd and
    # clamonacc gate the "protection running" state.
    protection_labels = [
        "com.resistine.desktop.clamd",
        "com.resistine.desktop.clamonacc",
    ]
    # Give launchd a moment to bring the daemons up after (re)registration.
    for _ in range(10):
        if all(_daemon_loaded(label) for label in protection_labels):
            return True, "Protection started."
        time.sleep(0.5)

    if any(_daemon_loaded(label) for label in protection_labels):
        return True, "Protection is starting…"

    # Nothing loaded — the daemons most likely still need approval in Login
    # Items (SMAppService can't bootstrap until the user approves).
    return False, (
        "Couldn't start protection automatically. Enable the Resistine ClamAV "
        "daemons in System Settings › General › Login Items."
    )


def _app_bundle_contents() -> str | None:
    """Return the Contents/ dir of the running .app bundle, or None."""
    for base in (sys.executable, os.path.abspath(sys.argv[0])):
        idx = base.find(".app/Contents/MacOS")
        if idx != -1:
            return os.path.realpath(base[: idx + len(".app/Contents")])
    return None


def _generate_system_clamd_conf() -> str:
    """Generate clamd.conf content for the system-level daemon.

    This config is shared by clamd AND clamonacc (which reads it via
    ``--config-file``).  The OnAccess* directives are required for
    clamonacc's real-time ESF monitoring — without OnAccessIncludePath
    clamonacc exits with "No OnAccessIncludePath configured".
    """
    import tempfile

    return (
        "# Auto-generated by Resistine — do not edit manually\n"
        f"LocalSocket {_SYSTEM_CLAMD_SOCKET}\n"
        f"PidFile {_SYSTEM_RUN_DIR}/clamd.pid\n"
        f"DatabaseDirectory {_SYSTEM_DB_DIR}\n"
        f"LogFile {_SYSTEM_LOG_DIR}/clamd.log\n"
        "LogFileMaxSize 5M\n"
        "LogTime yes\n"
        "LogVerbose yes\n"
        "LogClean yes\n"
        "MaxThreads 8\n"
        f"TemporaryDirectory {tempfile.gettempdir()}\n"
        "MaxDirectoryRecursion 20\n"
        "FollowDirectorySymlinks yes\n"
        "SelfCheck 60\n"
        "ExcludePath ^/proc\n"
        "ExcludePath ^/sys\n"
        "ExcludePath ^/dev\n"
        "\n"
        "# On-access real-time monitoring (clamonacc via ESF)\n"
        "OnAccessIncludePath /Users\n"
        "OnAccessIncludePath /Applications\n"
        "OnAccessIncludePath /private/tmp\n"
        f"OnAccessExcludePath {_SYSTEM_CLAMAV_DIR}\n"
        "OnAccessPrevention no\n"
        "OnAccessExtraScanning yes\n"
        "OnAccessMaxFileSize 50M\n"
    )


def _generate_system_freshclam_conf() -> str:
    """Generate freshclam.conf content for system-level DB updates."""
    conf = (
        "# Auto-generated by Resistine — do not edit manually\n"
        f"DatabaseDirectory {_SYSTEM_DB_DIR}\n"
        f"UpdateLogFile {_SYSTEM_LOG_DIR}/freshclam.log\n"
        "LogFileMaxSize 2M\n"
        "LogTime yes\n"
        "DatabaseMirror database.clamav.net\n"
        f"NotifyClamd {_SYSTEM_CLAMD_CONF}\n"
        # Run by the root LaunchDaemon. Without this, freshclam drops to the
        # default "clamav" user (absent on macOS) and fails to open the
        # root-owned UpdateLogFile, so signatures silently never update.
        "DatabaseOwner root\n"
    )
    certs_dir = find_certs_dir()
    if certs_dir:
        conf += f"CVDCertsDirectory {certs_dir}\n"
    return conf


def _get_postinstall_script_path() -> str:
    """Return the absolute path to the ClamAV postinstall shell script."""
    if getattr(sys, "frozen", False):
        # PyInstaller bundle: scripts/ is in the _MEIPASS resource dir
        return os.path.join(sys._MEIPASS, "scripts", "clamav-postinstall-darwin.sh")
    # Dev mode: project root is 2 levels up from this file
    return os.path.join(_PROJECT_ROOT, "scripts", "clamav-postinstall-darwin.sh")


def _launch_clamav_postinstall(db_source: str) -> tuple[bool, str]:
    """Launch the ClamAV postinstall script with admin privileges.

    Copies the script to /tmp/ to strip com.apple.provenance xattr
    (Sequoia). Launches via osascript with start_new_session=True so
    the script survives app quit.

    Returns (launched_ok, status_file_path, osascript_pid).
    """
    import uuid

    contents = _app_bundle_contents()
    if not contents:
        # Dev mode: fall back to the installed app bundle
        installed = "/Applications/Resistine.app/Contents"
        if os.path.isdir(installed):
            contents = installed
            logger.info("ClamAV: using installed app bundle for postinstall")
        else:
            logger.error("ClamAV: no app bundle found (install Resistine.app first)")
            return False, "", 0

    unique_id = uuid.uuid4().hex[:12]
    status_file = f"/tmp/resistine-clamav-install-{unique_id}.status"
    log_file = f"/tmp/resistine-clamav-install-{unique_id}.log"
    script_path = _get_postinstall_script_path()

    # Copy script to /tmp/ to strip com.apple.provenance xattr
    import shutil as _shutil

    tmp_script = f"/tmp/resistine-clamav-postinstall-{unique_id}.sh"
    _shutil.copy2(script_path, tmp_script)
    os.chmod(tmp_script, 0o755)

    args = [
        f"--app-contents {shlex.quote(contents)}",
        f"--db-source {shlex.quote(db_source)}",
        f"--status-file {shlex.quote(status_file)}",
        f"--log-file {shlex.quote(log_file)}",
    ]

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
            if proc.returncode != 0:
                stderr = proc.stderr.read().decode() if proc.stderr else ""
                logger.error(
                    f"ClamAV postinstall osascript failed: "
                    f"rc={proc.returncode} {stderr}",
                )
                return False, status_file, 0
        except subprocess.TimeoutExpired:
            # Still running = admin prompt accepted, script executing
            pass
        logger.info(
            f"ClamAV postinstall launched (pid={proc.pid}), "
            f"status_file={status_file}",
        )
        return True, status_file, proc.pid
    except Exception as e:
        logger.error(f"ClamAV: failed to launch postinstall: {e}")
        return False, status_file, 0


def _poll_setup_status(status_file: str) -> tuple[bool, bool, dict]:
    """Read the JSON status file written by the postinstall script.

    Returns (finished, success, details_dict).

    Hardening:
    - If status is "running" but PID is dead, treat as crashed.
    - If file is >5 min old and still "running", treat as stale.
    """
    import json

    try:
        with open(status_file) as f:
            data = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return False, False, {}

    status = data.get("status", "")

    if status == "success":
        return True, True, data

    if status == "failed":
        return True, False, data

    if status == "running":
        # Check if the process is still alive
        pid = data.get("pid")
        if pid:
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                logger.warning(
                    f"ClamAV: postinstall PID {pid} is dead — treating as crash",
                )
                data["error"] = "Script process died unexpectedly"
                data["error_code"] = "PROCESS_CRASHED"
                return True, False, data
            except PermissionError:
                pass  # Process exists but runs as root — still alive

        # Check for stale status file (>5 min)
        ts = data.get("ts", 0)
        if ts and (time.time() - ts) > 300:
            logger.warning("ClamAV: postinstall status file is stale (>5 min)")
            data["error"] = "Script timed out (stale status file)"
            data["error_code"] = "SCRIPT_STALE"
            return True, False, data

        return False, False, data

    return False, False, data


def deactivate_system_daemons() -> tuple[bool, str]:
    """Stop system-level ClamAV daemons. Requires admin privileges."""
    cmds = []
    for plist_name in reversed(_DAEMON_PLISTS):
        label = plist_name.replace(".plist", "")
        cmds.append(f"launchctl bootout system/{label} 2>/dev/null || true")
    # Also bootout legacy labels and remove their plists in case the user
    # is uninstalling after an incomplete migration from ≤4.12 — leaves
    # no orphaned daemons or plist files behind.
    for label in _LEGACY_DAEMON_LABELS:
        cmds.append(f"launchctl bootout system/{label} 2>/dev/null || true")
    for plist in _LEGACY_PLIST_PATHS:
        cmds.append(f"rm -f {shlex.quote(plist)}")

    script = "; ".join(cmds)
    logger.info("ClamAV: deactivating system daemons")

    try:
        result = subprocess.run(
            [
                "osascript", "-e",
                "do shell script " + _applescript_quote(script)
                + " with administrator privileges",
            ],
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode == 0:
            return True, "Protection deactivated."
        return False, (result.stderr or "").strip() or "Failed."
    except Exception as exc:
        return False, str(exc)


def set_freshclam_daemon_enabled(enabled: bool) -> tuple[bool, str]:
    """Enable or disable the freshclam signature auto-update daemon.

    On macOS the "auto-update" setting controls the OS-level LaunchDaemon
    (com.resistine.desktop.freshclam) rather than an in-process thread, so
    updates run even while the app is closed.

    Enable → ``ensure_daemons_registered()`` (idempotent; re-registering an
    already-loaded daemon is a cheap no-op). Disable → bootout ONLY the
    freshclam label via the osascript-admin pattern. We deliberately do NOT
    call ``deactivate_system_daemons()`` on disable — that would also bootout
    clamd/clamonacc and kill real-time protection.
    """
    if enabled:
        try:
            ensure_daemons_registered()
            return True, "Auto-update enabled."
        except Exception as exc:
            logger.error(f"ClamAV: enabling freshclam daemon failed: {exc}")
            return False, str(exc)

    # Disable: bootout just the freshclam daemon.
    script = (
        f"launchctl bootout system/{_FRESHCLAM_DAEMON_LABEL} "
        f"2>/dev/null || true"
    )
    logger.info("ClamAV: disabling freshclam auto-update daemon")
    try:
        result = subprocess.run(
            [
                "osascript", "-e",
                "do shell script " + _applescript_quote(script)
                + " with administrator privileges",
            ],
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode == 0:
            return True, "Auto-update disabled."
        return False, (result.stderr or "").strip() or "Failed."
    except Exception as exc:
        return False, str(exc)


def refresh_system_configs():
    """Rewrite system-level ClamAV configs if the DB dir is writable.

    Called after a Sparkle update to ensure configs reflect the current
    app bundle (e.g. updated CVDCertsDirectory path).  Only rewrites
    files the current user can write — no admin prompt.
    """
    if not os.path.isdir(_SYSTEM_CLAMAV_DIR):
        return  # System not set up yet

    for path, content in (
        (_SYSTEM_CLAMD_CONF, _generate_system_clamd_conf()),
        (_SYSTEM_FRESHCLAM_CONF, _generate_system_freshclam_conf()),
    ):
        try:
            with open(path, "w") as f:
                f.write(content)
            logger.debug(f"ClamAV: refreshed {os.path.basename(path)}")
        except PermissionError:
            logger.debug(f"ClamAV: cannot refresh {path} (permission denied)")
