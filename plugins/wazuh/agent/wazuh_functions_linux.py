"""
Wazuh Agent Functions for Linux
Handles download, install, start/stop of the Wazuh SIEM agent using systemd and package managers.
Author: Resistine Team
Copyright (c) Resistine 2025
Licensed under the GNU General Public License v2 or later
"""

import os
import socket
import subprocess
import tempfile
import shutil
import re

from utils import settings
from utils.logger import logger
from gui.dialogs import CTkPasswordDialog

from plugins.wazuh.agent import enrollment, phoenix_packages
from plugins.wazuh.config import (
    WAZUH_MANAGER,
    WAZUH_MANAGER_PORT,
    WAZUH_PROTOCOL,
    WAZUH_REGISTRATION_PORT,
    LINUX_WAZUH_DIR,
    LINUX_WAZUH_DIR_CANDIDATES,
)

# Deployment-variable prefix passed to the package installer.  Carries the
# manager address, ports, protocol, agent name, and group so the package's
# preinstall hook patches ossec.conf accordingly.
def _deploy_env(agent_name, agent_group):
    return (
        f"WAZUH_MANAGER='{WAZUH_MANAGER}' "
        f"WAZUH_MANAGER_PORT='{WAZUH_MANAGER_PORT}' "
        f"WAZUH_PROTOCOL='{WAZUH_PROTOCOL}' "
        f"WAZUH_REGISTRATION_SERVER='{WAZUH_MANAGER}' "
        f"WAZUH_REGISTRATION_PORT='{WAZUH_REGISTRATION_PORT}' "
        f"WAZUH_AGENT_NAME='{agent_name}' "
        f"WAZUH_AGENT_GROUP='{agent_group}'"
    )

def run_privileged_command(command, timeout=120):
    """
    Run a command with elevated privileges using pkexec or sudo.
    Shows the password dialog if sudo is used.
    Returns (success, output).
    """
    if os.geteuid() == 0:
        try:
            result = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
        except Exception as e:
            logger.error(f"Error running command as root: {e}")
            return False, str(e)
        out = result.stdout.strip()
        if result.returncode != 0:
            logger.error(f"Command failed as root (code {result.returncode}): {result.stderr.strip()}")
            return False, result.stderr.strip() + out
        return True, out

    logger.info(f"Attempting to run with pkexec: {command}")
    try:
        result = subprocess.run(
            ["pkexec"] + command, capture_output=True, text=True, timeout=timeout
        )
        if result.returncode == 0:
            return True, result.stdout.strip()
        else:
            logger.warning(
                f"pkexec failed (code {result.returncode}): {result.stderr.strip()}. Falling back to sudo."
            )
    except FileNotFoundError:
        logger.warning("pkexec not found, falling back to sudo")
    except Exception as e:
        logger.warning(f"Error running pkexec: {e}")

    logger.info("Falling back to sudo with themed password prompt")
    dialog = CTkPasswordDialog(title="Authentication Required", text="Enter password to modify Wazuh Agent settings:")
    password = dialog.get_input()

    if not password:
        logger.error("User cancelled password prompt")
        return False, "User cancelled"

    try:
        # Pass password to sudo via standard input
        sudo_command = ["sudo", "-S", "-p", ""] + command
        result = subprocess.run(
            sudo_command,
            input=password + "\n",
            capture_output=True,
            text=True,
            timeout=timeout
        )
        if result.returncode == 0:
            return True, result.stdout.strip()
        else:
            logger.error(f"sudo failed: {result.stderr.strip() + result.stdout.strip()}")
            return False, result.stderr.strip() + result.stdout.strip()
    except Exception as e:
        logger.error(f"Error executing command with sudo: {e}")
        return False, str(e)


def _get_machine_id():
    """Return the Linux machine ID."""
    for path in ["/etc/machine-id", "/var/lib/dbus/machine-id"]:
        try:
            with open(path, "r") as f:
                return f.read().strip()
        except Exception:
            pass
    return None

def get_agent_name():
    """Return a stable, org-unique agent name."""
    hostname = socket.gethostname()
    machine_id = _get_machine_id()
    if machine_id:
        suffix = machine_id.replace("-", "")[-12:].upper()
        name = f"{hostname}-{suffix}"
    else:
        name = hostname
    return re.sub(r"[^A-Za-z0-9.\-_]", "", name)

def get_agent_group():
    """The Wazuh group of this user's agents (u_<Matrix localpart>)."""
    return enrollment.agent_group()

def needs_reenrollment():
    enrolled = settings.get("wazuh", "enrolled_email", "")
    current = settings.get("auth", "email", "")
    if enrolled and current and enrolled != current:
        return True
    return False

def _set_ossec_agent_name(ossec_conf, agent_name):
    """Shell that pins wazuh-agentd's enrollment <agent_name> in ossec.conf.

    The stock Wazuh agent config ships with NO <agent_name> — and often no
    <enrollment> block at all (e.g. the RPM's CentOS-profile config) — so a
    plain sed-replace is a no-op and wazuh-agentd's built-in auto-enrollment
    falls back to the bare hostname ('archlinux' instead of the unique
    'archlinux-<uuid>'). Worst on Arch, where bsdtar extraction runs no postinst
    to apply WAZUH_AGENT_NAME. Handle all three shapes:

      1. <agent_name> already present  -> replace it
      2. <enrollment> present, no name -> insert <agent_name> into it
      3. neither                       -> insert a full <enrollment> block
                                          at the end of <agent> (5.0), or of
                                          <client> in a config kept from 4.x
    """
    return (
        f"if grep -q '<agent_name>' '{ossec_conf}'; then "
        f"sed -i 's|<agent_name>.*</agent_name>|<agent_name>{agent_name}</agent_name>|' '{ossec_conf}'; "
        f"elif grep -q '<enrollment>' '{ossec_conf}'; then "
        f"sed -i 's|<enrollment>|<enrollment>\\n      <agent_name>{agent_name}</agent_name>|' '{ossec_conf}'; "
        f"else "
        f"tag=client; grep -q '</agent>' '{ossec_conf}' && tag=agent; "
        f"sed -i \"s|</$tag>|  <enrollment>\\n      <agent_name>{agent_name}</agent_name>\\n    </enrollment>\\n  </$tag>|\" '{ossec_conf}'; "
        f"fi"
    )


def _set_ossec_enrollment(ossec_conf, agent_name, agent_group):
    """Pin BOTH <agent_name> and <groups> in the <enrollment> block.

    agent-auth's -A/-G only set the name/group for that one explicit
    registration. wazuh-agentd's built-in auto-enrollment (which fires on a
    plain restart with no valid key — e.g. a region switch or key wipe) reads
    <enrollment><agent_name>/<groups> from ossec.conf instead. The stock config
    has neither tag, so auto-enrollment lands under the bare hostname with NO
    group. Setting both here keeps every enrollment path (explicit or auto) on
    the same unique name AND the correct group. Runs after _set_ossec_agent_name
    so the <enrollment> block is guaranteed to exist for the <groups> insert.
    """
    return (
        _set_ossec_agent_name(ossec_conf, agent_name)
        + "\n"
        + (
            # Only the <groups> inside <enrollment>: other modules have their
            # own (syscollector's <groups>yes</groups>), and changing those
            # stops wazuh-modulesd ("Invalid content for tag 'groups'").
            f"sed -i '/<enrollment>/,/<\\/enrollment>/{{/<groups>/d}}' '{ossec_conf}'; "
            f"sed -i 's|<enrollment>|<enrollment>\\n      <groups>{agent_group}</groups>|' '{ossec_conf}'"
        )
        + "\n"
        + _set_ossec_manager(ossec_conf)
    )


def _set_ossec_manager(ossec_conf):
    """Shell that fills in the manager if the package left its placeholder.

    The package's install script normally writes the manager from
    WAZUH_MANAGER; when it fails (the 5.0.0-1 .deb's postinst looks in
    /var/ossec instead of /opt/phoenix-agent), ossec.conf keeps MANAGER_IP and
    wazuh-agentd exits with "Invalid server address found: 'MANAGER_IP'".
    """
    return (
        f"sed -i -e 's|<endpoint>MANAGER_IP</endpoint>|<endpoint>{WAZUH_MANAGER}:{WAZUH_MANAGER_PORT}</endpoint>|' "
        f"-e 's|<address>MANAGER_IP</address>|<address>{WAZUH_MANAGER}</address>|' '{ossec_conf}'"
    )


def _make_agent_state_readable():
    """Best-effort shell to let the (non-root) app read the agent's live state.

    wazuh-agentd.state + ossec.log are root-owned and /var/ossec/var/run isn't
    even traversable by the app user, so the UI's connection status reads as
    'unknown'. Make the dirs traversable and the files world-readable so
    get_agent_connection() can report connected/pending/disconnected. Guarded so
    a permissions quirk never fails the enroll. (wazuh-agentd truncate-writes
    the state file, so the mode persists across updates.)
    """
    run = f"{LINUX_WAZUH_DIR}/var/run"
    return (
        f"chmod o+rx '{LINUX_WAZUH_DIR}/var' '{run}' '{LINUX_WAZUH_DIR}/logs' 2>/dev/null || true; "
        f"chmod o+r '{run}/wazuh-agentd.state' 2>/dev/null || true; "
        f"chmod o+r '{LINUX_WAZUH_DIR}/logs/ossec.log' 2>/dev/null || true"
    )


def _get_os_info():
    """Determine package family (deb, rpm, arch) using LinuxDistro utility.

    openSUSE/SLES is rpm-based — it uses the same .rpm artifact and the same
    ``rpm -ihv`` install path as Fedora — so it maps to "rpm".  remove_agent
    picks the correct uninstall tool (zypper vs dnf/yum) from the detected
    package manager independently, so it doesn't need its own family here.
    """
    from utils.distro import LinuxDistro
    if LinuxDistro.is_debian_like():
        return "deb"
    if LinuxDistro.is_fedora_like() or LinuxDistro.is_suse_like():
        return "rpm"
    if LinuxDistro.is_arch_like():
        return "arch"
    return None

# Package store platform per package family (amd64 only).
_PACKAGE_PLATFORMS = {"deb": "linux-amd64", "rpm": "linux-amd64-rpm"}


def package_platform():
    """The package store platform for this machine, or None when none is built.

    Debian/Ubuntu get the .deb (linux-amd64), Fedora/RHEL/openSUSE the .rpm
    (linux-amd64-rpm).
    """
    if phoenix_packages.platform_key() != "linux-amd64":
        return None
    return _PACKAGE_PLATFORMS.get(_get_os_info())


def get_package_url():
    """Manifest URL of the Phoenix agent for this machine, or None."""
    plat = package_platform()
    return phoenix_packages.manifest_url(plat) if plat else None

def installed_agent_dir():
    """Return the install dir of an existing agent, or None.

    Only the directory itself is stat'ed, so a root-only (0700) tree such as
    the NixOS module's /opt/resistine is still detected.
    """
    for d in LINUX_WAZUH_DIR_CANDIDATES:
        if os.path.isdir(d):
            return d
    return None


def is_agent_installed():
    return installed_agent_dir() is not None


_APP_INSTALLED = "app_installed"  # wazuh settings flag, set by full_install()


def is_app_managed_agent():
    """True only for the agent this app installed (the Phoenix .deb in
    /opt/phoenix-agent, installed by full_install()).

    The same package may also have been installed by an admin, and an agent
    under another candidate dir was installed some other way (an upstream
    package, the NixOS module); the app shows those but never removes or
    re-enrolls them.
    """
    return os.path.isdir(LINUX_WAZUH_DIR) and bool(settings.get("wazuh", _APP_INSTALLED, False))

def get_agent_status():
    if not is_agent_installed():
        return "Not Installed"
    
    try:
        result = subprocess.run(
            ["systemctl", "is-active", "wazuh-agent"],
            capture_output=True,
            text=True,
            timeout=5
        )
        if result.stdout.strip() == "active":
            return "Running"
    except Exception as e:
        logger.warning(f"Could not check wazuh-agent status: {e}")
        
    # Check processes
    try:
        result = subprocess.run(
            ["pgrep", "-x", "wazuh-agentd"],
            capture_output=True,
            timeout=5,
        )
        if result.returncode == 0:
            return "Running"
    except Exception:
        pass
        
    return "Stopped"

def get_agent_connection():
    """Return the agent's live manager-connection status.

    One of ``connected`` / ``pending`` / ``disconnected`` / ``unknown``.
    Reads Wazuh's own wazuh-agentd.state; falls back to ossec.log. Distinct
    from get_agent_status(), which only reports whether the daemon is alive.
    """
    from plugins.wazuh.agent import agent_state

    agent_dir = installed_agent_dir() or LINUX_WAZUH_DIR
    return agent_state.read_agent_connection(
        os.path.join(agent_dir, "var", "run", "wazuh-agentd.state"),
        os.path.join(agent_dir, "logs", "ossec.log"),
    )

def download_package(progress_callback=None):
    """Download the signed Phoenix agent .deb or .rpm (needs a Phoenix sign-in).

    Returns the verified local path, or None.
    """
    plat = package_platform()
    if not plat:
        msg = ("Phoenix builds the Linux agent for Debian/Ubuntu and "
               "Fedora/RHEL/openSUSE (amd64) only.")
        logger.error(msg)
        if progress_callback:
            progress_callback(msg)
        return None
    return phoenix_packages.download_or_none(
        tempfile.mkdtemp(prefix="phoenix_agent_"), progress_callback, plat=plat)

def write_env_file(agent_name, agent_group):
    # Not using env file for Linux, we'll pass via environment to the installer or patch ossec.conf
    pass

_KEY_BACKUP = os.path.join(settings.get_config_dir(), "wazuh_client.keys")
_CLIENT_KEYS = f"{LINUX_WAZUH_DIR}/etc/client.keys"

def start_agent():
    if get_agent_status() == "Running":
        return True
        
    # Restore key if missing
    if os.path.exists(_KEY_BACKUP):
        script = f"""
        if [ ! -s '{_CLIENT_KEYS}' ]; then
            if [ -s '{_KEY_BACKUP}' ]; then
                cp '{_KEY_BACKUP}' '{_CLIENT_KEYS}'
                chmod 640 '{_CLIENT_KEYS}'
                chown wazuh:wazuh '{_CLIENT_KEYS}' || chown root:wazuh '{_CLIENT_KEYS}'
            fi
        fi
        systemctl enable wazuh-agent
        systemctl start wazuh-agent
        """
        success, output = run_privileged_command(["sh", "-c", script])
        return success
    else:
        success, output = run_privileged_command(["systemctl", "start", "wazuh-agent"])
        return success

def restore_client_key_if_needed():
    if needs_reenrollment():
        return False
        
    if not os.path.exists(_KEY_BACKUP):
        return True
        
    script = f"""
        if [ ! -s '{_CLIENT_KEYS}' ]; then
            if [ -s '{_KEY_BACKUP}' ]; then
                cp '{_KEY_BACKUP}' '{_CLIENT_KEYS}'
                chmod 640 '{_CLIENT_KEYS}'
                chown wazuh:wazuh '{_CLIENT_KEYS}' || chown root:wazuh '{_CLIENT_KEYS}'
                systemctl restart wazuh-agent
                echo KEY_RESTORED
            fi
        fi
        """
    success, output = run_privileged_command(["sh", "-c", script])
    return success

def stop_agent():
    if not is_agent_installed():
        return True
        
    success, output = run_privileged_command(["systemctl", "stop", "wazuh-agent"])
    
    # Verify stopped
    try:
        if subprocess.run(["pgrep", "-x", "wazuh-agentd"], capture_output=True).returncode == 0:
            run_privileged_command(["pkill", "-9", "-f", f"{LINUX_WAZUH_DIR}/bin/wazuh-"])
    except:
        pass
        
    return get_agent_status() != "Running"

def agent_present(wipe_keys: bool = False) -> bool:
    """Return True if there's a Wazuh agent (or key backup) worth removing.

    Mirrors remove_agent's guard so callers batching privileged work (e.g. the
    app uninstaller) can decide whether to include the teardown commands.
    """
    return is_app_managed_agent() or (wipe_keys and os.path.exists(_KEY_BACKUP))


def build_remove_script(wipe_keys: bool = False) -> str:
    """Build the privileged shell script that tears down the Wazuh agent.

    Split out from remove_agent so the app-level uninstaller can fold these
    commands into a single privilege-escalation prompt instead of running its
    own. See remove_agent for the per-distro rationale.
    """
    from utils.distro import LinuxDistro

    os_type = _get_os_info()
    pkg_mgr = LinuxDistro.get_package_manager()
    backup_dir = os.path.dirname(_KEY_BACKUP)

    # --- Stop + disable the service (init-system aware) ---
    # wazuh-control stops the agent regardless of init system; the unit/init
    # script teardown then differs between systemd and OpenRC/SysV.
    stop_cmd = f"'{LINUX_WAZUH_DIR}/bin/wazuh-control' stop 2>/dev/null || true"
    if LinuxDistro.is_systemd():
        service_teardown = (
            "systemctl stop wazuh-agent || true; "
            "systemctl disable wazuh-agent || true; "
            "rm -f /usr/lib/systemd/system/wazuh-agent.service "
            "/etc/systemd/system/wazuh-agent.service; "
            "systemctl daemon-reload || true"
        )
    else:
        # OpenRC (rc-service/rc-update) or SysV (service) fallback.
        service_teardown = (
            "(rc-service wazuh-agent stop 2>/dev/null || "
            "service wazuh-agent stop 2>/dev/null) || true; "
            "(rc-update del wazuh-agent 2>/dev/null || true); "
            "rm -f /etc/init.d/wazuh-agent"
        )

    # --- Package removal + orphan user/group cleanup ---
    # Recognized package managers run postrm/postun hooks that drop the wazuh
    # user/group, so we let them handle it. Arch and the no-package-manager
    # fallback are extraction-based, so they must remove the user/group by hand.
    manual_user_cleanup = (
        "userdel wazuh 2>/dev/null || true; groupdel wazuh 2>/dev/null || true"
    )
    if os_type == "arch":
        pkg_remove = ""
        cleanup_users = manual_user_cleanup
    elif pkg_mgr == "apt":
        pkg_remove = "apt-get remove -y wazuh-agent || true"
        cleanup_users = ""
    elif pkg_mgr in ("dnf", "yum"):
        pkg_remove = f"{pkg_mgr} remove -y wazuh-agent || true"
        cleanup_users = ""
    elif pkg_mgr == "zypper":
        pkg_remove = "zypper --non-interactive remove wazuh-agent || true"
        cleanup_users = ""
    else:
        # No recognized package manager: the install can only have been placed
        # by extraction, so tear it down by path like the Arch case.
        pkg_remove = ""
        cleanup_users = manual_user_cleanup

    # --- Preserve or wipe the enrollment key backup ---
    # Runs before pkg_remove/rm -rf so client.keys still exists to be copied.
    if wipe_keys:
        key_phase = f"rm -f '{_KEY_BACKUP}'"
    else:
        key_phase = (
            f"mkdir -p '{backup_dir}'; "
            f"cp '{_CLIENT_KEYS}' '{_KEY_BACKUP}' 2>/dev/null || true; "
            f"chown {os.getuid()}:{os.getgid()} '{_KEY_BACKUP}' 2>/dev/null || true"
        )

    if not is_app_managed_agent():
        # The only agent (if any) was installed some other way (by an admin,
        # an upstream package, the NixOS module). Its service, unit and wazuh user belong to
        # that install, so only the app's key backup is touched.
        return f"""
        {key_phase if wipe_keys else ""}
    """

    return f"""
        {stop_cmd}
        {service_teardown}
        {key_phase}
        {pkg_remove}
        {cleanup_users}
        rm -rf '{LINUX_WAZUH_DIR}'
    """


def remove_agent(wipe_keys: bool = False):
    """Uninstall the Wazuh agent and clean up system resources.

    Removal is driven by the detected package manager and init system rather
    than a single hard-coded path, so it works across apt/dnf/yum/zypper and
    both systemd and non-systemd (OpenRC/SysV) hosts:

    * Package-managed installs (deb/rpm/zypper) are removed by the package
      manager, whose postrm/postun hooks drop the wazuh user and group.
    * Arch installs are bsdtar-extracted and tracked by no package manager, so
      they are always torn down by path with a manual user/group cleanup.
    * Hosts with no recognized package manager fall back to the same manual
      teardown as Arch (the install can only have been extraction-based).

    When ``wipe_keys=True`` (used on user logout) the persistent client.keys
    backup is also deleted so the next user starts with a clean enrollment.
    """
    if not agent_present(wipe_keys):
        return True

    managed = is_app_managed_agent()
    script = build_remove_script(wipe_keys)
    success, output = run_privileged_command(["sh", "-c", script])
    if success:
        if managed:
            settings.set("wazuh", _APP_INSTALLED, False)
        logger.info("Wazuh agent removed successfully")
    else:
        logger.error(f"Failed to remove Wazuh agent: {output}")
    return success

def _rpm_install_cmd(deploy_env, pkg_path):
    """Shell command installing the agent .rpm with this system's package manager.

    The package is verified against the signed manifest before this runs; it
    carries no GPG signature, hence --nogpgcheck / --allow-unsigned-rpm.
    """
    if shutil.which("dnf"):
        return f"{deploy_env} dnf -y install --nogpgcheck '{pkg_path}'"
    if shutil.which("zypper"):
        return (f"{deploy_env} zypper --non-interactive install "
                f"--allow-unsigned-rpm '{pkg_path}'")
    if shutil.which("yum"):
        return f"{deploy_env} yum -y install --nogpgcheck '{pkg_path}'"
    return f"{deploy_env} rpm -Uvh '{pkg_path}'"


def full_install(progress_callback=None):
    pkg_path = download_package(progress_callback)
    if not pkg_path:
        if progress_callback: progress_callback("Download failed")
        return False
        
    agent_name = get_agent_name()
    agent_group = get_agent_group()
    # Server-side enrollment (user's group); None -> agent-auth below.
    enrolled = enrollment.request(agent_name)
    if enrolled:
        agent_name = enrolled.agent_name
        agent_group = enrolled.group

    os_type = _get_os_info()
    ossec_conf = f"{LINUX_WAZUH_DIR}/etc/ossec.conf"
    install_cmd = ""
    deploy_env = _deploy_env(agent_name, agent_group)
    if os_type == "deb":
        install_cmd = f"{deploy_env} dpkg -i '{pkg_path}'"
    elif os_type == "rpm":
        # dnf/zypper pull in the package's dependencies; rpm -U also upgrades.
        install_cmd = _rpm_install_cmd(deploy_env, pkg_path)
    elif os_type == "arch":
        # No postinst runs when extracting with bsdtar — create the wazuh user/group, extract,
        # fix ownership, then stamp manager + group into ossec.conf manually
        install_cmd = (
            "(getent group wazuh >/dev/null || groupadd --system wazuh) && "
            "(getent passwd wazuh >/dev/null || useradd --system --no-create-home "
            "--home /var/ossec --shell /sbin/nologin -g wazuh wazuh) && "
            f"bsdtar -xpf '{pkg_path}' -C / && "
            "chown -R wazuh:wazuh /var/ossec && "
            f"sed -i \"s|<address>.*</address>|<address>{WAZUH_MANAGER}</address>|\" '{ossec_conf}'"
        )

    agent_auth = f"{LINUX_WAZUH_DIR}/bin/agent-auth"
    backup_dir = os.path.dirname(_KEY_BACKUP)

    # The key from the Phoenix API, or (fallback) a fresh agent-auth
    # registration so the manager receives the group on every install.
    # The key backup is still written for future repair/recovery flows.
    # -p is the port flag; -P (uppercase) is the password-FILE path — passing
    # the port to -P is a no-op that only works because 1515 is the default.
    if enrolled:
        register = enrollment.key_write_sh(enrolled.key_file, _CLIENT_KEYS)
    else:
        register = (f"rm -f '{_CLIENT_KEYS}'\n"
                    f"            '{agent_auth}' -m '{WAZUH_MANAGER}' -p '{WAZUH_REGISTRATION_PORT}' "
                    f"-A '{agent_name}' -G '{agent_group}'")
    enrollment_script = f"""
            {register}
            mkdir -p '{backup_dir}' && cp '{_CLIENT_KEYS}' '{_KEY_BACKUP}'
            chown {os.getuid()}:{os.getgid()} '{_KEY_BACKUP}' 2>/dev/null
        """

    script = f"""
        {install_cmd}
        {_set_ossec_enrollment(ossec_conf, agent_name, agent_group)}
        {enrollment_script}
        systemctl daemon-reload
        systemctl enable wazuh-agent
        systemctl restart wazuh-agent
        sleep 2
        {_make_agent_state_readable()}
    """
    
    if progress_callback:
        progress_callback("Installing Wazuh agent (admin password required)...")
        
    success, output = run_privileged_command(["sh", "-c", script])
    enrollment.discard(enrolled)

    if success or is_agent_installed():
        settings.set("wazuh", _APP_INSTALLED, True)
        settings.set("wazuh", "enrolled_email", settings.get("auth", "email", ""))
        if progress_callback:
            progress_callback("Wazuh agent installed and running")
        return True
        
    if progress_callback:
        progress_callback("Installation failed")
    return False

def reenroll_agent():
    """Force a fresh manager registration to recover a dead/invalid key.

    Used when the agent is Running but never reaches ``connected`` (e.g. the
    old agent was deleted server-side after a reinstall, invalidating the
    reused key). Wipes the local key + backup, enrolls under a fresh unique
    name so the manager creates a brand-new record, then restarts.
    Returns (ok, msg).
    """
    import time

    if not is_agent_installed():
        return (False, "Wazuh agent is not installed")
    if not is_app_managed_agent():
        return (False, f"The agent in {installed_agent_dir()} is managed outside "
                       "this app; re-enroll it with its own installer")

    base = get_agent_name()
    new_name = f"{base}-{str(int(time.time()))[-6:]}"
    group = get_agent_group()
    agent_auth = f"{LINUX_WAZUH_DIR}/bin/agent-auth"
    ossec_conf = f"{LINUX_WAZUH_DIR}/etc/ossec.conf"
    backup_dir = os.path.dirname(_KEY_BACKUP)
    # The Phoenix API answers with the manager's current key for this device
    # (a new agent if the old one was deleted there); else agent-auth.
    enrolled = enrollment.request(new_name)
    if enrolled:
        new_name = enrolled.agent_name
        group = enrolled.group
        register = enrollment.key_write_sh(enrolled.key_file, _CLIENT_KEYS)
    else:
        register = (f"'{agent_auth}' -m '{WAZUH_MANAGER}' -p '{WAZUH_REGISTRATION_PORT}' "
                    f"-A '{new_name}' -G '{group}'")

    script = f"""
        systemctl stop wazuh-agent 2>/dev/null
        pkill -9 -f '{LINUX_WAZUH_DIR}/bin/wazuh-' 2>/dev/null
        rm -f '{_CLIENT_KEYS}' '{_KEY_BACKUP}'
        {register}
        if [ ! -s '{_CLIENT_KEYS}' ]; then echo REENROLL_NO_KEY; exit 1; fi
        chmod 640 '{_CLIENT_KEYS}'
        chown wazuh:wazuh '{_CLIENT_KEYS}' 2>/dev/null || chown root:wazuh '{_CLIENT_KEYS}' 2>/dev/null
        {_set_ossec_enrollment(ossec_conf, new_name, group)}
        mkdir -p '{backup_dir}'; cp '{_CLIENT_KEYS}' '{_KEY_BACKUP}' 2>/dev/null
        chown {os.getuid()}:{os.getgid()} '{_KEY_BACKUP}' 2>/dev/null
        systemctl enable wazuh-agent 2>/dev/null
        systemctl restart wazuh-agent
        sleep 2
        {_make_agent_state_readable()}
        echo REENROLL_OK
    """
    success, output = run_privileged_command(["sh", "-c", script])
    enrollment.discard(enrolled)
    if success and "REENROLL_NO_KEY" not in (output or ""):
        logger.info(f"Wazuh re-enrolled under fresh name {new_name}")
        return (True, f"Re-enrolled as {new_name}")
    logger.error(f"Wazuh re-enroll failed: {output!r}")
    return (False, output or "Re-enrollment failed")
