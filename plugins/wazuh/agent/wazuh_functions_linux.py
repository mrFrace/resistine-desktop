"""
Wazuh Agent Functions for Linux
Handles download, install, start/stop of the Wazuh SIEM agent using systemd and package managers.
Author: Resistine Team
Copyright (c) Resistine 2025
Licensed under the GNU General Public License v2 or later
"""

import os
import platform
import socket
import subprocess
import tempfile
import re
import urllib.error
import urllib.request

from utils import settings
from utils.logger import logger
from gui.dialogs import CTkPasswordDialog

from plugins.wazuh.config import (
    LINUX_WAZUH_DEB_URL,
    LINUX_WAZUH_RPM_URL,
    LINUX_PKG_ARCH_MAP_DEB,
    LINUX_PKG_ARCH_MAP_RPM,
    WAZUH_MANAGER,
    WAZUH_MANAGER_PORT,
    WAZUH_PROTOCOL,
    WAZUH_REGISTRATION_PORT,
    LINUX_WAZUH_DIR,
    LINUX_WAZUH_SEARCH_DIRS,
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
    import tkinter as tk
    try:
        root = tk._default_root
    except:
        root = None
    
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
    """Return the user's email with '@' replaced by '-' to match the
    canonical group name created by /verify-otp.
    """
    email = settings.get("auth", "email", "default")
    if email and email != "default":
        return email.replace("@", "-")
    return "default"

def needs_reenrollment():
    enrolled = settings.get("wazuh", "enrolled_email", "")
    current = settings.get("auth", "email", "")
    if enrolled and current and enrolled != current:
        return True
    return False

def _get_os_info():
    """Determine package family (deb, rpm, arch) using LinuxDistro utility."""
    from utils.distro import LinuxDistro
    if LinuxDistro.is_debian_like():
        return "deb"
    if LinuxDistro.is_fedora_like():
        return "rpm"
    if LinuxDistro.is_arch_like():
        return "arch"
    return None

def get_package_url():
    arch = platform.machine()
    os_type = _get_os_info()
    if os_type == "deb":
        arch_suffix = LINUX_PKG_ARCH_MAP_DEB.get(arch, "amd64")
        return LINUX_WAZUH_DEB_URL.format(arch=arch_suffix)
    elif os_type == "rpm" or os_type == "arch":
        # Arch uses the RPM artifact and extracts it with bsdtar (libarchive); upstream Wazuh ships no pacman package
        arch_suffix = LINUX_PKG_ARCH_MAP_RPM.get(arch, "x86_64")
        return LINUX_WAZUH_RPM_URL.format(arch=arch_suffix)
    elif os_type == "arch":
        # Wazuh doesn't have an official Arch package, usually installed via AUR
        # or we might need a specific handling. For now, mark as unsupported.
        return None
    return None

def is_agent_installed():
    return get_install_info()["path"] is not None

def _is_wazuh_dir(path):
    """True if *path* holds a Wazuh agent install.

    Installs are usually wazuh:wazuh 0750, so an unprivileged user can't
    look inside; ownership by the wazuh user or group counts as a match.
    """
    if not os.path.isdir(path):
        return False
    if os.path.exists(os.path.join(path, "bin", "wazuh-control")):
        return True
    try:
        import grp
        import pwd

        st = os.stat(path)
        return "wazuh" in (pwd.getpwuid(st.st_uid).pw_name,
                           grp.getgrgid(st.st_gid).gr_name)
    except (KeyError, OSError):
        return False

def get_install_info():
    """Return ``{"path", "system_managed"}`` for the agent install.

    Checks LINUX_WAZUH_SEARCH_DIRS in order, then the wazuh-agent systemd
    unit for any other location. Only LINUX_WAZUH_DIR is the app's own
    install; anything else is managed outside the app and must not be
    re-keyed or removed by it. ``path`` is None when nothing is found.
    """
    for path in LINUX_WAZUH_SEARCH_DIRS:
        if _is_wazuh_dir(path):
            return {"path": path, "system_managed": path != LINUX_WAZUH_DIR}
    try:
        result = subprocess.run(
            ["systemctl", "show", "wazuh-agent", "-p", "LoadState", "-p", "ExecStart"],
            capture_output=True, text=True, timeout=5,
        )
        props = dict(
            line.split("=", 1) for line in result.stdout.splitlines() if "=" in line
        )
        match = re.search(r"path=(\S+)", props.get("ExecStart", ""))
        if props.get("LoadState") == "loaded" and match:
            # .../bin/wazuh-control -> install root
            root = os.path.dirname(os.path.dirname(match.group(1)))
            return {"path": root, "system_managed": True}
    except Exception as e:
        logger.debug(f"Could not inspect wazuh-agent unit: {e}")
    return {"path": None, "system_managed": False}

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

def download_package(progress_callback=None):
    url = get_package_url()
    if not url:
        logger.error("Unsupported OS type or architecture for Wazuh install")
        return None
        
    tmp_dir = tempfile.mkdtemp(prefix="wazuh_")
    filename = url.split("/")[-1]
    pkg_path = os.path.join(tmp_dir, filename)

    if progress_callback:
        progress_callback("Downloading Wazuh agent...")

    logger.info(f"Downloading Wazuh package from {url}")
    try:
        urllib.request.urlretrieve(url, pkg_path)
        logger.info(f"Downloaded to {pkg_path}")
        return pkg_path
    except urllib.error.HTTPError as e:
        logger.error(f"Download failed: HTTP {e.code} {e.reason}")
        return None
    except urllib.error.URLError as e:
        logger.error(f"Download failed: {e.reason}")
        return None
    except Exception as e:
        logger.error(f"Download error: {e}")
        return None

def write_env_file(agent_name, agent_group):
    # Not using env file for Linux, we'll pass via environment to the installer or patch ossec.conf
    pass

_KEY_BACKUP = os.path.expanduser("~/.config/resistine/wazuh_client.keys")
_CLIENT_KEYS = f"{LINUX_WAZUH_DIR}/etc/client.keys"

def start_agent():
    if get_agent_status() == "Running":
        return True
        
    # Restore key if missing (only into the app's own install)
    if os.path.exists(_KEY_BACKUP) and not get_install_info()["system_managed"]:
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
        
    if not os.path.exists(_KEY_BACKUP) or get_install_info()["system_managed"]:
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
    install_dir = get_install_info()["path"]
    if not install_dir:
        return True
        
    success, output = run_privileged_command(["systemctl", "stop", "wazuh-agent"])
    
    # Verify stopped
    try:
        if subprocess.run(["pgrep", "-x", "wazuh-agentd"], capture_output=True).returncode == 0:
            run_privileged_command(["pkill", "-9", "-f", f"{install_dir}/bin/wazuh-"])
    except:
        pass
        
    return get_agent_status() != "Running"

def remove_agent(wipe_keys: bool = False):
    info = get_install_info()
    if info["system_managed"]:
        logger.warning(
            f"Wazuh agent at {info['path']} is managed outside the app; not removing it")
        return False
    if not is_agent_installed() and not (wipe_keys and os.path.exists(_KEY_BACKUP)):
        return True

    os_type = _get_os_info()
    backup_dir = os.path.dirname(_KEY_BACKUP)

    uninstall_cmd = ""
    if os_type == "deb":
        uninstall_cmd = "apt-get remove -y wazuh-agent"
    elif os_type == "rpm":
        uninstall_cmd = "yum remove -y wazuh-agent || dnf remove -y wazuh-agent"
    elif os_type == "arch":
        # bsdtar-extracted install isn't tracked by pacman, so tear down by path
        uninstall_cmd = (
            "systemctl disable wazuh-agent 2>/dev/null; "
            "rm -f /usr/lib/systemd/system/wazuh-agent.service /etc/systemd/system/wazuh-agent.service; "
            "systemctl daemon-reload"
        )

    if wipe_keys:
        key_phase = f"rm -f '{_KEY_BACKUP}'"
    else:
        key_phase = (
            f"mkdir -p '{backup_dir}'; "
            f"cp '{_CLIENT_KEYS}' '{_KEY_BACKUP}' 2>/dev/null; "
            f"chown {os.getuid()}:{os.getgid()} '{_KEY_BACKUP}' 2>/dev/null"
        )

    script = f"""
        systemctl stop wazuh-agent 2>/dev/null
        {key_phase}
        {uninstall_cmd}
        rm -rf '{LINUX_WAZUH_DIR}'
    """
    success, output = run_privileged_command(["sh", "-c", script])
    return success

def full_install(progress_callback=None):
    pkg_path = download_package(progress_callback)
    if not pkg_path:
        if progress_callback: progress_callback("Download failed")
        return False
        
    agent_name = get_agent_name()
    agent_group = get_agent_group()

    os_type = _get_os_info()
    ossec_conf = f"{LINUX_WAZUH_DIR}/etc/ossec.conf"
    install_cmd = ""
    deploy_env = _deploy_env(agent_name, agent_group)
    if os_type == "deb":
        install_cmd = f"{deploy_env} dpkg -i '{pkg_path}'"
    elif os_type == "rpm":
        install_cmd = f"{deploy_env} rpm -ihv '{pkg_path}'"
    elif os_type == "arch":
        # No postinst runs when extracting with bsdtar — create the wazuh user/group, extract,
        # fix ownership, then stamp manager + group into ossec.conf manually
        install_cmd = (
            "(getent group wazuh >/dev/null || groupadd --system wazuh) && "
            "(getent passwd wazuh >/dev/null || useradd --system --no-create-home "
            "--home /var/ossec --shell /sbin/nologin -g wazuh wazuh) && "
            f"bsdtar -xpf '{pkg_path}' -C / && "
            "chown -R wazuh:wazuh /var/ossec && "
            f"sed -i \"s|<address>.*</address>|<address>{WAZUH_MANAGER}</address>|\" '{ossec_conf}' && "
            f"sed -i \"s|<groups>.*</groups>|<groups>{agent_group}</groups>|\" '{ossec_conf}'"
        )

    agent_auth = f"{LINUX_WAZUH_DIR}/bin/agent-auth"
    backup_dir = os.path.dirname(_KEY_BACKUP)

    # Always re-enroll so the manager receives the group on every install.
    # The key backup is still written for future repair/recovery flows.
    enrollment_script = f"""
            rm -f '{_CLIENT_KEYS}'
            '{agent_auth}' -m '{WAZUH_MANAGER}' -P '{WAZUH_REGISTRATION_PORT}' -A '{agent_name}' -G '{agent_group}'
            mkdir -p '{backup_dir}' && cp '{_CLIENT_KEYS}' '{_KEY_BACKUP}'
            chown {os.getuid()}:{os.getgid()} '{_KEY_BACKUP}' 2>/dev/null
        """

    script = f"""
        {install_cmd}
        sed -i 's|<agent_name>.*</agent_name>|<agent_name>{agent_name}</agent_name>|' '{ossec_conf}'
        {enrollment_script}
        systemctl daemon-reload
        systemctl enable wazuh-agent
        systemctl restart wazuh-agent
    """
    
    if progress_callback:
        progress_callback("Installing Wazuh agent (admin password required)...")
        
    success, output = run_privileged_command(["sh", "-c", script])
    
    if success or is_agent_installed():
        settings.set("wazuh", "enrolled_email", settings.get("auth", "email", ""))
        if progress_callback:
            progress_callback("Wazuh agent installed and running")
        return True
        
    if progress_callback:
        progress_callback("Installation failed")
    return False
