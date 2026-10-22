"""
Wazuh Agent Plugin — Centralized Configuration
All changeable values (manager address, install paths) live here. The agent
packages themselves are the Phoenix builds from auth.phoenix.exposed, see
plugins/wazuh/agent/phoenix_packages.py.
Author: Resistine Team
Copyright (c) Resistine 2025
Licensed under the GNU General Public License v2 or later
"""

import os
import tempfile

# --- Manager Connection ---
WAZUH_MANAGER = "dashboard.phoenix.exposed"
# Wazuh 5.0: agents reach the manager over HTTPS on 1517 (written into
# <manager><endpoint>host:1517</endpoint>; 1514 was the 4.x channel) and enroll
# on 1515. WAZUH_PROTOCOL only meant something to 4.x installers.
WAZUH_MANAGER_PORT = "1517"
WAZUH_REGISTRATION_PORT = "1515"
WAZUH_PROTOCOL = "tcp"
# What the installers write from WAZUH_MANAGER + WAZUH_MANAGER_PORT.
WAZUH_MANAGER_ENDPOINT = f"{WAZUH_MANAGER}:{WAZUH_MANAGER_PORT}"

# --- Paths ---
# The Phoenix macOS agent (Resistine-Server-install build_agent_macos.sh) moves
# upstream's /Library/Ossec here; its pkg id and launchd label stay com.wazuh.*.
WAZUH_INSTALL_DIR = "/Library/Phoenix"
WAZUH_LAUNCHD_PLIST = "/Library/LaunchDaemons/com.wazuh.agent.plist"
# Wazuh's macOS .pkg install scripts read deployment variables (manager
# address, agent name/group, ...) from this hard-coded path and source it as
# root.  The unprivileged app must never write it: /tmp is world-writable, so a
# pre-planted file or symlink there would let another local user inject
# variables into a root-run script or redirect our write.  Instead the
# privileged install command stages it atomically as root (see
# wazuh_functions_darwin._stage_pkg_env_cmd) and removes it afterwards.
WAZUH_PKG_ENV_FILE = "/tmp/wazuh_envs"

# The app's own copy of the env file lives in a private, per-user 0700 temp
# dir created on first use (see get_wazuh_env_file()).  Tests may override
# this with an explicit path; None means "use the private default".
WAZUH_ENV_FILE = None
_private_env_file = None


def get_wazuh_env_file():
    """Return the app's env-file path inside a private 0700 temp directory.

    ``tempfile.mkdtemp`` creates a fresh, uniquely named directory with mode
    0700 using O_EXCL semantics, so unlike a fixed name under /tmp it cannot
    be pre-created or symlinked by another local user.  The directory is
    created lazily (not at import) so importing this module has no side
    effects on any platform.
    """
    global _private_env_file
    if WAZUH_ENV_FILE:
        return WAZUH_ENV_FILE
    if _private_env_file is None or not os.path.isdir(os.path.dirname(_private_env_file)):
        private_dir = tempfile.mkdtemp(prefix="resistine-wazuh-")
        _private_env_file = os.path.join(private_dir, "wazuh_envs")
    return _private_env_file


LINUX_WAZUH_DIR = "/opt/phoenix-agent"  # where the Phoenix .deb this app installs lands
# Where an already-installed agent may live, checked in order: upstream
# packages, the NixOS wazuh-agent module (~/.flakes
# modules/services/wazuh-agent.nix, installDir default), and the Phoenix
# agent packages.
LINUX_WAZUH_DIR_CANDIDATES = (
    "/var/ossec",
    "/opt/resistine",
    "/opt/phoenix-agent",
    "/opt/agent-phoenix",
)

# --- Windows Config ---
# The Phoenix MSI keeps upstream's folder and WazuhSvc service name.
WINDOWS_WAZUH_DIR = r"C:\Program Files (x86)\ossec-agent"

# --- Sysmon ---
WINDOWS_SYSMON_ZIP_URL = "https://download.sysinternals.com/files/Sysmon.zip"
WINDOWS_SYSMON_CONFIG_URL = "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml"
