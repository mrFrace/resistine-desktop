"""
Wazuh Agent Plugin — Centralized Configuration
All changeable values (package URL, version, manager address) live here.
Author: Resistine Team
Copyright (c) Resistine 2025
Licensed under the GNU General Public License v2 or later
"""

# --- Package Download ---
WAZUH_BASE_URL = "https://packages.wazuh.com/4.x/macos"
WAZUH_VERSION = "4.14.2-1"

# Maps platform.machine() output to the expected filename component
WAZUH_PKG_ARCH_MAP = {
    "arm64": "arm64",
    "x86_64": "intel64",
}

# --- Linux Config ---
LINUX_WAZUH_VERSION = "4.11.0"
LINUX_WAZUH_REVISION = "1"
LINUX_WAZUH_DEB_URL = f"https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_{LINUX_WAZUH_VERSION}-{LINUX_WAZUH_REVISION}_{{arch}}.deb"
LINUX_WAZUH_RPM_URL = f"https://packages.wazuh.com/4.x/yum/wazuh-agent-{LINUX_WAZUH_VERSION}-{LINUX_WAZUH_REVISION}.{{arch}}.rpm"

LINUX_PKG_ARCH_MAP_DEB = {
    "x86_64": "amd64",
    "aarch64": "arm64",
}

LINUX_PKG_ARCH_MAP_RPM = {
    "x86_64": "x86_64",
    "aarch64": "aarch64",
}

# --- Manager Connection ---
WAZUH_MANAGER = "dashboard.phoenix.exposed"
WAZUH_MANAGER_PORT = "1514"
WAZUH_REGISTRATION_PORT = "1515"
WAZUH_PROTOCOL = "tcp"

# --- Paths ---
WAZUH_INSTALL_DIR = "/Library/Ossec"
WAZUH_LAUNCHD_PLIST = "/Library/LaunchDaemons/com.wazuh.agent.plist"
WAZUH_ENV_FILE = "/tmp/wazuh_envs"

LINUX_WAZUH_DIR = "/var/ossec"  # where the app itself installs the agent
# Where an existing agent is looked for, in order. Anything other than
# LINUX_WAZUH_DIR is managed outside the app (e.g. a NixOS module).
LINUX_WAZUH_SEARCH_DIRS = (
    LINUX_WAZUH_DIR,
    "/opt/resistine",
    "/opt/phoenix-agent",
    "/opt/agent-phoenix",
)

# --- Windows Config ---
WINDOWS_WAZUH_VERSION = "4.11.0"
WINDOWS_WAZUH_REVISION = "1"
WINDOWS_WAZUH_MSI_URL = f"https://packages.wazuh.com/4.x/windows/wazuh-agent-{WINDOWS_WAZUH_VERSION}-{WINDOWS_WAZUH_REVISION}.msi"
WINDOWS_WAZUH_DIR = r"C:\Program Files (x86)\ossec-agent"

# --- Sysmon ---
WINDOWS_SYSMON_ZIP_URL = "https://download.sysinternals.com/files/Sysmon.zip"
WINDOWS_SYSMON_CONFIG_URL = "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml"
