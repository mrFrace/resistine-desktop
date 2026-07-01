"""
Wazuh Agent Functions for Windows
Handles download, install, start/stop of the Wazuh SIEM agent and Sysmon
using PowerShell privilege escalation.
Author: Resistine Team
Copyright (c) Resistine 2025
Licensed under the GNU General Public License v2 or later
"""

import base64
import os
import platform
import re
import socket
import subprocess
import tempfile
import time
import winreg
import zipfile

from utils import settings
from utils.logger import logger
from utils.windows_admin import is_admin as _is_admin  # noqa: F401
from utils.windows_admin import run_privileged as _run_privileged

from plugins.wazuh.config import (
    WAZUH_MANAGER,
    WAZUH_MANAGER_PORT,
    WAZUH_PROTOCOL,
    WAZUH_REGISTRATION_PORT,
    WINDOWS_WAZUH_MSI_URL,
    WINDOWS_WAZUH_DIR,
    WINDOWS_SYSMON_ZIP_URL,
    WINDOWS_SYSMON_CONFIG_URL,
)

_OSSEC_CONF = os.path.join(WINDOWS_WAZUH_DIR, "ossec.conf")
_CLIENT_KEYS = os.path.join(WINDOWS_WAZUH_DIR, "client.keys")
_KEY_BACKUP = os.path.join(os.environ.get("APPDATA", ""), "Resistine", "wazuh_client.keys")
_AGENT_AUTH = os.path.join(WINDOWS_WAZUH_DIR, "agent-auth.exe")
_SERVICE_NAME = "WazuhSvc"

_RESISTINE_API_BASE = "https://validate.resistine.work"

# Sysmon paths
_SYSMON_DIR = os.path.join(os.environ.get("PROGRAMFILES", r"C:\Program Files"), "Resistine", "Sysmon")
_SYSMON_EXE = os.path.join(_SYSMON_DIR, "Sysmon64.exe")
_SYSMON_CONFIG = os.path.join(_SYSMON_DIR, "sysmonconfig-export.xml")

# Sysmon localfile block to inject into ossec.conf
_SYSMON_LOCALFILE_BLOCK = """
  <localfile>
    <location>Microsoft-Windows-Sysmon/Operational</location>
    <log_format>eventchannel</log_format>
  </localfile>"""

# Windows Defender localfile block to inject into ossec.conf
_DEFENDER_LOCALFILE_BLOCK = """
  <localfile>
    <location>Microsoft-Windows-Windows Defender/Operational</location>
    <log_format>eventchannel</log_format>
  </localfile>"""




def _get_machine_guid():
    """Return the Windows MachineGuid from the registry."""
    try:
        key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Cryptography",
        )
        guid, _ = winreg.QueryValueEx(key, "MachineGuid")
        winreg.CloseKey(key)
        return guid
    except Exception as e:
        logger.warning(f"Could not read MachineGuid: {e}")
        return None


def get_agent_name():
    """Return a stable, unique agent name: hostname + last 12 chars of MachineGuid."""
    hostname = socket.gethostname()
    guid = _get_machine_guid()
    if guid:
        suffix = guid.replace("-", "")[-12:].upper()
        name = f"{hostname}-{suffix}"
    else:
        name = hostname
    sanitized = re.sub(r"[^A-Za-z0-9.\-_]", "", name)
    if sanitized:
        return sanitized
    # Hostname was entirely non-ASCII or special chars. Fall back to a name
    # derived from the GUID so Wazuh enrollment still gets a unique value.
    if guid:
        return f"agent-{guid.replace('-', '')[-12:].upper()}"
    return "resistine-agent"


def get_agent_group():
    """Return the user's email (sanitized) as the agent group.

    Replaces '@' with '-' to match the canonical group name created by
    the /verify-otp backend.  Email flows into PowerShell commands
    (msiexec args) so it must also be stripped of shell metacharacters
    using the same allowlist as get_agent_name.
    """
    email = settings.get("auth", "email", "default")
    if email and email != "default":
        sanitized = re.sub(r"[^A-Za-z0-9.\-_]", "", email.replace("@", "-"))
        if sanitized:
            return sanitized
    return "default"


def needs_reenrollment():
    """Return True if the agent was enrolled under a different email."""
    enrolled = settings.get("wazuh", "enrolled_email", "")
    current = settings.get("auth", "email", "")
    if enrolled and current and enrolled != current:
        logger.info(f"[WAZUH] Enrollment mismatch: enrolled={enrolled!r} current={current!r}")
        return True
    return False


def is_agent_installed():
    """Check whether the Wazuh agent is installed on Windows."""
    return os.path.isdir(WINDOWS_WAZUH_DIR) and os.path.exists(
        os.path.join(WINDOWS_WAZUH_DIR, "wazuh-agent.exe")
    )


def get_agent_status():
    """Return 'Running', 'Stopped', or 'Not Installed'."""
    if not is_agent_installed():
        return "Not Installed"

    try:
        result = subprocess.run(
            ["sc", "query", _SERVICE_NAME],
            capture_output=True, text=True, timeout=10,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        if "RUNNING" in result.stdout:
            return "Running"
        if "START_PENDING" in result.stdout:
            # Service is mid-startup (common right after install). Treat it as
            # running so the UI doesn't flash a Stopped/Error state during the
            # transition; the next poll confirms the real state.
            return "Running"
        if "STOPPED" in result.stdout:
            return "Stopped"
    except Exception as e:
        logger.warning(f"Could not query {_SERVICE_NAME} service: {e}")

    return "Stopped"


def get_package_url():
    """Return the Wazuh MSI download URL."""
    return WINDOWS_WAZUH_MSI_URL


def _is_sysmon_installed():
    """Check if Sysmon service is installed."""
    try:
        result = subprocess.run(
            ["sc", "query", "Sysmon64"],
            capture_output=True, text=True, timeout=10,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        if result.returncode == 0:
            return True
        # Try 32-bit service name
        result = subprocess.run(
            ["sc", "query", "Sysmon"],
            capture_output=True, text=True, timeout=10,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        return result.returncode == 0
    except Exception:
        return False


def _download_file(url, dest_path, progress_callback=None, label="Downloading..."):
    """Download a file using PowerShell Invoke-WebRequest."""
    if progress_callback:
        progress_callback(label)

    logger.info(f"Downloading {url} -> {dest_path}")
    try:
        ps_cmd = (
            f"[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; "
            f"Invoke-WebRequest -Uri '{url}' -OutFile '{dest_path}' -UseBasicParsing"
        )
        result = subprocess.run(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps_cmd],
            capture_output=True, text=True, timeout=300,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        if result.returncode == 0 and os.path.exists(dest_path):
            logger.info(f"Downloaded to {dest_path}")
            return True
        logger.error(f"Download failed: {result.stderr}")
        return False
    except Exception as e:
        logger.error(f"Download error: {e}")
        return False


def _prepare_sysmon_download(progress_callback=None):
    """Download and extract Sysmon (no elevation needed).

    Returns a {dir, exe, config} paths dict whose install PowerShell can be
    folded into the combined elevated script, or None if Sysmon is already
    installed or the download/extract failed. Sysmon is non-fatal for the
    Wazuh install, so None simply means "skip Sysmon".
    """
    if _is_sysmon_installed():
        logger.info("Sysmon already installed, skipping")
        return None

    if progress_callback:
        progress_callback("Downloading Sysmon...")

    # Download and extract to a temp directory (no admin needed)
    tmp_sysmon = os.path.join(tempfile.gettempdir(), "resistine_sysmon")
    os.makedirs(tmp_sysmon, exist_ok=True)

    sysmon_zip = os.path.join(tmp_sysmon, "Sysmon.zip")
    if not _download_file(WINDOWS_SYSMON_ZIP_URL, sysmon_zip, progress_callback, "Downloading Sysmon..."):
        return None

    try:
        with zipfile.ZipFile(sysmon_zip, "r") as zf:
            zf.extractall(tmp_sysmon)
        logger.info(f"Extracted Sysmon to {tmp_sysmon}")
    except Exception as e:
        logger.error(f"Failed to extract Sysmon: {e}")
        return None

    # Determine correct Sysmon executable (64-bit or 32-bit)
    tmp_sysmon_exe = os.path.join(tmp_sysmon, "Sysmon64.exe")
    if not os.path.exists(tmp_sysmon_exe):
        tmp_sysmon_exe = os.path.join(tmp_sysmon, "Sysmon.exe")
        if not os.path.exists(tmp_sysmon_exe):
            logger.error("Sysmon executable not found after extraction")
            return None

    tmp_sysmon_config = os.path.join(tmp_sysmon, "sysmonconfig-export.xml")
    if not _download_file(WINDOWS_SYSMON_CONFIG_URL, tmp_sysmon_config, progress_callback, "Downloading Sysmon config..."):
        return None

    return {"dir": tmp_sysmon, "exe": tmp_sysmon_exe, "config": tmp_sysmon_config}


def _sysmon_install_ps(sysmon):
    """PowerShell that installs Sysmon from a prepared download dict."""
    return (
        f"New-Item -ItemType Directory -Path '{_SYSMON_DIR}' -Force | Out-Null; "
        f"Copy-Item -Path '{sysmon['dir']}\\*' -Destination '{_SYSMON_DIR}' -Recurse -Force; "
        f"& '{sysmon['exe']}' -accepteula -i '{sysmon['config']}'"
    )


def _inject_ossec_localfiles(blocks):
    """Inject one or more <localfile> blocks into ossec.conf under elevation.

    The Wazuh agent restricts ACLs on ossec.conf so a non-admin process can't
    even read it. This helper does the entire read/check/modify/write inside
    a single elevated PowerShell call, producing exactly one UAC prompt for
    the whole batch. Already-present blocks (matched by `marker`) are skipped.

    blocks: list of (marker, xml_block) tuples. `marker` is a substring whose
        presence in ossec.conf means the block is already installed.
    """
    if not blocks:
        return True

    if not os.path.exists(_OSSEC_CONF):
        logger.warning("ossec.conf not found, cannot inject localfile blocks")
        return False

    success, output = _run_privileged(_localfile_injection_ps(blocks))
    if success:
        logger.info("Injected ossec.conf localfile blocks under elevation")
    else:
        logger.error(f"Failed to inject ossec.conf localfile blocks: {output}")
    return success


def _localfile_injection_ps(blocks):
    """Build the elevated PowerShell that injects <localfile> blocks into
    ossec.conf.

    Markers and blocks go through Base64 to dodge any quoting headaches when
    embedded in PowerShell. Used both standalone (via _inject_ossec_localfiles,
    one UAC prompt) and inlined into the combined install script.
    """
    entries_ps = []
    for marker, block in blocks:
        m_b64 = base64.b64encode(marker.encode("utf-8")).decode("ascii")
        b_b64 = base64.b64encode(block.encode("utf-8")).decode("ascii")
        entries_ps.append(
            "    @{ "
            f"Marker = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{m_b64}')); "
            f"Block  = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{b_b64}')) "
            "}"
        )
    # Separate array entries with comma + real newline. (A literal backtick-n
    # here is NOT a newline outside a double-quoted string — it's a parse error:
    # "Unexpected token '`n'". That was latent while injection ran in its own
    # elevated call, but it breaks the whole batched install script.)
    entries_ps_str = ",\n".join(entries_ps)

    return (
        f"$conf = '{_OSSEC_CONF}'\n"
        "if (-not (Test-Path $conf)) { throw 'ossec.conf missing' }\n"
        "$utf8NoBom = New-Object System.Text.UTF8Encoding($false)\n"
        "$content = [System.IO.File]::ReadAllText($conf, $utf8NoBom)\n"
        "if (-not $content.Contains('</ossec_config>')) { throw 'closing tag not found in ossec.conf' }\n"
        "$entries = @(\n"
        f"{entries_ps_str}\n"
        ")\n"
        "$changed = $false\n"
        "foreach ($e in $entries) {\n"
        "    if (-not $content.Contains($e.Marker)) {\n"
        "        $content = $content.Replace('</ossec_config>', $e.Block + \"`n</ossec_config>\")\n"
        "        $changed = $true\n"
        "    }\n"
        "}\n"
        "if ($changed) {\n"
        "    [System.IO.File]::WriteAllText($conf, $content, $utf8NoBom)\n"
        f"    $svc = Get-Service -Name '{_SERVICE_NAME}' -ErrorAction SilentlyContinue\n"
        "    if ($svc -and $svc.Status -eq 'Running') {\n"
        f"        Restart-Service -Name '{_SERVICE_NAME}' -Force\n"
        "    }\n"
        "}\n"
    )


def _inject_sysmon_config():
    """Add Sysmon eventchannel monitoring to ossec.conf (UAC prompt)."""
    return _inject_ossec_localfiles([
        ("Microsoft-Windows-Sysmon/Operational", _SYSMON_LOCALFILE_BLOCK),
    ])


def inject_defender_config():
    """Add Windows Defender eventchannel monitoring to ossec.conf (UAC prompt)."""
    return _inject_ossec_localfiles([
        ("Microsoft-Windows-Windows Defender/Operational", _DEFENDER_LOCALFILE_BLOCK),
    ])


def download_package(progress_callback=None):
    """Download the Wazuh MSI to a temporary directory.

    Returns the local path on success, or None on failure.
    """
    url = get_package_url()
    tmp_dir = tempfile.mkdtemp(prefix="wazuh_")
    msi_path = os.path.join(tmp_dir, "wazuh-agent.msi")

    if _download_file(url, msi_path, progress_callback, "Downloading Wazuh agent..."):
        return msi_path
    return None


def _ensure_ossec_address():
    """Patch ossec.conf if the manager address is wrong (e.g. left as 0.0.0.0 by MSI)."""
    try:
        with open(_OSSEC_CONF, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
        if f"<address>{WAZUH_MANAGER}</address>" in content:
            return
    except Exception:
        return
    logger.warning(f"ossec.conf has wrong manager address — patching to {WAZUH_MANAGER}")
    patch_cmd = (
        f"(Get-Content '{_OSSEC_CONF}') "
        f"-replace '<address>.*</address>', '<address>{WAZUH_MANAGER}</address>' | "
        f"Set-Content '{_OSSEC_CONF}'"
    )
    _run_privileged(patch_cmd)


def start_agent():
    """Start the Wazuh agent Windows service."""
    if get_agent_status() == "Running":
        return True

    _ensure_ossec_address()

    # Restore key if missing
    if os.path.exists(_KEY_BACKUP) and not os.path.exists(_CLIENT_KEYS):
        restore_cmd = (
            f"Copy-Item -Path '{_KEY_BACKUP}' -Destination '{_CLIENT_KEYS}' -Force"
        )
        _run_privileged(restore_cmd)

    success, output = _run_privileged(f"NET START {_SERVICE_NAME}")
    if success:
        logger.info("Wazuh agent started")
    else:
        logger.error(f"Failed to start agent: {output}")
    return success


def stop_agent():
    """Stop the Wazuh agent Windows service."""
    if not is_agent_installed():
        return True

    success, output = _run_privileged(f"NET STOP {_SERVICE_NAME}")

    # Verify stopped
    if get_agent_status() == "Running":
        logger.warning("Service still running after NET STOP, force-stopping")
        _run_privileged(f"Stop-Service -Name '{_SERVICE_NAME}' -Force")

    stopped = get_agent_status() != "Running"
    if stopped:
        logger.info("Wazuh agent stopped")
    else:
        logger.error("Failed to stop Wazuh agent")
    return stopped


def restore_client_key_if_needed():
    """Restore client.keys from backup if missing, then restart the agent."""
    if needs_reenrollment():
        logger.info("[WAZUH] Skipping key restore — enrolled under different email")
        return False

    if not os.path.exists(_KEY_BACKUP):
        logger.info("No client.keys backup found")
        return True

    # Only restore if missing
    script = (
        f"if (-not (Test-Path '{_CLIENT_KEYS}')) {{ "
        f"  Copy-Item -Path '{_KEY_BACKUP}' -Destination '{_CLIENT_KEYS}' -Force; "
        f"  Restart-Service -Name '{_SERVICE_NAME}'; "
        f"  Write-Output 'KEY_RESTORED' "
        f"}} else {{ "
        f"  Write-Output 'KEY_OK' "
        f"}}"
    )
    success, output = _run_privileged(script)
    if success:
        if "KEY_RESTORED" in output:
            logger.info("Restored client.keys from backup and restarted agent")
        else:
            logger.info("client.keys already present")
    return success


def remove_agent(wipe_keys: bool = False):
    """Stop and uninstall the Wazuh agent.

    When ``wipe_keys=True`` (used on user logout) the persistent client.keys
    backup is also deleted so the next user starts with a clean enrollment.
    """
    if not is_agent_installed() and not (wipe_keys and os.path.exists(_KEY_BACKUP)):
        return True

    backup_dir = os.path.dirname(_KEY_BACKUP)
    if wipe_keys:
        key_phase = (
            f"if (Test-Path '{_KEY_BACKUP}') {{ Remove-Item -Force '{_KEY_BACKUP}' }}; "
        )
    else:
        key_phase = (
            f"New-Item -ItemType Directory -Path '{backup_dir}' -Force | Out-Null; "
            f"if (Test-Path '{_CLIENT_KEYS}') {{ Copy-Item '{_CLIENT_KEYS}' '{_KEY_BACKUP}' -Force }}; "
        )

    script = (
        f"NET STOP {_SERVICE_NAME} 2>$null; "
        f"{key_phase}"
        # Uninstall via MSI product code lookup
        f"$app = Get-WmiObject -Class Win32_Product | Where-Object {{ $_.Name -like '*Wazuh*' }}; "
        f"if ($app) {{ $app.Uninstall() }}; "
        # Fallback: remove directory
        f"if (Test-Path '{WINDOWS_WAZUH_DIR}') {{ Remove-Item -Recurse -Force '{WINDOWS_WAZUH_DIR}' }}"
    )
    success, output = _run_privileged(script, timeout=300)
    if success:
        logger.info(f"Wazuh agent removed successfully (wipe_keys={wipe_keys})")
    else:
        logger.error(f"Failed to remove agent: {output}")
    return success


def _build_install_script(sysmon, msi_path, agent_name, agent_group, backup_dir):
    """Assemble ONE elevated PowerShell script for every privileged install step.

    Batching the Sysmon install, the Wazuh MSI, the ossec.conf patch +
    localfile injection, enrollment, key backup and service start into a single
    elevated invocation means the user approves UAC once instead of ~8 times.
    Each step is wrapped in its own try/catch so a soft failure in one (e.g.
    Sysmon) can't abort the rest; real success is verified in Python afterwards
    via is_agent_installed()/get_agent_status().

    msiexec runs under Start-Process -Wait so the package fully installs
    (creating ossec.conf, agent-auth.exe and the service) before the steps
    that depend on it run.
    """
    def _guard(ps):
        return f"try {{\n{ps}\n}} catch {{ }}"

    # msiexec args as a PowerShell ARRAY so Start-Process quotes each element
    # itself. Passing a single pre-joined string makes Start-Process re-split on
    # spaces, which corrupts an MSI path that contains spaces (e.g. a user named
    # "Jane Doe"). Property values are space-free (see config.py); the package
    # path is its own element so its spaces survive.
    msi_args = ",".join([
        "'/i'",
        f"'{msi_path}'",
        "'/qn'",
        f"'WAZUH_MANAGER={WAZUH_MANAGER}'",
        f"'WAZUH_MANAGER_PORT={WAZUH_MANAGER_PORT}'",
        f"'WAZUH_PROTOCOL={WAZUH_PROTOCOL}'",
        f"'WAZUH_REGISTRATION_SERVER={WAZUH_MANAGER}'",
        f"'WAZUH_REGISTRATION_PORT={WAZUH_REGISTRATION_PORT}'",
        f"'WAZUH_AGENT_NAME={agent_name}'",
        f"'WAZUH_AGENT_GROUP={agent_group}'",
    ])

    parts = ["$ErrorActionPreference = 'Continue'"]

    # Sysmon (optional — folded in only if it downloaded successfully).
    if sysmon:
        parts.append(_guard(_sysmon_install_ps(sysmon)))

    # Wazuh MSI — wait for full completion before configuring/enrolling.
    parts.append(_guard(
        f"Start-Process -FilePath 'msiexec.exe' -Wait -ArgumentList @({msi_args})"
    ))

    # Stop the service before enrollment so the final Start-Service loads the
    # freshly enrolled client.keys (the MSI may register it as auto-start).
    parts.append(_guard(
        f"Stop-Service -Name '{_SERVICE_NAME}' -Force -ErrorAction SilentlyContinue"
    ))

    # Patch manager address + agent name in ossec.conf.
    parts.append(_guard(
        f"if (Test-Path '{_OSSEC_CONF}') {{ "
        f"(Get-Content '{_OSSEC_CONF}') "
        f"-replace '<address>.*</address>', '<address>{WAZUH_MANAGER}</address>' "
        f"-replace '<agent_name>.*</agent_name>', '<agent_name>{agent_name}</agent_name>' | "
        f"Set-Content '{_OSSEC_CONF}' }}"
    ))

    # Inject Sysmon + Defender eventchannel monitoring.
    parts.append(_guard(_localfile_injection_ps([
        ("Microsoft-Windows-Sysmon/Operational", _SYSMON_LOCALFILE_BLOCK),
        ("Microsoft-Windows-Windows Defender/Operational", _DEFENDER_LOCALFILE_BLOCK),
    ])))

    # Enroll with the manager (writes client.keys).
    parts.append(_guard(
        f"if (Test-Path '{_AGENT_AUTH}') {{ "
        f"& '{_AGENT_AUTH}' -m '{WAZUH_MANAGER}' "
        f"-P '{WAZUH_REGISTRATION_PORT}' "
        f"-A '{agent_name}' -G '{agent_group}' }}"
    ))

    # Back up client.keys for future repair/recovery.
    parts.append(_guard(
        f"New-Item -ItemType Directory -Path '{backup_dir}' -Force | Out-Null; "
        f"if (Test-Path '{_CLIENT_KEYS}') {{ Copy-Item '{_CLIENT_KEYS}' '{_KEY_BACKUP}' -Force }}"
    ))

    # Start the service (stopped after a fresh MSI install, so it now loads
    # the freshly enrolled client.keys).
    parts.append(_guard(f"Start-Service -Name '{_SERVICE_NAME}'"))

    return "\n\n".join(parts)


def full_install(progress_callback=None):
    """Install the Wazuh agent (and Sysmon) in a SINGLE elevation prompt.

    All downloads run unprivileged first; then every privileged step is batched
    into one elevated PowerShell invocation (see _build_install_script), so the
    user approves UAC just once instead of ~8 times.
    """
    def _p(msg):
        if progress_callback:
            progress_callback(msg)

    # --- Unprivileged downloads (no prompt) ---
    sysmon = _prepare_sysmon_download(progress_callback)

    _p("Downloading Wazuh agent...")
    msi_path = download_package(progress_callback)
    if not msi_path:
        _p("Download failed")
        return False

    # Agent name/group (server-side group auto-created on enroll).
    agent_name = get_agent_name()
    agent_group = get_agent_group()
    backup_dir = os.path.dirname(_KEY_BACKUP)

    # --- Single elevated batch: one UAC prompt for the whole install ---
    _p("Installing — please approve the administrator prompt...")
    script = _build_install_script(
        sysmon, msi_path, agent_name, agent_group, backup_dir)
    success, output = _run_privileged(script, timeout=600)
    logger.info(f"[WAZUH] combined install ok={success} output={output!r}")

    if not is_agent_installed():
        logger.error(f"Install failed (agent not present): {output}")
        _p("Installation failed")
        return False

    # --- Unprivileged verify (no prompt) ---
    # Start-Service can return while the service is still START_PENDING, so
    # poll briefly until it actually reports Running before declaring success.
    _p("Starting Wazuh agent...")
    for _ in range(15):
        if get_agent_status() == "Running":
            break
        time.sleep(1)

    if get_agent_status() == "Running":
        logger.info("Wazuh agent installed and running")
        _p("Wazuh agent installed and running")
    else:
        logger.warning("Agent installed but not yet running")
        _p("Wazuh agent installed (may need manual start)")

    # Record enrollment email
    settings.set("wazuh", "enrolled_email", settings.get("auth", "email", ""))

    logger.info("Wazuh full install completed successfully")
    return True
