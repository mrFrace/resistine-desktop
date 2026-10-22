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
from utils.windows_admin import is_admin as _is_admin

from plugins.wazuh.agent import enrollment, phoenix_packages
from plugins.wazuh.config import (
    WAZUH_MANAGER,
    WAZUH_MANAGER_ENDPOINT,
    WAZUH_MANAGER_PORT,
    WAZUH_PROTOCOL,
    WAZUH_REGISTRATION_PORT,
    WINDOWS_WAZUH_DIR,
    WINDOWS_SYSMON_ZIP_URL,
    WINDOWS_SYSMON_CONFIG_URL,
)

_OSSEC_CONF = os.path.join(WINDOWS_WAZUH_DIR, "ossec.conf")
_CLIENT_KEYS = os.path.join(WINDOWS_WAZUH_DIR, "client.keys")
_KEY_BACKUP = os.path.join(os.environ.get("APPDATA", ""), "Phoenix", "wazuh_client.keys")
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

# PowerShell treats the typographic quotes U+2018..U+201B exactly like an ASCII
# apostrophe as single-quote string delimiters, so all of them must be doubled.
_PS_SINGLE_QUOTES = ("'", "\u2018", "\u2019", "\u201a", "\u201b")


def _ps_escape_path(value):
    """Escape *value* for use inside a PowerShell single-quoted string.

    Single-quoted PowerShell strings expand nothing ($, backtick, double
    quotes are literal); the only way out is a single quote, which is escaped
    by doubling it.  Prevents injection via crafted paths/URLs (e.g. a user
    profile directory named ``O'Brien`` or ``x'; Remove-Item ...``).
    """
    value = str(value)
    for q in _PS_SINGLE_QUOTES:
        value = value.replace(q, q + q)
    return value


def _ps_quote(value):
    """Return *value* as a complete, safely escaped PowerShell '...' literal."""
    return f"'{_ps_escape_path(value)}'"


_PS_EXE = ["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass"]


def _write_temp_ps1(body):
    """Write *body* to a new temp .ps1 file and return its path.

    UTF-8 *with BOM*: Windows PowerShell 5.1 reads BOM-less scripts as the
    ANSI code page, which would corrupt non-ASCII paths.
    """
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".ps1", delete=False, encoding="utf-8-sig",
    ) as f:
        f.write(body)
        return f.name


def _run_privileged(command, timeout=300):
    """Run a PowerShell script with admin privileges.  Returns (success, output).

    The script is always written to a temp .ps1 and executed with ``-File``
    (never interpolated into a ``-Command`` string).  If already admin it runs
    directly; otherwise it is elevated with ``Start-Process -Verb RunAs`` and
    the only values embedded in that launcher are our own temp paths, escaped
    with _ps_escape_path.  Every value interpolated into *command* itself
    must be quoted with _ps_quote().
    """
    script_path = ""
    result_file = ""
    try:
        if _is_admin():
            script_path = _write_temp_ps1(command)
            result = subprocess.run(
                _PS_EXE + ["-File", script_path],
                capture_output=True, text=True, timeout=timeout,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
            output = result.stdout.strip() or result.stderr.strip()
            logger.info(f"_run_privileged: rc={result.returncode} output={output!r}")
            return (result.returncode == 0, output)

        # Not admin: wrap the command so the elevated process reports back via
        # a result file, then elevate the script via -File.
        result_file = os.path.join(
            tempfile.gettempdir(), f"phoenix-wazuh-{os.getpid()}-{time.time_ns()}.result"
        )
        rf = _ps_quote(result_file)
        script_path = _write_temp_ps1(
            f"try {{\n{command}\n'SUCCESS' | Out-File -FilePath {rf} -Encoding utf8\n}}\n"
            f"catch {{ $_.Exception.Message | Out-File -FilePath {rf} -Encoding utf8 }}\n"
        )
        # Start-Process joins -ArgumentList with spaces without quoting, so the
        # script path is wrapped in literal double quotes (paths can't contain ").
        elevate_cmd = (
            "Start-Process powershell -Verb RunAs -Wait -WindowStyle Hidden "
            "-ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-NonInteractive',"
            f"'-File','\"{_ps_escape_path(script_path)}\"'"
        )
        subprocess.run(
            _PS_EXE + ["-Command", elevate_cmd],
            capture_output=True, text=True, timeout=timeout,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        if os.path.exists(result_file):
            with open(result_file, encoding="utf-8-sig") as f:
                output = f.read().strip()
            return ("SUCCESS" in output, output)
        return (False, "No result from elevated process")
    except subprocess.TimeoutExpired:
        return (False, "Command timed out")
    except Exception as e:
        return (False, str(e))
    finally:
        for path in (script_path, result_file):
            if path:
                try:
                    os.unlink(path)
                except OSError:
                    pass


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
    return "phoenix-agent"


def get_agent_group():
    """The Wazuh group of this user's agents (u_<Matrix localpart>)."""
    return enrollment.agent_group()


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


def get_agent_connection():
    """Return the agent's live manager-connection status.

    One of ``connected`` / ``pending`` / ``disconnected`` / ``unknown``.
    Reads Wazuh's own wazuh-agentd.state; falls back to ossec.log. Distinct
    from get_agent_status(), which only reports whether the service is alive.
    """
    from plugins.wazuh.agent import agent_state

    return agent_state.read_agent_connection(
        os.path.join(WINDOWS_WAZUH_DIR, "wazuh-agentd.state"),
        os.path.join(WINDOWS_WAZUH_DIR, "ossec.log"),
    )


def get_package_url():
    """Return the manifest URL of the Phoenix agent MSI."""
    return phoenix_packages.manifest_url("windows")


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
            f"Invoke-WebRequest -Uri {_ps_quote(url)} -OutFile {_ps_quote(dest_path)} -UseBasicParsing"
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
        f"New-Item -ItemType Directory -Path {_ps_quote(_SYSMON_DIR)} -Force | Out-Null; "
        f"Copy-Item -Path {_ps_quote(os.path.join(sysmon['dir'], '*'))} "
        f"-Destination {_ps_quote(_SYSMON_DIR)} -Recurse -Force; "
        f"& {_ps_quote(sysmon['exe'])} -accepteula -i {_ps_quote(sysmon['config'])}"
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
        f"$conf = {_ps_quote(_OSSEC_CONF)}\n"
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
        f"    $svc = Get-Service -Name {_ps_quote(_SERVICE_NAME)} -ErrorAction SilentlyContinue\n"
        "    if ($svc -and $svc.Status -eq 'Running') {\n"
        f"        Restart-Service -Name {_ps_quote(_SERVICE_NAME)} -Force\n"
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
    """Download the signed Phoenix agent MSI (needs a Phoenix sign-in).

    Returns the verified local path, or None on failure.
    """
    return phoenix_packages.download_or_none(
        tempfile.mkdtemp(prefix="phoenix_agent_"), progress_callback,
        filename="phoenix-agent.msi")


def _key_write_ps(key_file):
    """PowerShell installing the key line from ``key_file`` (written by
    enrollment.request) as client.keys, after re-checking its shape."""
    return (
        f"$k = Get-Content -LiteralPath {_ps_quote(key_file)} -TotalCount 1 -ErrorAction Stop; "
        f"if ($k -cnotmatch {_ps_quote('^' + enrollment.KEY_LINE_PATTERN + '$')}) "
        f"{{ Write-Output 'KEY_INVALID'; throw 'KEY_INVALID' }}; "
        f"[IO.File]::WriteAllText({_ps_quote(_CLIENT_KEYS)}, $k + \"`n\", [Text.Encoding]::ASCII)"
    )


def _register_ps(enrolled, agent_name, agent_group):
    """Write the API-enrolled key, or (fallback) register with agent-auth."""
    if enrolled:
        return _key_write_ps(enrolled.key_file)
    return (
        f"if (Test-Path {_ps_quote(_AGENT_AUTH)}) {{ "
        f"& {_ps_quote(_AGENT_AUTH)} -m {_ps_quote(WAZUH_MANAGER)} "
        f"-p {_ps_quote(WAZUH_REGISTRATION_PORT)} "
        f"-A {_ps_quote(agent_name)} -G {_ps_quote(agent_group)} }}"
    )


def _ensure_ossec_address():
    """Patch ossec.conf if the manager endpoint is wrong (e.g. left as 0.0.0.0 by MSI)."""
    try:
        with open(_OSSEC_CONF, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
        if f"<endpoint>{WAZUH_MANAGER_ENDPOINT}</endpoint>" in content:
            return
    except Exception:
        return
    logger.warning(f"ossec.conf has wrong manager endpoint — patching to {WAZUH_MANAGER_ENDPOINT}")
    patch_cmd = (
        f"(Get-Content {_ps_quote(_OSSEC_CONF)}) "
        f"-replace '<endpoint>.*</endpoint>', '<endpoint>{_ps_escape_path(WAZUH_MANAGER_ENDPOINT)}</endpoint>' | "
        f"Set-Content {_ps_quote(_OSSEC_CONF)}"
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
            f"Copy-Item -Path {_ps_quote(_KEY_BACKUP)} -Destination {_ps_quote(_CLIENT_KEYS)} -Force"
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
        _run_privileged(f"Stop-Service -Name {_ps_quote(_SERVICE_NAME)} -Force")

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
        f"if (-not (Test-Path {_ps_quote(_CLIENT_KEYS)})) {{ "
        f"  Copy-Item -Path {_ps_quote(_KEY_BACKUP)} -Destination {_ps_quote(_CLIENT_KEYS)} -Force; "
        f"  Restart-Service -Name {_ps_quote(_SERVICE_NAME)}; "
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


def reenroll_agent():
    """Force a fresh manager registration to recover a dead/invalid key.

    Used when the agent is Running but never reaches ``connected`` (e.g. the
    old agent was deleted server-side after a reinstall, invalidating the
    reused key). Wipes the local key + backup, enrolls under a fresh unique
    name so the manager creates a brand-new record, then restarts the service.
    Returns (ok, msg).
    """
    if not is_agent_installed():
        return (False, "Wazuh agent is not installed")

    base = get_agent_name()
    new_name = f"{base}-{str(int(time.time()))[-6:]}"
    group = get_agent_group()
    # The Phoenix API answers with the manager's current key for this device
    # (a new agent if the old one was deleted there); else agent-auth.
    enrolled = enrollment.request(new_name)
    if enrolled:
        new_name = enrolled.agent_name
        group = enrolled.group

    script = (
        f"Stop-Service -Name {_ps_quote(_SERVICE_NAME)} -Force -ErrorAction SilentlyContinue; "
        f"Remove-Item -Path {_ps_quote(_CLIENT_KEYS)},{_ps_quote(_KEY_BACKUP)} -Force "
        f"-ErrorAction SilentlyContinue; "
        f"{_register_ps(enrolled, new_name, group)}; "
        f"if (-not (Test-Path {_ps_quote(_CLIENT_KEYS)}) -or "
        f"((Get-Item {_ps_quote(_CLIENT_KEYS)}).Length -eq 0)) "
        f"{{ Write-Output 'REENROLL_NO_KEY'; exit 1 }}; "
        f"if (Test-Path {_ps_quote(_OSSEC_CONF)}) {{ (Get-Content {_ps_quote(_OSSEC_CONF)}) "
        f"-replace '<agent_name>.*</agent_name>', '<agent_name>{_ps_escape_path(new_name)}</agent_name>' | "
        f"Set-Content {_ps_quote(_OSSEC_CONF)} }}; "
        f"New-Item -ItemType Directory -Path (Split-Path {_ps_quote(_KEY_BACKUP)}) -Force "
        f"| Out-Null; "
        f"Copy-Item {_ps_quote(_CLIENT_KEYS)} {_ps_quote(_KEY_BACKUP)} -Force; "
        f"Start-Service -Name {_ps_quote(_SERVICE_NAME)}; "
        f"Write-Output 'REENROLL_OK'"
    )
    success, output = _run_privileged(script)
    enrollment.discard(enrolled)
    if success and "REENROLL_OK" in (output or "") \
            and "REENROLL_NO_KEY" not in (output or ""):
        logger.info(f"Wazuh re-enrolled under fresh name {new_name}")
        return (True, f"Re-enrolled as {new_name}")
    logger.error(f"Wazuh re-enroll failed: {output!r}")
    return (False, output or "Re-enrollment failed")


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
            f"if (Test-Path {_ps_quote(_KEY_BACKUP)}) {{ Remove-Item -Force {_ps_quote(_KEY_BACKUP)} }}; "
        )
    else:
        key_phase = (
            f"New-Item -ItemType Directory -Path {_ps_quote(backup_dir)} -Force | Out-Null; "
            f"if (Test-Path {_ps_quote(_CLIENT_KEYS)}) {{ Copy-Item {_ps_quote(_CLIENT_KEYS)} {_ps_quote(_KEY_BACKUP)} -Force }}; "
        )

    script = (
        f"NET STOP {_SERVICE_NAME} 2>$null; "
        f"{key_phase}"
        # Uninstall the MSI, so Windows no longer counts the agent as installed
        f"{_PS_UNINSTALL_AGENT_MSI}; "
        # Fallback: remove directory
        f"if (Test-Path {_ps_quote(WINDOWS_WAZUH_DIR)}) {{ Remove-Item -Recurse -Force {_ps_quote(WINDOWS_WAZUH_DIR)} }}"
    )
    success, output = _run_privileged(script, timeout=300)
    if success:
        logger.info(f"Wazuh agent removed successfully (wipe_keys={wipe_keys})")
    else:
        logger.error(f"Failed to remove agent: {output}")
    return success


# Uninstalls every registered agent MSI (ours is "Phoenix Agent"; older ones
# "Wazuh Agent ...") by product code, read from the Uninstall registry keys.
# Win32_Product is avoided: it is slow and makes Windows check every MSI.
_PS_UNINSTALL_AGENT_MSI = (
    "Get-ItemProperty "
    "'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*',"
    "'HKLM:\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*' "
    "-ErrorAction SilentlyContinue | "
    "Where-Object { $_.DisplayName -eq 'Phoenix Agent' -or $_.DisplayName -like 'Wazuh Agent*' } | "
    "ForEach-Object { if ($_.PSChildName -match '^\\{[0-9A-Fa-f-]{36}\\}$') { "
    "Start-Process -FilePath 'msiexec.exe' -Wait -ArgumentList @('/x', $_.PSChildName, '/qn', '/norestart') } }"
)


def _msi_log_path(msi_path):
    """Where msiexec writes its verbose log for *msi_path* (next to the package)."""
    return os.path.splitext(msi_path)[0] + "-install.log"


_MSI_EXIT_MEANING = {
    1602: "the install was cancelled",
    1603: "the installer hit a fatal error",
    1618: "another installation is already running",
    1638: "another version of the agent is already installed",
    1925: "the installer needs administrator rights",
}


def msi_failure_summary(log_path, max_lines=25):
    """Explain a failed MSI install from its verbose log, for our own log.

    Returns "" when there is no log. Otherwise the exit code (from the
    "MainEngineThread is returning N" line) and the lines before the first
    "Return value 3", which is where Windows Installer records the failing
    action and its error.
    """
    try:
        with open(log_path, encoding="utf-16", errors="replace") as f:
            lines = f.read().splitlines()
    except UnicodeError:
        with open(log_path, encoding="utf-8", errors="replace") as f:
            lines = f.read().splitlines()
    except OSError:
        return ""
    code = None
    for line in lines:
        m = re.search(r"MainEngineThread is returning (\d+)", line)
        if m:
            code = int(m.group(1))
    summary = [f"msiexec exit code {code}"
               + (f" ({_MSI_EXIT_MEANING[code]})" if code in _MSI_EXIT_MEANING else "")
               if code is not None else "msiexec exit code unknown"]
    for i, line in enumerate(lines):
        if "Return value 3" in line:
            summary += [x for x in lines[max(0, i - max_lines):i + 1] if x.strip()]
            break
    return "\n".join(summary)


def _build_install_script(sysmon, msi_path, agent_name, agent_group, backup_dir, enrolled=None):
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
        _ps_quote(msi_path),
        "'/qn'",
        _ps_quote(f"WAZUH_MANAGER={WAZUH_MANAGER}"),
        _ps_quote(f"WAZUH_MANAGER_PORT={WAZUH_MANAGER_PORT}"),
        _ps_quote(f"WAZUH_PROTOCOL={WAZUH_PROTOCOL}"),
        _ps_quote(f"WAZUH_REGISTRATION_SERVER={WAZUH_MANAGER}"),
        _ps_quote(f"WAZUH_REGISTRATION_PORT={WAZUH_REGISTRATION_PORT}"),
        _ps_quote(f"WAZUH_AGENT_NAME={agent_name}"),
        _ps_quote(f"WAZUH_AGENT_GROUP={agent_group}"),
        "'/l*v'",
        _ps_quote(_msi_log_path(msi_path)),
    ])

    parts = ["$ErrorActionPreference = 'Continue'"]

    # Sysmon (optional — folded in only if it downloaded successfully).
    if sysmon:
        parts.append(_guard(_sysmon_install_ps(sysmon)))

    # An agent MSI still registered without its files (its folder was deleted
    # by hand, or by an older uninstall) makes msiexec /i a silent no-op.
    # Uninstall that registration first.
    parts.append(_guard(
        f"if (-not (Test-Path {_ps_quote(os.path.join(WINDOWS_WAZUH_DIR, 'wazuh-agent.exe'))})) "
        f"{{ {_PS_UNINSTALL_AGENT_MSI} }}"
    ))

    # Wazuh MSI — wait for full completion before configuring/enrolling.
    parts.append(_guard(
        f"Start-Process -FilePath 'msiexec.exe' -Wait -ArgumentList @({msi_args})"
    ))

    # Stop the service before enrollment so the final Start-Service loads the
    # freshly enrolled client.keys (the MSI may register it as auto-start).
    parts.append(_guard(
        f"Stop-Service -Name {_ps_quote(_SERVICE_NAME)} -Force -ErrorAction SilentlyContinue"
    ))

    # Patch manager endpoint + agent name in ossec.conf.
    parts.append(_guard(
        f"if (Test-Path {_ps_quote(_OSSEC_CONF)}) {{ "
        f"(Get-Content {_ps_quote(_OSSEC_CONF)}) "
        f"-replace '<endpoint>.*</endpoint>', '<endpoint>{_ps_escape_path(WAZUH_MANAGER_ENDPOINT)}</endpoint>' "
        f"-replace '<agent_name>.*</agent_name>', '<agent_name>{_ps_escape_path(agent_name)}</agent_name>' | "
        f"Set-Content {_ps_quote(_OSSEC_CONF)} }}"
    ))

    # Inject Sysmon + Defender eventchannel monitoring.
    parts.append(_guard(_localfile_injection_ps([
        ("Microsoft-Windows-Sysmon/Operational", _SYSMON_LOCALFILE_BLOCK),
        ("Microsoft-Windows-Windows Defender/Operational", _DEFENDER_LOCALFILE_BLOCK),
    ])))

    # Enroll (writes client.keys): the key from the Phoenix API, or agent-auth.
    parts.append(_guard(_register_ps(enrolled, agent_name, agent_group)))

    # Back up client.keys for future repair/recovery.
    parts.append(_guard(
        f"New-Item -ItemType Directory -Path {_ps_quote(backup_dir)} -Force | Out-Null; "
        f"if (Test-Path {_ps_quote(_CLIENT_KEYS)}) {{ Copy-Item {_ps_quote(_CLIENT_KEYS)} {_ps_quote(_KEY_BACKUP)} -Force }}"
    ))

    # Start the service (stopped after a fresh MSI install, so it now loads
    # the freshly enrolled client.keys).
    parts.append(_guard(f"Start-Service -Name {_ps_quote(_SERVICE_NAME)}"))

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

    # Agent name/group. The Phoenix API enrolls server side, in the user's
    # group; without it agent-auth registers with this group.
    agent_name = get_agent_name()
    agent_group = get_agent_group()
    enrolled = enrollment.request(agent_name)
    if enrolled:
        agent_name = enrolled.agent_name
        agent_group = enrolled.group
    backup_dir = os.path.dirname(_KEY_BACKUP)

    # --- Single elevated batch: one UAC prompt for the whole install ---
    _p("Installing — please approve the administrator prompt...")
    script = _build_install_script(
        sysmon, msi_path, agent_name, agent_group, backup_dir, enrolled)
    success, output = _run_privileged(script, timeout=600)
    enrollment.discard(enrolled)
    logger.info(f"[WAZUH] combined install ok={success} output={output!r}")

    if not is_agent_installed():
        logger.error(f"Install failed (agent not present): {output}")
        why = msi_failure_summary(_msi_log_path(msi_path))
        logger.error(f"[WAZUH] MSI log {_msi_log_path(msi_path)}:\n{why or 'no MSI log written'}")
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
