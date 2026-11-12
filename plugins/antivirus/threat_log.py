"""Syslog-formatted threat logger for Wazuh SIEM integration.

Writes antivirus events to a log file in RFC 3164 syslog format.
The Wazuh agent reads this file via a <localfile> entry in
ossec.conf and forwards events to the SIEM dashboard.

Log format (RFC 3164):
    MMM DD HH:MM:SS hostname resistine-av: EVENT key="value" ...

Author: Phoenix Team
Copyright (c) Phoenix 2025
Licensed under the GNU General Public License v2 or later
"""
from __future__ import annotations

import base64
import os
import platform
import shlex
import subprocess
import threading
import time

from utils import settings
from utils.logger import logger

_PROGRAM = "resistine-av"
_write_lock = threading.Lock()


def _log_dir() -> str:
    from plugins.antivirus.clamav_common import _LOG_DIR, _ensure_dirs

    _ensure_dirs()
    return _LOG_DIR


def get_log_path() -> str:
    """Return the threat log file path."""
    return os.path.join(_log_dir(), "threats.log")


def get_log_display() -> str:
    """Return a UI-friendly description of where threat events come from.

    Defender writes to the Windows event log, not a syslog file, so the
    file path on Mac/Linux maps to an event-channel name on Windows.
    """
    if platform.system() == "Windows":
        return "Microsoft-Windows-Windows Defender/Operational"
    return get_log_path()


def _hostname() -> str:
    return platform.node() or "localhost"


def _syslog_ts() -> str:
    """RFC 3164 timestamp: 'Apr 16 13:18:05'."""
    return time.strftime("%b %d %H:%M:%S")


def _write(line: str):
    with _write_lock:
        try:
            with open(get_log_path(), "a") as f:
                f.write(line + "\n")
        except OSError as exc:
            logger.error(f"AV: failed to write threat log: {exc}")


def _escape(v: str) -> str:
    """Escape user-controlled values for safe syslog embedding."""
    return str(v).replace("\\", "\\\\").replace('"', '\\"').replace(
        "\n", "\\n",
    ).replace("\r", "\\r")


def _fmt(event: str, **kv) -> str:
    ts = _syslog_ts()
    host = _hostname()
    fields = " ".join(f'{k}="{_escape(v)}"' for k, v in kv.items())
    return f"{ts} {host} {_PROGRAM}: {event} {fields}"


# ── Event loggers ────────────────────────────────────────


def log_threat_detected(signature: str, filepath: str):
    """Log a threat detection event."""
    _write(_fmt("THREAT_DETECTED", signature=signature, path=filepath))


def log_threat_quarantined(signature: str, filepath: str, dest: str):
    """Log a quarantine action."""
    _write(_fmt(
        "THREAT_QUARANTINED",
        signature=signature, path=filepath, dest=dest,
    ))


def log_threat_deleted(filepath: str):
    """Log permanent deletion of a quarantined file."""
    _write(_fmt("THREAT_DELETED", path=filepath))


# ── Helpers ──────────────────────────────────────────────


def parse_infection_line(line: str) -> tuple[str, str]:
    """Parse '/path: Sig.Name FOUND' into (filepath, signature)."""
    parts = line.rsplit(":", 1)
    if len(parts) != 2:
        return line.strip(), "Unknown"
    filepath = parts[0].strip()
    sig_part = parts[1].strip()
    if sig_part.endswith(" FOUND"):
        sig_part = sig_part[:-6].strip()
    return filepath, sig_part


# ── Wazuh ossec.conf integration ─────────────────────────

def _wazuh_dir():
    """The agent's install dir on this platform (Linux: the first one present)."""
    from plugins.wazuh.config import (
        LINUX_WAZUH_DIR, LINUX_WAZUH_DIR_CANDIDATES, WAZUH_INSTALL_DIR, WINDOWS_WAZUH_DIR,
    )
    system = platform.system()
    if system == "Darwin":
        return WAZUH_INSTALL_DIR
    if system == "Windows":
        return WINDOWS_WAZUH_DIR
    if system == "Linux":
        return next((d for d in LINUX_WAZUH_DIR_CANDIDATES if os.path.isdir(d)), LINUX_WAZUH_DIR)
    return None


def is_wazuh_installed() -> bool:
    """Check if the Wazuh agent is installed.

    The config directory is root-only, so we check for the install
    directory rather than the config file itself.
    """
    d = _wazuh_dir()
    return bool(d and os.path.isdir(d))


def is_forwarding_enabled() -> bool:
    """True if AV log forwarding to the SIEM is configured and the agent is present.

    On Windows the endpoint installer always injects the Defender eventchannel
    localfile during full_install, so a present agent means forwarding is
    already on. On macOS/Linux forwarding is configured only via
    setup_wazuh_forwarding(), so it's tracked with a settings flag (ossec.conf
    is root-only and can't be read to verify directly).

    macOS default: ON. When the Wazuh agent is installed on Mac the switch
    appears already enabled — the user doesn't need to discover and flip a
    toggle to get protection. The actual ossec.conf localfile entry is
    written the first time the user explicitly toggles or via the Wazuh
    install flow's follow-up step. Until then the flag-only state matches
    user expectation; toggling off saves False explicitly and persists.
    Linux remains opt-in (default False) because the Linux Wazuh path is
    less mature and silently auto-enabling could mask a half-finished install.
    """
    if not is_wazuh_installed():
        return False
    if platform.system() != "Windows":
        _default = platform.system() == "Darwin"
        return bool(settings.get("antivirus", "siem_forwarding", _default))
    conf = r"C:\Program Files (x86)\ossec-agent\ossec.conf"
    if not os.path.exists(conf):
        return False
    try:
        with open(conf, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
        return (
            "Microsoft-Windows-Windows Defender/Operational" in content
            and "<localfile>" in content
        )
    except (OSError, PermissionError):
        # ACL'd ossec.conf (locked to SYSTEM on some deployments). Use the
        # same default-True policy as Mac when on Windows here too — if the
        # installer ran far enough to install the agent, forwarding is the
        # expected end-state.
        return bool(settings.get("antivirus", "siem_forwarding", True))


def get_ossec_snippet() -> str:
    """Return the XML localfile block for ossec.conf."""
    return (
        "  <localfile>\n"
        "    <log_format>syslog</log_format>\n"
        f"    <location>{get_log_path()}</location>\n"
        "  </localfile>"
    )


def setup_wazuh_forwarding() -> tuple[bool, str]:
    """Add our localfile entry to ossec.conf (requires admin).

    Returns (success, message). On success the forwarding flag is recorded so
    the UI can reflect it without re-reading the root-only ossec.conf.
    """
    if not is_wazuh_installed():
        return False, "Wazuh agent not installed."

    d = _wazuh_dir()
    conf = os.path.join(d, "ossec.conf" if platform.system() == "Windows" else "etc/ossec.conf") if d else None
    if not conf:
        return False, "Unsupported platform."

    # ossec.conf is root-only — skip unprivileged checks,
    # the privileged script validates everything itself.
    system = platform.system()
    if system == "Darwin":
        ok, msg = _inject_darwin(conf)
    elif system == "Linux":
        ok, msg = _inject_linux(conf)
    elif system == "Windows":
        ok, msg = _inject_windows()
    else:
        return False, f"Unknown platform: {system}"

    if ok:
        try:
            settings.set("antivirus", "siem_forwarding", True)
        except Exception:
            pass
    return ok, msg


def _inject_darwin(conf: str) -> tuple[bool, str]:
    """Inject localfile entry via osascript with admin privileges."""
    import json
    snippet = get_ossec_snippet()

    # Python script runs as root: validate, backup, read, check, modify, write.
    # Use json.dumps/json.loads for string serialisation to avoid code injection
    # via repr() with attacker-controlled path or snippet content.
    py_script = (
        "import json, os, shutil, sys\n"
        f"conf = json.loads({json.dumps(json.dumps(conf))})\n"
        "if not os.path.isfile(conf):\n"
        "    print('error: ossec.conf not found at ' + conf)\n"
        "    sys.exit(1)\n"
        "with open(conf) as f:\n"
        "    content = f.read()\n"
        "if 'threats.log' in content:\n"
        "    print('already_configured')\n"
        "    sys.exit(0)\n"
        "shutil.copy2(conf, conf + '.bak')\n"
        f"snippet = json.loads({json.dumps(json.dumps(snippet))})\n"
        "new = content.replace("
        "'</ossec_config>', snippet + '\\n\\n</ossec_config>')\n"
        "with open(conf, 'w') as f:\n"
        "    f.write(new)\n"
        "print('configured')\n"
    )
    encoded = base64.b64encode(py_script.encode()).decode()

    # Use shlex.quote to safely embed the base64 blob in the shell command.
    shell_cmd = (
        f"printf '%s' {shlex.quote(encoded)} | base64 -d | python3 && "
        f"launchctl kickstart -k system/com.wazuh.agent 2>/dev/null; true"
    )
    escaped = shell_cmd.replace("\\", "\\\\").replace('"', '\\"')
    apple_script = (
        f'do shell script "{escaped}" with administrator privileges'
    )

    try:
        result = subprocess.run(
            ["osascript", "-e", apple_script],
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode == 0:
            output = result.stdout.strip()
            if "already_configured" in output:
                return True, "Already configured."
            logger.info("AV: Wazuh forwarding configured")
            return True, "Configured. Wazuh agent restarted."
        err = result.stderr.strip()
        if "User cancelled" in err or "(-128)" in err:
            return False, "Admin approval cancelled."
        return False, err or "Failed to update ossec.conf"
    except subprocess.TimeoutExpired:
        return False, "Timed out waiting for admin approval."
    except Exception as exc:
        return False, str(exc)


def _inject_linux(conf: str) -> tuple[bool, str]:
    """Inject localfile entry via pkexec/sudo."""
    import json
    snippet = get_ossec_snippet()

    # Use json.dumps/json.loads for string serialisation to avoid code injection
    # via repr() with attacker-controlled path or snippet content.
    py_script = (
        "import json, os, shutil, sys\n"
        f"conf = json.loads({json.dumps(json.dumps(conf))})\n"
        "if not os.path.isfile(conf):\n"
        "    print('error: ossec.conf not found at ' + conf)\n"
        "    sys.exit(1)\n"
        "with open(conf) as f:\n"
        "    content = f.read()\n"
        "if 'threats.log' in content:\n"
        "    print('already_configured')\n"
        "    sys.exit(0)\n"
        "shutil.copy2(conf, conf + '.bak')\n"
        f"snippet = json.loads({json.dumps(json.dumps(snippet))})\n"
        "new = content.replace("
        "'</ossec_config>', snippet + '\\n\\n</ossec_config>')\n"
        "with open(conf, 'w') as f:\n"
        "    f.write(new)\n"
        "print('configured')\n"
    )
    encoded = base64.b64encode(py_script.encode()).decode()
    # Multi-init dispatcher: try systemd, sysv-init, OpenRC, then wazuh-control
    # so non-systemd Linux (Alpine, Devuan-sysvinit, WSL1) actually reloads the
    # agent instead of silently succeeding. Exit code 2 => configured but
    # restart failed; the caller surfaces that distinctly from a config failure.
    restart_chain = (
        "systemctl restart wazuh-agent 2>/dev/null "
        "|| service wazuh-agent restart 2>/dev/null "
        "|| rc-service wazuh-agent restart 2>/dev/null "
        "|| /var/ossec/bin/wazuh-control restart 2>/dev/null "
        "|| { echo restart_failed; exit 2; }"
    )
    # Use shlex.quote to safely embed the base64 blob in the shell command.
    shell_cmd = (
        f"printf '%s' {shlex.quote(encoded)} | base64 -d | python3 || exit 1; "
        f"{restart_chain}"
    )

    elevate = [[]] if os.geteuid() == 0 else [["pkexec"], ["sudo"]]
    for cmd in ([*e, "bash", "-c", shell_cmd] for e in elevate):
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=30,
            )
            output = (result.stdout or "").strip()
            if result.returncode == 0:
                if "already_configured" in output:
                    return True, "Already configured."
                logger.info("AV: Wazuh forwarding configured")
                return True, "Configured. Wazuh agent restarted."
            if result.returncode == 2:
                # Config injected but no known init system accepted the restart.
                logger.error(
                    "AV: Wazuh forwarding configured but agent restart "
                    "failed under all known init systems (systemd/service/"
                    "rc-service/wazuh-control). stderr=%s",
                    (result.stderr or "").strip(),
                )
                return True, (
                    "Configured, but Wazuh agent restart failed. "
                    "Restart it manually to apply the new config."
                )
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue
        except Exception as exc:
            return False, str(exc)
    return False, "Could not obtain admin privileges."


def _inject_windows() -> tuple[bool, str]:
    """Register the Windows Defender event channel with the Wazuh agent.

    Defender writes to Microsoft-Windows-Windows Defender/Operational, which
    the Wazuh agent reads directly via an <eventchannel> localfile entry — no
    syslog file needed (unlike the ClamAV path used on Mac/Linux).
    """
    from plugins.wazuh.agent.wazuh_functions_windows import inject_defender_config

    try:
        ok = inject_defender_config()
    except Exception as exc:
        return False, str(exc)
    if ok:
        return True, "Configured. Defender events will forward to Wazuh."
    return False, "Failed to update ossec.conf. See logs for details."
