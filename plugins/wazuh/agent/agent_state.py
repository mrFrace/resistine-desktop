"""
Wazuh agent connection-state parsing — platform-agnostic.

The Wazuh agent writes its live manager-connection status to
``<install>/var/run/wazuh-agentd.state`` (an ini-like file with lines such
as ``status='connected'``). The plugin previously only checked whether the
agent *process* was alive, which cannot distinguish a healthy agent from one
whose key was invalidated server-side (e.g. the operator deleted the old
agent after a reinstall). Reading the real status lets the UI show
"connected vs not" and lets the auto-heal path re-enroll a dead key.

This module is pure (no platform imports, no I/O side effects beyond reading
the caller-supplied paths) so it is trivially unit-testable on any OS.

Author: Resistine Team
Copyright (c) Resistine 2025
Licensed under the GNU General Public License v2 or later
"""

import os
import platform
import subprocess

# Canonical connection states returned by this module.
CONNECTED = "connected"
PENDING = "pending"
DISCONNECTED = "disconnected"
UNKNOWN = "unknown"

_VALID_STATES = (CONNECTED, PENDING, DISCONNECTED)

# TCP port the Wazuh agent keeps its persistent manager session on.
AGENT_TCP_PORT = 1514


def parse_agentd_state(text: str) -> str:
    """Parse ``wazuh-agentd.state`` contents into a canonical status.

    The file looks like::

        # State file
        status='connected'
        last_keepalive='2026-06-30 22:00:00'
        last_ack='2026-06-30 22:00:00'

    Returns one of ``connected``/``pending``/``disconnected``, or
    ``unknown`` if no recognizable status line is present.
    """
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        key, sep, value = line.partition("=")
        if sep and key.strip().lower() == "status":
            value = value.strip().strip("'\"").lower()
            if value in _VALID_STATES:
                return value
    return UNKNOWN


def parse_ossec_log_tail(text: str) -> str:
    """Infer connection status from recent ``ossec.log`` lines.

    Used only as a fallback when the state file is missing (older agents, or
    before the first status write). Scans in order and keeps the *last*
    decisive signal, since the log is chronological.
    """
    result = UNKNOWN
    for raw in text.splitlines():
        line = raw.strip()
        if "Connected to the server" in line:
            result = CONNECTED
        elif (
            "Unable to connect to any configured manager" in line
            or "Lost connection with manager" in line
            or "Unable to connect to enrollment service" in line
            or "Unable to connect to" in line
        ):
            result = DISCONNECTED
    return result


def established_in_netstat(text: str, port: int = AGENT_TCP_PORT) -> bool:
    """True if any ESTABLISHED line's REMOTE endpoint uses *port*.

    Pure parser for ``netstat -an`` output. Handles both BSD/macOS
    (``tcp4 0 0 10.0.0.5.59667 10.0.0.9.1514 ESTABLISHED``) and Windows
    (``TCP 10.0.0.5:52034 10.0.0.9:1514 ESTABLISHED``) address formats.
    Only the SECOND address column (the remote peer) is matched, so a
    local listener on the same port never false-positives.
    """
    suffixes = (f".{port}", f":{port}")
    for line in text.splitlines():
        if "ESTABLISHED" not in line.upper():
            continue
        addrs = [t for t in line.split()
                 if ("." in t or ":" in t) and t[-1].isdigit()]
        if len(addrs) >= 2 and addrs[1].endswith(suffixes):
            return True
    return False


def established_in_proc_net(text: str, port: int = AGENT_TCP_PORT) -> bool:
    """True if ``/proc/net/tcp``-format *text* has an ESTABLISHED (state 01)
    row whose remote address uses *port* (hex-encoded). Pure parser."""
    hex_port = f":{port:04X}"
    for line in text.splitlines()[1:]:
        parts = line.split()
        if len(parts) > 3 and parts[3] == "01" and parts[2].endswith(hex_port):
            return True
    return False


def probe_manager_socket(port: int = AGENT_TCP_PORT) -> bool:
    """True if this machine holds an ESTABLISHED TCP session to *port*.

    Unprivileged on every platform: Linux reads /proc/net/tcp[6] directly
    (no net-tools dependency); macOS and Windows shell out to ``netstat
    -an``, which lists all sockets without root/admin. Never raises.
    """
    try:
        if platform.system() == "Linux":
            for path in ("/proc/net/tcp", "/proc/net/tcp6"):
                try:
                    with open(path, "r") as fh:
                        if established_in_proc_net(fh.read(), port):
                            return True
                except OSError:
                    pass
            return False
        result = subprocess.run(
            ["netstat", "-an"], capture_output=True, text=True, timeout=5)
        return established_in_netstat(result.stdout, port)
    except Exception:
        return False


def read_agent_connection(
    state_path: str,
    log_path: str | None = None,
    log_tail_bytes: int = 16384,
) -> str:
    """Read the agent's manager-connection status.

    Resolution order:

    1. The authoritative ``wazuh-agentd.state`` file (knows ``pending``).
    2. An unprivileged socket-table probe — the state file and ossec.log
       are root-owned on macOS/Linux, so a user-session GUI can't read
       them even while the agent is healthily connected (which showed as
       "Unknown" in the UI). An ESTABLISHED TCP session to the manager's
       agent port is positive proof of connection. Probe misses do NOT
       demote to disconnected (the session flaps briefly during
       enrollment) — they fall through.
    3. The tail of ``ossec.log``.

    Never raises — returns ``unknown`` when nothing can be determined.
    """
    try:
        with open(state_path, "r", errors="replace") as fh:
            status = parse_agentd_state(fh.read())
        if status != UNKNOWN:
            return status
    except OSError:
        pass

    if probe_manager_socket():
        return CONNECTED

    if log_path:
        try:
            with open(log_path, "rb") as fh:
                try:
                    fh.seek(-log_tail_bytes, os.SEEK_END)
                except OSError:
                    fh.seek(0)
                tail = fh.read().decode("utf-8", "replace")
            return parse_ossec_log_tail(tail)
        except OSError:
            pass

    return UNKNOWN
