# -*- coding: utf-8 -*-
# @file plugins/wazuh/agent/log_forwarding.py
# Description: Wire ClamAV detections into the Wazuh agent's log pipeline.
#
# The endpoint (Wazuh) install and the antivirus (ClamAV) install are fully
# independent — neither depends on the other. This module is the *optional*
# bridge between them: once BOTH are set up, it injects a <localfile> pointing
# at the ClamAV log into the agent's ossec.conf and restarts the agent so
# ClamAV events are forwarded to the manager.
#
# It is idempotent and best-effort: a settings flag prevents re-prompting once
# enabled, the ossec.conf edit is a no-op if the block is already present, and
# any failure is logged without disturbing the caller. Requires one admin
# prompt the first time (ossec.conf is root-owned).
#
# Author: Phoenix Team
# Copyright: Phoenix (c) 2025
# Licensed under the GNU General Public License v2 or later

import os
import platform
import shlex
import tempfile

from utils import settings
from utils.logger import logger

_PLATFORM = platform.system()
_NAMESPACE = "wazuh"
_FLAG = "clamav_forwarding_enabled"

# Per-platform ClamAV log locations; the agent dir comes from _agent_dir().
if _PLATFORM == "Darwin":
    _CLAMAV_LOG = "/Library/Application Support/Resistine/clamav/log/clamd.log"
elif _PLATFORM == "Linux":
    # Distro ClamAV logs here by default; harmless if the path differs — the
    # agent simply finds nothing to tail until the file exists.
    _CLAMAV_LOG = "/var/log/clamav/clamav.log"
else:  # Windows uses Defender (its own eventchannel localfile) — nothing to do.
    _CLAMAV_LOG = ""


def _agent_dir() -> str:
    """The agent's install dir, looked up on each call (it may be installed
    after this module is imported); empty where there is nothing to do."""
    if _PLATFORM == "Darwin":
        from plugins.wazuh.config import WAZUH_INSTALL_DIR
        return WAZUH_INSTALL_DIR
    if _PLATFORM == "Linux":
        from plugins.wazuh.config import LINUX_WAZUH_DIR, LINUX_WAZUH_DIR_CANDIDATES
        return next((d for d in LINUX_WAZUH_DIR_CANDIDATES if os.path.isdir(d)), LINUX_WAZUH_DIR)
    return ""


def is_enabled() -> bool:
    """Return True once forwarding has been configured (persisted flag)."""
    return bool(settings.get(_NAMESPACE, _FLAG, False))


def _both_present() -> bool:
    """True only if the Wazuh agent is installed AND ClamAV has produced a log."""
    if _PLATFORM not in ("Darwin", "Linux"):
        return False
    if not os.path.isfile(os.path.join(_agent_dir(), "etc", "ossec.conf")):
        return False
    # ClamAV set up = its log file exists (created by clamd once running).
    return os.path.exists(_CLAMAV_LOG)


def _inject_script() -> str:
    """Return a shell script (run as root) that idempotently adds the ClamAV
    <localfile> to ossec.conf and restarts the agent."""
    # Edit via python3 to avoid brittle in-place sed/XML quoting. The block is
    # inserted immediately before the closing </ossec_config>.
    py = (
        "import sys\n"
        f"conf={os.path.join(_agent_dir(), 'etc', 'ossec.conf')!r}\n"
        f"log={_CLAMAV_LOG!r}\n"
        "s=open(conf, encoding='utf-8').read()\n"
        "if log in s:\n"
        "    print('ALREADY'); sys.exit(0)\n"
        "block=('  <localfile>\\n'\n"
        "       '    <log_format>syslog</log_format>\\n'\n"
        "       '    <location>%s</location>\\n'\n"
        "       '  </localfile>\\n') % log\n"
        "if '</ossec_config>' in s:\n"
        "    s=s.replace('</ossec_config>', block+'</ossec_config>', 1)\n"
        "else:\n"
        "    s=s+'\\n'+block\n"
        "open(conf,'w',encoding='utf-8').write(s)\n"
        "print('INJECTED')\n"
    )
    # Write the python to a temp file the root shell will run, then restart.
    fd, py_path = tempfile.mkstemp(suffix=".py", prefix="resistine-clamav-fwd-")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(py)
    return (
        f"/usr/bin/python3 {shlex.quote(py_path)} && "
        f"{shlex.quote(os.path.join(_agent_dir(), 'bin', 'wazuh-control'))} restart; "
        f"rm -f {shlex.quote(py_path)}"
    ), py_path


def _run_privileged(script: str) -> bool:
    """Run a script as root using the platform's existing privileged helper."""
    try:
        if _PLATFORM == "Darwin":
            from plugins.wazuh.agent.wazuh_functions_darwin import _run_privileged as rp
            ok, _out = rp(script)
            return ok
        from plugins.wazuh.agent.wazuh_functions_linux import run_privileged_command
        # run_privileged_command returns (success, output) — not a CompletedProcess.
        ok, _out = run_privileged_command(["sh", "-c", script])
        return bool(ok)
    except Exception as e:  # noqa: BLE001
        logger.error(f"[CLAMAV-FWD] privileged run failed: {e}")
        return False


def ensure_clamav_log_forwarding(on_status=None) -> bool:
    """Enable ClamAV→Wazuh log forwarding if both are set up. Idempotent.

    Returns True if forwarding is (now or already) enabled, False otherwise.
    Safe to call from a worker thread or at app startup.
    """
    if is_enabled():
        return True
    if not _both_present():
        logger.info("[CLAMAV-FWD] skip — ClamAV and Wazuh not both set up yet")
        return False

    logger.info("[CLAMAV-FWD] enabling ClamAV log forwarding to Wazuh")
    if on_status:
        on_status("Connecting ClamAV to endpoint monitoring…")

    script, py_path = _inject_script()
    ok = _run_privileged(script)
    try:
        os.unlink(py_path)  # best-effort cleanup if the root shell didn't
    except OSError:
        pass

    if ok:
        settings.set(_NAMESPACE, _FLAG, True)
        logger.info("[CLAMAV-FWD] forwarding enabled and agent restarted")
    else:
        logger.warning("[CLAMAV-FWD] failed to enable forwarding")
    return ok
