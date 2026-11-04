"""Give the server this device's agent for the current sign-in.

LLMAgent-api's Matrix bridge finds "this machine" through phoenix-provisioning's
device -> agent record, which only an enrollment or a link made with the
signed-in Matrix device creates. Signing out drops it, and signing in again
does not go through the setup wizard (setup is complete), so after sign-in and
at startup ensure_in_background() makes the record again:

- an agent this app installed is re-enrolled (reenroll_agent: the server
  deleted its old agent at sign-out, so its key is dead anyway);
- an agent installed some other way (the NixOS module, an upstream package)
  is linked (enrollment.link): its key is read as root and proves to the
  server that this device holds it. The agent itself is left as it is.

Both need the admin prompt once per sign-in. When the prompt is dismissed the
device is remembered, so the app doesn't ask again until the next sign-in.
"""

from __future__ import annotations

import platform
import threading
from typing import Callable, Optional

from utils import settings
from utils.logger import logger

_NS = "wazuh"
_DECLINED = "link_declined_device"
_lock = threading.Lock()


def _wazuh_mod():
    system = platform.system()
    if system == "Darwin":
        from plugins.wazuh.agent import wazuh_functions_darwin as m
    elif system == "Linux":
        from plugins.wazuh.agent import wazuh_functions_linux as m
    elif system == "Windows":
        from plugins.wazuh.agent import wazuh_functions_windows as m
    else:
        return None
    return m


def _device() -> str:
    return settings.get("auth", "device_id", "") or ""


def app_managed() -> bool:
    """Whether the installed agent is this app's (re-enrolled, not linked)."""
    m = _wazuh_mod()
    check = getattr(m, "is_app_managed_agent", None)
    # macOS and Windows only ever use the agent this app installs.
    return bool(m) and (check is None or bool(check()))


def enroll_for_sign_in(on_status: Optional[Callable[[str], None]] = None) -> bool:
    """Enroll or link the installed agent for the current sign-in.

    True when the server now has it for this device. Worker thread only:
    it can show the admin prompt and restart the agent.
    """
    from plugins.wazuh.agent import enrollment

    m = _wazuh_mod()
    if not (m and m.is_agent_installed()):
        return False
    if app_managed():
        if on_status:
            on_status("Reconnecting to the monitoring server…")
        ok, msg = m.reenroll_agent()
        logger.info(f"[AGENT-SIGN-IN] reenroll_agent -> {ok} ({msg})")
        if ok and not enrollment.enrolled_for_this_sign_in():
            enrollment.mark_enrolled()  # the agent-auth fallback enrolled it
        return ok
    read = getattr(m, "read_agent_key_line", None)
    if read is None:
        return False
    line = read()
    if line is None:
        settings.set(_NS, _DECLINED, _device())
        return False
    return enrollment.link(line)


def _check() -> None:
    from plugins.wazuh.agent import enrollment

    if not _lock.acquire(blocking=False):
        return
    try:
        if not settings.get("auth", "logged_in", False):
            return
        if not settings.get("setup", "complete", False):
            return  # the setup wizard's endpoint step does it
        if enrollment.enrolled_for_this_sign_in():
            return
        device = _device()
        if device and settings.get(_NS, _DECLINED, "") == device:
            return
        m = _wazuh_mod()
        if not (m and m.is_agent_installed()):
            return
        logger.info(f"[AGENT-SIGN-IN] agent not enrolled for device {device}; "
                    f"{'re-enrolling' if app_managed() else 'linking'}")
        if not enroll_for_sign_in():
            logger.warning("[AGENT-SIGN-IN] the server still has no agent for this device")
            if app_managed():
                # Don't re-run the admin prompt and agent restart at every start.
                settings.set(_NS, _DECLINED, device)
    except Exception as e:  # noqa: BLE001
        logger.warning(f"[AGENT-SIGN-IN] check failed: {e}")
    finally:
        _lock.release()


def ensure_in_background() -> None:
    """Run the check on a daemon thread (after sign-in, at startup)."""
    threading.Thread(target=_check, name="agent-sign-in", daemon=True).start()
