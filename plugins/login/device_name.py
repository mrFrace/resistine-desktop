"""The name this install shows under in Element's session list.

MAS names a new device after the client and the browser's user agent
("Phoenix Desktop on Unknown device"), which tells two installs apart by
nothing. After sign-in and once per start the app sets
``Phoenix Desktop · <hostname> (<OS>)`` with ``PUT /devices/{id}``; Synapse
accepts it under MAS delegation (checked live 2026-11-12). Best effort:
any failure is logged and ignored.
"""

from __future__ import annotations

import platform
import socket
import threading
from urllib.parse import quote

from utils import settings
from utils.logger import logger

_OS = {"Darwin": "macOS", "Windows": "Windows", "Linux": "Linux"}
_MAX_HOST = 63


def display_name(hostname: str | None = None, system: str | None = None) -> str:
    host = hostname if hostname is not None else socket.gethostname()
    host = "".join(c for c in str(host) if c.isprintable()).strip()[:_MAX_HOST]
    os_name = _OS.get(system or platform.system(), "")
    name = "Phoenix Desktop"
    if host:
        name += f" · {host}"
    if os_name:
        name += f" ({os_name})"
    return name


def name_this_device() -> bool:
    """Set the display name if it differs; True when it is now right."""
    from plugins.login import cross_signing as cs

    device = settings.get("auth", "device_id")
    if not device:
        return False
    path = f"/_matrix/client/v3/devices/{quote(device, safe='')}"
    wanted = display_name()
    try:
        _, current = cs._request("GET", path)
        if isinstance(current, dict) and current.get("display_name") == wanted:
            return True
        cs._request("PUT", path, {"display_name": wanted})
    except cs.VerificationError as e:
        logger.info(f"[OIDC] device name not set: {e.code}")
        return False
    except Exception as e:  # noqa: BLE001 - best effort
        logger.info(f"[OIDC] device name not set: {type(e).__name__}")
        return False
    logger.info("[OIDC] device name set")
    return True


def name_in_background() -> None:
    threading.Thread(target=name_this_device, name="device-name", daemon=True).start()
