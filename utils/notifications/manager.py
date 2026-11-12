"""
Cross-Platform System Notification Manager.

Provides a single interface for all platforms. Dispatches to the
appropriate backend.

Architecture:
    utils/notifications/
    +-- manager.py         <- shared interface (this file)
    +-- darwin.py          <- macOS: UNUserNotificationCenter via PyObjC
    +-- linux.py           <- Linux: freedesktop D-Bus (jeepney) / notify-send
    +-- windows.py         <- Windows: stub (TODO: WinRT toast)

Usage:
    from utils import notifications

    notifications.init()
    notifications.send("Title", "Body", urgency="critical")

Author: Phoenix Team
Copyright (c) Phoenix 2025
Licensed under the GNU General Public License v2 or later
"""

import platform

from utils.logger import logger

# ---------------------------------------------------------------------------
# Platform detection (same pattern as utils/updates/manager.py)
# ---------------------------------------------------------------------------
_PLATFORM = platform.system()

_backend = None

if _PLATFORM == "Darwin":
    from utils.notifications import darwin as _backend
elif _PLATFORM == "Linux":
    from utils.notifications import linux as _backend
elif _PLATFORM == "Windows":
    from utils.notifications import windows as _backend

_VALID_URGENCIES = {"low", "normal", "critical"}

# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def init():
    """Initialize the platform notification backend.

    Call once from main.py on the main thread (macOS requires it).
    Safe to call multiple times (idempotent).
    """
    if _backend is None:
        logger.debug("No notification backend for %s", _PLATFORM)
        return
    try:
        _backend.init()
    except Exception as e:
        logger.warning("Failed to initialize notification backend: %s", e)


def send(title: str, body: str, urgency: str = "normal", on_click=None):
    """Send a system notification. Never raises.

    Args:
        title: Notification title.
        body: Notification body text.
        urgency: One of "low", "normal", "critical". Defaults to "normal"
                 if an invalid value is passed.
        on_click: optional callable run when the user clicks the
                  notification, where the platform reports clicks. It may
                  run on any thread: marshal to the UI thread yourself.
    """
    if urgency not in _VALID_URGENCIES:
        urgency = "normal"

    if _backend is None:
        logger.debug("No notification backend for %s", _PLATFORM)
        return
    try:
        if on_click is None:
            _backend.send(title, body, urgency)
        else:
            _backend.send(title, body, urgency, on_click=on_click)
    except Exception as e:
        logger.warning("Failed to send notification: %s", e)
