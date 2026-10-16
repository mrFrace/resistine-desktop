"""Windows system notifications through the app's tray icon.

The tray (gui/system_tray.py) registers itself with set_tray(); send() then
shows a balloon / Action Center toast through QSystemTrayIcon.showMessage,
which also reports clicks. Without a tray nothing is shown.

TODO: a WinRT toast (winsdk) for when the tray is unavailable.
"""

from utils.logger import logger

_tray = None


def set_tray(tray) -> None:
    """Route notifications through *tray* (an object with notify())."""
    global _tray
    _tray = tray


def init():
    return


def send(title: str, body: str, urgency: str = "normal", on_click=None):
    if _tray is None:
        logger.debug("Windows notification (no tray): %s — %s", title, body)
        return
    _tray.notify(title, body, urgency, on_click)
