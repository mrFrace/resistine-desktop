"""The quiet daily update check.

Asks the signed channel (utils/updates/channel.py) a few minutes after start
and then about once a day, and says so when there is something to say: a
newer build, a channel past its signed expiry, or a server offering an older
release than before. It never downloads or installs anything: the user does
that from Settings (utils/updates/installer.py) or, on Linux, the system's
package manager does.

Without this the freeze defence is only on paper: an expired or held-back
channel is noticed only by whoever happens to click "Check for updates".
"""

from __future__ import annotations

import random
import threading
import time
from typing import Optional

from utils import settings
from utils.logger import logger

_NS = "updates"
INTERVAL = 24 * 3600        # between checks
FIRST_DELAY = (60, 180)     # after start, so sign-in and the plugins go first
JITTER = 3600               # spread installs over an hour
RETRY = 3600                # after a check that could not be made
REMIND = 7 * 24 * 3600      # say the same thing again at most this often

_lock = threading.Lock()
_last = None                # the newest channel.check() answer of this run
_running = False


def enabled() -> bool:
    return bool(settings.get(_NS, "auto_check", True))


def set_enabled(on: bool) -> None:
    settings.set(_NS, "auto_check", bool(on))


def last_result():
    """The newest answer of this run (None before the first check)."""
    return _last


def remember(result) -> None:
    """Keep an answer, also one the user asked for in Settings."""
    global _last
    _last = result


def _number(key: str) -> float:
    try:
        return float(settings.get(_NS, key, 0) or 0)
    except (TypeError, ValueError):
        return 0.0


def next_delay(now: Optional[float] = None, rand=random.uniform) -> float:
    """Seconds until the next check: a day after the last one that got an
    answer, never sooner than the start-up delay."""
    now = time.time() if now is None else now
    last = _number("last_check")
    if last > now:  # the clock went back
        last = 0.0
    return max(rand(*FIRST_DELAY), last + INTERVAL - now + rand(0, JITTER))


def _due(what: str, value, now: float) -> bool:
    """True when *what* (a build, an expiry) was not announced yet, or long
    enough ago to say it again; records that it is being announced."""
    told = settings.get(_NS, "told", None)
    told = told if isinstance(told, dict) else {}
    seen = told.get(what)
    if (isinstance(seen, list) and len(seen) == 2 and seen[0] == value
            and isinstance(seen[1], (int, float)) and 0 <= now - seen[1] < REMIND):
        return False
    told[what] = [value, now]
    settings.set(_NS, "told", told)
    return True


def notice(result, now: Optional[float] = None) -> Optional[tuple[str, str]]:
    """What to tell the user about a channel.check() answer: (text, kind),
    or None when there is nothing new to say."""
    now = time.time() if now is None else now
    if result is None or result.latest is None:
        return None
    if result.available and _due("build", result.latest.build, now):
        if str(result.os_key).startswith("linux"):
            how = "Your system's software updates install it."
        else:
            how = "Install it from Settings."
        text = f"Phoenix build {result.latest.build} is available. {how}"
        if result.stale:
            _due("stale", result.latest.expires, now)
            text += (f" The update channel expired on {result.latest.expires}: "
                     "newer releases may be held back.")
        return text, "info"
    if result.stale and _due("stale", result.latest.expires, now):
        return (f"The Phoenix update channel expired on {result.latest.expires}: "
                "newer releases may be held back.", "warning")
    return None


def run_once(now: Optional[float] = None) -> tuple[bool, Optional[tuple[str, str]]]:
    """One check. (answered, notice): *answered* is False when the channel
    could not be asked (offline, signed out) and the check should be retried
    sooner."""
    from plugins.wazuh.agent.phoenix_packages import PackageError
    from utils.updates import channel

    now = time.time() if now is None else now
    try:
        result = channel.check()
    except PackageError as e:
        logger.info(f"[UPDATE] background check: {e}")
        # A rollback is the one failure worth interrupting for.
        if "older Phoenix release" in str(e) and _due("rollback", str(e), now):
            return False, (str(e), "warning")
        return False, None
    except Exception as e:  # noqa: BLE001
        logger.warning(f"[UPDATE] background check failed: {e}")
        return False, None
    settings.set(_NS, "last_check", now)
    if result is None:
        return True, None
    remember(result)
    return True, notice(result, now)


def _show(window, text: str, kind: str) -> None:
    """On the GUI thread: a toast, and a desktop notification when the
    window is hidden (closed to the tray)."""
    def open_settings():
        try:
            window.show()
            window.raise_()
            window.activateWindow()
            window.navigate("Settings")
        except Exception as e:  # noqa: BLE001
            logger.debug(f"[UPDATE] could not open Settings: {e}")

    try:
        window.show_notification(text, kind, action="Open Settings",
                                 on_action=open_settings)
        if not window.isVisible():
            from utils import notifications
            notifications.send("Phoenix update", text,
                               on_click=lambda: window.after(0, open_settings))
    except Exception as e:  # noqa: BLE001
        logger.debug(f"[UPDATE] notice failed: {e}")


def _tick(window) -> None:
    """GUI thread: start one check off-thread and plan the next."""
    def work():
        delay = RETRY
        try:
            from utils.updates import channel
            if channel.os_key() is None:
                logger.info("[UPDATE] this copy isn't updated from the channel; "
                            "no background checks")
                return  # nothing is scheduled again
            answered, note = run_once()
            if note:
                window.after(0, _show, window, *note)
            if answered:
                delay = next_delay()
        except Exception as e:  # noqa: BLE001
            logger.warning(f"[UPDATE] background check failed: {e}")
        _schedule(window, delay)

    if not enabled() or not settings.get("auth", "logged_in", False):
        # Off, or signed out (the channel needs the session): look again later.
        _schedule(window, RETRY)
        return
    threading.Thread(target=work, name="update-auto-check", daemon=True).start()


def _schedule(window, delay: float) -> None:
    window.after(int(max(1.0, delay) * 1000), _tick, window)


def start(window) -> None:
    """Begin the background checks for this run (once)."""
    global _running
    with _lock:
        if _running:
            return
        _running = True
    _schedule(window, next_delay())
