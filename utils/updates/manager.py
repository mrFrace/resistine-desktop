"""
Cross-Platform Auto-Update Manager.

Provides a single interface for all platforms. Dispatches to the
appropriate backend (Sparkle on macOS, WinSparkle on Windows, etc.)
and manages a jittered background check scheduler.

Architecture:
    utils/updates/
    ├── manager.py         ← shared interface (this file)
    ├── darwin.py          ← macOS: Sparkle via PyObjC
    ├── windows.py         ← Windows: WinSparkle via ctypes
    └── linux.py           ← Linux: Ed25519-verified tarball

Usage:
    from utils import updates

    updates.init(app)           # Initialize backend + start scheduler
    updates.check_for_updates() # Manual "Check for Updates" button
    updates.shutdown()          # App closing

Author: Resistine Team
Copyright (c) Resistine 2025
Licensed under the GNU General Public License v2 or later
"""

import platform
import random
import threading

from utils.logger import logger

# ---------------------------------------------------------------------------
# Platform detection (same pattern as plugins/vpn/main.py)
# ---------------------------------------------------------------------------
_PLATFORM = platform.system()

_backend = None

if _PLATFORM == "Darwin":
    from utils.updates import darwin as _backend
elif _PLATFORM == "Windows":
    from utils.updates import windows as _backend
elif _PLATFORM == "Linux":
    from utils.updates import linux as _backend

# ---------------------------------------------------------------------------
# Jittered scheduler (shared across all platforms)
# ---------------------------------------------------------------------------
_BASE_INTERVAL = 14400     # 4 hours in seconds
_JITTER_RANGE = 1800       # ±30 minutes
_INITIAL_DELAY_MAX = 1800  # 0–30 minutes


class _UpdateScheduler:
    """Timer-based scheduler with randomized jitter.

    Ensures that even if all clients launch simultaneously, their update
    checks are spread across a 30-minute window (initial) and a 60-minute
    window (ongoing).
    """

    def __init__(self):
        self._timer = None
        self._running = False

    def start(self):
        self._running = True
        delay = random.uniform(0, _INITIAL_DELAY_MAX)
        logger.info(
            f"[UPDATE] Scheduler started. First check in {delay:.0f}s "
            f"({delay / 60:.1f} min)"
        )
        self._schedule(delay)

    def stop(self):
        self._running = False
        if self._timer is not None:
            self._timer.cancel()
            self._timer = None
        logger.info("[UPDATE] Scheduler stopped")

    def _schedule(self, delay):
        if not self._running:
            return
        self._timer = threading.Timer(delay, self._tick)
        self._timer.daemon = True
        self._timer.start()

    def _tick(self):
        if not self._running:
            return

        logger.info("[UPDATE] Running scheduled background check")
        try:
            if _backend is not None:
                _backend.check_for_updates_in_background()
        except Exception as e:
            logger.error(f"[UPDATE] Background check error: {e}")

        jitter = random.uniform(-_JITTER_RANGE, _JITTER_RANGE)
        interval = _BASE_INTERVAL + jitter
        logger.info(
            f"[UPDATE] Next check in {interval:.0f}s ({interval / 3600:.1f}h)"
        )
        self._schedule(interval)


_scheduler = _UpdateScheduler()

# ---------------------------------------------------------------------------
# Public API — used by main.py and plugins
# ---------------------------------------------------------------------------


def init(app):
    """Initialize the platform-specific update backend and start the scheduler.

    Call once from main.py after the window is created.
    """
    if _backend is None:
        logger.warning("[UPDATE] No update backend for this platform")
        return

    _backend.init_updater(app)

    if _backend.is_available():
        # macOS Sparkle and Windows WinSparkle manage their own background
        # check timers.  Only start the Python scheduler on Linux.
        if _PLATFORM == "Linux":
            _scheduler.start()


def check_for_updates():
    """Trigger an interactive update check (manual "Check for Updates" button).

    Returns "update_available", "up_to_date", or "error".
    """
    if _backend is None:
        return "error"
    return _backend.check_for_updates()


def is_available():
    """Return True if the update backend is operational on this platform."""
    if _backend is None:
        return False
    return _backend.is_available()


def shutdown():
    """Stop the scheduler and clean up. Call from the app's close handler."""
    _scheduler.stop()
    if _backend is not None and hasattr(_backend, 'shutdown'):
        _backend.shutdown()
    if _backend is not None and hasattr(_backend, 'stop_runloop_pump'):
        _backend.stop_runloop_pump()
