"""
macOS Auto-Update Backend — Sparkle via PyObjC.

Loads Sparkle.framework from the app bundle and provides update check
functionality. Only used on macOS frozen (PyInstaller) builds.

Author: Resistine Team
Copyright (c) Resistine 2025
Licensed under the GNU General Public License v2 or later
"""

import os
import sys

from utils.logger import logger

_sparkle_loaded = False
_controller = None


def _get_sparkle_framework_path():
    """Return path to Sparkle.framework inside the app bundle, or None."""
    if not getattr(sys, "frozen", False):
        return None
    # sys.executable = Phoenix.app/Contents/MacOS/Phoenix
    contents_dir = os.path.dirname(os.path.dirname(sys.executable))
    path = os.path.join(contents_dir, "Frameworks", "Sparkle.framework")
    if os.path.exists(path):
        return path
    return None


def _load_sparkle():
    """Load Sparkle.framework via PyObjC. Returns True on success."""
    global _sparkle_loaded
    if _sparkle_loaded:
        return True

    sparkle_path = _get_sparkle_framework_path()
    if not sparkle_path:
        logger.info("[SPARKLE] Framework not found (dev mode or missing)")
        return False

    try:
        import objc

        objc.loadBundle(
            "Sparkle", bundle_path=sparkle_path, module_globals=globals()
        )
        _sparkle_loaded = True
        logger.info(f"[SPARKLE] Framework loaded from {sparkle_path}")
        return True
    except Exception as e:
        logger.error(f"[SPARKLE] Failed to load framework: {e}")
        return False


def init_updater(app):
    """Initialize the Sparkle updater controller.

    Must be called on the main thread after the app window is created.
    The controller is stored on *app* to prevent garbage collection.

    NOTE: No NSRunLoop pump is used.  Tkinter on macOS already integrates
    with the Cocoa event loop (via the Tk Aqua backend), which processes
    the mach-port and GCD sources that Sparkle's XPC services rely on.
    An explicit runUntilDate_ pump causes fatal re-entrant Tk/Python
    callbacks on Python 3.14 (PyEval_RestoreThread abort).
    """
    global _controller

    if not _load_sparkle():
        return False

    try:
        import objc

        SPUStandardUpdaterController = objc.lookUpClass(
            "SPUStandardUpdaterController"
        )
        controller = (
            SPUStandardUpdaterController.alloc()
            .initWithStartingUpdater_updaterDelegate_userDriverDelegate_(
                False, None, None
            )
        )
        # startingUpdater=False avoids an immediate auto-check on launch.
        # We still need to start the updater so checkForUpdates_ shows UI.
        controller.startUpdater()

        app._sparkle_controller = controller
        _controller = controller

        logger.info("[SPARKLE] Updater controller initialized and started")
        return True
    except Exception as e:
        logger.error(f"[SPARKLE] Failed to init updater: {e}")
        return False


def check_for_updates():
    """Trigger an interactive update check (shows UI even if up-to-date).

    Returns "up_to_date" on success (Sparkle handles its own UI for available
    updates) or "error" on failure.
    """
    if _controller is None:
        logger.warning("[SPARKLE] Controller not initialized")
        return "error"
    try:
        _controller.checkForUpdates_(None)
        logger.info("[SPARKLE] Interactive check triggered")
        return "up_to_date"
    except Exception as e:
        logger.error(f"[SPARKLE] Interactive check failed: {e}")
        return "error"


def check_for_updates_in_background():
    """Trigger a silent background update check (no UI if up-to-date)."""
    if _controller is None:
        return False
    try:
        _controller.updater().checkForUpdatesInBackground()
        logger.info("[SPARKLE] Background check triggered")
        return True
    except Exception as e:
        logger.error(f"[SPARKLE] Background check failed: {e}")
        return False


def stop_runloop_pump():
    """No-op. Kept for API compatibility with manager.py."""
    pass


def is_available():
    """Return True if Sparkle is loaded and the controller is initialized."""
    return _controller is not None
