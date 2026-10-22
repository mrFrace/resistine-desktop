"""
Windows Auto-Update Backend — WinSparkle via ctypes.

Loads WinSparkle.dll from the app bundle and provides update check
functionality. Only used on Windows frozen (PyInstaller) builds.
Mirrors the macOS Sparkle integration in darwin.py.

Author: Resistine Team
Copyright (c) Resistine 2025
Licensed under the GNU General Public License v2 or later
"""

import ctypes
import os
import sys

from utils.logger import logger
from utils.updates.version import get_current_version

_dll = None
_initialized = False
_app = None

# Same Ed25519 public key used by macOS Sparkle and Linux updater
_ED25519_PUBLIC_KEY = "2eiUHVoMgl+qqhEWO8iix5SUcRAKfkWYESh9F7jG6ls="

APPCAST_URL = "https://resistine.github.io/appcast.xml"


def _get_winsparkle_dll_path():
    """Return path to WinSparkle.dll, or None."""
    # Frozen build: DLL is in _internal/ (PyInstaller bundles with binaries=[..., '.'])
    if getattr(sys, "frozen", False):
        app_dir = os.path.dirname(sys.executable)
        # Try _internal/ subdirectory first (PyInstaller layout)
        path = os.path.join(app_dir, "_internal", "WinSparkle.dll")
        if os.path.exists(path):
            return path
        # Fallback: try next to exe (in case bundle structure differs)
        path = os.path.join(app_dir, "WinSparkle.dll")
        if os.path.exists(path):
            return path

    # Dev mode: check frameworks/WinSparkle/
    dev_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
        "frameworks", "WinSparkle", "WinSparkle.dll"
    )
    if os.path.exists(dev_path):
        return dev_path

    return None


def _load_winsparkle():
    """Load WinSparkle.dll via ctypes. Returns True on success."""
    global _dll
    if _dll is not None:
        return True

    dll_path = _get_winsparkle_dll_path()
    if not dll_path:
        logger.info("[WINSPARKLE] DLL not found (dev mode or missing)")
        return False

    try:
        _dll = ctypes.CDLL(dll_path)

        # Configure function signatures
        _dll.win_sparkle_init.argtypes = []
        _dll.win_sparkle_init.restype = None

        _dll.win_sparkle_cleanup.argtypes = []
        _dll.win_sparkle_cleanup.restype = None

        _dll.win_sparkle_set_appcast_url.argtypes = [ctypes.c_char_p]
        _dll.win_sparkle_set_appcast_url.restype = None

        _dll.win_sparkle_set_app_details.argtypes = [
            ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_wchar_p
        ]
        _dll.win_sparkle_set_app_details.restype = None

        _dll.win_sparkle_set_eddsa_public_key.argtypes = [ctypes.c_char_p]
        _dll.win_sparkle_set_eddsa_public_key.restype = ctypes.c_int

        _dll.win_sparkle_set_automatic_check_for_updates.argtypes = [ctypes.c_int]
        _dll.win_sparkle_set_automatic_check_for_updates.restype = None

        _dll.win_sparkle_set_update_check_interval.argtypes = [ctypes.c_int]
        _dll.win_sparkle_set_update_check_interval.restype = None

        _dll.win_sparkle_check_update_with_ui.argtypes = []
        _dll.win_sparkle_check_update_with_ui.restype = None

        _dll.win_sparkle_check_update_without_ui.argtypes = []
        _dll.win_sparkle_check_update_without_ui.restype = None

        # Callback types
        _shutdown_cb_type = ctypes.CFUNCTYPE(None)
        _dll.win_sparkle_set_shutdown_request_callback.argtypes = [_shutdown_cb_type]
        _dll.win_sparkle_set_shutdown_request_callback.restype = None

        _can_shutdown_cb_type = ctypes.CFUNCTYPE(ctypes.c_int)
        _dll.win_sparkle_set_can_shutdown_callback.argtypes = [_can_shutdown_cb_type]
        _dll.win_sparkle_set_can_shutdown_callback.restype = None

        # Callback to launch installer with /SILENT for seamless upgrades
        _run_installer_cb_type = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_wchar_p)
        _dll.win_sparkle_set_user_run_installer_callback.argtypes = [
            _run_installer_cb_type
        ]
        _dll.win_sparkle_set_user_run_installer_callback.restype = None

        logger.info(f"[WINSPARKLE] DLL loaded from {dll_path}")
        return True
    except Exception as e:
        logger.error(f"[WINSPARKLE] Failed to load DLL: {e}")
        _dll = None
        return False


# Prevent garbage collection of callback pointers
_stored_callbacks = {}


def init_updater(app):
    """Initialize the WinSparkle updater.

    Must be called after the app window is created.
    Configures WinSparkle and calls win_sparkle_init().
    """
    global _initialized, _app
    _app = app

    if not _load_winsparkle():
        return False

    try:
        version = get_current_version()

        # All configuration must happen before win_sparkle_init()
        _dll.win_sparkle_set_appcast_url(APPCAST_URL.encode("utf-8"))
        _dll.win_sparkle_set_app_details("Phoenix", "Phoenix", version)

        result = _dll.win_sparkle_set_eddsa_public_key(
            _ED25519_PUBLIC_KEY.encode("utf-8")
        )
        if result != 1:
            logger.warning("[WINSPARKLE] EdDSA public key was not accepted")

        _dll.win_sparkle_set_automatic_check_for_updates(1)
        _dll.win_sparkle_set_update_check_interval(14400)  # 4 hours

        # Set shutdown callbacks so WinSparkle can close the app before installing
        @ctypes.CFUNCTYPE(ctypes.c_int)
        def _can_shutdown():
            return 1  # Always allow shutdown

        @ctypes.CFUNCTYPE(None)
        def _shutdown_request():
            # WinSparkle wants us to quit so the installer can replace our
            # (locked) files and relaunch. FULLY terminate the process — the
            # window-close handler (_on_closing) only hides to the tray, which
            # kept the app running, made WinSparkle nag "force close", and left
            # the files locked so the update silently failed.
            def _quit():
                try:
                    if _app is not None:
                        _app.destroy()
                except Exception:
                    pass
                os._exit(0)

            if _app is not None:
                try:
                    _app.after(0, _quit)
                    return
                except Exception:
                    pass
            os._exit(0)

        @ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_wchar_p)
        def _run_installer(installer_path):
            """Launch the downloaded installer silently for seamless upgrades.

            /SUPPRESSMSGBOXES auto-dismisses the "files in use" prompt (the app
            is exiting via the shutdown callback); /NORESTART stops the
            installer from rebooting. The installer's [Run] entry relaunches the
            app afterward (its 'skipifsilent' flag was removed for this).
            """
            import subprocess
            try:
                subprocess.Popen(
                    [installer_path, "/SILENT", "/SUPPRESSMSGBOXES", "/NORESTART"])
                logger.info(f"[WINSPARKLE] Launched installer: {installer_path}")
                return 1  # 1 = handled
            except Exception as e:
                logger.error(f"[WINSPARKLE] Failed to launch installer: {e}")
                return 0  # 0 = let WinSparkle handle it

        _stored_callbacks["can_shutdown"] = _can_shutdown
        _stored_callbacks["shutdown_request"] = _shutdown_request
        _stored_callbacks["run_installer"] = _run_installer
        _dll.win_sparkle_set_can_shutdown_callback(_can_shutdown)
        _dll.win_sparkle_set_shutdown_request_callback(_shutdown_request)
        _dll.win_sparkle_set_user_run_installer_callback(_run_installer)

        _dll.win_sparkle_init()
        _initialized = True

        logger.info(
            f"[WINSPARKLE] Initialized (version={version}, "
            f"appcast={APPCAST_URL})"
        )
        return True
    except Exception as e:
        logger.error(f"[WINSPARKLE] Failed to init: {e}")
        return False


def check_for_updates():
    """Trigger an interactive update check (shows native WinSparkle UI).

    WinSparkle handles its own UI: progress, "up to date", or "update
    available" dialogs — same as Sparkle on macOS.

    Returns "up_to_date" on success or "error" on failure.
    """
    if not _initialized:
        logger.warning("[WINSPARKLE] Not initialized")
        return "error"
    try:
        _dll.win_sparkle_check_update_with_ui()
        logger.info("[WINSPARKLE] Interactive check triggered")
        return "up_to_date"
    except Exception as e:
        logger.error(f"[WINSPARKLE] Interactive check failed: {e}")
        return "error"


def check_for_updates_in_background():
    """Trigger a silent background update check (no UI if up-to-date)."""
    if not _initialized:
        return False
    try:
        _dll.win_sparkle_check_update_without_ui()
        logger.info("[WINSPARKLE] Background check triggered")
        return True
    except Exception as e:
        logger.error(f"[WINSPARKLE] Background check failed: {e}")
        return False


def shutdown():
    """Clean up WinSparkle. Call from the app's close handler."""
    if _dll is not None and _initialized:
        try:
            _dll.win_sparkle_cleanup()
            logger.info("[WINSPARKLE] Cleanup complete")
        except Exception as e:
            logger.error(f"[WINSPARKLE] Cleanup failed: {e}")


def stop_runloop_pump():
    """No-op. Kept for API compatibility with manager.py."""
    pass


def is_available():
    """Return True if WinSparkle is loaded and initialized."""
    return _initialized
