## @file main.py
## @namespace main
"""Entry point for the Phoenix AI EndPoint application (PyQt6).

Author: Petr, Javier, Jackie and the Resistine Team
Copyright (c) Resistine 2025
Licensed under the GNU General Public License v2 or later
"""

import argparse
import os
import signal
import sys

from PyQt6.QtWidgets import QApplication

from utils import functions as functions
from utils import settings
from utils.logger import logger, setup_logging

DEBUG = False



def _install_excepthook() -> None:
    """Log unhandled errors instead of dying.

    With the default sys.excepthook, PyQt6 aborts the whole app on an
    exception in any slot or event handler, and the traceback goes to
    stderr, which a packaged build has nowhere to show. The traceback is
    formatted without local variables (they may hold tokens)."""
    import threading
    import traceback

    def hook(exc_type, exc, tb):
        if issubclass(exc_type, KeyboardInterrupt):
            sys.__excepthook__(exc_type, exc, tb)
            return
        text = "".join(traceback.format_exception(exc_type, exc, tb))
        logger.error(f"Unhandled error (the app keeps running):\n{text}")

    def thread_hook(args):
        if args.exc_type is SystemExit:
            return
        name = args.thread.name if args.thread else "?"
        text = "".join(traceback.format_exception(args.exc_type, args.exc_value, args.exc_traceback))
        logger.error(f"Unhandled error in thread {name}:\n{text}")

    sys.excepthook = hook
    threading.excepthook = thread_hook


def _set_resolution_scaling() -> None:
    """Pre-flight check to scale the Qt app based on screen resolution.
    Runs a fast subprocess to read QApplication.primaryScreen() before the main app
    is instantiated, setting QT_SCALE_FACTOR if needed.
    """
    import subprocess
    try:
        # We use a subprocess because QT_SCALE_FACTOR must be set before QApplication,
        # but we need QApplication to read the logical screen size.
        code = (
            "from PyQt6.QtWidgets import QApplication; import sys; "
            "app = QApplication(sys.argv); s = app.primaryScreen().geometry(); "
            "print(f'{s.width()},{s.height()}')"
        )
        flags = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
        output = subprocess.check_output(
            [sys.executable, "-c", code],
            creationflags=flags,
            stderr=subprocess.DEVNULL
        ).decode().strip()
        
        w_str, h_str = output.split(",")
        w, h = int(w_str), int(h_str)
        
        # 1920x1080 is the 1.0x baseline
        raw_scale = min(w / 1920.0, h / 1080.0)
        
        # Soften the scaling by interpolating halfway to the 1.0 baseline
        scale = 1.0 + (raw_scale - 1.0) * 0.5
        
        # Clamp scale between 0.5x and 2.0x to prevent unusable extremes
        scale = max(0.5, min(scale, 2.0))
        
        # Only set if it deviates significantly from 1.0
        if abs(scale - 1.0) > 0.05:
            os.environ["QT_SCALE_FACTOR"] = f"{scale:.3f}"
    except Exception as e:
        logger.debug(f"Failed to auto-scale resolution: {e}")


def _build_app() -> tuple[QApplication, object]:
    """Create the QApplication + main window and wire startup services."""
    _set_resolution_scaling()
    qt_app = QApplication(sys.argv)
    qt_app.setApplicationName("Phoenix")
    qt_app.setApplicationDisplayName("Phoenix")
    # Drives the GNOME dock-tile/.desktop association on Linux (parallels the
    # WM_CLASS approach the CTk app used). Harmless elsewhere.
    qt_app.setDesktopFileName("phoenix")

    # One Phoenix per user: a second launch shows the running one and exits.
    from utils import single_instance
    if not single_instance.acquire():
        logger.info("Phoenix is already running; showed that window instead")
        return qt_app, None

    from gui.app_window import AppWindow

    window = AppWindow(qt_app)

    # Login plugin is uninstallable via the Store; respect that here so
    # users who removed it don't get the login screen on next launch.
    login_uninstalled = _is_login_plugin_uninstalled()

    if settings.get("auth", "logged_in", False) and not _session_still_valid():
        logger.info("🔐 Phoenix session ended on the server — signing in again.")
        settings.clear_namespace("auth")

    if settings.get("auth", "logged_in", False) or login_uninstalled:
        if login_uninstalled:
            logger.info("ℹ️  Login plugin uninstalled — skipping login screen.")
        else:
            logger.info("✅ User already logged in.")
        window.create_dashboard()
        if sys.platform == "darwin":
            _resume_macos_installs()
    else:
        logger.info("🔐 Showing login screen…")
        window.show_login()

    try:
        from utils import notifications
        notifications.init()
    except Exception as e:
        logger.warning(f"Failed to initialize system notifications: {e}")

    try:
        from utils.linux_desktop import ensure_desktop_entry
        ensure_desktop_entry()
    except Exception as e:
        logger.debug(f"Desktop entry setup skipped: {e}")

    # Auto-update is off for now. Without init no backend starts (Sparkle,
    # WinSparkle or the Linux scheduler), so the app never checks on its own;
    # Settings' "Check for updates" reports updates as unavailable.
    # try:
    #     from utils import updates
    #     updates.init(window)
    # except Exception as e:
    #     logger.warning(f"Failed to start auto-updater: {e}")

    # Native system tray (Windows). Replaces the old standalone pystray tray
    # that the packaged build never launched. Closing the window then hides to
    # the tray; only the tray's Quit exits. See gui/system_tray.py.
    if sys.platform == "win32":
        try:
            from gui.system_tray import SystemTray
            tray = SystemTray(window)
            if tray.install():
                window._tray = tray  # window.closeEvent hides to it
        except Exception as e:  # noqa: BLE001
            logger.warning(f"Failed to start system tray: {e}")

    single_instance.listen(lambda: _bring_forward(window))

    return qt_app, window


def _bring_forward(window) -> None:
    """Show the window, also when minimized or hidden to the tray."""
    if window.isMinimized():
        window.showNormal()
    window.show()
    window.raise_()
    window.activateWindow()


def _session_still_valid() -> bool:
    """False only when MAS rejected the stored session (signed out elsewhere).

    Offline or no MAS session (legacy OTP login) counts as valid."""
    try:
        from plugins.login.oidc import validate_session
        return validate_session()
    except Exception as e:
        logger.warning(f"Session check skipped: {e}")
        return True


def _is_login_plugin_uninstalled() -> bool:
    """Return True if the user uninstalled the Login plugin via the Store."""
    try:
        import json

        from utils.settings import get_config_dir
        state_path = os.path.join(get_config_dir(), "plugin_state.json")
        if not os.path.exists(state_path):
            return False
        with open(state_path, "r", encoding="utf-8") as f:
            state = json.load(f)
        return "007" in state.get("uninstalled", [])
    except Exception as e:
        logger.warning(f"Could not read plugin state: {e}")
        return False


def _resume_macos_installs() -> None:
    import threading
    try:
        from plugins.wazuh.agent.installer_service import check_and_advance
        threading.Thread(target=check_and_advance, daemon=True).start()
    except Exception:
        pass
    try:
        from plugins.antivirus.installer_service import (
            check_and_advance as av_advance,
        )
        threading.Thread(target=av_advance, daemon=True).start()
    except Exception:
        pass


def main() -> int:
    global DEBUG

    # Before anything can spawn a child process: on Windows, default every
    # subprocess to CREATE_NO_WINDOW so the windowed build stops flashing
    # console windows. No-op on other platforms.
    from utils.win_console import suppress_child_console_windows
    suppress_child_console_windows()
    # Linux build: children get the system's libraries, not the bundle's.
    functions.restore_system_library_path()

    parser = argparse.ArgumentParser(
        description="Phoenix Desktop Application",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("-d", "--debug", action="store_true",
                        help="Enable debug mode")
    parser.add_argument("-l", "--log-level",
                        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
                        default="INFO", help="Set logging level (default: INFO)")
    parser.add_argument("--trace", action="store_true",
                        help="Write every HTTP exchange (secrets masked) to logs/trace-*.log")
    args = parser.parse_args()

    if args.debug or functions.is_running_in_ide():
        DEBUG = True
        # Plugins can't import main's DEBUG global (circular import), so
        # expose debug mode through the environment. The VPN plugin uses
        # this to auto-connect on macOS in dev runs. (Grafted from develop.)
        os.environ["RESISTINE_DEBUG"] = "1"

    log_level = args.log_level
    if DEBUG and log_level == "INFO" and not any(
        a in sys.argv for a in ["-l", "--log-level"]
    ):
        log_level = "DEBUG"
    # Before the file log sink creates the new config dir.
    settings.migrate_legacy_config_dir()
    setup_logging(level=log_level)
    if args.trace or os.environ.get("PHOENIX_TRACE") == "1":
        from utils import http_trace
        trace_file = http_trace.enable(os.path.join(settings.get_config_dir(), "logs"))
        logger.info(f"HTTP trace enabled: {trace_file}")
    _install_excepthook()
    if sys.platform == "darwin":
        from utils.functions import remove_legacy_bundle

        if remove_legacy_bundle():
            logger.info("Removed the old /Applications/Resistine.app")

    qt_app, window = _build_app()
    if window is None:
        return 0

    if DEBUG:
        logger.info("Debug mode enabled")
        logger.info(f"Platform: {sys.platform}")
        logger.info(f"Python version: {sys.version}")

    signal.signal(signal.SIGINT, signal.SIG_DFL)

    window.show()
    window.raise_()
    window.activateWindow()
    try:
        rc = qt_app.exec()
    except KeyboardInterrupt:
        rc = 0
    # Orderly teardown, then hard exit: non-daemon helper threads (updater,
    # spawned installers) must not hold the process open after the Qt loop
    # ends — the CTk app had the same terminal-hang failure mode.
    try:
        from utils import updates
        updates.shutdown()
    except Exception:
        pass
    try:
        logger.complete()
    except Exception:
        pass
    os._exit(rc)


if __name__ == "__main__":
    raise SystemExit(main())
