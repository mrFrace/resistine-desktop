## @file gui/system_tray.py
## @namespace gui.system_tray
"""Native system-tray icon for the running PyQt6 app.

Replaces the old standalone ``gui/tray.py`` (pystray). That one was never
launched by the packaged Windows build — nothing spawned it — and it assumed
a source-tree layout (``main.py`` on disk, project-relative paths), so it
could not work from a frozen install. This lives *inside* the app process
instead: no second Python interpreter, works in the PyInstaller build, and
closing the main window hides it to the tray instead of quitting.

Menu: a (disabled) VPN status line, Open Phoenix, VPN Settings, and Quit.
Single/double-click on the icon restores the window. VPN status is polled so
the line and tooltip stay current.

Windows-only for now (that's where a tray is expected and where the old one
was wired). The code itself is platform-neutral, so enabling it on
macOS/Linux is just a matter of calling ``install()`` there too.
"""

import os

from PyQt6.QtCore import QObject, QTimer, pyqtSignal
from PyQt6.QtGui import QAction, QIcon
from PyQt6.QtWidgets import QApplication, QMenu, QSystemTrayIcon

from gui.qt_widgets import resource
from utils.logger import logger

_POLL_MS = 3000  # VPN status refresh cadence


class SystemTray(QObject):
    """Owns a ``QSystemTrayIcon`` bound to the main window's lifetime."""

    # notify() may be called from any thread; the signal hops to the GUI one.
    _notify = pyqtSignal(str, str, str, object)

    def __init__(self, window) -> None:
        # Parent to the window so the tray is destroyed with it.
        super().__init__(window)
        self._window = window
        self._app = QApplication.instance()
        self._tray: QSystemTrayIcon | None = None
        self._status_action: QAction | None = None
        self._poll: QTimer | None = None
        self._notified_hidden = False
        self._on_message_click = None
        self._notify.connect(self._show_notification)

    # -- setup -------------------------------------------------------------

    def install(self) -> bool:
        """Create and show the tray icon. Returns False if unavailable."""
        if self._tray is not None:
            return True
        if not QSystemTrayIcon.isSystemTrayAvailable():
            logger.warning("[TRAY] system tray not available on this desktop")
            return False

        self._tray = QSystemTrayIcon(self._load_icon(), self)
        self._tray.setToolTip("Phoenix")
        self._tray.setContextMenu(self._build_menu())
        self._tray.activated.connect(self._on_activated)
        self._tray.messageClicked.connect(self._message_clicked)
        self._tray.show()
        try:
            from utils.notifications import windows as win_notifications
            win_notifications.set_tray(self)
        except Exception:  # noqa: BLE001
            pass

        # Keep the process (and this tray) alive when the window is closed to
        # the tray. Only the tray's Quit action performs a real exit.
        try:
            self._app.setQuitOnLastWindowClosed(False)
        except Exception:  # noqa: BLE001
            pass

        self._poll = QTimer(self)
        self._poll.timeout.connect(self._refresh_status)
        self._poll.start(_POLL_MS)
        self._refresh_status()
        logger.info("[TRAY] native system tray installed")
        return True

    def _load_icon(self) -> QIcon:
        for name in ("icon.ico", "app_icon.ico", "app_icon.png"):
            path = resource("resources", "icons", name)
            if os.path.isfile(path):
                return QIcon(path)
        # Last resort: reuse whatever the window is already using.
        return self._window.windowIcon()

    def _build_menu(self) -> QMenu:
        menu = QMenu()
        self._status_action = QAction("VPN: …", menu)
        self._status_action.setEnabled(False)  # a status line, not clickable
        menu.addAction(self._status_action)
        menu.addSeparator()

        open_action = QAction("Open Phoenix", menu)
        open_action.triggered.connect(self._show_window)
        menu.addAction(open_action)

        vpn_action = QAction("VPN Settings", menu)
        vpn_action.triggered.connect(self._open_vpn)
        menu.addAction(vpn_action)

        menu.addSeparator()
        quit_action = QAction("Quit Phoenix", menu)
        quit_action.triggered.connect(self._quit)
        menu.addAction(quit_action)
        return menu

    # -- actions -----------------------------------------------------------

    def _on_activated(self, reason) -> None:
        # Left-click (Trigger) or double-click restores the window; right-click
        # (Context) is handled by the context menu automatically.
        if reason in (
            QSystemTrayIcon.ActivationReason.Trigger,
            QSystemTrayIcon.ActivationReason.DoubleClick,
        ):
            self._show_window()

    def _show_window(self) -> None:
        try:
            self._window.showNormal()  # un-minimise if needed
            self._window.raise_()
            self._window.activateWindow()
        except Exception as e:  # noqa: BLE001
            logger.debug(f"[TRAY] show window failed: {e}")

    def _open_vpn(self) -> None:
        self._show_window()
        try:
            self._window.navigate("VPN")
        except Exception as e:  # noqa: BLE001
            logger.debug(f"[TRAY] navigate to VPN failed: {e}")

    def _quit(self) -> None:
        """Real exit — the only path that actually closes the app."""
        try:
            self._app.setQuitOnLastWindowClosed(True)
        except Exception:  # noqa: BLE001
            pass
        if self._poll is not None:
            self._poll.stop()
        if self._tray is not None:
            self._tray.hide()
        self._app.quit()

    # -- status ------------------------------------------------------------

    def _refresh_status(self) -> None:
        connected = False
        try:
            from plugins.vpn.main import is_vpn_connected
            connected = bool(is_vpn_connected())
        except Exception:  # noqa: BLE001 - VPN plugin may be absent/uninstalled
            connected = False
        label = "Connected" if connected else "Disconnected"
        dot = "🟢" if connected else "⚪"
        # The tray objects can be torn down between timer ticks; guard the
        # deleted-C++-object case rather than crash the poll.
        try:
            if self._status_action is not None:
                self._status_action.setText(f"{dot}  VPN: {label}")
            if self._tray is not None:
                self._tray.setToolTip(f"Phoenix — VPN {label}")
        except RuntimeError:
            pass

    # -- notifications -----------------------------------------------------

    def notify(self, title: str, body: str, urgency: str = "normal", on_click=None) -> None:
        """A tray notification; *on_click* runs when it is clicked. Any thread."""
        self._notify.emit(title, body, urgency, on_click)

    def _show_notification(self, title, body, urgency, on_click) -> None:
        if self._tray is None:
            return
        self._on_message_click = on_click  # Qt reports clicks on the latest message only
        icon = (QSystemTrayIcon.MessageIcon.Critical if urgency == "critical"
                else QSystemTrayIcon.MessageIcon.Warning)
        try:
            self._tray.showMessage(title, body, icon, 10000)
        except RuntimeError:
            pass

    def _message_clicked(self) -> None:
        fn, self._on_message_click = self._on_message_click, None
        if fn is None:
            self._show_window()
            return
        try:
            fn()
        except Exception as e:  # noqa: BLE001
            logger.warning(f"[TRAY] notification click failed: {e}")

    # -- close-to-tray -----------------------------------------------------

    def on_window_close(self) -> bool:
        """Hide the window to the tray instead of quitting.

        Returns True if the close was intercepted (caller should ignore the
        event), False if the tray isn't active and the app should close
        normally. Shows a one-time hint the first time it happens.
        """
        if self._tray is None:
            return False
        self._window.hide()
        if not self._notified_hidden:
            self._notified_hidden = True
            self._on_message_click = None
            try:
                self._tray.showMessage(
                    "Phoenix is still running",
                    "The app was minimised to the tray. "
                    "Right-click the tray icon to quit.",
                    QSystemTrayIcon.MessageIcon.Information,
                    4000,
                )
            except Exception:  # noqa: BLE001
                pass
        return True
