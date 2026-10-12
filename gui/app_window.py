"""AppWindow — the PyQt6 host shell.

The Qt counterpart of the old ``gui/user_interface.py`` ``AppUI``: a 250 px
sidebar (logo + one checkable nav button per plugin) beside a ``QStackedWidget``
content area, with plugins discovered via ``PluginManager``.

It also exposes a small set of **Tk-compatibility shims** (``after`` /
``after_cancel`` / ``show_notification`` / ``select_frame_by_name`` /
``update_plugin`` / ``winfo_width`` …) so each plugin's existing
worker-thread + ``app.after(0, ...)`` marshalling logic keeps working verbatim
against Qt. ``after`` is thread-safe: a call from any thread is marshalled onto
the GUI thread via a queued signal before a ``QTimer`` is armed.

Author: Resistine Team
Copyright (c) Resistine 2025
Licensed under the GNU General Public License v2 or later
"""

from __future__ import annotations

import os
import threading

from PyQt6.QtCore import (
    QEasingCurve,
    QPropertyAnimation,
    QSize,
    Qt,
    QTimer,
    pyqtSignal,
    pyqtSlot,
)
from PyQt6.QtGui import QColor, QIcon, QPixmap
from PyQt6.QtWidgets import (
    QButtonGroup,
    QFrame,
    QGraphicsDropShadowEffect,
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QPushButton,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from gui import theme
from gui.qt_toast import Toast
from gui.qt_widgets import resource
from utils.logger import logger


class AppWindow(QMainWindow):
    # (ms, token, callable) marshalled onto the GUI thread for after().
    _after_signal = pyqtSignal(int, int, object)

    def __init__(self, qt_app):
        super().__init__()
        self._app_qt = qt_app
        self._hidpi_factor = 1.0  # Tk-compat attr some plugins read

        # after() bookkeeping
        self._after_lock = threading.Lock()
        self._after_counter = 0
        self._after_cancelled: set[int] = set()
        self._after_signal.connect(
            self._schedule_after, Qt.ConnectionType.QueuedConnection)

        # Shell state
        self.plugins: list = []
        self.plugin_list: list = []
        self.frames: dict = {}
        self._screens: dict[str, QWidget] = {}
        self._nav_buttons: dict[str, QPushButton] = {}
        self.current_frame_name = ""
        self._current_main_screen = None

        self.setWindowTitle("Phoenix")
        self.resize(1120, 720)
        self.setMinimumSize(820, 480)
        icon_png = resource("resources", "icons", "app_icon.png")
        if os.path.isfile(icon_png):
            self.setWindowIcon(QIcon(icon_png))

        # Honour the persisted appearance choice (defaults to System).
        try:
            from utils import settings as _settings
            saved_mode = _settings.get("ui", "appearance_mode", "System")
        except Exception:
            saved_mode = "System"
        self.apply_theme(self._resolve_mode(saved_mode))

    def closeEvent(self, event) -> None:  # noqa: N802 (Qt override)
        # When a system tray is active (Windows), closing the window hides it
        # to the tray instead of quitting — only the tray's Quit truly exits.
        tray = getattr(self, "_tray", None)
        if tray is not None:
            try:
                if tray.on_window_close():
                    event.ignore()
                    return
            except Exception as e:  # noqa: BLE001
                logger.debug(f"close-to-tray failed, closing normally: {e}")
        super().closeEvent(event)

    # ===================================================================
    #  Plugin manager
    # ===================================================================
    def get_plugin_manager(self):
        if not hasattr(self.__class__, "plugin_manager"):
            from plugins.plugin_manager import PluginManager
            self.__class__.plugin_manager = PluginManager(self)
        return self.__class__.plugin_manager

    # ===================================================================
    #  Login vs main shell
    # ===================================================================
    def show_login(self) -> None:
        """Show the Login plugin full-window (no sidebar)."""
        try:
            from plugins.login.main import Plugin as LoginPlugin
            login = LoginPlugin(self)
            login.app = self
            self._login_plugin = login
            screen = login.create_main_screen()
        except Exception as e:
            logger.error(f"Failed to load login plugin: {e}")
            self.create_dashboard()
            return
        # Cancel plugin timers BEFORE the swap deletes their widgets —
        # a re-arming poll firing into a deleted widget tree is a hard
        # crash (access violation) on Windows, not a catchable exception.
        self._teardown_plugins()
        self.setCentralWidget(screen)

    def _teardown_plugins(self) -> None:
        """Stop plugin timers/polls ahead of a central-widget swap."""
        for p in getattr(self, "plugins", []):
            if hasattr(p, "destroy"):
                try:
                    p.destroy()
                except Exception as e:
                    logger.warning(f"{p.get_name()} teardown failed: {e}")

    def create_dashboard(self) -> None:
        """Build (or rebuild) the main sidebar+content shell and show Dashboard.

        Named for source-compatibility — the Login plugin calls this on a
        successful sign-in to transition out of the login screen.
        """
        self._build_main_ui()
        self.navigate("Dashboard")

    def _build_main_ui(self) -> None:
        # Rebuilding replaces (deletes) the old central widget — stop the
        # old plugin set's timers first (same crash hazard as show_login).
        self._teardown_plugins()
        pm = self.get_plugin_manager()
        self.plugins = sorted(pm.plugins, key=lambda p: p.order)
        self.plugin_list = self.plugins
        for p in self.plugins:
            p.app = self
        self.frames = {f"frame_{p.get_name()}": p for p in self.plugins}
        self._screens = {}
        self._nav_buttons = {}

        root = QWidget()
        layout = QHBoxLayout(root)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        self._build_sidebar(layout)
        self.stack = QStackedWidget()
        layout.addWidget(self.stack, 1)
        self.setCentralWidget(root)

    # ---- Sidebar ----------------------------------------------------------
    # Icon-only rail: the plugin name is the tooltip and accessible name.
    SIDEBAR_WIDTH = 76

    def _build_sidebar(self, layout: QHBoxLayout) -> None:
        self.sidebar = QFrame()
        self.sidebar.setObjectName("Sidebar")
        self.sidebar.setFixedWidth(self.SIDEBAR_WIDTH)
        sb = QVBoxLayout(self.sidebar)
        sb.setContentsMargins(12, 18, 12, 16)
        sb.setSpacing(6)
        sb.setAlignment(Qt.AlignmentFlag.AlignHCenter)

        sb.addWidget(self._logo_widget(), 0, Qt.AlignmentFlag.AlignHCenter)
        sb.addSpacing(14)

        self._nav_group = QButtonGroup(self)
        self._nav_group.setExclusive(True)
        bottom = []
        for p in self.plugins:
            if p.order <= 0 or getattr(p, "hidden", False):
                continue  # Login (0), explicitly-hidden (-1) and hidden plugins
            btn = QPushButton()
            btn.setObjectName("NavButton")
            btn.setCheckable(True)
            btn.setFixedSize(52, 48)
            btn.setCursor(Qt.CursorShape.PointingHandCursor)
            btn.setIconSize(QSize(24, 24))
            btn.setIcon(p.get_nav_icon())
            btn.setToolTip(p.get_name())
            btn.setAccessibleName(p.get_name())
            btn.clicked.connect(
                lambda _=False, n=p.get_name(): self.select_frame_by_name(
                    f"frame_{n}"))
            self._nav_group.addButton(btn)
            self._nav_buttons[p.get_name()] = btn
            p.set_button(btn)
            # Help + Settings (order >= 1000) sit at the bottom of the rail.
            if p.order >= 1000:
                bottom.append(btn)
            else:
                sb.addWidget(btn, 0, Qt.AlignmentFlag.AlignHCenter)

        sb.addStretch(1)
        for btn in bottom:
            sb.addWidget(btn, 0, Qt.AlignmentFlag.AlignHCenter)
        layout.addWidget(self.sidebar)

    def _logo_widget(self) -> QWidget:
        # The square Phoenix app mark (same art as the login screen). It
        # doubles as the protection indicator: see set_protection_status().
        label = QLabel()
        label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        label.setToolTip("Phoenix")
        self._logo = label
        self._logo_anim = None
        size = 44
        path = resource("resources", "icons", "PhoenixMark.png")
        pm = QPixmap(path) if os.path.isfile(path) else QPixmap()
        if not pm.isNull():
            ratio = 2.0
            pm = pm.scaled(int(size * ratio), int(size * ratio),
                           Qt.AspectRatioMode.KeepAspectRatio,
                           Qt.TransformationMode.SmoothTransformation)
            pm.setDevicePixelRatio(ratio)
            label.setPixmap(pm)
        else:
            label.setText("P")
            label.setStyleSheet(
                f"font-size: 24px; font-weight: 800; color: {theme.color('accent')};")
        self._apply_logo_glow()
        return label

    # Glow colour per protection state; None (unknown) = no glow.
    _GLOW = {"ok": "#2CC985", "error": "#FF4040"}

    def set_protection_status(self, state: str | None) -> None:
        """Make the sidebar logo glow green ("ok") or red ("error")."""
        if state == getattr(self, "_protection", None):
            return
        self._protection = state
        self._apply_logo_glow()

    def _apply_logo_glow(self) -> None:
        label = getattr(self, "_logo", None)
        if label is None:
            return
        if self._logo_anim is not None:
            self._logo_anim.stop()
            self._logo_anim = None
        state = getattr(self, "_protection", None)
        colour = self._GLOW.get(state)
        try:
            if colour is None:
                label.setGraphicsEffect(None)
                label.setToolTip("Phoenix")
                return
            glow = QGraphicsDropShadowEffect(label)
            glow.setOffset(0, 0)
            glow.setColor(QColor(colour))
            glow.setBlurRadius(22)
            label.setGraphicsEffect(glow)
            label.setToolTip("Phoenix — protected" if state == "ok"
                             else "Phoenix — not protected")
            if state == "error":
                # Unprotected: a slow breathing pulse to draw the eye.
                anim = QPropertyAnimation(glow, b"blurRadius", label)
                anim.setDuration(2400)
                anim.setStartValue(10.0)
                anim.setKeyValueAt(0.5, 30.0)
                anim.setEndValue(10.0)
                anim.setEasingCurve(QEasingCurve.Type.InOutSine)
                anim.setLoopCount(-1)
                anim.start()
                self._logo_anim = anim
        except RuntimeError:  # logo deleted by a shell rebuild
            self._logo = None

    # ===================================================================
    #  Navigation
    # ===================================================================
    def select_frame_by_name(self, name: str, button=None) -> None:
        plugin = self.frames.get(name)
        if plugin is None:
            return
        # Login is a full-window flow (no sidebar), not an in-shell screen —
        # e.g. the Dashboard's sign-in card routes here when logged out.
        if plugin.get_name() == "Login":
            self.show_login()
            return
        self.navigate(plugin.get_name())

    def navigate(self, name: str) -> None:
        plugin = self._plugin_by_name(name)
        if plugin is None:
            return
        screen = self._screens.get(name)
        if screen is None:
            try:
                screen = plugin.create_main_screen()
            except Exception as e:
                logger.error(f"Error building screen for {name}: {e}")
                self.show_notification(f"Error loading {name}: {e}", "error")
                return
            self._screens[name] = screen
            self.stack.addWidget(screen)
        else:
            try:
                plugin.on_screen_shown()
            except Exception:
                pass
        self.stack.setCurrentWidget(screen)
        self._current_main_screen = screen
        self.current_frame_name = f"frame_{name}"
        # Exclusive selection: uncheck every other nav button. Without this
        # the checked states accumulated as you navigated (several sidebar
        # rows rendered "selected").
        for n, b in self._nav_buttons.items():
            b.setChecked(n == name)

    def refresh_navigation(self) -> None:
        """Rebuild the whole shell (e.g. after install/uninstall)."""
        self._build_main_ui()
        self.navigate("Dashboard")

    def update_plugin(self, plugin_id=None) -> None:
        """Rebuild the affected plugin's live screen + invalidate Dashboard."""
        names = {"Dashboard"}
        if plugin_id is not None:
            p = next((p for p in self.plugins if p.id == plugin_id), None)
            if p is not None:
                names.add(p.get_name())
                btn = self._nav_buttons.get(p.get_name())
                if btn is not None:
                    btn.setIcon(p.get_nav_icon())
        for n in names:
            self._rebuild_screen(n)

    def _rebuild_screen(self, name: str) -> None:
        old = self._screens.get(name)
        if old is None:
            return
        plugin = self._plugin_by_name(name)
        if plugin is None:
            return
        try:
            new = plugin.create_main_screen()
        except Exception as e:
            logger.error(f"Error rebuilding {name}: {e}")
            return
        was_current = self.stack.currentWidget() is old
        self._screens[name] = new
        self.stack.addWidget(new)
        self.stack.removeWidget(old)
        old.deleteLater()
        if was_current:
            self.stack.setCurrentWidget(new)
            self._current_main_screen = new

    def _plugin_by_name(self, name: str):
        return next((p for p in self.plugins if p.get_name() == name), None)

    # ===================================================================
    #  Theme
    # ===================================================================
    def set_appearance_mode(self, mode: str) -> None:
        resolved = self._resolve_mode(mode)
        if resolved == theme.get_mode():
            return
        self.apply_theme(resolved)
        # Mode-specific icons + logo: rebuild the sidebar buttons' icons.
        # Also unpolish/repolish each button: the app-wide restyle can leave
        # a stale hover/underMouse state behind, which rendered several rows
        # with the hover background as if "selected" after a theme toggle.
        for name, btn in self._nav_buttons.items():
            p = self._plugin_by_name(name)
            if p is not None:
                btn.setIcon(p.get_nav_icon())
            try:
                btn.setAttribute(
                    Qt.WidgetAttribute.WA_UnderMouse, False)
                btn.style().unpolish(btn)
                btn.style().polish(btn)
                btn.update()
            except Exception:
                pass

        # Notify plugins of the theme change so they can update custom-coloured UI
        for p in self.plugins:
            if hasattr(p, "on_theme_changed"):
                try:
                    p.on_theme_changed()
                except Exception as e:
                    logger.error(f"Plugin {p.get_name()} on_theme_changed error: {e}")

    def apply_theme(self, resolved: str) -> None:
        theme.set_mode(resolved)
        # Sync the QPalette to the theme, not just the stylesheet. Natively
        # painted widgets (document-mode QTabBar, menus, native scroll areas)
        # use the PALETTE — which otherwise follows the macOS system
        # appearance. With system-dark + app-light that leaked as black
        # bands/strips in light mode wherever QSS doesn't reach.
        from PyQt6.QtGui import QPalette
        pal = QPalette()
        window = QColor(theme.color("window_bg"))
        base = QColor(theme.color("card_bg"))
        text = QColor(theme.color("text_primary"))
        muted = QColor(theme.color("text_secondary"))
        accent = QColor(theme.color("accent"))
        pal.setColor(QPalette.ColorRole.Window, window)
        pal.setColor(QPalette.ColorRole.Base, base)
        pal.setColor(QPalette.ColorRole.AlternateBase, window)
        pal.setColor(QPalette.ColorRole.Button, base)
        pal.setColor(QPalette.ColorRole.WindowText, text)
        pal.setColor(QPalette.ColorRole.Text, text)
        pal.setColor(QPalette.ColorRole.ButtonText, text)
        pal.setColor(QPalette.ColorRole.PlaceholderText, muted)
        pal.setColor(QPalette.ColorRole.Highlight, accent)
        pal.setColor(QPalette.ColorRole.HighlightedText,
                     QColor(theme.color("on_accent")))
        pal.setColor(QPalette.ColorRole.ToolTipBase, base)
        pal.setColor(QPalette.ColorRole.ToolTipText, text)
        self._app_qt.setPalette(pal)
        self._app_qt.setStyleSheet(theme.build_qss())

    def _resolve_mode(self, mode: str) -> str:
        if mode in ("Light", "Dark"):
            return mode
        try:
            from PyQt6.QtGui import QGuiApplication
            scheme = QGuiApplication.styleHints().colorScheme()
            if scheme == Qt.ColorScheme.Light:
                return "Light"
            if scheme == Qt.ColorScheme.Dark:
                return "Dark"
        except Exception:
            pass
        return "Dark"

    # ===================================================================
    #  Tk-compatibility shims (so plugin backend logic ports unchanged)
    # ===================================================================
    def after(self, ms, fn=None, *args):
        """Schedule fn(*args) after ms. Thread-safe. Returns a cancel token."""
        if not callable(fn):
            return None  # tk's after(ms) "sleep" form — unsupported, ignored
        with self._after_lock:
            self._after_counter += 1
            token = self._after_counter
        cb = (lambda: fn(*args)) if args else fn
        self._after_signal.emit(int(ms), token, cb)
        return token

    def after_idle(self, fn, *args):
        return self.after(0, fn, *args)

    def after_cancel(self, token) -> None:
        if token is not None:
            self._after_cancelled.add(token)

    @pyqtSlot(int, int, object)
    def _schedule_after(self, ms: int, token: int, cb) -> None:
        def run():
            if token in self._after_cancelled:
                self._after_cancelled.discard(token)
                return
            try:
                cb()
            except Exception:
                logger.exception("after() callback failed")
        QTimer.singleShot(max(0, ms), run)

    def update_idletasks(self) -> None:
        self._app_qt.processEvents()

    def update(self) -> None:  # noqa: A003 - Tk-compat name
        self._app_qt.processEvents()

    def winfo_width(self) -> int:
        return self.width()

    def winfo_height(self) -> int:
        return self.height()

    def winfo_exists(self) -> bool:
        return True

    # ===================================================================
    #  Notifications
    # ===================================================================
    def show_notification(self, message, type="info", centered=False) -> None:
        try:
            host = self.centralWidget() or self
            toast = Toast(host, str(message), kind=type)
            toast.show_for()
        except Exception as e:
            logger.debug(f"Toast failed: {e}")
