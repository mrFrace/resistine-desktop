## @file plugins/dashboard/main.py
## @namespace dashboard_plugin
"""Dashboard plugin UI (PyQt6): an at-a-glance view of this device.

A branded header (the Phoenix mark links to https://phoenix.exposed), then
four panels: the security posture of the user's machines (from the Phoenix
service, see posture.py), the Endpoint agent, the AI assistant, and system
facts. Data is gathered off the UI thread and refreshed on a
timer; the last result is cached on the plugin so a rebuild (any plugin's
status change rebuilds this screen) paints immediately. Protection status
is shown by the glow on the sidebar logo (green/red), driven from here.

Author: P3, Peres J. and the Resistine Team
Copyright (c) Resistine 2025
Licensed under the GNU General Public License v2 or later
"""

import os
import threading
import time
import webbrowser
from urllib.parse import urlsplit

from PyQt6.QtCore import QMimeData, QPoint, QSize, Qt, QTimer
from PyQt6.QtGui import QDrag, QIcon, QPixmap
from PyQt6.QtWidgets import (
    QApplication,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

from gui import theme
from gui.page_kit import (
    Page, PageHeader, RowList, SlideStack, back_link, icon_button, line_icon, muted)
from gui.qt_widgets import StatusBadge, scroll_page, set_pill
from gui.toggle import ToggleSwitch
from plugins.base_plugin import BasePlugin
from plugins.dashboard import alerts as recent_alerts
from plugins.dashboard import mitigations, posture, protection
from utils import chat_config
from utils.functions import get_resource_path
from utils.logger import logger

_DIR = os.path.dirname(os.path.realpath(__file__))
_PLUGINS_DIR = os.path.dirname(_DIR)
WEBSITE_URL = "https://phoenix.exposed"
_REFRESH_MS = 20_000


# --------------------------------------------------------------------------
# Data (worker thread)
# --------------------------------------------------------------------------

def _endpoint_info() -> dict:
    try:
        from plugins.wazuh import main as wz
    except Exception as e:  # noqa: BLE001
        return {"badge": ("error", "Unavailable"), "rows": {"Error": str(e)}}
    if not getattr(wz, "_platform_supported", False):
        return {"badge": ("info", "Unsupported"), "rows": {}}
    installed = bool(wz._safe(wz.is_agent_installed, False))
    if not installed:
        return {"badge": ("warning", "Not installed"),
                "rows": {"Agent": "Not installed on this device",
                         "Manager": wz.WAZUH_MANAGER}}
    state = wz._safe(wz.get_agent_status, "Unknown")
    conn = (wz._safe(wz.get_agent_connection, "unknown")
            if state == "Running" else "unknown")
    if state != "Running":
        badge = ("error", "Stopped")
    elif conn == "connected":
        badge = ("ok", "Connected")
    elif conn == "disconnected":
        badge = ("error", "Not connected")
    elif conn == "pending":
        badge = ("warning", "Connecting")
    else:
        badge = ("ok", "Running")
    rows = {
        "Service": state,
        "Connection": "—" if conn == "unknown" else conn.capitalize(),
        "Agent name": wz._safe(wz.get_agent_name, "—"),
        "Group": wz._safe(wz.get_agent_group, "—"),
        "Manager": wz.WAZUH_MANAGER,
    }
    if wz._PLATFORM == "Linux":
        # Which install: the app's /var/ossec, or a system-managed one.
        try:
            from plugins.wazuh.agent import wazuh_functions_linux as wl
            rows["Install"] = (f"{wl.installed_agent_dir()}"
                               + ("" if wl.is_app_managed_agent()
                                  else " (system-managed)"))
        except Exception:
            pass
    return {"badge": badge, "rows": rows}


def _ai_info(chat_plugin) -> dict:
    from utils import settings
    try:
        from plugins.chat import main as chat
    except Exception as e:  # noqa: BLE001
        return {"badge": ("error", "Unavailable"), "rows": {"Error": str(e)}}
    base = chat_config.base_url()
    model = getattr(chat_plugin, "model", None) or "—"
    rows = {"Server": urlsplit(base).netloc or base, "Model": model}
    try:
        from plugins.wazuh.main import is_agent_running
        unlocked = bool(is_agent_running())
    except Exception:
        unlocked = False
    rows["Access"] = ("Unlocked (Endpoint agent running)" if unlocked
                      else "Locked: start the Endpoint agent")
    try:
        import httpx
        key = settings.get_secret("chat", "openai_api_key") or "unused"
        t0 = time.monotonic()
        r = httpx.get(base.rstrip("/") + "/models", timeout=6,
                      verify=chat._tls_verify(),
                      headers={"Authorization": f"Bearer {key}"})
        ms = int((time.monotonic() - t0) * 1000)
        if r.status_code == 200:
            n = len(r.json().get("data", []))
            rows["Models"] = f"{n} available"
            rows["Latency"] = f"{ms} ms"
            badge = ("ok", "Online") if unlocked else ("warning", "Locked")
        else:
            rows["Response"] = f"HTTP {r.status_code}"
            badge = ("warning", f"HTTP {r.status_code}")
    except Exception as e:  # noqa: BLE001
        rows["Response"] = type(e).__name__
        badge = ("error", "Unreachable")
    return {"badge": badge, "rows": rows}


def _plugin(app, name: str):
    return next((p for p in getattr(app, "plugins", []) if p.get_name() == name), None)


def _antivirus_info(app) -> dict:
    from utils import settings
    av = _plugin(app, "Antivirus")
    if av is None:
        return protection.antivirus_panel(None, None, None, None)
    from plugins.antivirus import clamav
    status = getattr(av, "_last_status", None)
    if status is None:
        status = clamav.get_realtime_status()
    db = quarantined = None
    try:
        db = clamav.get_db_info()
    except Exception as e:  # noqa: BLE001
        logger.debug(f"Dashboard: antivirus DB info failed: {e}")
    try:
        quarantined = len(clamav.list_quarantined())
    except Exception as e:  # noqa: BLE001
        logger.debug(f"Dashboard: quarantine list failed: {e}")
    return protection.antivirus_panel(status, db, settings.get("antivirus", "last_scan"), quarantined)


def _vpn_info(app) -> dict:
    from utils import settings
    vpn = _plugin(app, "VPN")
    if vpn is None:
        return protection.vpn_panel(False, None, None, False)
    from plugins.vpn import main as vm
    try:
        config = vpn.get_selected_conf_file_name()
    except Exception:  # noqa: BLE001
        config = None
    return protection.vpn_panel(True, vm.my_vpn_status, config,
                                bool(settings.get("auth", "logged_in", False)))


def _system_info(app) -> dict:
    from utils import system_info
    rows = system_info.collect()
    vpn = next((p for p in getattr(app, "plugins", [])
                if p.get_name() == "VPN"), None)
    try:
        rows["VPN"] = ("Connected" if vpn and vpn.get_status() == "OK"
                       else "Off")
    except Exception:
        rows["VPN"] = "—"
    try:
        from utils.updates.version import get_current_version
        rows["Phoenix"] = get_current_version()
    except Exception:
        pass
    return {"badge": None, "rows": rows}


# --------------------------------------------------------------------------
# UI
# --------------------------------------------------------------------------

_PANEL_MIME = "application/x-phoenix-dashboard-panel"


class _Panel(QFrame):
    """Card with an icon tile, title, status pill and key/value rows. Drag
    it by its header to move it (the grid re-aligns)."""

    def __init__(self, title: str, icon_path: str, on_open=None, key: str = ""):
        super().__init__()
        self.key = key
        self._press: QPoint | None = None
        self.setMouseTracking(True)  # open-hand cursor over the header
        self.setObjectName("Surface")
        self.setMinimumWidth(260)
        self.setSizePolicy(QSizePolicy.Policy.Expanding,
                           QSizePolicy.Policy.Maximum)
        v = QVBoxLayout(self)
        v.setContentsMargins(18, 16, 18, 16)
        v.setSpacing(12)

        head = QHBoxLayout()
        head.setSpacing(12)
        tile = QLabel()
        tile.setFixedSize(40, 40)
        tile.setAlignment(Qt.AlignmentFlag.AlignCenter)
        tile.setStyleSheet(
            f"background-color: {theme.color('sidebar_active_bg')};"
            "border-radius: 10px;")
        if icon_path.startswith("lucide:"):  # a Lucide line icon from resources/icons/ui
            tile.setPixmap(line_icon(icon_path[7:], theme.color("sidebar_active_text"), 22))
        elif os.path.isfile(icon_path):
            pm = BasePlugin._tint(
                QPixmap(icon_path).scaled(
                    44, 44, Qt.AspectRatioMode.KeepAspectRatio,
                    Qt.TransformationMode.SmoothTransformation),
                theme.color("sidebar_active_text"))
            pm.setDevicePixelRatio(2.0)
            tile.setPixmap(pm)
        head.addWidget(tile)
        name = QLabel(title)
        name.setObjectName("CardTitle")
        head.addWidget(name)
        head.addStretch(1)
        self._head = head
        self.badge = None
        self._badge_at = head.count()
        self._controls_at = head.count()
        if on_open:
            btn = QPushButton("Open")
            btn.setObjectName("Link")
            btn.setCursor(Qt.CursorShape.PointingHandCursor)
            btn.clicked.connect(on_open)
            head.addWidget(btn)
        v.addLayout(head)

        div = QFrame()
        div.setObjectName("Divider")
        div.setFixedHeight(1)
        v.addWidget(div)

        self._grid = QGridLayout()
        self._grid.setHorizontalSpacing(16)
        self._grid.setVerticalSpacing(8)
        self._grid.setColumnStretch(1, 1)
        v.addLayout(self._grid)

    def add_header_control(self, widget: QWidget) -> QWidget:
        """A control (e.g. a switch) in the header, after the status pill."""
        self._head.insertWidget(self._controls_at + 1, widget, 0, Qt.AlignmentFlag.AlignVCenter)
        return widget

    # ---- drag by the header ------------------------------------------------
    def _in_header(self, pos: QPoint) -> bool:
        return pos.y() <= 64

    def mousePressEvent(self, e):  # noqa: N802
        if e.button() == Qt.MouseButton.LeftButton and self._in_header(e.position().toPoint()):
            self._press = e.position().toPoint()
        super().mousePressEvent(e)

    def mouseMoveEvent(self, e):  # noqa: N802
        if self._press is None or not (e.buttons() & Qt.MouseButton.LeftButton):
            self.setCursor(Qt.CursorShape.OpenHandCursor if self._in_header(e.position().toPoint())
                           else Qt.CursorShape.ArrowCursor)
            return super().mouseMoveEvent(e)
        if (e.position().toPoint() - self._press).manhattanLength() < QApplication.startDragDistance():
            return
        self._press = None
        drag = QDrag(self)
        mime = QMimeData()
        mime.setData(_PANEL_MIME, self.key.encode())
        drag.setMimeData(mime)
        shot = self.grab()
        drag.setPixmap(shot.scaledToWidth(max(1, shot.width() * 2 // 3),
                                          Qt.TransformationMode.SmoothTransformation))
        drag.setHotSpot(QPoint(24, 24))
        self.setEnabled(False)  # dims it while it is being moved
        try:
            drag.exec(Qt.DropAction.MoveAction)
        finally:
            self.setEnabled(True)

    def mouseReleaseEvent(self, e):  # noqa: N802
        self._press = None
        super().mouseReleaseEvent(e)

    def set_data(self, data: dict | None) -> None:
        while self._grid.count():
            w = self._grid.takeAt(0).widget()
            if w:
                w.deleteLater()
        if data is None:
            self._row(0, "Loading…", "")
            return
        badge = data.get("badge")
        if badge:
            # A fresh pill per update: re-styling a live one in place kept
            # its old (unpadded) geometry.
            status, text = badge
            if self.badge is not None:
                self._head.removeWidget(self.badge)
                self.badge.deleteLater()
            self.badge = StatusBadge(status)
            self.badge.setText(text)
            self._head.insertWidget(self._badge_at, self.badge)
        for i, (k, val) in enumerate(data.get("rows", {}).items()):
            self._row(i, k, str(val))

    def _row(self, i: int, key: str, val: str) -> None:
        k = QLabel(key)
        k.setStyleSheet(f"color: {theme.color('text_secondary')};")
        k.setAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignTop)
        v = QLabel(val)
        v.setTextFormat(Qt.TextFormat.PlainText)  # values include server text
        v.setWordWrap(True)
        v.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        v.setStyleSheet("font-weight: 600;")
        self._grid.addWidget(k, i, 0)
        self._grid.addWidget(v, i, 1)


DEFAULT_ORDER = ["posture", "alerts", "antivirus", "vpn", "endpoint", "ai", "system"]
_GAP = 16


def panel_order(saved, keys=DEFAULT_ORDER) -> list:
    """The saved order, keeping only known panels; new ones go at the end."""
    saved = [k for k in (saved if isinstance(saved, list) else []) if k in keys]
    return list(dict.fromkeys(saved)) + [k for k in keys if k not in saved]


def masonry_columns(heights: list, n_cols: int) -> list:
    """Column per panel, in order: each goes into the shortest column so far
    (ties: leftmost). Gapless however tall the panels are."""
    totals = [0] * max(1, n_cols)
    cols = []
    for h in heights:
        i = totals.index(min(totals))
        cols.append(i)
        totals[i] += h + _GAP
    return cols


def move_panel(order: list, key: str, target: str | None, after: bool) -> list:
    """Move ``key`` before/after ``target`` (None: to the end)."""
    if key not in order or key == target:
        return list(order)
    rest = [k for k in order if k != key]
    if target is None or target not in rest:
        return rest + [key]
    i = rest.index(target) + (1 if after else 0)
    return rest[:i] + [key] + rest[i:]


class _PanelGrid(QWidget):
    """Gapless grid: 1-4 columns by width, panels in the user's order, each
    placed in the shortest column. Accepts panel drops to reorder."""

    # Width per column: a panel needs ~420 px for its title, pill and Open
    # link and for unbreakable values (hostnames, paths) without clipping.
    _CARD_STEP = 420

    def __init__(self, panels: dict, order: list, on_reorder):
        super().__init__()
        self.setObjectName("Transparent")
        self.setAcceptDrops(True)
        self._panels = panels
        self._order = order
        self._on_reorder = on_reorder
        self._placed: tuple | None = None
        self._row = QHBoxLayout(self)
        self._row.setContentsMargins(0, 0, 0, 0)
        self._row.setSpacing(_GAP)
        self._cols: list = []
        self._debounce = QTimer(self)
        self._debounce.setSingleShot(True)
        self._debounce.setInterval(60)
        self._debounce.timeout.connect(self.relayout)
        self.relayout()

    def schedule(self) -> None:
        self._debounce.start()

    def set_order(self, order: list) -> None:
        self._order = order
        self._placed = None
        self.relayout()

    def resizeEvent(self, e):  # noqa: N802
        super().resizeEvent(e)
        self.schedule()

    def _n_cols(self) -> int:
        return max(1, min(4, len(self._order), max(1, self.width()) // self._CARD_STEP))

    def relayout(self) -> None:
        n = self._n_cols()
        col_w = max(1, (self.width() - _GAP * (n - 1)) // n)
        panels = [self._panels[k] for k in self._order]
        heights = [p.heightForWidth(col_w) if p.hasHeightForWidth() else p.sizeHint().height()
                   for p in panels]
        cols = masonry_columns(heights, n)
        placed = (n, tuple(self._order), tuple(cols))
        if placed == self._placed:
            return
        self._placed = placed
        for col in self._cols:
            for p in panels:
                col.removeWidget(p)
        while len(self._cols) < n:
            col = QVBoxLayout()
            col.setSpacing(_GAP)
            col.addStretch(1)
            self._row.addLayout(col, 1)
            self._cols.append(col)
        while len(self._cols) > n:
            col = self._cols.pop()
            self._row.removeItem(col)
            col.deleteLater()
        for p, c in zip(panels, cols):
            col = self._cols[c]
            col.insertWidget(col.count() - 1, p)

    # ---- drops ----------------------------------------------------------------
    def dragEnterEvent(self, e):  # noqa: N802
        if e.mimeData().hasFormat(_PANEL_MIME):
            e.acceptProposedAction()

    def dragMoveEvent(self, e):  # noqa: N802
        if e.mimeData().hasFormat(_PANEL_MIME):
            e.acceptProposedAction()

    def dropEvent(self, e):  # noqa: N802
        key = bytes(e.mimeData().data(_PANEL_MIME)).decode()
        pos = e.position().toPoint()
        target, after = None, False
        for k, p in self._panels.items():
            if p.geometry().contains(pos):
                target, after = k, pos.y() > p.geometry().center().y()
                break
        order = move_panel(self._order, key, target, after)
        e.acceptProposedAction()
        if order != self._order:
            self.set_order(order)
            self._on_reorder(order)


class Plugin(BasePlugin):
    """Dashboard plugin."""

    def __init__(self, app):
        super().__init__(
            id="001", version="2025.01.01", order=1, name="Dashboard",
            status=None,
            description="See your protection status at a glance.",
            supported_systems=["Windows", "Linux", "Mac"],
            translations={"US": "Dashboard", "ES": "Panel",
                          "FR": "Tableau de bord"},
            icon_light_path=os.path.join(_DIR, "home_light.png"),
            icon_dark_path=os.path.join(_DIR, "home_dark.png"),
            uninstall_enabled=False,
        )
        self.app = app
        self._data: dict = {"posture": posture.panel_data(
                                posture.state(), posture.local_names(include_agent=False)),
                            "endpoint": None, "ai": None, "system": None}
        self._panels: dict = {}
        self._grid: _PanelGrid | None = None
        self._vpn_switch = None
        self._views: SlideStack | None = None
        self._detail = None          # (page widget, RowList, PageHeader) while open
        self._posture_view = None    # (state, names) of the last refresh
        self._timer: QTimer | None = None
        self._busy = False

    # ---- screen -----------------------------------------------------------
    def create_main_screen(self):
        from utils import settings as app_settings

        inner = QWidget()
        v = QVBoxLayout(inner)
        v.setContentsMargins(24, 18, 24, 24)
        v.setSpacing(0)

        # Header: Phoenix mark (links to the website) + who is signed in.
        head = QHBoxLayout()
        head.setSpacing(14)
        mark = QPushButton()
        mark.setObjectName("Link")
        mark.setCursor(Qt.CursorShape.PointingHandCursor)
        mark.setToolTip(WEBSITE_URL.removeprefix("https://"))
        mark.setIcon(QIcon(get_resource_path(
            os.path.join("resources", "icons", "PhoenixMark.png"))))
        mark.setIconSize(QSize(40, 40))
        mark.setFixedSize(44, 44)
        mark.clicked.connect(lambda: webbrowser.open(WEBSITE_URL))
        head.addWidget(mark, 0, Qt.AlignmentFlag.AlignVCenter)
        titles = QVBoxLayout()
        titles.setSpacing(0)
        title = QLabel("Phoenix")
        title.setObjectName("H1")
        titles.addWidget(title)
        user_id = app_settings.get("auth", "user_id")
        who = QLabel(f"Signed in as {user_id}" if user_id else
                     ("Signed in" if app_settings.get("auth", "logged_in")
                      else "Not signed in"))
        who.setObjectName("Muted")
        titles.addWidget(who)
        head.addLayout(titles)
        head.addStretch(1)
        if not app_settings.get("auth", "logged_in", False):
            sign_in = QPushButton("Sign in")
            sign_in.setCursor(Qt.CursorShape.PointingHandCursor)
            sign_in.clicked.connect(self.app.show_login)
            head.addWidget(sign_in, 0, Qt.AlignmentFlag.AlignVCenter)
        self._reset_layout = QPushButton("Reset layout")
        self._reset_layout.setObjectName("Link")
        self._reset_layout.setCursor(Qt.CursorShape.PointingHandCursor)
        self._reset_layout.setToolTip("Drag panels by their header to move them")
        self._reset_layout.clicked.connect(lambda: self._save_order(list(DEFAULT_ORDER)))
        head.addWidget(self._reset_layout, 0, Qt.AlignmentFlag.AlignVCenter)
        site = QPushButton("phoenix.exposed ↗")
        site.setObjectName("Link")
        site.setCursor(Qt.CursorShape.PointingHandCursor)
        site.clicked.connect(lambda: webbrowser.open(WEBSITE_URL))
        head.addWidget(site, 0, Qt.AlignmentFlag.AlignVCenter)
        v.addLayout(head)
        v.addSpacing(16)

        # Protection = the Endpoint (Wazuh) agent is installed and healthy;
        # shown as the sidebar logo's glow. The VPN only protects traffic
        # and has its own status. Refined by the endpoint probe in _apply().
        self._set_protection(
            self._data["endpoint"]["badge"][0] if self._data.get("endpoint")
            else ("ok" if self._agent_installed() else "error"))

        self._panels = {
            "posture": _Panel(
                "Security posture",
                os.path.join(_PLUGINS_DIR, "antivirus", "antivirus_dark.png"),
                self._show_posture_detail, key="posture"),
            "alerts": _Panel(
                "Recent alerts", "lucide:activity",
                self._open_alerts, key="alerts"),
            "antivirus": _Panel(
                "Antivirus", "lucide:shield-check",
                lambda: self.app.select_frame_by_name("frame_Antivirus"), key="antivirus"),
            "vpn": _Panel(
                "VPN", "lucide:globe",
                lambda: self.app.select_frame_by_name("frame_VPN"), key="vpn"),
            "endpoint": _Panel(
                "Endpoint",
                os.path.join(_PLUGINS_DIR, "wazuh", "add_user_dark.png"),
                lambda: self.app.select_frame_by_name("frame_Endpoint"), key="endpoint"),
            "ai": _Panel(
                "AI assistant",
                os.path.join(_PLUGINS_DIR, "chat", "chat_dark.png"),
                lambda: self.app.select_frame_by_name("frame_Chat"), key="ai"),
            "system": _Panel(
                "System", os.path.join(_DIR, "home_dark.png"), key="system"),
        }
        self._data["alerts"] = self._alerts_data()
        self._vpn_switch = self._panels["vpn"].add_header_control(ToggleSwitch())
        self._vpn_switch.setToolTip("Connect or disconnect the VPN")
        self._vpn_switch.clicked.connect(self._toggle_vpn)
        self._sync_vpn_switch()
        for key, panel in self._panels.items():
            panel.set_data(self._data.get(key))
        self._subscribe_alerts()
        order = panel_order(app_settings.get("dashboard", "panel_order"), list(self._panels))
        self._grid = _PanelGrid(self._panels, order, self._save_order)
        self._reset_layout.setVisible(order != DEFAULT_ORDER)
        v.addWidget(self._grid)
        v.addStretch(1)

        self._ensure_timer()
        self.refresh()
        self._views = SlideStack(fit_height=False)
        self._views.addWidget(scroll_page(inner))
        self._detail = None
        return self._views

    def on_theme_changed(self) -> None:
        # Panels bake theme colours in at build time.
        try:
            self.app.update_plugin()
        except Exception:
            pass

    def on_screen_shown(self):
        self.refresh()

    def destroy(self):
        if self._timer is not None:
            self._timer.stop()
        try:
            from plugins.chat import siem_alerts
            siem_alerts.unsubscribe(self._alert_arrived)
        except Exception:  # noqa: BLE001
            pass

    # ---- data -------------------------------------------------------------
    def _ensure_timer(self):
        if self._timer is None:
            self._timer = QTimer()
            self._timer.setInterval(_REFRESH_MS)
            self._timer.timeout.connect(self.refresh)
        if not self._timer.isActive():
            self._timer.start()

    def refresh(self):
        if self._busy:
            return
        self._busy = True
        chat = next((p for p in getattr(self.app, "plugins", [])
                     if p.get_name() == "Chat"), None)

        def work():
            data = {}
            try:
                # Recent alerts arrive over Matrix; (re)start the listener
                # after a sign-in or a dropped connection. Cheap when it's up.
                from plugins.chat import matrix_transport
                matrix_transport.ensure_alerts_listener()
            except Exception as e:  # noqa: BLE001
                logger.debug(f"Dashboard alerts listener: {e}")
            try:
                st, names = posture.fetch(), posture.local_names()
                mine, _ = posture.split_cards(st["cards"], names)
                states = mitigations.check(mine, True) if mine else []
                data["posture"] = posture.panel_data(
                    st, names, todo=mitigations.summary(states) if states else None)
                data["_posture_view"] = (st, names)
            except Exception as e:  # noqa: BLE001
                logger.warning(f"Dashboard posture probe failed: {e}")
            for key, fn in (("antivirus", lambda: _antivirus_info(self.app)),
                            ("vpn", lambda: _vpn_info(self.app)),
                            ("endpoint", _endpoint_info),
                            ("system", lambda: _system_info(self.app)),
                            ("ai", lambda: _ai_info(chat))):
                try:
                    data[key] = fn()
                except Exception as e:  # noqa: BLE001
                    logger.warning(f"Dashboard {key} probe failed: {e}")
                    data[key] = {"badge": ("error", "Error"),
                                 "rows": {"Error": str(e)}}
            try:
                self.app.after(0, lambda: self._apply(data))
            except Exception:
                self._busy = False

        threading.Thread(target=work, daemon=True).start()

    def _apply(self, data: dict):
        self._busy = False
        data["alerts"] = self._alerts_data()  # local store: cheap, read on the UI thread
        view = data.pop("_posture_view", None)
        if view is not None:
            self._posture_view = view
            self._fill_posture_detail()
        self._data.update(data)
        badge = (self._data.get("endpoint") or {}).get("badge")
        if badge:
            self._set_protection(badge[0])
        for panel_key, panel in self._panels.items():
            try:
                panel.set_data(self._data.get(panel_key))
            except RuntimeError:  # panel deleted by a rebuild
                pass
        self._sync_vpn_switch()
        if self._grid is not None:
            try:
                self._grid.schedule()  # heights changed: re-pack the columns
            except RuntimeError:
                self._grid = None

    # ---- recent alerts (SIEM alerts from siemgent over Matrix) --------------
    @staticmethod
    def _alerts_data() -> dict:
        try:
            from plugins.chat import siem_alerts
            st = siem_alerts.store()
            return recent_alerts.panel_data(st.all(), st.unread)
        except Exception as e:  # noqa: BLE001
            logger.warning(f"Dashboard alerts unavailable: {e}")
            return {"badge": ("info", "Unavailable"), "rows": {"Alerts": "Alerts are unavailable."}}

    def _subscribe_alerts(self) -> None:
        try:
            from plugins.chat import siem_alerts
            siem_alerts.subscribe(self._alert_arrived)  # idempotent
        except Exception:  # noqa: BLE001
            pass

    def _alert_arrived(self, _alert: dict) -> None:
        # Matrix thread: repaint on the Qt thread.
        try:
            self.app.after(0, self._repaint_alerts)
        except Exception:  # noqa: BLE001
            pass

    def _repaint_alerts(self) -> None:
        self._data["alerts"] = self._alerts_data()
        panel = self._panels.get("alerts")
        if panel is None:
            return
        try:
            panel.set_data(self._data["alerts"])
            if self._grid is not None:
                self._grid.schedule()
        except RuntimeError:  # panel deleted by a rebuild
            pass

    def _open_alerts(self) -> None:
        self.app.select_frame_by_name("frame_Chat")
        chat = next((p for p in getattr(self.app, "plugins", []) if p.get_name() == "Chat"), None)
        show = getattr(chat, "_show_alerts", None)
        if show is not None:
            def go():
                try:
                    show()
                except Exception as e:  # noqa: BLE001 (chat screen not ready)
                    logger.debug(f"Dashboard: could not open SIEM alerts: {e}")
                self._repaint_alerts()  # opening marks them read
            QTimer.singleShot(0, go)

    # ---- VPN switch ----------------------------------------------------------
    def _sync_vpn_switch(self) -> None:
        switch = getattr(self, "_vpn_switch", None)
        if switch is None:
            return
        vpn = _plugin(self.app, "VPN")
        try:
            if vpn is None:
                switch.hide()
                return
            from plugins.vpn import main as vm
            switch.select() if vm.my_vpn_status == "Running" else switch.deselect()
            switch.setEnabled(not vpn.is_toggle_busy())
        except RuntimeError:  # rebuilt
            self._vpn_switch = None

    def _toggle_vpn(self) -> None:
        vpn = _plugin(self.app, "VPN")
        switch = getattr(self, "_vpn_switch", None)
        if vpn is None or switch is None:
            return
        switch.setEnabled(False)
        vpn.request_toggle(switch.get())
        # The connect/disconnect runs on the VPN plugin's worker; re-read.
        for ms in (2500, 7000, 15000):
            QTimer.singleShot(ms, self._refresh_after_toggle)

    def _refresh_after_toggle(self) -> None:
        self.refresh()

    def _save_order(self, order: list) -> None:
        from utils import settings as app_settings
        app_settings.set("dashboard", "panel_order", order)
        try:
            if self._grid is not None:
                self._grid.set_order(order)
            self._reset_layout.setVisible(order != DEFAULT_ORDER)
        except RuntimeError:  # screen rebuilt meanwhile
            pass

    # ---- security posture detail (slides in over the panels) ---------------
    _PILLS = {
        mitigations.OPEN: ("error", "To fix"),
        mitigations.FIXED_HERE: ("ok", "Fixed here"),
        mitigations.UNKNOWN: ("info", "Can't check here"),
        mitigations.SERVER: ("info", "Next scan"),
        None: ("info", "Checking…"),
    }

    def _show_posture_detail(self) -> None:
        if self._views is None:
            return
        page = Page()
        page.add(back_link("Dashboard", self._hide_posture_detail))
        header = PageHeader("Security posture")
        again = icon_button("refresh-cw", "Check again")
        again.clicked.connect(self._recheck_mitigations)
        header.add_control(again)
        page.add(header)
        rows = RowList()
        page.spacing(18)
        page.add(rows)
        page.spacing(14)
        page.add(muted(
            "Fixed here means the vulnerable version is no longer installed on this "
            "machine. The daily scan confirms it and the item disappears. Phoenix never "
            "changes your system on its own: update packages with your system's "
            "software updater."))
        page.stretch()
        self._views.addWidget(page.widget)
        self._detail = (page.widget, rows, header)
        self._fill_posture_detail()
        self._views.push(page.widget)

    def _hide_posture_detail(self) -> None:
        if self._views is None or self._detail is None:
            return
        page = self._detail[0]
        self._detail = None
        self._views.back()
        QTimer.singleShot(400, lambda: (self._views.removeWidget(page), page.deleteLater())
                          if self._views is not None else None)

    def _recheck_mitigations(self) -> None:
        if self._posture_view is None:
            return
        st, names = self._posture_view

        def work():
            mine, _ = posture.split_cards(st["cards"], names)
            if mine:
                mitigations.check(mine, True, force=True)
            self.app.after(0, self._fill_posture_detail)

        threading.Thread(target=work, daemon=True).start()

    def _fill_posture_detail(self) -> None:
        if self._detail is None:
            return
        _, rows, header = self._detail
        try:
            rows.clear()
        except RuntimeError:  # page deleted by a rebuild
            self._detail = None
            return
        st, names = self._posture_view or (posture.state(), posture.local_names(include_agent=False))
        mine, others = posture.split_cards(st.get("cards") or [], names)
        if mine is None and not others:
            header.set_subtitle("No posture yet. It appears after the first daily scan.")
            header.set_status(None)
            return
        if mine is not None:
            header.set_subtitle(
                f"This machine: {mine.get('hostname')} · grade {mine.get('grade')} · "
                f"{mine.get('score')}/100 · computed {str(mine.get('computed_at', ''))[:16].replace('T', ' ')}")
            header.set_status(*posture.panel_data(st, names)["badge"])
            items = mitigations.cached(mine, True)
            self._add_section(rows, "THIS MACHINE", items, "Nothing to fix on this machine.")
        else:
            header.set_subtitle("No posture for this machine yet.")
            header.set_status("info", "No data for this machine")
        for card in others:
            self._add_section(rows, f"{str(card.get('hostname') or card.get('agent_id')).upper()} · "
                                    f"GRADE {card.get('grade')}",
                              mitigations.cached(card, False), "Nothing to fix.")

    def _add_section(self, rows, title: str, items: list, empty: str) -> None:
        heading = QLabel(title)
        heading.setObjectName("Section")
        heading.setTextFormat(Qt.TextFormat.PlainText)
        heading.setContentsMargins(0, 16, 0, 4)
        rows.add_row(heading)
        if not items:
            rows.add_row(muted(empty))
            return
        for item, state in items:
            rows.add_row(self._item_row(item, state))

    def _item_row(self, item: dict, state) -> QWidget:
        row = QWidget()
        row.setObjectName("Transparent")
        h = QHBoxLayout(row)
        h.setContentsMargins(4, 10, 4, 10)
        h.setSpacing(14)
        text = QVBoxLayout()
        text.setSpacing(2)
        title = QLabel(item["title"] or item["kind"])
        title.setObjectName("RowTitle")
        title.setTextFormat(Qt.TextFormat.PlainText)
        text.addWidget(title)
        hint = QLabel(mitigations.detail_line(item))
        hint.setObjectName("Hint")
        hint.setTextFormat(Qt.TextFormat.PlainText)
        hint.setWordWrap(True)
        hint.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        text.addWidget(hint)
        h.addLayout(text, 1)
        if state != mitigations.REMOTE:
            kind, label = self._PILLS.get(state, self._PILLS[None])
            if state == mitigations.OPEN and item["severity"] not in ("critical", "high"):
                kind = "warning"
            pill = QLabel()
            set_pill(pill, kind, label)
            h.addWidget(pill, 0, Qt.AlignmentFlag.AlignVCenter)
        return row

    def _set_protection(self, kind: str) -> None:
        # Endpoint badge kind -> logo glow: ok = green, info (unsupported
        # platform) = none, anything else (stopped / not installed /
        # disconnected) = red.
        state = {"ok": "ok", "info": None}.get(kind, "error")
        setter = getattr(self.app, "set_protection_status", None)
        if setter is not None:
            setter(state)

    @staticmethod
    def _agent_installed() -> bool:
        try:
            from plugins.wazuh.main import is_agent_installed
            return bool(is_agent_installed())
        except Exception:
            return False
