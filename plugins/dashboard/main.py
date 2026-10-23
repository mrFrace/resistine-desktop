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

from PyQt6.QtCore import (QEasingCurve, QMimeData, QPoint, QPointF, QPropertyAnimation, QRect,
                          QRectF, QSize, Qt, QTimer)
from PyQt6.QtGui import QColor, QDrag, QIcon, QPainter, QPainterPath, QPen, QPixmap
from PyQt6.QtWidgets import (
    QApplication,
    QFrame,
    QTextBrowser,
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
    KVList, MenuRow, Page, PageHeader, RowList, SlideStack, back_link, icon_button, line_icon,
    muted)
from gui.qt_widgets import StatusBadge, scroll_page, set_pill
from gui.toggle import ToggleSwitch
from plugins.base_plugin import BasePlugin
from plugins.dashboard import alerts as recent_alerts
from plugins.dashboard import mitigations, posture, protection, tile_layout
from utils import chat_config
from utils.functions import get_resource_path
from utils.logger import logger

_DIR = os.path.dirname(os.path.realpath(__file__))
_PLUGINS_DIR = os.path.dirname(_DIR)
WEBSITE_URL = "https://phoenix.exposed"
_REFRESH_MS = 20_000
# Alert notifications: only alerts sent after the app started pop up, each
# once (module level, so a rebuilt plugin instance doesn't repeat them).
_STARTED_AT = time.time()
_NOTIFIED: set = set()
_notified_lock = threading.Lock()


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
    it by its header to move it; drag its right edge to make it wider or
    narrower (the grid, _PanelGrid, places it)."""

    _EDGE = 10  # px at the right edge that resize instead of drag

    def __init__(self, title: str, icon_path: str, on_open=None, key: str = "", on_row=None):
        super().__init__()
        self.key = key
        self.title = title
        self._on_row = on_row  # on_row(id) for rows listed in data["ids"]
        self._press: QPoint | None = None
        self._resizing = False
        self._edge_hover = False
        self.on_resize = None  # grid callback: on_resize(key, x in the grid, done)
        self.grab_offset = QPoint(0, 0)  # where the drag picked the panel up
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
        self._extras = QVBoxLayout()  # charts under the rows (data "strip" / "spark")
        self._extras.setContentsMargins(0, 0, 0, 0)
        v.addLayout(self._extras)

    def add_header_control(self, widget: QWidget) -> QWidget:
        """A control (e.g. a switch) in the header, after the status pill."""
        self._head.insertWidget(self._controls_at + 1, widget, 0, Qt.AlignmentFlag.AlignVCenter)
        return widget

    # ---- drag by the header, resize by the right edge ----------------------
    def _on_edge(self, pos: QPoint) -> bool:
        return self.on_resize is not None and pos.x() >= self.width() - self._EDGE

    def _in_header(self, pos: QPoint) -> bool:
        return pos.y() <= 64 and not self._on_edge(pos)

    def _set_edge_hover(self, on: bool) -> None:
        if on != self._edge_hover:
            self._edge_hover = on
            self.update()

    def _grid_x(self, e) -> int:
        return self.mapToParent(e.position().toPoint()).x()

    def mousePressEvent(self, e):  # noqa: N802
        pos = e.position().toPoint()
        if e.button() == Qt.MouseButton.LeftButton and self._on_edge(pos):
            self._resizing = True
            self.update()
            return
        if e.button() == Qt.MouseButton.LeftButton and self._in_header(pos):
            self._press = pos
        super().mousePressEvent(e)

    def mouseDoubleClickEvent(self, e):  # noqa: N802
        if self._on_edge(e.position().toPoint()):
            self.on_resize(self.key, None, True)  # back to the default width
            return
        super().mouseDoubleClickEvent(e)

    def leaveEvent(self, e):  # noqa: N802
        if not self._resizing:
            self._set_edge_hover(False)
        super().leaveEvent(e)

    def mouseMoveEvent(self, e):  # noqa: N802
        pos = e.position().toPoint()
        if self._resizing:
            self.on_resize(self.key, self._grid_x(e), False)
            return
        if self._press is None or not (e.buttons() & Qt.MouseButton.LeftButton):
            edge = self._on_edge(pos)
            self._set_edge_hover(edge)
            self.setCursor(Qt.CursorShape.SizeHorCursor if edge
                           else Qt.CursorShape.OpenHandCursor if self._in_header(pos)
                           else Qt.CursorShape.ArrowCursor)
            return super().mouseMoveEvent(e)
        if (pos - self._press).manhattanLength() < QApplication.startDragDistance():
            return
        self.grab_offset = self._press
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
        if self._resizing:
            self._resizing = False
            self._set_edge_hover(self._on_edge(e.position().toPoint()))
            self.on_resize(self.key, self._grid_x(e), True)
            self.update()
            return
        self._press = None
        super().mouseReleaseEvent(e)

    def paintEvent(self, e):  # noqa: N802
        super().paintEvent(e)
        if not (self._edge_hover or self._resizing):
            return
        # The resize grip: a short accent bar in the middle of the right edge.
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(QColor(theme.color("sidebar_active_text")))
        p.drawRoundedRect(QRectF(self.width() - 7, self.height() / 2 - 22, 4, 44), 2, 2)
        p.end()

    def set_data(self, data: dict | None) -> None:
        for lay in (self._grid, self._extras):
            while lay.count():
                w = lay.takeAt(0).widget()
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
        ids = data.get("ids") or {}
        for i, (k, val) in enumerate(data.get("rows", {}).items()):
            row_id = ids.get(k) if self._on_row else None
            self._row(i, k, str(val), (lambda r=row_id: self._on_row(r)) if row_id else None)
        if data.get("strip"):
            self._extras.addWidget(_DayStrip(data["strip"]))
        if data.get("spark"):
            self._extras.addWidget(_Sparkline(data["spark"]))

    def _row(self, i: int, key: str, val: str, on_click=None) -> None:
        k = QLabel(key)
        k.setStyleSheet(f"color: {theme.color('text_secondary')};")
        k.setAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignTop)
        v = QLabel(val)
        v.setTextFormat(Qt.TextFormat.PlainText)  # values include server text
        v.setWordWrap(True)
        v.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        v.setStyleSheet("font-weight: 600;")
        if on_click is not None:  # opens the row's item; a click, not a text selection
            v.setTextInteractionFlags(Qt.TextInteractionFlag.NoTextInteraction)
            v.setCursor(Qt.CursorShape.PointingHandCursor)
            v.mouseReleaseEvent = lambda e, fn=on_click: (
                fn() if e.button() == Qt.MouseButton.LeftButton else None)
        self._grid.addWidget(k, i, 0)
        self._grid.addWidget(v, i, 1)


# Bar colour per worst severity of a day (badge text colours of the theme).
_SEV_KIND = {"critical": "critical", "high": "error", "medium": "warning", "low": "info"}


def _sev_color(sev) -> QColor:
    if sev in _SEV_KIND:
        return QColor(theme.badge_colors(_SEV_KIND[sev])[1])
    return QColor(theme.color("text_secondary"))


class _DayStrip(QWidget):
    """Alerts per day, oldest left: one bar per day, its height the count
    (square-root scale, so one busy day doesn't flatten the rest) and its
    colour the day's worst severity. Weekday initials underneath."""

    BAR_H = 30

    def __init__(self, days: list):
        super().__init__()
        self._days = [d for d in days if isinstance(d, dict)]
        self.setFixedHeight(self.BAR_H + 18)
        self.setMinimumWidth(140)
        busiest = max((d["count"] for d in self._days), default=0)
        parts = [f"{d['day']:%a %d %b}: {d['count']} alert{'s' if d['count'] != 1 else ''}"
                 + (f", worst {d['worst']}" if d["worst"] else "") for d in self._days]
        self.setToolTip("\n".join(parts))
        self._max = busiest

    def paintEvent(self, _e):  # noqa: N802
        if not self._days:
            return
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        n = len(self._days)
        gap = 6
        w = (self.width() - gap * (n - 1)) / n
        muted = QColor(theme.color("text_secondary"))
        f = p.font()
        f.setPointSizeF(max(7.0, f.pointSizeF() - 2))
        p.setFont(f)
        for i, d in enumerate(self._days):
            x = i * (w + gap)
            if d["count"] and self._max:
                h = max(5.0, self.BAR_H * (d["count"] / self._max) ** 0.5)
                p.setPen(Qt.PenStyle.NoPen)
                p.setBrush(_sev_color(d["worst"]))
            else:
                h = 2.0
                p.setPen(Qt.PenStyle.NoPen)
                p.setBrush(QColor(theme.color("divider")))
            p.drawRoundedRect(QRectF(x, self.BAR_H - h, w, h), 2, 2)
            p.setPen(muted)
            p.drawText(QRectF(x, self.BAR_H + 2, w, 16), Qt.AlignmentFlag.AlignCenter,
                       f"{d['day']:%a}"[:2])
        p.end()


class _Sparkline(QWidget):
    """The posture score over the last days: a line, the latest point dotted."""

    def __init__(self, points: list):
        super().__init__()
        self._pts = [int(v) for v in points if isinstance(v, (int, float))]
        self.setFixedHeight(50)
        self.setMinimumWidth(120)
        if self._pts:
            self.setToolTip(f"Score over the last {len(self._pts)} days: "
                            f"{min(self._pts)}–{max(self._pts)}, now {self._pts[-1]}")

    def paintEvent(self, _e):  # noqa: N802
        if len(self._pts) < 2:
            return
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        f = p.font()
        f.setPointSizeF(max(7.0, f.pointSizeF() - 2))
        p.setFont(f)
        p.setPen(QColor(theme.color("text_secondary")))
        cap = 16.0
        p.drawText(QRectF(0, 0, self.width(), cap), Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter,
                   f"Score, last {len(self._pts)} days")
        lo, hi = min(self._pts), max(self._pts)
        span = max(hi - lo, 10)  # small wobbles stay small
        mid = (hi + lo) / 2
        pad = 5.0
        w, h = self.width() - 2 * pad, self.height() - cap - 2 * pad
        step = w / (len(self._pts) - 1)

        def at(i, v):
            return QPointF(pad + i * step, cap + pad + h * (0.5 - (v - mid) / span))

        path = QPainterPath(at(0, self._pts[0]))
        for i, v in enumerate(self._pts[1:], 1):
            path.lineTo(at(i, v))
        accent = QColor(theme.color("sidebar_active_text"))  # reads on dark cards too
        p.setPen(QPen(accent, 2))
        p.drawPath(path)
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(accent)
        p.drawEllipse(at(len(self._pts) - 1, self._pts[-1]), 3.5, 3.5)
        p.end()


class _AlertText(QTextBrowser):
    """An alert's text as rich text, as tall as its content (the page
    scrolls, not this). Raw HTML in the alert is escaped and links never
    open: the text quotes the monitored system and is not ours."""

    def __init__(self, md: str):
        super().__init__()
        from plugins.chat.qt_markdown import markdown_to_html, stylesheet

        self.setObjectName("Transparent")
        self.setFrameShape(QFrame.Shape.NoFrame)
        self.setOpenLinks(False)
        self.setOpenExternalLinks(False)
        self.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self.setStyleSheet("QTextBrowser { background: transparent; border: none; }")
        self.document().setDocumentMargin(0)
        self.document().setDefaultStyleSheet(
            stylesheet(theme.color("text_primary")) + "pre { white-space: pre-wrap; }")
        self.setHtml(markdown_to_html(md, allow_html=False))
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)

    def resizeEvent(self, e):  # noqa: N802
        super().resizeEvent(e)
        self.document().setTextWidth(self.viewport().width())
        h = int(self.document().size().height()) + 4
        if h != self.height():
            self.setFixedHeight(h)


DEFAULT_ORDER = ["posture", "alerts", "antivirus", "vpn", "endpoint", "ai", "system"]
_GAP = tile_layout.GAP
_MOVE_MS = 160  # tiles glide to a new place instead of jumping


def panel_order(saved, keys=DEFAULT_ORDER) -> list:
    """The saved order, keeping only known panels; new ones go at the end."""
    saved = [k for k in (saved if isinstance(saved, list) else []) if k in keys]
    return list(dict.fromkeys(saved)) + [k for k in keys if k not in saved]


class _DropOverlay(QWidget):
    """Over the grid: the dashed outline where a dragged tile will land, and
    the width chip while a tile is resized."""

    def __init__(self, parent: QWidget):
        super().__init__(parent)
        self.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents, True)
        self.target: QRect | None = None
        self.chip: QRect | None = None
        self.chip_text = ""

    def paintEvent(self, e):  # noqa: N802
        if self.target is None and self.chip is None:
            return
        accent = QColor(theme.color("sidebar_active_text"))
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        if self.target is not None:
            fill = QColor(accent)
            fill.setAlpha(28)
            p.setBrush(fill)
            p.setPen(QPen(accent, 2, Qt.PenStyle.DashLine))
            p.drawRoundedRect(QRectF(self.target).adjusted(1, 1, -1, -1), 14, 14)
        if self.chip is not None:
            fill = QColor(accent)
            fill.setAlpha(60)
            p.setPen(Qt.PenStyle.NoPen)
            p.setBrush(fill)
            p.drawRoundedRect(QRectF(self.chip), 11, 11)
            p.setPen(accent)
            p.drawText(QRectF(self.chip), Qt.AlignmentFlag.AlignCenter, self.chip_text)
        p.end()


class _PanelGrid(QWidget):
    """The Dashboard's tiles on a unit grid (tile_layout.py): each tile as
    wide as its span, as tall as its content, in the user's order. A tile is
    moved by dragging its header (a dashed outline shows where it lands) and
    resized by dragging its right edge; tiles glide to new places."""

    def __init__(self, panels: dict, order: list, on_change, layout: dict | None = None):
        super().__init__()
        self.setObjectName("Transparent")
        self.setAcceptDrops(True)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self._panels = panels
        self._order = order
        self._layout = tile_layout.clean_layout(layout or {}, list(panels))
        self._on_change = on_change  # on_change(order, layout)
        self._units: int | None = None
        self._placed: dict = {}
        self._anims: dict = {}
        self._drop = None  # (order, layout) the current drag would make
        for p in panels.values():
            p.setParent(self)
            p.on_resize = self._resize_from
            p.show()
        self._overlay = _DropOverlay(self)
        self._debounce = QTimer(self)
        self._debounce.setSingleShot(True)
        self._debounce.setInterval(60)
        self._debounce.timeout.connect(self.relayout)
        self.relayout(animate=False)

    @property
    def layout_state(self) -> dict:
        return {k: dict(v) for k, v in self._layout.items()}

    def schedule(self) -> None:
        self._debounce.start()

    def set_order(self, order: list, layout: dict | None = None) -> None:
        self._order = order
        if layout is not None:
            self._layout = tile_layout.clean_layout(layout, list(self._panels))
        self.relayout()

    def resizeEvent(self, e):  # noqa: N802
        super().resizeEvent(e)
        self._overlay.setGeometry(self.rect())
        if e.size().width() != e.oldSize().width():  # our own height changes don't count
            self.schedule()

    # ---- placement --------------------------------------------------------------
    def _unit_w(self) -> float:
        return tile_layout.unit_width(self.width(), self._units or tile_layout.MIN_UNITS)

    def _span_w(self, span: int) -> int:
        return int(span * self._unit_w() + (span - 1) * _GAP)

    def _height(self, key: str, span: int) -> int:
        p = self._panels[key]
        w = self._span_w(span)
        lay = p.layout()
        h = lay.totalHeightForWidth(w) if lay is not None and lay.hasHeightForWidth() else -1
        return max(h, p.minimumSizeHint().height())

    def _place(self, order: list, layout: dict) -> tuple[dict, int]:
        return tile_layout.place(order, layout, self._units, self._height)

    def _rect(self, col: int, span: int, top: int, h: int) -> QRect:
        x = int(round(col * (self._unit_w() + _GAP)))
        return QRect(x, top, self._span_w(span), h)

    def relayout(self, animate: bool = True) -> None:
        if self._drop is not None:
            return  # a drag preview is showing; the drop or leave lays out
        self._units = tile_layout.units_for(max(1, self.width()), self._units)
        self._placed, total = self._place(self._order, self._layout)
        self.setFixedHeight(max(1, total))
        visible = animate and self.isVisible()
        for key, spot in self._placed.items():
            self._move(self._panels[key], self._rect(*spot), visible)

    def _move(self, panel, rect: QRect, animate: bool) -> None:
        old = self._anims.pop(panel.key, None)
        if old is not None:
            old.stop()
        if not animate or panel.geometry() == rect or panel.geometry().isEmpty():
            panel.setGeometry(rect)
            return
        anim = QPropertyAnimation(panel, b"geometry", self)
        anim.setDuration(_MOVE_MS)
        anim.setEasingCurve(QEasingCurve.Type.OutCubic)
        anim.setStartValue(panel.geometry())
        anim.setEndValue(rect)
        anim.start()
        self._anims[panel.key] = anim

    # ---- resize by the right edge ------------------------------------------------
    def _resize_from(self, key: str, x: int | None, done: bool) -> None:
        col, span = self._placed[key][0], self._placed[key][1]
        if x is None:  # double-click: back to the default width
            layout = {k: dict(v) for k, v in self._layout.items()}
            layout.get(key, {}).pop("span", None)
            self._layout = {k: v for k, v in layout.items() if v}
        else:
            step = self._unit_w() + _GAP
            left = col * step
            want = int(round((x - left + _GAP) / step))
            want = max(tile_layout.MIN_SPAN, min(want, self._units - col))
            if want != span:
                self._layout = tile_layout.resize(self._layout, key, want, col)
        self.relayout()
        if done:
            self._overlay.chip = None
            self._on_change(list(self._order), self.layout_state)
        else:
            r = self._rect(*self._placed[key])
            self._overlay.chip = QRect(r.right() - 78, r.bottom() - 34, 58, 22)
            self._overlay.chip_text = tile_layout.width_label(self._placed[key][1]) + "  ↔"
        self._overlay.raise_()
        self._overlay.update()

    # ---- drops ----------------------------------------------------------------
    def _drop_at(self, key: str, pos: QPoint) -> tuple[list, dict]:
        panel = self._panels.get(key)
        left = pos.x() - (panel.grab_offset.x() if panel is not None else 0)
        top = pos.y() - (panel.grab_offset.y() if panel is not None else 0)
        col = int(round(left / (self._unit_w() + _GAP)))
        span = self._placed[key][1] if key in self._placed else tile_layout.MIN_SPAN
        col = max(0, min(col, self._units - span))
        return tile_layout.drop(self._order, self._layout, key, col, top, self._placed)

    def _key_of(self, e) -> str | None:
        if not e.mimeData().hasFormat(_PANEL_MIME):
            return None
        key = bytes(e.mimeData().data(_PANEL_MIME)).decode()
        return key if key in self._panels else None

    def dragEnterEvent(self, e):  # noqa: N802
        if self._key_of(e):
            e.acceptProposedAction()

    def dragMoveEvent(self, e):  # noqa: N802
        key = self._key_of(e)
        if not key:
            return
        e.acceptProposedAction()
        drop = self._drop_at(key, e.position().toPoint())
        if drop == self._drop:
            return
        # Preview: the others glide aside and the (dimmed) tile sits where it
        # would land, under the outline. The drop point is worked out against
        # the committed layout, so the preview can't chase the mouse.
        self._drop = drop
        placed, total = self._place(*drop)
        self.setFixedHeight(max(1, total, self.height()))
        for k, spot in placed.items():
            self._move(self._panels[k], self._rect(*spot), True)
        self._overlay.target = self._rect(*placed[key])
        self._overlay.raise_()
        self._overlay.update()

    def dragLeaveEvent(self, e):  # noqa: N802
        self._drop = None
        self._overlay.target = None
        self._overlay.update()
        self.relayout()  # back to the committed layout

    def dropEvent(self, e):  # noqa: N802
        key = self._key_of(e)
        self._drop = None  # the preview ends either way
        self._overlay.target = None
        self._overlay.update()
        if not key:
            self.relayout()
            return
        order, layout = self._drop_at(key, e.position().toPoint())
        e.acceptProposedAction()
        changed = order != self._order or layout != self._layout
        self._order, self._layout = order, layout
        self.relayout()
        if changed:
            self._on_change(list(order), self.layout_state)


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
                                posture.state(), posture.local_names(include_agent=False),
                                score_trend=posture.trend(posture.history())),
                            "endpoint": None, "ai": None, "system": None}
        self._panels: dict = {}
        self._grid: _PanelGrid | None = None
        self._vpn_switch = None
        self._views: SlideStack | None = None
        self._detail = None          # (page widget, RowList, PageHeader) while open
        self._posture_view = None    # (state, names) of the last refresh
        self._posture_cards = (None, [])  # (this machine's card, others) as shown
        self._recheck_btn = None
        self._mitigation_page = None  # one posture item's page while open
        self._timer: QTimer | None = None
        self._busy = False
        self._alert_pages: list = []  # alert list/detail pages pushed over the panels
        self._alerts_list = None      # (RowList, PageHeader) while the list is open
        self._subscribe_alerts()  # notify even before the Dashboard is opened

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
        self._reset_layout.setToolTip("Drag panels by their header to move them, "
                                      "and by their right edge to resize them")
        self._reset_layout.clicked.connect(lambda: self._save_layout(list(DEFAULT_ORDER), {}))
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
                self._open_alerts, key="alerts", on_row=self._open_alert),
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
        self._grid = _PanelGrid(self._panels, order, self._save_layout,
                                app_settings.get("dashboard", "panel_layout"))
        self._reset_layout.setVisible(order != DEFAULT_ORDER or bool(self._grid.layout_state))
        v.addWidget(self._grid)
        v.addStretch(1)

        self._ensure_timer()
        self.refresh()
        self._views = SlideStack(fit_height=False)
        self._views.addWidget(scroll_page(inner))
        self._detail = None
        self._recheck_btn = None
        self._mitigation_page = None
        self._alert_pages = []
        self._alerts_list = None
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
                hist = posture.record_score(mine) if mine else posture.history()
                data["posture"] = posture.panel_data(
                    st, names, todo=mitigations.summary(states) if states else None,
                    score_trend=posture.trend(hist))
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

    def _alert_arrived(self, alert: dict) -> None:
        # Matrix thread: repaint on the Qt thread.
        try:
            self.app.after(0, self._repaint_alerts)
        except Exception:  # noqa: BLE001
            pass
        self._notify_alert(alert)

    def _notify_alert(self, alert: dict) -> None:
        """A desktop notification for a new high or critical alert."""
        from utils import settings as app_settings

        if not app_settings.get("dashboard", "alert_notifications", True):
            return
        note = recent_alerts.notification(alert, _STARTED_AT)
        with _notified_lock:
            if note is None or note["event_id"] in _NOTIFIED:
                return
            _NOTIFIED.add(note["event_id"])
        eid = note["event_id"]
        try:
            from utils import notifications
            notifications.send(note["title"], note["body"], urgency=note["urgency"],
                               on_click=(lambda: self.app.after(0, self._show_alert, eid))
                               if eid else None)
        except Exception as e:  # noqa: BLE001
            logger.debug(f"Alert notification failed: {e}")

    def _show_alert(self, event_id: str) -> None:
        """Clicked notification: bring the window up on that alert."""
        try:
            win = self.app
            win.showNormal()
            win.raise_()
            win.activateWindow()
            win.navigate(self.get_name())
        except Exception as e:  # noqa: BLE001
            logger.debug(f"Could not show the window for an alert: {e}")
        if self._views is not None:
            self._open_alert(event_id)

    def _repaint_alerts(self) -> None:
        if self._alerts_list is not None:
            self._fill_alerts_list()  # open list: the new alert is seen
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

    # ---- alert list and detail (slide in over the panels) ------------------
    _SEV_PILL = {"critical": "error", "high": "error", "medium": "warning", "low": "info", "info": "ok"}
    _KIND_ICON = {"triage": "activity", "hunt": "folder-search", "result": "shield-check"}

    def _push_page(self, page: Page) -> None:
        if self._views is None:
            return
        self._views.addWidget(page.widget)
        self._alert_pages.append(page.widget)
        self._views.push(page.widget)

    def _pop_page(self) -> None:
        if self._views is None or not self._alert_pages:
            return
        page = self._alert_pages.pop()
        if not self._alert_pages:
            self._alerts_list = None
        self._views.back(self._alert_pages[-1] if self._alert_pages else None)
        QTimer.singleShot(400, lambda: (self._views.removeWidget(page), page.deleteLater())
                          if self._views is not None else None)

    def _open_alerts(self) -> None:
        """The panel's Open: every stored alert, newest first."""
        if self._views is None or self._alerts_list is not None:
            return
        page = Page()
        page.add(back_link("Dashboard", self._pop_page))
        header = PageHeader("Recent alerts")
        page.add(header)
        rows = RowList()
        page.spacing(18)
        page.add(rows)
        page.spacing(14)
        page.add(muted("Alerts come from Phoenix's SIEM about the machines you own. "
                       "Triage sums up a batch of alerts, Investigating means a hunt "
                       "started, and the hunt result says whether it was a real threat."))
        page.stretch()
        self._alerts_list = (rows, header)
        self._fill_alerts_list()
        self._push_page(page)

    def _fill_alerts_list(self) -> None:
        from plugins.chat import siem_alerts
        rows, header = self._alerts_list
        try:
            rows.clear()
        except RuntimeError:  # page deleted by a rebuild
            self._alerts_list = None
            return
        st = siem_alerts.store()
        alerts = recent_alerts.newest_first(st.all())
        header.set_subtitle(f"{len(alerts)} alert{'s' if len(alerts) != 1 else ''}, newest first"
                            if alerts else "No alerts yet. Alerts about machines you own appear here.")
        for a in alerts:
            info = recent_alerts.parse(a.get("body", ""))
            hint = " · ".join(p for p in (info["host"], recent_alerts.ago(a.get("ts"))) if p)
            row = MenuRow(self._KIND_ICON.get(info["kind"], "info"), info["title"], hint,
                          on_click=lambda e=a.get("event_id"): self._open_alert(e))
            row._title.setWordWrap(True)  # long file paths
            row.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
            pill = QLabel()
            set_pill(pill, *self._pill(info))
            row.layout().insertWidget(2, pill, 0, Qt.AlignmentFlag.AlignVCenter)
            rows.add_row(row)
        if st.unread:
            st.mark_read()
            self._data["alerts"] = self._alerts_data()
            panel = self._panels.get("alerts")
            if panel is not None:
                try:
                    panel.set_data(self._data["alerts"])
                except RuntimeError:
                    pass

    def _pill(self, info: dict) -> tuple:
        if info["kind"] == "result" and info["verdict"]:
            v = info["verdict"].lower()
            return ("ok" if "false" in v else "error" if "true" in v else "warning"), info["verdict"]
        return self._SEV_PILL[info["severity"]], info["severity"].capitalize()

    def _open_alert(self, event_id: str) -> None:
        """One alert, in full: what it is about, its findings and the text."""
        from plugins.chat import siem_alerts
        alert = next((a for a in siem_alerts.store().all() if a.get("event_id") == event_id), None)
        if alert is None or self._views is None:
            return
        body = alert.get("body", "")
        info = recent_alerts.parse(body)
        page = Page()
        page.add(back_link("Recent alerts" if self._alerts_list else "Dashboard", self._pop_page))
        header = PageHeader(info["title"], recent_alerts.subtitle(info, alert.get("ts")),
                            status=self._pill(info))
        header.title.setTextFormat(Qt.TextFormat.PlainText)
        header.title.setWordWrap(True)
        header.subtitle.setTextFormat(Qt.TextFormat.PlainText)
        ask = QPushButton("Ask AI")
        ask.setIcon(QIcon(line_icon("message-circle", "#ffffff", 18)))
        ask.setCursor(Qt.CursorShape.PointingHandCursor)
        ask.setToolTip("Start a chat with Phoenix AI about this alert")
        ask.clicked.connect(lambda: self._ask_ai(body))
        header.add_control(ask)
        page.add(header)
        if info["findings"]:
            page.section("Findings")
            found = RowList()
            for f in info["findings"]:
                found.add_row(self._finding_row(f))
            page.add(found)
        page.section("Details")
        page.spacing(6)
        page.add(_AlertText(recent_alerts.detail_text(body) or body))
        page.stretch()
        self._push_page(page)

    def _finding_row(self, finding: dict) -> QWidget:
        row = QWidget()
        row.setObjectName("Transparent")
        h = QHBoxLayout(row)
        h.setContentsMargins(4, 8, 4, 8)
        h.setSpacing(14)
        name = QLabel(finding["name"])
        name.setObjectName("RowTitle")
        name.setTextFormat(Qt.TextFormat.PlainText)
        name.setWordWrap(True)
        h.addWidget(name, 1)
        pill = QLabel()
        set_pill(pill, self._SEV_PILL[finding["severity"]], finding["severity"].capitalize())
        h.addWidget(pill, 0, Qt.AlignmentFlag.AlignVCenter)
        return row

    def _ask_ai(self, body: str) -> None:
        self._start_chat(lambda chat: chat.ask_about_alert(body))

    def _ask_ai_text(self, text: str) -> None:
        self._start_chat(lambda chat: chat.ask(text))

    def _start_chat(self, send) -> None:
        chat = next((p for p in getattr(self.app, "plugins", []) if p.get_name() == "Chat"), None)
        if chat is None or getattr(chat, "client", None) is None:
            self.app.show_notification(
                "Phoenix AI isn't set up yet. Choose an AI in Settings first.", type="warning")
            return
        self.app.select_frame_by_name("frame_Chat")

        def go():
            try:
                if not send(chat):
                    self.app.show_notification("The chat isn't ready yet. Try again.", type="warning")
            except Exception as e:  # noqa: BLE001
                logger.warning(f"Dashboard: Ask AI failed: {e}")
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

    def _save_layout(self, order: list, layout: dict) -> None:
        """Keep the tiles' order and their spans/columns (Reset passes the
        default order and no layout)."""
        from utils import settings as app_settings
        app_settings.set("dashboard", "panel_order", order)
        app_settings.set("dashboard", "panel_layout", layout)
        try:
            if self._grid is not None:
                self._grid.set_order(order, layout)
            self._reset_layout.setVisible(order != DEFAULT_ORDER or bool(layout))
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
        self._recheck_btn = again
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
        self._recheck_btn = None
        self._views.back()
        QTimer.singleShot(400, lambda: (self._views.removeWidget(page), page.deleteLater())
                          if self._views is not None else None)

    def _recheck_mitigations(self) -> None:
        """Fetch the posture again and re-check this machine's items."""
        if self._recheck_btn is not None:
            self._recheck_btn.setEnabled(False)
        if self._detail is not None:
            self._detail[2].set_subtitle("Checking…")

        def work():
            note = None
            try:
                st, names = posture.fetch(force=True), posture.local_names()
                mine, _ = posture.split_cards(st["cards"], names)
                if mine:
                    mitigations.check(mine, True, force=True)
                self._posture_view = (st, names)
                if st.get("status") == "error":
                    note = st.get("error") or "The Phoenix service is unavailable."
            except Exception as e:  # noqa: BLE001
                logger.warning(f"Dashboard posture re-check failed: {e}")
                note = str(e)
            self.app.after(0, lambda: self._rechecked(note))

        threading.Thread(target=work, daemon=True).start()

    def _rechecked(self, note) -> None:
        try:
            if self._recheck_btn is not None:
                self._recheck_btn.setEnabled(True)
        except RuntimeError:  # page closed meanwhile
            self._recheck_btn = None
        self._fill_posture_detail()
        if note:
            self.app.show_notification(f"Couldn't refresh the posture: {note}", type="warning")
        else:
            self.app.show_notification("Security posture checked.", type="info")

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
        self._posture_cards = (mine, others)
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
            self._add_section(rows, "THIS MACHINE", items, "Nothing to fix on this machine.", mine)
        else:
            header.set_subtitle("No posture for this machine yet.")
            header.set_status("info", "No data for this machine")
        for card in others:
            self._add_section(rows, f"{str(card.get('hostname') or card.get('agent_id')).upper()} · "
                                    f"GRADE {card.get('grade')}",
                              mitigations.cached(card, False), "Nothing to fix.", card)

    def _add_section(self, rows, title: str, items: list, empty: str, card: dict) -> None:
        heading = QLabel(title)
        heading.setObjectName("Section")
        heading.setTextFormat(Qt.TextFormat.PlainText)
        heading.setContentsMargins(0, 16, 0, 4)
        rows.add_row(heading)
        if not items:
            rows.add_row(muted(empty))
            return
        for item, state in items:
            rows.add_row(self._item_row(item, state, card))

    _ITEM_ICON = {"package_update": "package", "cis_checks": "shield-check",
                  "agent_connection": "activity"}

    def _item_pill(self, item: dict, state) -> tuple | None:
        if state == mitigations.REMOTE:
            return None
        kind, label = self._PILLS.get(state, self._PILLS[None])
        if state == mitigations.OPEN and item["severity"] not in ("critical", "high"):
            kind = "warning"
        return kind, label

    def _item_row(self, item: dict, state, card: dict) -> QWidget:
        row = MenuRow(self._ITEM_ICON.get(item["kind"], "info"), item["title"] or item["kind"],
                      mitigations.detail_line(item),
                      on_click=lambda: self._open_mitigation(item, state, card))
        row._title.setTextFormat(Qt.TextFormat.PlainText)
        row._hint.setTextFormat(Qt.TextFormat.PlainText)
        row.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
        pill = self._item_pill(item, state)
        if pill:
            label = QLabel()
            set_pill(label, *pill)
            row.layout().insertWidget(2, label, 0, Qt.AlignmentFlag.AlignVCenter)
        return row

    def _open_mitigation(self, item: dict, state, card: dict) -> None:
        """One posture item: its evidence, how to fix it, and Ask AI."""
        if self._views is None or self._detail is None:
            return
        this_machine = card is self._posture_cards[0]
        host = str(card.get("hostname") or card.get("agent_id") or "")
        page = Page()
        page.add(back_link("Security posture", self._close_mitigation))
        header = PageHeader(item["title"] or item["kind"],
                            ("This machine: " if this_machine else "") + host,
                            status=self._item_pill(item, state))
        header.title.setTextFormat(Qt.TextFormat.PlainText)
        header.wrap_title()
        ask = QPushButton("Ask AI")
        ask.setIcon(QIcon(line_icon("message-circle", "#ffffff", 18)))
        ask.setCursor(Qt.CursorShape.PointingHandCursor)
        ask.setToolTip("Start a chat with Phoenix AI about this item")
        ask.clicked.connect(lambda: self._ask_ai_text(
            mitigations.question(item, host, this_machine)))
        header.add_control(ask)
        page.add(header)
        page.section("Status")
        page.spacing(6)
        page.add(muted(mitigations.state_text(state)))
        facts = self._mitigation_facts(item)
        if facts:
            page.section("Evidence")
            page.add(KVList(facts))
        steps = mitigations.fix_steps(item)
        if steps:
            page.section("How to fix")
            page.spacing(6)
            for step in steps:
                line = muted(step)
                line.setTextFormat(Qt.TextFormat.PlainText)
                line.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
                page.add(line)
        page.stretch()
        self._views.addWidget(page.widget)
        self._mitigation_page = page.widget
        self._views.push(page.widget)

    @staticmethod
    def _mitigation_facts(item: dict) -> list:
        ev, c = item["evidence"], item["check"]
        facts = [("Severity", item["severity"].capitalize())]
        if item["kind"] == "package_update":
            facts.append(("Package", c["package"] + (f" ({c['package_type']})" if c["package_type"] else "")))
            facts.append(("Installed", c["version"]))
            if ev["fixed_version"]:
                facts.append(("Fixed in", ev["fixed_version"]))
            elif ev["fix_available"] is False:
                facts.append(("Fixed in", "No fix released yet"))
            facts.append(("Vulnerabilities", f"{ev['critical']} critical · {ev['high']} high"))
            if ev["cves"]:
                facts.append(("CVEs", ", ".join(ev["cves"])))
        elif item["kind"] == "cis_checks":
            facts.append(("Failed checks", f"{ev['failed_checks']} of {ev['checks']}"))
        return facts

    def _close_mitigation(self) -> None:
        page, self._mitigation_page = self._mitigation_page, None
        if self._views is None or page is None:
            return
        self._views.back(self._detail[0] if self._detail is not None else None)
        QTimer.singleShot(400, lambda: (self._views.removeWidget(page), page.deleteLater())
                          if self._views is not None else None)

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
