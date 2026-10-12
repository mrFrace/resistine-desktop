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

from PyQt6.QtCore import QSize, Qt, QTimer
from PyQt6.QtGui import QIcon, QPixmap
from PyQt6.QtWidgets import (
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
    Page, PageHeader, RowList, SlideStack, back_link, icon_button, muted)
from gui.qt_widgets import CardGrid, StatusBadge, scroll_page, set_pill
from plugins.base_plugin import BasePlugin
from plugins.dashboard import mitigations, posture
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

class _Panel(QFrame):
    """Card with an icon tile, title, status pill and key/value rows."""

    def __init__(self, title: str, icon_path: str, on_open=None):
        super().__init__()
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
        if os.path.isfile(icon_path):
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


class _PanelGrid(CardGrid):
    """CardGrid with wider cells and panels pinned to the top of their row
    (panels differ in height; centred they look misaligned)."""

    _CARD_STEP = 340

    def _relayout(self):
        super()._relayout()
        for card in self._cards:
            self._grid.setAlignment(card, Qt.AlignmentFlag.AlignTop)
        for r in range(self._grid.rowCount()):
            self._grid.setRowStretch(r, 0)


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
                self._show_posture_detail),
            "endpoint": _Panel(
                "Endpoint",
                os.path.join(_PLUGINS_DIR, "wazuh", "add_user_dark.png"),
                lambda: self.app.select_frame_by_name("frame_Endpoint")),
            "ai": _Panel(
                "AI assistant",
                os.path.join(_PLUGINS_DIR, "chat", "chat_dark.png"),
                lambda: self.app.select_frame_by_name("frame_Chat")),
            "system": _Panel(
                "System", os.path.join(_DIR, "home_dark.png")),
        }
        for key, panel in self._panels.items():
            panel.set_data(self._data[key])
        grid = _PanelGrid()
        grid.set_cards(list(self._panels.values()))
        v.addWidget(grid)
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
                st, names = posture.fetch(), posture.local_names()
                mine, _ = posture.split_cards(st["cards"], names)
                states = mitigations.check(mine, True) if mine else []
                data["posture"] = posture.panel_data(
                    st, names, todo=mitigations.summary(states) if states else None)
                data["_posture_view"] = (st, names)
            except Exception as e:  # noqa: BLE001
                logger.warning(f"Dashboard posture probe failed: {e}")
            for key, fn in (("endpoint", _endpoint_info),
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
                panel.set_data(self._data[panel_key])
            except RuntimeError:  # panel deleted by a rebuild
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
