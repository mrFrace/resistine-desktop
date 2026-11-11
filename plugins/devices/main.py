"""Devices plugin (PyQt6): the security posture of every device on the account.

Successor to the removed Wazuh Overview plugin. That page read vulnerability,
inventory and SCA tables from the old company's dashboard API by source IP;
the Phoenix API has none of those endpoints. This page is built on what the
new system provides:

  * posture cards for the signed-in user's agents (plugins/dashboard/posture.py,
    ``GET /v1/me/posture``): grade and score, vulnerability counts by severity,
    compliance checks, alert counts over the last day, recommendations and the
    structured mitigations the Dashboard already verifies locally;
  * the SIEM alerts siem-bot sends over Matrix (plugins/chat/siem_alerts.py);
  * this machine's own agent state, from the Endpoint plugin's cache.

Layout: a header with a device scope selector, the focused device's card,
four stat cards, the to-do list, the week's alerts with a chart, and the
fleet list. Sub-pages (an alert, a mitigation) slide in over the page.
Network and probes run on worker threads; the page always paints at once
from the cached posture and refreshes in place.

Alert bodies and posture text quote monitored systems and the server: they
are rendered as plain text, or through markdown_to_html(allow_html=False)
with links disabled (the Dashboard's _AlertText), never as HTML.
"""

from __future__ import annotations

import os
import threading

from PyQt6.QtCore import Qt
from PyQt6.QtGui import QIcon
from PyQt6.QtWidgets import (
    QComboBox,
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QSizePolicy,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from gui import theme
from gui.page_kit import (
    KVList,
    MenuRow,
    Page,
    PageHeader,
    RowList,
    SlideStack,
    back_link,
    hairline,
    icon_button,
    line_icon,
    muted,
)
from gui.qt_widgets import Card, CardGrid, scroll_page, set_pill
from plugins.base_plugin import BasePlugin
from plugins.dashboard import alerts as recent_alerts
from plugins.dashboard import mitigations, posture
from plugins.devices import data, remote
from plugins.devices.tabs import EventsTab, InventoryTab, VulnerabilitiesTab
from plugins.devices.widgets import DailyBars, GradeBadge, SeverityBar, StatCard
from utils import settings
from utils.i18n import get_text
from utils.logger import logger

_HERE = os.path.dirname(os.path.realpath(__file__))
_WAZUH_DIR = os.path.join(os.path.dirname(_HERE), "wazuh")
_NS = "devices"
_REFRESH_MS = 5 * 60 * 1000  # posture changes daily; fetch() is ETag-cheap
_SEV_PILL = {
    "critical": "critical",
    "high": "error",
    "medium": "warning",
    "unknown": "warning",
    "low": "info",
    "info": "ok",
}
_KIND_ICON = {"triage": "activity", "hunt": "folder-search", "result": "shield-check"}
_MITIGATION_ICON = {
    "package_update": "package",
    "cis_checks": "shield-check",
    "agent_connection": "monitor",
}


def _t(key: str, **fmt) -> str:
    return get_text(f"{_NS}.{key}", **fmt)


def _plain(label: QLabel) -> QLabel:
    label.setTextFormat(Qt.TextFormat.PlainText)
    return label


class _ClickRow(QFrame):
    """A fleet row: hostname and OS on the left, grade pill, score, three
    compact figures, a chevron. Styled as a MenuRow so hover matches."""

    def __init__(self, row: dict, on_click):
        super().__init__()
        self.setObjectName("MenuRow")
        self.setProperty("interactive", True)  # this row IS clickable
        self.setAttribute(Qt.WidgetAttribute.WA_Hover, True)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setFocusPolicy(Qt.FocusPolicy.TabFocus)
        self.setAccessibleName(row["hostname"])
        self._on_click = on_click
        h = QHBoxLayout(self)
        h.setContentsMargins(12, 10, 12, 10)
        h.setSpacing(14)

        text = QVBoxLayout()
        text.setSpacing(1)
        title = _plain(QLabel(row["hostname"]))
        title.setObjectName("RowTitle")
        title.setWordWrap(True)
        text.addWidget(title)
        sub_text = row["os"] or "—"
        if row["this_machine"]:
            sub_text += f"  ·  {_t('this_device')}"
        sub = _plain(QLabel(sub_text))
        sub.setObjectName("Hint")
        sub.setWordWrap(True)
        text.addWidget(sub)
        h.addLayout(text, 1)

        pill = QLabel()
        set_pill(pill, data.grade_kind(row["grade"]), row["grade"])
        h.addWidget(pill, 0, Qt.AlignmentFlag.AlignVCenter)

        v = row["vulns"]
        figures = [
            (f"{row['score']}" if row["score"] is not None else "—", _t("col_score")),
            (f"{v['critical'] + v['high']:,}", _t("col_crit_high")),
            (
                (
                    f"{row['compliance_pct']}%"
                    if row["compliance_pct"] is not None
                    else "—"
                ),
                _t("col_compliance"),
            ),
            (f"{row['alerts_critical'] + row['alerts_high']}", _t("col_alerts")),
        ]
        for value, label in figures:
            col = QVBoxLayout()
            col.setSpacing(0)
            val = _plain(QLabel(value))
            val.setObjectName("RowTitle")
            val.setAlignment(Qt.AlignmentFlag.AlignRight)
            lab = _plain(QLabel(label))
            lab.setObjectName("Hint")
            lab.setAlignment(Qt.AlignmentFlag.AlignRight)
            col.addWidget(val)
            col.addWidget(lab)
            wrap = QWidget()
            wrap.setObjectName("Transparent")
            wrap.setLayout(col)
            wrap.setFixedWidth(88)
            h.addWidget(wrap)
        chev = QLabel()
        chev.setPixmap(line_icon("chevron-right", theme.color("text_secondary"), 18))
        h.addWidget(chev)
        for w in self.findChildren(QLabel):
            w.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)

    def mouseReleaseEvent(self, e):
        if e.button() == Qt.MouseButton.LeftButton and self.rect().contains(e.pos()):
            self._on_click()
        super().mouseReleaseEvent(e)

    def keyPressEvent(self, e):
        if e.key() in (Qt.Key.Key_Return, Qt.Key.Key_Enter, Qt.Key.Key_Space):
            self._on_click()
            return
        super().keyPressEvent(e)


class _Ctx:
    """What a tab (plugins/devices/tabs.py) needs from the plugin."""

    def __init__(self, plugin):
        self._p = plugin
        self.app = plugin.app
        self.store = plugin._store
        self.t = _t

    def rows(self) -> list:
        return self._p._rows(posture.state())

    def scope(self):
        return self._p.scope_host()

    def scoped_rows(self) -> list:
        return data.scope_rows(self.rows(), self._p._scope)

    def alerts(self, hosts) -> list:
        return self._p._parsed_alerts(hosts)


class Plugin(BasePlugin):
    """Security posture, alerts and agents across the account's devices."""

    def __init__(self, app):
        super().__init__(
            id="013",
            version="2026.11.04",
            order=5.5,
            name="Devices",
            status=None,
            description=_t("description"),
            supported_systems=["Darwin", "Linux", "Windows"],
            translations={"US": "Devices", "ES": "Dispositivos", "FR": "Appareils"},
            icon_light_path=os.path.join(_WAZUH_DIR, "wazuh_light.png"),
            icon_dark_path=os.path.join(_WAZUH_DIR, "wazuh_dark.png"),
            uninstall_enabled=True,
        )
        self.app = app
        self._destroyed = False
        self.main_container: SlideStack | None = None
        self._main_page: QWidget | None = None
        self._pages: list = []
        self._scope = str(
            settings.get(_NS, "scope", data.ALL_DEVICES) or data.ALL_DEVICES
        )
        self._scope_changed = False
        self._loading = False
        self._rebuild_pending = False
        self._subscribed = False
        self._poll_armed = False
        self._remote_kicked = False
        self._store = remote.store()
        # Shell: fixed header + tab strip over a stack (overview | tabs).
        self._shell: QWidget | None = None
        self._header: PageHeader | None = None
        self._combo_holder: QWidget | None = None
        self._note: QLabel | None = None
        self._stack: QStackedWidget | None = None
        self._overview: QWidget | None = None
        self._tabs: dict = {}
        self._tab_buttons: dict = {}
        self._active_tab = "overview"

    # ── Status (cheap: cached posture only) ─────────────────────────────

    @staticmethod
    def _local_agent_ids() -> list:
        """The agent id this device enrolled with (plugins/wazuh/agent/enrollment.py)."""
        aid = settings.get("wazuh", "enrolled_agent_id", "")
        return [str(aid)] if aid else []

    def _rows(self, st: dict) -> list:
        return data.fleet_rows(
            st.get("cards") or [],
            posture.local_names(include_agent=False),
            self._local_agent_ids(),
        )

    def check_status(self):
        rows = self._rows(posture.state())
        mine = data.this_machine_row(rows)
        if mine is None:
            return None
        kind = data.grade_kind(mine["grade"])
        return {"ok": "OK", "warning": "Warning"}.get(kind, "Error")

    def on_theme_changed(self):
        if getattr(self, "app", None):
            self.app.update_plugin(self.id)

    # ── Screen ──────────────────────────────────────────────────────────

    def create_main_screen(self):
        self._destroyed = False
        self._pages = []
        self._tabs = {}
        self._tab_buttons = {}
        stack = SlideStack(fit_height=False)
        self._shell = self._build_shell()
        self._main_page = self._shell
        stack.addWidget(self._shell)
        self.main_container = stack
        self._subscribe()
        self._kick_fetch()
        self._arm_poll()
        return stack

    def on_screen_shown(self):
        self._kick_fetch()

    def destroy(self):
        self._destroyed = True
        if self._subscribed:
            try:
                from plugins.chat import siem_alerts

                siem_alerts.unsubscribe(self._alert_arrived)
            except Exception as e:  # noqa: BLE001
                logger.debug(f"[DEVICES] unsubscribe: {e}")
            self._store.unsubscribe(self._remote_changed)
            self._subscribed = False
        if self.main_container is not None:
            try:
                self.main_container.deleteLater()
            except Exception as e:  # noqa: BLE001
                logger.debug(f"[DEVICES] teardown: {e}")
            self.main_container = None

    # ── Data refresh ────────────────────────────────────────────────────

    def _subscribe(self):
        if self._subscribed:
            return
        try:
            from plugins.chat import siem_alerts

            siem_alerts.subscribe(self._alert_arrived)
        except Exception as e:  # noqa: BLE001
            logger.debug(f"[DEVICES] alert subscription unavailable: {e}")
        self._store.subscribe(self._remote_changed)
        self._subscribed = True

    def _alert_arrived(self, _alert: dict) -> None:
        # Called on the Matrix thread; coalesce into one repaint.
        self._schedule_rebuild(400)

    def _remote_changed(self, _slot: str) -> None:
        # Called on a loader thread; coalesce into one repaint.
        self._schedule_rebuild(150)

    def _arm_poll(self):
        if self._poll_armed:
            return
        self._poll_armed = True

        def tick():
            self._poll_armed = False
            if self._destroyed or self.main_container is None:
                return
            self._kick_fetch()
            self._arm_poll()

        try:
            self.app.after(_REFRESH_MS, tick)
        except Exception:  # noqa: BLE001
            self._poll_armed = False

    def _kick_fetch(self, force: bool = False):
        if self._loading or self._destroyed:
            return
        self._loading = True

        def work():
            try:
                st = posture.fetch(force=force)
                rows = data.fleet_rows(
                    st.get("cards") or [],
                    posture.local_names(),
                    self._local_agent_ids(),
                )
                mine_row = data.this_machine_row(rows)
                mine = mine_row["card"] if mine_row else None
                if mine is not None:
                    mitigations.check(mine, True, force=force)
                    posture.record_score(mine)
                # The tabs' datasets, once per screen (and on explicit refresh).
                if force or not self._remote_kicked:
                    self._remote_kicked = True
                    self._store.refresh(
                        [
                            {"agent_id": r["agent_id"], "agent_name": r["hostname"]}
                            for r in rows
                            if r.get("agent_id")
                        ]
                    )
            except Exception as e:  # noqa: BLE001
                logger.warning(f"[DEVICES] refresh failed: {e}")
            finally:
                self._loading = False
            self._schedule_rebuild(0)

        threading.Thread(target=work, daemon=True, name="devices-refresh").start()

    def _refresh(self):
        self._kick_fetch(force=True)

    def _schedule_rebuild(self, delay_ms: int):
        if self._destroyed or self._rebuild_pending:
            return
        self._rebuild_pending = True
        try:
            self.app.after(delay_ms, self._rebuild_main)
        except Exception:  # noqa: BLE001
            self._rebuild_pending = False

    def _rebuild_main(self):
        """Refresh the header, rebuild the Overview, refresh the built tabs."""
        self._rebuild_pending = False
        if self._destroyed or self.main_container is None or self._stack is None:
            return
        scope_changed, self._scope_changed = self._scope_changed, False
        try:
            self._refresh_header()
            self._replace_overview()
            for tab in self._tabs.values():
                if scope_changed:
                    tab.set_scope()
                else:
                    tab.refresh()
        except Exception as e:  # noqa: BLE001
            logger.error(f"[DEVICES] rebuild failed: {e}")
            return
        try:
            new_status = self.check_status()
            if new_status != self.status:
                self.status = new_status
                self.app._refresh_nav_status()  # repaint the sidebar glow
        except Exception as e:  # noqa: BLE001
            logger.debug(f"[DEVICES] status refresh: {e}")

    # ── Sub-pages ───────────────────────────────────────────────────────

    def _push(self, page: QWidget):
        stack = self.main_container
        if stack is None:
            return
        stack.addWidget(page)
        stack.push(page)
        self._pages.append(page)

    def _pop(self):
        stack = self.main_container
        if stack is None or not self._pages:
            return
        top = self._pages.pop()
        target = self._pages[-1] if self._pages else self._main_page
        stack.back(target)

        def drop():
            try:
                stack.removeWidget(top)
                top.deleteLater()
            except RuntimeError:
                pass

        self.app.after(SlideStack.DURATION_MS + 80, drop)

    # ── Main page ───────────────────────────────────────────────────────

    # ---- shell: header, tab strip, stack ---------------------------------------

    _TABS = (
        ("overview", "tab_overview"),
        ("vulns", "tab_vulns"),
        ("events", "tab_events"),
        ("inventory", "tab_inventory"),
    )

    def _build_shell(self) -> QWidget:
        shell = QWidget()
        shell.setObjectName("Transparent")
        v = QVBoxLayout(shell)
        v.setContentsMargins(48, 36, 48, 0)
        v.setSpacing(0)
        self._header = PageHeader(_t("title"), "", ("info", _t("loading_pill")))
        self._header.subtitle.setTextFormat(Qt.TextFormat.PlainText)
        self._combo_holder = QWidget()
        self._combo_holder.setObjectName("Transparent")
        ch = QHBoxLayout(self._combo_holder)
        ch.setContentsMargins(0, 0, 0, 0)
        self._header.add_control(self._combo_holder)
        refresh = icon_button("refresh-cw", _t("refresh"))
        refresh.clicked.connect(self._refresh)
        self._header.add_control(refresh)
        v.addWidget(self._header)
        self._note = _plain(muted(""))
        self._note.hide()
        v.addSpacing(6)
        v.addWidget(self._note)
        v.addSpacing(10)
        v.addWidget(self._tab_strip())
        v.addWidget(hairline())
        self._stack = QStackedWidget()
        self._overview = self._build_overview()
        self._stack.addWidget(self._overview)
        v.addWidget(self._stack, 1)
        self._refresh_header()
        self._style_tabs()
        return shell

    def _tab_strip(self) -> QWidget:
        strip = QWidget()
        strip.setObjectName("Transparent")
        h = QHBoxLayout(strip)
        h.setContentsMargins(0, 0, 0, 0)
        h.setSpacing(24)
        for key, label in self._TABS:
            btn = QPushButton(_t(label))
            btn.setFlat(True)
            btn.setCursor(Qt.CursorShape.PointingHandCursor)
            btn.clicked.connect(lambda _=False, k=key: self._switch_tab(k))
            h.addWidget(btn)
            self._tab_buttons[key] = btn
        h.addStretch(1)
        return strip

    def _style_tabs(self) -> None:
        accent = theme.color("sidebar_active_text")
        for key, btn in self._tab_buttons.items():
            try:
                if key == self._active_tab:
                    btn.setStyleSheet(
                        "QPushButton { background: transparent; border: none; border-radius: 0; "
                        f"color: {accent}; font-size: 14px; font-weight: 700; "
                        f"padding: 9px 2px 7px 2px; border-bottom: 2px solid {accent}; }}"
                    )
                else:
                    btn.setStyleSheet(
                        "QPushButton { background: transparent; border: none; border-radius: 0; "
                        f"color: {theme.color('text_secondary')}; font-size: 14px; "
                        "padding: 9px 2px 9px 2px; }"
                        f"QPushButton:hover {{ color: {theme.color('text_primary')}; }}"
                    )
            except RuntimeError:
                pass

    def _switch_tab(self, key: str) -> None:
        if self._stack is None:
            return
        self._active_tab = key
        self._style_tabs()
        if key == "overview":
            self._stack.setCurrentWidget(self._overview)
            return
        tab = self._tabs.get(key)
        if tab is None:
            cls = {
                "vulns": VulnerabilitiesTab,
                "events": EventsTab,
                "inventory": InventoryTab,
            }[key]
            try:
                tab = cls(_Ctx(self))
            except Exception as e:  # noqa: BLE001
                logger.error(f"[DEVICES] building the {key} tab failed: {e}")
                # Returning here kept the PREVIOUS tab's widget on screen, so
                # a broken tab silently impersonated its neighbour ("the
                # Events page looks identical to Vulnerabilities"). Show an
                # explicit failure panel instead.
                fail = QLabel(_t("tab_failed", error=str(e)))
                fail.setWordWrap(True)
                fail.setAlignment(Qt.AlignmentFlag.AlignCenter)
                fail.setStyleSheet(
                    f"color: {theme.color('text_secondary')}; padding: 40px;")
                page = scroll_page(fail)
                self._stack.addWidget(page)
                self._stack.setCurrentWidget(page)
                return
            tab.page = scroll_page(tab.widget)
            self._tabs[key] = tab
            self._stack.addWidget(tab.page)
        self._stack.setCurrentWidget(tab.page)

    def _refresh_header(self) -> None:
        if self._header is None or self._combo_holder is None or self._note is None:
            return
        st = posture.state()
        rows = self._rows(st)
        if self._scope != data.ALL_DEVICES and not data.scope_rows(rows, self._scope):
            self._scope = data.ALL_DEVICES  # the device is gone from the account
        summary = data.header_summary(
            st.get("status"), rows, st.get("fetched_at"), st.get("error")
        )
        self._header.set_status(*summary["pill"])
        self._header.set_subtitle(summary["subtitle"])
        self._note.setText(summary["note"])
        self._note.setVisible(bool(summary["note"]))
        lay = self._combo_holder.layout()
        while lay.count():
            item = lay.takeAt(0)
            if item.widget() is not None:
                item.widget().deleteLater()
        if rows:
            lay.addWidget(self._scope_combo(rows))

    def _replace_overview(self) -> None:
        if self._stack is None:
            return
        old = self._overview
        new = self._build_overview()
        self._stack.insertWidget(0, new)
        if old is not None:
            if self._stack.currentWidget() is old:
                self._stack.setCurrentWidget(new)
            self._stack.removeWidget(old)
            old.deleteLater()
        self._overview = new

    # ---- overview tab ------------------------------------------------------------

    def _build_overview(self) -> QWidget:
        st = posture.state()
        rows = self._rows(st)
        page = Page()
        # The shell already carries the page's side margins and the header.
        page.widget.widget().layout().setContentsMargins(0, 20, 0, 32)

        if not rows:
            page.add(self._empty_card(st.get("status")))
            page.stretch()
            return page.widget

        scoped = data.scope_rows(rows, self._scope)
        focus = (
            scoped[0] if len(scoped) == 1 else (data.this_machine_row(rows) or rows[0])
        )

        fleet_view = self._scope == data.ALL_DEVICES
        page.add(self._device_card(focus, fleet_view=fleet_view))
        page.spacing(16)
        page.add(self._stat_grid(scoped))

        def _add_fleet():
            page.section(_t("section_fleet"))
            page.add(_plain(muted(_t("fleet_hint"))))
            page.spacing(8)
            fleet = RowList()
            for r in rows:
                fleet.add_row(
                    _ClickRow(r, lambda host=r["hostname"]: self._set_scope(host))
                )
            page.add(fleet)

        # Viewing all devices, the device list IS the point — put it right
        # under the stats ("Show all devices" used to land on a page whose
        # list was below the to-do and alert sections, reading as a no-op).
        if fleet_view and len(rows) > 1:
            _add_fleet()

        page.section(_t("section_todo"))
        page.add(self._todo_list(focus))

        page.section(_t("section_alerts"))
        page.add(self._alerts_block(scoped))

        if not (fleet_view and len(rows) > 1):
            _add_fleet()

        page.spacing(24)
        page.add(_plain(muted(_t("footer"))))
        page.stretch()
        return page.widget

    def _scope_combo(self, rows: list) -> QComboBox:
        combo = QComboBox()
        combo.setMinimumWidth(200)
        combo.addItem(_t("scope_all"), data.ALL_DEVICES)
        for r in rows:
            label = (
                _t("scope_this_device", host=r["hostname"])
                if r["this_machine"]
                else r["hostname"]
            )
            combo.addItem(label, r["hostname"])
        combo.setCurrentIndex(max(combo.findData(self._scope), 0))
        combo.currentIndexChanged.connect(
            lambda i, c=combo: self._set_scope(c.itemData(i) or data.ALL_DEVICES)
        )
        return combo

    def _set_scope(self, scope: str):
        if scope == self._scope:
            return
        self._scope = scope
        self._scope_changed = True
        settings.set(_NS, "scope", scope)
        self._schedule_rebuild(0)

    def scope_host(self) -> str | None:
        """The selected device's hostname, or None for all devices."""
        return None if self._scope == data.ALL_DEVICES else self._scope

    def _empty_card(self, status) -> QWidget:
        card = Card()
        title = _plain(QLabel(_t("empty_title")))
        title.setObjectName("H2")
        card.body.addWidget(title)
        card.body.addWidget(_plain(muted(_t("empty_body"))))
        if status not in ("signed_out",):
            btn = QPushButton(_t("install_agent"))
            btn.setCursor(Qt.CursorShape.PointingHandCursor)
            btn.clicked.connect(lambda: self.app.navigate("Endpoint"))
            row = QHBoxLayout()
            row.addWidget(btn)
            row.addStretch(1)
            card.body.addLayout(row)
        return card

    # ---- focused device card --------------------------------------------------

    def _device_card(self, row: dict, fleet_view: bool) -> QWidget:
        card = Card()
        card.body.setSpacing(10)
        top = QHBoxLayout()
        top.setSpacing(16)
        left = QVBoxLayout()
        left.setSpacing(2)
        label = _plain(
            QLabel(_t("this_device") if row["this_machine"] else _t("selected_device"))
        )
        label.setObjectName("Section")
        left.addWidget(label)
        name = _plain(QLabel(row["hostname"]))
        name.setObjectName("H1")
        name.setWordWrap(True)
        left.addWidget(name)
        meta = [row["os"]] if row["os"] else []
        if row["agent_id"]:
            meta.append(_t("agent_number", id=row["agent_id"]))
        if meta:
            left.addWidget(_plain(muted("  ·  ".join(meta))))
        pill_row = QHBoxLayout()
        pill_row.setSpacing(8)
        agent_pill = QLabel()
        active = row["agent_status"] in ("active", "connected")
        set_pill(
            agent_pill,
            "ok" if active else "error",
            _t("agent_active") if active else _t("agent_inactive"),
        )
        pill_row.addWidget(agent_pill)
        if row["health"]:
            health_pill = QLabel()
            set_pill(
                health_pill,
                data.health_kind(row["health"], row["grade"]),
                row["health"].capitalize(),
            )
            pill_row.addWidget(health_pill)
        pill_row.addStretch(1)
        left.addSpacing(6)
        left.addLayout(pill_row)
        top.addLayout(left, 1)
        top.addWidget(
            GradeBadge(row["grade"], row["score"]), 0, Qt.AlignmentFlag.AlignTop
        )
        card.body.addLayout(top)

        facts = KVList()
        facts.add(_t("updated"), row["updated"])
        if row["this_machine"]:
            local = self._local_agent_text()
            if local:
                facts.add(_t("local_agent"), local)
            enrolled = settings.get("wazuh", "enrolled_agent_id", "")
            if enrolled and row.get("agent_id") and enrolled != row["agent_id"]:
                # Re-registered (dev reinstall, key wipe): the posture card
                # is the OLD agent's. Flag it until the first new scan lands.
                facts.add(
                    _t("reenrolled_label"),
                    _t("reenrolled_stale", old=row["agent_id"], new=enrolled),
                )
        if not row["vulns_available"]:
            facts.add(
                _t("card_vulns"),
                (
                    _t("vulns_not_scanned")
                    if row["vulns_reason"] == "not_covered"
                    else _t("vulns_unavailable")
                ),
            )
        card.body.addWidget(facts)

        if row["this_machine"]:
            trend = posture.trend(posture.history())
            if trend:
                spark = self._sparkline(trend["points"])
                if spark is not None:
                    card.body.addWidget(spark)
                card.body.addWidget(
                    _plain(muted(_t("score_trend", text=trend["text"])))
                )
        actions = QHBoxLayout()
        actions.setSpacing(8)
        if row["this_machine"]:
            open_ep = QPushButton(_t("open_endpoint"))
            open_ep.setCursor(Qt.CursorShape.PointingHandCursor)
            open_ep.clicked.connect(lambda: self.app.navigate("Endpoint"))
            actions.addWidget(open_ep)
        if not fleet_view:
            show_all = QPushButton(_t("show_all_devices"))
            show_all.setObjectName("SurfaceBtn")
            show_all.setCursor(Qt.CursorShape.PointingHandCursor)
            show_all.clicked.connect(lambda: self._set_scope(data.ALL_DEVICES))
            actions.addWidget(show_all)
        actions.addStretch(1)
        if actions.count() > 1:
            card.body.addSpacing(4)
            card.body.addLayout(actions)
        return card

    def _local_agent_text(self) -> str:
        """This machine's agent service state from the Endpoint plugin's cache
        (never a live probe on the UI thread)."""
        ep = next(
            (p for p in getattr(self.app, "plugins", []) if p.get_name() == "Endpoint"),
            None,
        )
        if ep is None:
            return ""
        state = getattr(ep, "_cached_state", None)
        conn = getattr(ep, "_cached_conn", None)
        if not state:
            return ""
        if state == "Running":
            return {
                "connected": _t("local_connected"),
                "disconnected": _t("local_disconnected"),
                "pending": _t("local_pending"),
            }.get(conn or "", _t("local_running"))
        return _t("local_stopped")

    @staticmethod
    def _sparkline(points: list):
        try:
            from plugins.dashboard.main import _Sparkline

            return _Sparkline(points)
        except Exception:  # noqa: BLE001
            return None

    # ---- stat cards -----------------------------------------------------------

    def _stat_grid(self, scoped: list) -> QWidget:
        grid = CardGrid()
        grid._CARD_STEP = 360  # the page column is ~760 px: four cards as 2x2, not 3+1
        vt = data.vuln_totals(scoped)
        ct = data.compliance_totals(scoped)
        at = data.alert_totals(scoped)
        ag = data.agent_totals(scoped)
        n = len(scoped)

        if not vt["scanned"]:
            v_detail = (
                _t("vulns_not_scanned")
                if any(r["vulns_reason"] == "not_covered" for r in scoped)
                else _t("vulns_unavailable")
            )
            v_kind = "info"
        else:
            v_detail = (
                _t("card_vulns_detail", n=n) if n > 1 else _t("card_vulns_detail_one")
            )
            v_kind = (
                "critical"
                if vt["critical"]
                else "error" if vt["high"] else "warning" if vt["medium"] else "ok"
            )
        grid.addWidget(
            StatCard(
                _t("card_vulns"), f"{vt['total']:,}", v_detail, v_kind, SeverityBar(vt)
            )
        )

        if ct["pct"] is None:
            grid.addWidget(
                StatCard(_t("card_compliance"), "—", _t("card_compliance_none"), "info")
            )
        else:
            c_kind = (
                "ok" if ct["pct"] >= 80 else "warning" if ct["pct"] >= 50 else "error"
            )
            grid.addWidget(
                StatCard(
                    _t("card_compliance"),
                    f"{ct['pct']}%",
                    _t(
                        "card_compliance_detail",
                        failed=f"{ct['failed']:,}",
                        checks=f"{ct['checks']:,}",
                    ),
                    c_kind,
                )
            )

        hosts = (
            None if self._scope == data.ALL_DEVICES else [r["hostname"] for r in scoped]
        )
        feed = self._parsed_alerts(hosts)
        a_total = at["critical"] + at["high"]
        a_kind = (
            ("critical" if at["critical"] else "error" if at["high"] else "ok")
            if at["available"]
            else "info"
        )
        grid.addWidget(
            StatCard(
                _t("card_alerts", hours=at["window_h"]),
                f"{a_total}",
                _t(
                    "card_alerts_detail",
                    critical=at["critical"],
                    high=at["high"],
                    feed=len(feed),
                ),
                a_kind,
            )
        )

        missing = ag["total"] - ag["active"]
        grid.addWidget(
            StatCard(
                _t("card_agents"),
                _t("card_agents_value", active=ag["active"], total=ag["total"]),
                (
                    _t("card_agents_detail_ok")
                    if not missing
                    else _t("card_agents_detail_warn", n=missing)
                ),
                "ok" if not missing else "warning",
            )
        )
        return grid

    # ---- to do ----------------------------------------------------------------

    def _todo_list(self, row: dict) -> QWidget:
        states = mitigations.cached(row["card"], row["this_machine"])
        if not states:
            if row["recommendations"]:
                lst = RowList()
                for rec in row["recommendations"]:
                    r = MenuRow("shield-check", rec, "", chevron=False)
                    lst.add_row(r)
                return lst
            return _plain(muted(_t("todo_none")))
        lst = RowList()
        for item, state in states:
            hint = mitigations.detail_line(item)
            status = mitigations.list_status(state)
            sub = "\n".join(s for s in (hint, status) if s)
            lst.add_row(
                MenuRow(
                    _MITIGATION_ICON.get(item["kind"], "shield-check"),
                    item["title"],
                    sub,
                    on_click=lambda it=item, st=state, r=row: self._open_mitigation(
                        it, st, r
                    ),
                )
            )
        return lst

    def _open_mitigation(self, item: dict, state, row: dict):
        page = Page()
        page.add(back_link(_t("title"), self._pop))
        header = PageHeader(
            item["title"],
            row["hostname"],
            (
                _SEV_PILL.get(item["severity"], "warning"),
                str(item["severity"]).capitalize(),
            ),
        )
        header.title.setTextFormat(Qt.TextFormat.PlainText)
        header.title.setWordWrap(True)
        ask = QPushButton(_t("ask_ai"))
        ask.setIcon(QIcon(line_icon("message-circle", theme.color("on_accent"), 18)))
        ask.setCursor(Qt.CursorShape.PointingHandCursor)
        ask.clicked.connect(
            lambda: self._ask_ai_text(
                mitigations.question(item, row["hostname"], row["this_machine"])
            )
        )
        header.add_control(ask)
        page.add(header)
        page.section(_t("section_details"))
        facts = KVList()
        structured = mitigations.detail_facts(item)
        if structured:
            for label, value in structured:
                facts.add(label, value)
        else:
            detail = mitigations.detail_line(item)
            if detail:
                facts.add(_t("mitigation_evidence"), detail)
        facts.add(_t("mitigation_status"), mitigations.state_text(state))
        page.add(facts)
        if item["kind"] == "agent_connection" and row["this_machine"]:
            open_ep = QPushButton(_t("open_endpoint"))
            open_ep.setCursor(Qt.CursorShape.PointingHandCursor)
            open_ep.clicked.connect(lambda: self.app.navigate("Endpoint"))
            page.add(open_ep)
        if item["kind"] == "package_update" and item["check"].get("package"):
            view = QPushButton(_t("view_in_vulns"))
            view.setObjectName("Secondary")
            view.setCursor(Qt.CursorShape.PointingHandCursor)
            view.clicked.connect(
                lambda _=False, pkg=item["check"]["package"]:
                self._jump_to_vulns(pkg))
            page.add(view)
        steps = mitigations.fix_steps(item, row.get("os") or "")
        if steps:
            page.section(_t("mitigation_fix"))
            lst = RowList()
            for i, step in enumerate(steps, 1):
                lst.add_row(self._step_row(i, step))
            page.add(lst)
        page.stretch()
        self._push(page.widget)

    def _jump_to_vulns(self, package: str) -> None:
        """Leave the mitigation page for the Vulnerabilities tab, searched
        to this package, so every one of its CVEs is listed individually."""
        self._pop()
        self._switch_tab("vulns")
        tab = self._tabs.get("vulns")
        if tab is not None:
            try:
                tab._clear_sev()
                tab.search.setText(package)
            except Exception as e:  # noqa: BLE001
                logger.debug(f"[DEVICES] vulns jump failed: {e}")

    @staticmethod
    def _step_row(n: int, text: str) -> QWidget:
        """A numbered, wrapping line; a command gets the terminal icon and a
        selectable monospace label so it can be copied."""
        row = QWidget()
        row.setObjectName("Transparent")
        h = QHBoxLayout(row)
        h.setContentsMargins(4, 10, 4, 10)
        h.setSpacing(14)
        icon = QLabel()
        is_cmd = text.startswith("sudo ")
        icon.setPixmap(
            line_icon(
                "terminal" if is_cmd else "info", theme.color("text_secondary"), 18
            )
        )
        h.addWidget(icon, 0, Qt.AlignmentFlag.AlignTop)
        lbl = _plain(QLabel(f"{n}. {text}"))
        lbl.setObjectName("RowTitle")
        lbl.setWordWrap(True)
        lbl.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        if is_cmd:
            f = lbl.font()
            f.setFamily("Consolas, Menlo, monospace")
            lbl.setFont(f)
        h.addWidget(lbl, 1)
        return row

    # ---- alerts ---------------------------------------------------------------

    def _parsed_alerts(self, hosts) -> list:
        try:
            from plugins.chat import siem_alerts

            return data.scoped_alerts(
                siem_alerts.store().all(), recent_alerts.parse, hosts
            )
        except Exception as e:  # noqa: BLE001
            logger.debug(f"[DEVICES] alerts unavailable: {e}")
            return []

    def _alerts_block(self, scoped: list) -> QWidget:
        hosts = (
            None if self._scope == data.ALL_DEVICES else [r["hostname"] for r in scoped]
        )
        parsed = self._parsed_alerts(hosts)
        box = QWidget()
        box.setObjectName("Transparent")
        lay = QVBoxLayout(box)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(10)
        if not parsed:
            scope = _t("scope_all_lower") if hosts is None else scoped[0]["hostname"]
            lay.addWidget(_plain(muted(_t("alerts_none", scope=scope))))
            return box
        chart_card = Card()
        chart_card.body.addWidget(DailyBars(data.alerts_by_day(parsed)))
        counts = data.severity_counts(parsed)
        chart_card.body.addWidget(
            _plain(
                muted(
                    _t(
                        "alerts_counts",
                        total=len(parsed),
                        critical=counts["critical"],
                        high=counts["high"],
                        medium=counts["medium"],
                        low=counts["low"],
                    )
                )
            )
        )
        lay.addWidget(chart_card)
        lst = RowList()
        for a in data.recent_alert_rows(parsed):
            hint = _t(
                "alert_row_hint",
                severity=a["severity"].capitalize(),
                host=a["host"] or "—",
                ago=recent_alerts.ago(a["ts"]),
            )
            lst.add_row(
                MenuRow(
                    _KIND_ICON.get(a["kind"], "activity"),
                    a["title"],
                    hint,
                    on_click=lambda eid=a["event_id"]: self._open_alert(eid),
                )
            )
        lay.addWidget(lst)
        return box

    def _open_alert(self, event_id: str):
        try:
            from plugins.chat import siem_alerts

            alert = next(
                (a for a in siem_alerts.store().all() if a.get("event_id") == event_id),
                None,
            )
        except Exception:  # noqa: BLE001
            alert = None
        if alert is None:
            return
        body = alert.get("body", "")
        info = recent_alerts.parse(body)
        page = Page()
        page.add(back_link(_t("title"), self._pop))
        if info["kind"] == "result" and info["verdict"]:
            v = info["verdict"].lower()
            pill = (
                ("ok" if "false" in v else "error" if "true" in v else "warning"),
                info["verdict"],
            )
        else:
            pill = (
                _SEV_PILL.get(info["severity"], "warning"),
                info["severity"].capitalize(),
            )
        header = PageHeader(
            info["title"], recent_alerts.subtitle(info, alert.get("ts")), pill
        )
        header.title.setTextFormat(Qt.TextFormat.PlainText)
        header.title.setWordWrap(True)
        header.subtitle.setTextFormat(Qt.TextFormat.PlainText)
        ask = QPushButton(_t("ask_ai"))
        ask.setIcon(QIcon(line_icon("message-circle", theme.color("on_accent"), 18)))
        ask.setCursor(Qt.CursorShape.PointingHandCursor)
        ask.clicked.connect(
            lambda: self._start_chat(
                lambda chat: chat.ask_about_alert(body, alert.get("ts"))
            )
        )
        header.add_control(ask)
        page.add(header)
        if info["findings"]:
            page.section(_t("section_findings"))
            lst = RowList()
            for f in info["findings"]:
                row = QWidget()
                row.setObjectName("Transparent")
                h = QHBoxLayout(row)
                h.setContentsMargins(4, 8, 4, 8)
                name = _plain(QLabel(f["name"]))
                name.setObjectName("RowTitle")
                name.setWordWrap(True)
                h.addWidget(name, 1)
                p = QLabel()
                set_pill(
                    p,
                    _SEV_PILL.get(f["severity"], "warning"),
                    str(f["severity"]).capitalize(),
                )
                h.addWidget(p, 0, Qt.AlignmentFlag.AlignVCenter)
                lst.add_row(row)
            page.add(lst)
        page.section(_t("section_details"))
        page.spacing(6)
        page.add(self._alert_text(recent_alerts.detail_text(body) or body))
        page.stretch()
        self._push(page.widget)

    @staticmethod
    def _alert_text(text: str) -> QWidget:
        """The alert body as rich text with HTML escaped and links disabled
        (the Dashboard's widget); plain text if that widget is unavailable."""
        try:
            from plugins.dashboard.main import _AlertText

            return _AlertText(text)
        except Exception:  # noqa: BLE001
            lbl = _plain(QLabel(text))
            lbl.setWordWrap(True)
            lbl.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            lbl.setSizePolicy(
                QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred
            )
            return lbl

    # ---- chat hand-off ----------------------------------------------------------

    def _ask_ai_text(self, text: str):
        self._start_chat(lambda chat: chat.ask(text))

    def _start_chat(self, send):
        chat = next(
            (p for p in getattr(self.app, "plugins", []) if p.get_name() == "Chat"),
            None,
        )
        if chat is None or getattr(chat, "client", None) is None:
            self.app.show_notification(_t("ai_not_setup"), type="warning")
            return
        self.app.select_frame_by_name("frame_Chat")

        def go():
            try:
                if not send(chat):
                    self.app.show_notification(_t("chat_not_ready"), type="warning")
            except Exception as e:  # noqa: BLE001
                logger.warning(f"[DEVICES] chat hand-off failed: {e}")

        self.app.after(150, go)
