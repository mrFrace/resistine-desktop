"""Devices page: the Vulnerabilities, Events and Inventory tabs.

Each tab is a QWidget built once and refreshed in place as data lands, so
search text, severity selection, selected row and page survive a refresh.
A tab reads everything through its ``ctx`` (see main.py): the posture
rows, the device scope, the remote store and the SIEM alert feed, and
``ctx.t`` for strings.

The data for these tabs comes from the Phoenix server
(dev-docs/plans/devices-data-contract.md). While an endpoint is not
available the tab says so in a banner and shows what the new system does
provide: the posture scan's CVEs, the SIEM alert feed, the posture devices.
"""

from __future__ import annotations

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QComboBox,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QProgressBar,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

from gui import theme
from gui.qt_widgets import Card, ResponsiveStack, set_pill
from plugins.devices import api, tables
from plugins.devices.charts import Donut, Pager, SeverityPills, StackedBars
from plugins.devices.tables import SEVERITIES

_SEV_PILL = {
    "critical": "critical",
    "high": "error",
    "medium": "warning",
    "low": "info",
}


def _plain(lbl: QLabel) -> QLabel:
    lbl.setTextFormat(Qt.TextFormat.PlainText)
    return lbl


def _label(text, *, hint=False, bold=False, wrap=False, size=None) -> QLabel:
    lbl = _plain(QLabel(str(text)))
    lbl.setObjectName("Hint" if hint else "RowTitle" if bold else "Val")
    lbl.setWordWrap(wrap)
    if size:
        f = lbl.font()
        f.setPointSize(size)
        lbl.setFont(f)
    return lbl


def _fixed(lbl: QLabel, width: int) -> QLabel:
    lbl.setFixedWidth(width)
    lbl.setToolTip(lbl.text())
    from PyQt6.QtGui import QFontMetrics

    lbl.setText(
        QFontMetrics(lbl.font()).elidedText(
            lbl.text(), Qt.TextElideMode.ElideRight, width - 4
        )
    )
    return lbl


def _clear(layout) -> None:
    while layout.count():
        item = layout.takeAt(0)
        w = item.widget()
        if w is not None:
            w.setParent(None)
            w.deleteLater()
        elif item.layout() is not None:
            _clear(item.layout())


def _rows_scroll() -> tuple:
    area = QScrollArea()
    area.setWidgetResizable(True)
    area.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
    area.setFrameShape(QFrame.Shape.NoFrame)
    host = QWidget()
    host.setObjectName("Transparent")
    lay = QVBoxLayout(host)
    lay.setContentsMargins(2, 2, 2, 2)
    lay.setSpacing(2)
    lay.addStretch(1)
    area.setWidget(host)
    return area, lay


def _clear_rows(lay) -> None:
    while lay.count() > 1:
        item = lay.takeAt(0)
        w = item.widget()
        if w is not None:
            w.setParent(None)
            w.deleteLater()


class _ClickRow(QFrame):
    def __init__(self, on_click, selectable: bool = True):
        super().__init__()
        self.setObjectName("ListRow")
        self._on_click = on_click
        self._selected = False
        if on_click:
            self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.set_selected(False)

    def set_selected(self, selected: bool) -> None:
        self._selected = selected
        bg = theme.color("sidebar_active_bg") if selected else "transparent"
        self.setStyleSheet(
            f"QFrame#ListRow {{ background: {bg}; border-radius: 8px; }}"
            + (
                ""
                if selected
                else f"QFrame#ListRow:hover {{ background: {theme.color('sidebar_hover_bg')}; }}"
            )
        )

    def mouseReleaseEvent(self, e):
        if self._on_click and e.button() == Qt.MouseButton.LeftButton:
            self._on_click()
        super().mouseReleaseEvent(e)


class _Banner(QWidget):
    """One line above a tab: loading bar, an 'endpoint not available' note,
    or an error. Hidden when there is nothing to say."""

    def __init__(self):
        super().__init__()
        self.setObjectName("Transparent")
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(4)
        self._text = _label("", hint=True, wrap=True)
        self._bar = QProgressBar()
        self._bar.setRange(0, 0)
        self._bar.setFixedHeight(4)
        self._bar.setTextVisible(False)
        lay.addWidget(self._text)
        lay.addWidget(self._bar)
        self.hide()

    def show_text(self, text: str, loading: bool = False) -> None:
        self._text.setText(text)
        self._text.setVisible(bool(text))
        self._bar.setVisible(loading)
        self.setVisible(bool(text) or loading)


# ==========================================================================
# Vulnerabilities
# ==========================================================================


class VulnerabilitiesTab:
    def __init__(self, ctx):
        self.ctx = ctx
        self.t = ctx.t
        self._sev = None
        self._page = 1
        self._selected = None
        self._search_token = None
        self.widget = QWidget()
        self.widget.setObjectName("Transparent")
        col = QVBoxLayout(self.widget)
        col.setContentsMargins(0, 12, 0, 0)
        col.setSpacing(12)
        self.banner = _Banner()
        col.addWidget(self.banner)

        # charts row
        donut_card = Card()
        donut_card.body.addWidget(_label(self.t("vuln_breakdown"), hint=True))
        body = QHBoxLayout()
        self.donut = Donut({}, on_toggle=self._toggle_sev)
        body.addWidget(self.donut, 1)
        self._legend_holder = QVBoxLayout()
        body.addLayout(self._legend_holder)
        donut_card.body.addLayout(body, 1)
        timeline_card = Card()
        timeline_card.body.addWidget(_label(self.t("vuln_timeline"), hint=True))
        self.timeline = StackedBars(
            [],
            {},
            {},
            on_severity=self._toggle_sev,
            empty_text=self.t("vuln_timeline_empty"),
        )
        timeline_card.body.addWidget(self.timeline, 1)
        col.addWidget(ResponsiveStack(donut_card, timeline_card, stretches=(2, 3)))

        # search header
        head = QHBoxLayout()
        head.addWidget(_label(self.t("vuln_table_title"), hint=True))
        self.search = QLineEdit()
        self.search.setPlaceholderText(self.t("vuln_search"))
        self.search.setClearButtonEnabled(True)
        self.search.textChanged.connect(self._search_changed)
        head.addWidget(self.search, 1)
        # Visible marker for an active severity filter (set by clicking a
        # donut slice / legend / timeline segment). Without it, a selected
        # severity with zero matches reads as "the page is broken".
        from PyQt6.QtWidgets import QPushButton
        from PyQt6.QtGui import QCursor
        self.filter_chip = QPushButton()
        self.filter_chip.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.filter_chip.setStyleSheet(
            "QPushButton { border: 1px solid rgba(96,165,250,0.55);"
            " border-radius: 10px; padding: 2px 10px; font-size: 11px;"
            " color: #93C5FD; background: rgba(59,130,246,0.12); }"
            "QPushButton:hover { background: rgba(59,130,246,0.25); }")
        self.filter_chip.clicked.connect(self._clear_sev)
        self.filter_chip.hide()
        head.addWidget(self.filter_chip)
        self.count = _label("", hint=True)
        head.addWidget(self.count)
        col.addLayout(head)

        # list + detail
        list_card = Card()
        list_card.body.setSpacing(4)
        cols = QHBoxLayout()
        cols.setContentsMargins(6, 0, 6, 0)
        for text, w in (
            (self.t("col_sev"), 64),
            (self.t("col_cve"), 180),
            (self.t("col_package"), 0),
        ):
            lbl = _label(text, hint=True)
            if w:
                lbl.setFixedWidth(w)
                cols.addWidget(lbl)
            else:
                cols.addWidget(lbl, 1)
        list_card.body.addLayout(cols)
        self.scroll, self.rows = _rows_scroll()
        self.scroll.setMinimumHeight(260)
        list_card.body.addWidget(self.scroll, 1)
        self.pager = Pager()
        list_card.body.addWidget(self.pager)
        self.detail = Card()
        self.detail.setSizePolicy(
            QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Expanding
        )
        col.addWidget(ResponsiveStack(list_card, self.detail, stretches=(3, 2)), 1)
        self._row_frames: dict = {}
        self.refresh()

    # ---- data -----------------------------------------------------------------
    def _vulns(self) -> list:
        """API CVEs when loaded; otherwise the posture scan's CVEs."""
        slot = self.ctx.store.slot("vulns")
        if slot.ready and not slot.error and slot.data:
            vulns = slot.data
        else:
            vulns = tables.posture_cves([r["card"] for r in self.ctx.rows()])
        return tables.scope_records(vulns, "agent_name", self.ctx.scope())

    def _counts(self) -> dict:
        """Severity totals: the posture card's full counts when the API has
        not delivered the list (the scan's CVE list is partial)."""
        slot = self.ctx.store.slot("vulns")
        if slot.ready and not slot.error and slot.data:
            return tables.bucket_by_severity(self._vulns())
        rows = self.ctx.scoped_rows()
        totals = {s: sum(r["vulns"][s] for r in rows) for s in SEVERITIES}
        return totals

    def _banner_text(self) -> tuple:
        slot = self.ctx.store.slot("vulns")
        if not slot.ready:
            return self.t("loading_vulns"), True
        if slot.unavailable:
            n = len(self._vulns())
            return self.t("vulns_partial", n=n), False
        if slot.error:
            return self.t("vulns_error", error=slot.error), False
        return "", False

    # ---- refresh --------------------------------------------------------------
    def set_scope(self) -> None:
        self._page = 1
        self.refresh()

    def refresh(self) -> None:
        text, loading = self._banner_text()
        self.banner.show_text(text, loading)
        counts = self._counts()
        self.donut.set_counts(counts)
        self.donut.set_selected(self._sev)
        _clear(self._legend_holder)
        self._legend_holder.addStretch(1)
        for s in SEVERITIES:
            from plugins.devices.widgets import severity_color

            row = QHBoxLayout()
            dot = QLabel("●")
            dot.setStyleSheet(f"color: {severity_color(s).name()};")
            row.addWidget(dot)
            row.addWidget(_label(s.capitalize()))
            row.addStretch(1)
            n = _label(f"{counts.get(s, 0):,}", bold=True)
            n.setStyleSheet(f"color: {severity_color(s).name()};")
            row.addWidget(n)
            self._legend_holder.addLayout(row)
        self._legend_holder.addStretch(1)
        dates, by_day = tables.bucket_vulns_daily(self._vulns())
        labels = {
            d: d.strftime("%b %d")
            for i, d in enumerate(dates)
            if i % 5 == 4 or i == len(dates) - 1
        }
        self.timeline.set_data(dates, by_day, labels)
        self.timeline.set_selected_severity(self._sev)
        self._render_list()

    def _toggle_sev(self, sev: str) -> None:
        self._sev = None if self._sev == sev else sev
        self._page = 1
        self.donut.set_selected(self._sev)
        self.timeline.set_selected_severity(self._sev)
        self._render_list()

    def _clear_sev(self) -> None:
        if self._sev is not None:
            self._toggle_sev(self._sev)

    def _search_changed(self, _text) -> None:
        if self._search_token is not None:
            self.ctx.app.after_cancel(self._search_token)
        self._search_token = self.ctx.app.after(150, self._apply_search)

    def _apply_search(self) -> None:
        self._search_token = None
        self._page = 1
        self._render_list()

    def _render_list(self) -> None:
        vulns = tables.filter_vulns(self._vulns(), self.search.text(), self._sev)
        total = len(self._vulns())
        self.count.setText(
            self.t("vulns_count", shown=len(vulns))
            if len(vulns) == total
            else self.t("vulns_count_of", shown=len(vulns), total=total)
        )
        if self._sev:
            self.filter_chip.setText(
                self.t("vulns_filter_chip", sev=self._sev.capitalize()))
            self.filter_chip.show()
        else:
            self.filter_chip.hide()
        page_items, self._page, pages = tables.page_slice(
            vulns, self._page, tables.PAGE_SIZE
        )
        self.pager.set_state(self._page, pages, self._set_page)
        _clear_rows(self.rows)
        self._row_frames = {}
        keys = {tables.vuln_key(v) for v in vulns}
        if self._selected not in keys:
            self._selected = tables.vuln_key(vulns[0]) if vulns else None
        for v in page_items:
            self._add_row(v)
        if not vulns:
            if self._sev and not self.search.text().strip():
                msg = self.t("vulns_none_filtered",
                             sev=self._sev.capitalize(), total=total)
            else:
                msg = self.t("vulns_none")
            empty = _label(msg, hint=True, wrap=True)
            empty.setAlignment(Qt.AlignmentFlag.AlignCenter)
            self.rows.insertWidget(self.rows.count() - 1, empty)
        self._render_detail(
            next((v for v in vulns if tables.vuln_key(v) == self._selected), None)
        )

    def _set_page(self, page: int) -> None:
        self._page = page
        self._render_list()

    def _add_row(self, v: dict) -> None:
        key = tables.vuln_key(v)
        row = _ClickRow(lambda k=key: self._select(k))
        row.set_selected(key == self._selected)
        h = QHBoxLayout(row)
        h.setContentsMargins(6, 6, 6, 6)
        h.setSpacing(0)
        sev = (v.get("severity") or "low").lower()
        pill = QLabel()
        set_pill(
            pill,
            _SEV_PILL.get(sev, "info"),
            tables.SEVERITY_SHORT.get(sev, sev.upper()),
        )
        cell = QWidget()
        cell.setObjectName("Transparent")
        cell.setFixedWidth(64)
        ch = QHBoxLayout(cell)
        ch.setContentsMargins(0, 0, 0, 0)
        ch.addWidget(pill)
        ch.addStretch(1)
        h.addWidget(cell)
        cve = QWidget()
        cve.setObjectName("Transparent")
        cve.setFixedWidth(180)
        cv = QVBoxLayout(cve)
        cv.setContentsMargins(0, 0, 0, 0)
        cv.setSpacing(0)
        cv.addWidget(_label(v.get("id") or "—", bold=True))
        sub = (
            self.t("modified_ago", ago=tables.format_relative(v.get("modified_date")))
            if v.get("modified_date")
            else self.t("from_posture_scan") if v.get("source") == "posture" else ""
        )
        cv.addWidget(_label(sub, hint=True))
        h.addWidget(cve)
        pkg = QWidget()
        pkg.setObjectName("Transparent")
        pv = QVBoxLayout(pkg)
        pv.setContentsMargins(0, 0, 0, 0)
        pv.setSpacing(0)
        pv.addWidget(_label(v.get("package_name") or "—", bold=True))
        pv.addWidget(_label(v.get("package_version") or "", hint=True))
        h.addWidget(pkg, 1)
        for w in row.findChildren(QLabel):
            w.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)
        self.rows.insertWidget(self.rows.count() - 1, row)
        self._row_frames[key] = row

    def _select(self, key: str) -> None:
        if key == self._selected:
            return
        self._selected = key
        for k, frame in self._row_frames.items():
            try:
                frame.set_selected(k == key)
            except RuntimeError:
                pass
        self._render_detail(
            next((v for v in self._vulns() if tables.vuln_key(v) == key), None)
        )

    def _render_detail(self, v: dict | None) -> None:
        _clear(self.detail.body)
        if v is None:
            self.detail.body.addStretch(1)
            lbl = _label(self.t("vuln_select"), hint=True)
            lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
            self.detail.body.addWidget(lbl)
            self.detail.body.addStretch(1)
            return
        sev = (v.get("severity") or "low").lower()
        head = QHBoxLayout()
        pill = QLabel()
        set_pill(
            pill,
            _SEV_PILL.get(sev, "info"),
            tables.SEVERITY_SHORT.get(sev, sev.upper()),
        )
        head.addWidget(pill)
        head.addWidget(_label(v.get("id") or "—", hint=True))
        head.addStretch(1)
        if v.get("modified_date"):
            head.addWidget(
                _label(tables.format_relative(v.get("modified_date")), hint=True)
            )
        self.detail.body.addLayout(head)
        pkg = f"{v.get('package_name') or ''} {v.get('package_version') or ''}".strip()
        title = _label(pkg or v.get("id") or "—", bold=True, wrap=True, size=15)
        self.detail.body.addWidget(title)
        grid = QGridLayout()
        grid.setHorizontalSpacing(12)
        grid.setVerticalSpacing(4)
        rows = []
        if v.get("cvss_score") is not None:
            rows.append((self.t("cvss"), f"{float(v['cvss_score']):.1f}"))
        if v.get("epss") is not None:
            rows.append((self.t("epss"), f"{float(v['epss']) * 100:.0f}%"))
        if v.get("status"):
            rows.append((self.t("status"), str(v["status"]).capitalize()))
        if v.get("agent_name"):
            rows.append((self.t("device"), v["agent_name"]))
        for label, key in (
            (self.t("first_detected"), "first_detected_at"),
            (self.t("published"), "published_date"),
            (self.t("last_modified"), "modified_date"),
        ):
            if v.get(key):
                rows.append((label, tables.format_timestamp(v[key])))
        for r, (k, val) in enumerate(rows):
            grid.addWidget(_label(k, hint=True), r, 0, Qt.AlignmentFlag.AlignTop)
            grid.addWidget(_label(val, wrap=True), r, 1)
        grid.setColumnStretch(1, 1)
        self.detail.body.addLayout(grid)
        self.detail.body.addWidget(_label(self.t("description_label"), hint=True))
        box = QPlainTextEdit()
        box.setPlainText(v.get("description") or self.t("no_description"))
        box.setReadOnly(True)
        box.setMinimumHeight(80)
        self.detail.body.addWidget(box, 1)


# ==========================================================================
# Events
# ==========================================================================


class EventsTab:
    def __init__(self, ctx):
        self.ctx = ctx
        self.t = ctx.t
        self._sev = None
        self._bucket = None
        self._page = 1
        self._selected = None
        self._search_token = None
        self._row_frames: dict = {}
        self.widget = QWidget()
        self.widget.setObjectName("Transparent")
        col = QVBoxLayout(self.widget)
        col.setContentsMargins(0, 12, 0, 0)
        col.setSpacing(12)
        self.banner = _Banner()
        col.addWidget(self.banner)
        self.pills = SeverityPills({}, on_toggle=self._toggle_sev)
        col.addWidget(self.pills)
        chart_card = Card()
        chart_card.body.addWidget(_label(self.t("events_chart"), hint=True))
        self.chart = StackedBars(
            [],
            {},
            {},
            on_bucket=self._toggle_bucket,
            empty_text=self.t("events_chart_empty"),
        )
        self.chart.setMinimumHeight(150)
        self.chart.setMaximumHeight(190)
        chart_card.body.addWidget(self.chart)
        col.addWidget(chart_card)
        head = QHBoxLayout()
        head.addWidget(_label(self.t("event_search_title"), hint=True))
        self.search = QLineEdit()
        self.search.setPlaceholderText(self.t("event_search"))
        self.search.setClearButtonEnabled(True)
        self.search.textChanged.connect(self._search_changed)
        head.addWidget(self.search, 1)
        # Visible marker for an active severity filter (set by clicking a
        # donut slice / legend / timeline segment). Without it, a selected
        # severity with zero matches reads as "the page is broken".
        from PyQt6.QtWidgets import QPushButton
        from PyQt6.QtGui import QCursor
        self.filter_chip = QPushButton()
        self.filter_chip.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.filter_chip.setStyleSheet(
            "QPushButton { border: 1px solid rgba(96,165,250,0.55);"
            " border-radius: 10px; padding: 2px 10px; font-size: 11px;"
            " color: #93C5FD; background: rgba(59,130,246,0.12); }"
            "QPushButton:hover { background: rgba(59,130,246,0.25); }")
        self.filter_chip.clicked.connect(self._clear_sev)
        self.filter_chip.hide()
        head.addWidget(self.filter_chip)
        self.count = _label("", hint=True)
        head.addWidget(self.count)
        col.addLayout(head)
        list_card = Card()
        list_card.body.setSpacing(4)
        cols = QHBoxLayout()
        cols.setContentsMargins(6, 0, 6, 0)
        for text, w, stretch in (
            ("", 14, 0),
            (self.t("col_rule"), 76, 0),
            ("", 0, 1),
            (self.t("col_metric"), 100, 0),
            (self.t("col_when"), 110, 0),
        ):
            lbl = _label(text, hint=True)
            if w:
                lbl.setFixedWidth(w)
            cols.addWidget(lbl, stretch)
        list_card.body.addLayout(cols)
        self.scroll, self.rows = _rows_scroll()
        self.scroll.setMinimumHeight(240)
        list_card.body.addWidget(self.scroll, 1)
        self.pager = Pager()
        list_card.body.addWidget(self.pager)
        self.detail = Card()
        self.detail.setSizePolicy(
            QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Expanding
        )
        col.addWidget(ResponsiveStack(list_card, self.detail, stretches=(3, 2)), 1)
        self.refresh()

    def _events(self) -> list:
        """Detection events from the API (when available) plus the SIEM alert
        feed, scoped to the selected device, newest first."""
        slot = self.ctx.store.slot("events")
        events = list(slot.data) if slot.ready and not slot.error and slot.data else []
        hosts = None if self.ctx.scope() is None else [self.ctx.scope()]
        events += tables.alerts_as_events(self.ctx.alerts(hosts))
        events = (
            tables.scope_records(events, "agent", self.ctx.scope())
            if self.ctx.scope()
            else events
        )
        events.sort(key=lambda e: e.get("timestamp") or "", reverse=True)
        return events

    def _banner_text(self) -> tuple:
        slot = self.ctx.store.slot("events")
        if not slot.ready:
            return self.t("loading_events"), True
        if slot.unavailable:
            return self.t("events_partial"), False
        if slot.error:
            return self.t("events_error", error=slot.error), False
        return "", False

    def set_scope(self) -> None:
        self._page = 1
        self._bucket = None
        self.refresh()

    def refresh(self) -> None:
        text, loading = self._banner_text()
        self.banner.show_text(text, loading)
        events = self._events()
        counts = tables.bucket_by_severity(events)
        if self._sev and counts.get(self._sev, 0) <= 0:
            self._sev = None
        self.pills.set_counts(counts)
        self.pills.set_selected(self._sev)
        buckets, by_hour = tables.bucket_events_hourly(events)
        labels = {
            b: b.astimezone().strftime("%H:%M")
            for i, b in enumerate(buckets)
            if i % 3 == 0
        }
        self.chart.set_data(buckets, by_hour, labels)
        if self._bucket is not None and self._bucket not in buckets:
            self._bucket = None
        self.chart.set_selected_bucket(self._bucket)
        self.chart.set_selected_severity(self._sev)
        self._render_list()

    def _toggle_sev(self, sev: str) -> None:
        self._sev = None if self._sev == sev else sev
        self._page = 1
        self.pills.set_selected(self._sev)
        self.chart.set_selected_severity(self._sev)
        self._render_list()

    def _toggle_bucket(self, key) -> None:
        self._bucket = None if self._bucket == key else key
        self._page = 1
        self.chart.set_selected_bucket(self._bucket)
        self._render_list()

    def _search_changed(self, _text) -> None:
        if self._search_token is not None:
            self.ctx.app.after_cancel(self._search_token)
        self._search_token = self.ctx.app.after(150, self._apply_search)

    def _apply_search(self) -> None:
        self._search_token = None
        self._page = 1
        self._render_list()

    def _render_list(self) -> None:
        all_events = self._events()
        events = tables.filter_events(
            all_events, self.search.text(), self._sev, self._bucket
        )
        text = (
            self.t("events_count", shown=len(events))
            if len(events) == len(all_events)
            else self.t("events_count_of", shown=len(events), total=len(all_events))
        )
        if self._bucket is not None:
            from datetime import timedelta

            start = self._bucket.astimezone()
            text += f" · {start.strftime('%H:%M')}–{(start + timedelta(hours=1)).strftime('%H:%M')}"
        self.count.setText(text)
        page_items, self._page, pages = tables.page_slice(
            events, self._page, tables.PAGE_SIZE
        )
        self.pager.set_state(self._page, pages, self._set_page)
        _clear_rows(self.rows)
        self._row_frames = {}
        ids = {e["id"] for e in events}
        if self._selected not in ids:
            self._selected = events[0]["id"] if events else None
        for ev in page_items:
            self._add_row(ev)
        if not events:
            empty = _label(self.t("events_none"), hint=True, wrap=True)
            empty.setAlignment(Qt.AlignmentFlag.AlignCenter)
            self.rows.insertWidget(self.rows.count() - 1, empty)
        self._render_detail(
            next((e for e in events if e["id"] == self._selected), None)
        )

    def _set_page(self, page: int) -> None:
        self._page = page
        self._render_list()

    def _add_row(self, ev: dict) -> None:
        from plugins.devices.widgets import severity_color

        row = _ClickRow(lambda eid=ev["id"]: self._select(eid))
        row.set_selected(ev["id"] == self._selected)
        h = QHBoxLayout(row)
        h.setContentsMargins(6, 8, 6, 8)
        h.setSpacing(0)
        dot = QLabel("●")
        dot.setFixedWidth(14)
        dot.setStyleSheet(
            f"color: {severity_color(ev.get('severity') or 'low').name()};"
        )
        h.addWidget(dot)
        rule = _label(ev.get("rule_id") or "—", bold=True)
        rule.setFixedWidth(76)
        h.addWidget(rule)
        desc = _label(ev.get("description") or "—")
        desc.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Preferred)
        h.addWidget(desc, 1)
        metric = _label(
            (ev.get("mitre") or [None])[0] or ev.get("ip") or ev.get("agent") or "—",
            hint=True,
        )
        metric.setFixedWidth(100)
        h.addWidget(metric)
        when = _label(tables.format_timestamp(ev.get("timestamp")), hint=True)
        when.setFixedWidth(110)
        h.addWidget(when)
        for w in row.findChildren(QLabel):
            w.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)
        self.rows.insertWidget(self.rows.count() - 1, row)
        self._row_frames[ev["id"]] = row

    def _select(self, eid: str) -> None:
        if eid == self._selected:
            return
        self._selected = eid
        for k, frame in self._row_frames.items():
            try:
                frame.set_selected(k == eid)
            except RuntimeError:
                pass
        self._render_detail(next((e for e in self._events() if e["id"] == eid), None))

    def _render_detail(self, ev: dict | None) -> None:
        _clear(self.detail.body)
        if ev is None:
            self.detail.body.addStretch(1)
            lbl = _label(self.t("event_select"), hint=True)
            lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
            self.detail.body.addWidget(lbl)
            self.detail.body.addStretch(1)
            return
        sev = (ev.get("severity") or "low").lower()
        head = QHBoxLayout()
        pill = QLabel()
        set_pill(pill, _SEV_PILL.get(sev, "info"), sev.upper())
        head.addWidget(pill)
        head.addWidget(
            _label(self.t("rule_n", rule=ev.get("rule_id") or "—"), hint=True)
        )
        head.addStretch(1)
        head.addWidget(_label(tables.format_relative(ev.get("timestamp")), hint=True))
        self.detail.body.addLayout(head)
        self.detail.body.addWidget(
            _label(ev.get("description") or "—", bold=True, wrap=True, size=15)
        )
        grid = QGridLayout()
        grid.setHorizontalSpacing(12)
        grid.setVerticalSpacing(4)
        rows = [
            (self.t("agent"), ev.get("agent") or "—"),
            (self.t("host"), ev.get("host") or "—"),
        ]
        if ev.get("ip"):
            rows.append((self.t("ip"), ev["ip"]))
        if ev.get("mitre"):
            rows.append((self.t("mitre"), ", ".join(ev["mitre"])))
        rows.append((self.t("hash"), ev.get("hash") or "—"))
        rows.append(
            (
                self.t("source"),
                (
                    self.t("source_siem")
                    if ev.get("source") == "siem"
                    else self.t("source_api")
                ),
            )
        )
        for r, (k, val) in enumerate(rows):
            grid.addWidget(_label(k, hint=True), r, 0, Qt.AlignmentFlag.AlignTop)
            grid.addWidget(_label(val, wrap=True), r, 1)
        grid.setColumnStretch(1, 1)
        self.detail.body.addLayout(grid)
        self.detail.body.addWidget(_label(self.t("raw_log"), hint=True))
        raw = QPlainTextEdit()
        raw.setPlainText(ev.get("raw_log") or "")
        raw.setReadOnly(True)
        raw.setMinimumHeight(90)
        self.detail.body.addWidget(raw, 1)


# ==========================================================================
# Inventory
# ==========================================================================


class InventoryTab:
    def __init__(self, ctx):
        self.ctx = ctx
        self.t = ctx.t
        self._view = "Devices"
        self._group = tables.GROUP_ALL
        self._page = 1
        self._expanded: set = set()
        self._limits: dict = {}
        self.widget = QWidget()
        self.widget.setObjectName("Transparent")
        col = QVBoxLayout(self.widget)
        col.setContentsMargins(0, 12, 0, 0)
        col.setSpacing(12)
        self.banner = _Banner()
        col.addWidget(self.banner)
        card = Card()
        card.body.setSpacing(6)
        title = QHBoxLayout()
        title.setSpacing(8)
        self.view_combo = QComboBox()
        for v in tables.INVENTORY_VIEWS:
            self.view_combo.addItem(self.t(f"inv_view_{v.lower()}"), v)
        self.view_combo.currentIndexChanged.connect(
            lambda i: self._set_view(self.view_combo.itemData(i))
        )
        title.addWidget(self.view_combo)
        self.group_combo = QComboBox()
        self.group_combo.currentTextChanged.connect(self._set_group)
        title.addWidget(self.group_combo)
        title.addStretch(1)
        self.pager = Pager()
        title.addWidget(self.pager)
        card.body.addLayout(title)
        self.count = _label("", hint=True)
        card.body.addWidget(self.count)
        self._header_holder = QVBoxLayout()
        card.body.addLayout(self._header_holder)
        self.scroll, self.rows = _rows_scroll()
        self.scroll.setMinimumHeight(300)
        card.body.addWidget(self.scroll, 1)
        col.addWidget(card, 1)
        self._agents_cache: list = []
        self.refresh()

    def _agents(self) -> list:
        slot = self.ctx.store.slot("agents")
        if slot.ready and not slot.error and slot.data:
            return slot.data
        return tables.devices_from_posture(self.ctx.rows())

    def _banner_text(self) -> tuple:
        slot = self.ctx.store.slot("agents")
        if not slot.ready:
            return self.t("loading_inventory"), True
        if slot.unavailable:
            return self.t("inventory_partial"), False
        if slot.error:
            return self.t("inventory_error", error=slot.error), False
        return "", False

    def set_scope(self) -> None:  # inventory is fleet-wide
        pass

    def refresh(self) -> None:
        text, loading = self._banner_text()
        self.banner.show_text(text, loading)
        agents = self._agents()
        values = tables.inventory_group_values(agents)
        self.group_combo.blockSignals(True)
        self.group_combo.clear()
        self.group_combo.addItems(values)
        if self._group not in values:
            self._group = tables.GROUP_ALL
        self.group_combo.setCurrentText(self._group)
        self.group_combo.blockSignals(False)
        self.group_combo.setVisible(len(values) >= 3)
        self._render_body()

    def _set_view(self, view: str) -> None:
        if view and view != self._view:
            self._view = view
            self._page = 1
            idx = self.view_combo.findData(view)
            if idx >= 0 and self.view_combo.currentIndex() != idx:
                self.view_combo.blockSignals(True)
                self.view_combo.setCurrentIndex(idx)
                self.view_combo.blockSignals(False)
            self._render_body()

    def _set_group(self, group: str) -> None:
        if group and group != self._group:
            self._group = group
            self._page = 1
            self._render_body()

    def _set_page(self, page: int) -> None:
        self._page = page
        self._render_body()

    def _render_body(self) -> None:
        agents = self._agents()
        view = self._view
        is_devices = view == "Devices"
        if is_devices:
            vulns_slot = self.ctx.store.slot("vulns")
            vulns = vulns_slot.data if vulns_slot.ready and not vulns_slot.error else []
            events_slot = self.ctx.store.slot("events")
            events = (
                events_slot.data if events_slot.ready and not events_slot.error else []
            )
            rows = [
                r
                for r in tables.inventory_rows(agents, events, vulns)
                if tables.row_in_group(r, self._group)
            ]
            self.count.setText(self.t("inv_count_devices", n=len(rows)))
        else:
            rows = [
                r
                for r in tables.inventory_counts_rows(agents, view)
                if tables.row_in_group(r, self._group)
            ]
            total = sum(r["count"] for r in rows)
            with_data = sum(1 for r in rows if r["count"])
            self.count.setText(
                self.t(
                    "inv_count_items",
                    with_data=with_data,
                    total=total,
                    word=self.t(f"inv_word_{view.lower()}"),
                )
            )
        _clear(self._header_holder)
        self._header_holder.addWidget(self._column_header())
        page_rows, self._page, pages = tables.page_slice(
            rows, self._page, tables.INVENTORY_PAGE_SIZE
        )
        self.pager.set_state(self._page, pages, self._set_page)
        bar = self.scroll.verticalScrollBar()
        offset = bar.value()
        _clear_rows(self.rows)
        for dev in page_rows:
            self._add_row(dev, is_devices, view)
        if not rows:
            empty = _label(self.t("inv_none"), hint=True, wrap=True)
            empty.setAlignment(Qt.AlignmentFlag.AlignCenter)
            self.rows.insertWidget(self.rows.count() - 1, empty)
        self.ctx.app.after(0, lambda b=bar, v=offset: b.setValue(min(v, b.maximum())))

    _LEAD_W, _DISCLOSE_W = 100, 18

    def _column_header(self) -> QWidget:
        head = QWidget()
        head.setObjectName("Transparent")
        h = QHBoxLayout(head)
        h.setContentsMargins(2, 0, 2, 0)
        h.setSpacing(12)
        spacer = _label("", hint=True)
        spacer.setFixedWidth(self._DISCLOSE_W)
        h.addWidget(spacer)
        lead = _label(self.t(f"inv_lead_{self._view.lower()}"), hint=True)
        lead.setFixedWidth(self._LEAD_W)
        h.addWidget(lead)
        h.addWidget(_label(self.t("col_device"), hint=True), 1)
        for title, width, _g in tables.INVENTORY_SUMMARY_COLUMNS[self._view]:
            lbl = _label(title, hint=True)
            lbl.setFixedWidth(width)
            h.addWidget(lbl)
        return head

    def _add_row(self, dev: dict, is_devices: bool, view: str) -> None:
        expandable = not is_devices and dev["count"] > 0
        key = (view, dev["agent_id"])
        expanded = expandable and key in self._expanded
        row = _ClickRow((lambda d=dev: self._toggle(view, d)) if expandable else None)
        h = QHBoxLayout(row)
        h.setContentsMargins(2, 6, 2, 6)
        h.setSpacing(12)
        disclose = _label(("▼" if expanded else "▶") if expandable else "", hint=True)
        disclose.setFixedWidth(self._DISCLOSE_W)
        h.addWidget(disclose)
        lead = QWidget()
        lead.setObjectName("Transparent")
        lead.setFixedWidth(self._LEAD_W)
        lh = QHBoxLayout(lead)
        lh.setContentsMargins(0, 0, 0, 0)
        if is_devices:
            pill = QLabel()
            status = tables.SEV_TO_STATUS.get(dev["threat"], "OK")
            set_pill(
                pill,
                {
                    "CRITICAL": "critical",
                    "HIGH": "error",
                    "WARNING": "warning",
                    "OK": "ok",
                }[status],
                status,
            )
            lh.addWidget(pill)
        else:
            lh.addWidget(
                _label(str(dev["count"]), bold=dev["count"] > 0, hint=dev["count"] == 0)
            )
        lh.addStretch(1)
        h.addWidget(lead)
        name_cell = QWidget()
        name_cell.setObjectName("Transparent")
        nv = QVBoxLayout(name_cell)
        nv.setContentsMargins(0, 0, 0, 0)
        nv.setSpacing(1)
        nv.addWidget(_label(dev["name"], bold=True))
        nv.addWidget(_label(f"id {dev['agent_id']} · {dev['ip']}", hint=True))
        h.addWidget(name_cell, 1)
        for _title, width, getter in tables.INVENTORY_SUMMARY_COLUMNS[view]:
            try:
                text = tables.cell_text(getter(dev))
            except (AttributeError, TypeError, ValueError):
                text = "—"
            h.addWidget(_fixed(_label(text, hint=True), width))
        for w in row.findChildren(QLabel):
            w.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)
        self.rows.insertWidget(self.rows.count() - 1, row)
        if expanded:
            self.rows.insertWidget(self.rows.count() - 1, self._items_panel(view, dev))

    def _toggle(self, view: str, dev: dict) -> None:
        key = (view, dev["agent_id"])
        if key in self._expanded:
            self._expanded.discard(key)
        else:
            self._expanded.add(key)
        self._render_body()

    def _show_more(self, view: str, dev: dict) -> None:
        key = (view, dev["agent_id"])
        self._limits[key] = (
            self._limits.get(key, tables.INV_ITEM_PAGE) + tables.INV_ITEM_PAGE
        )
        self._render_body()

    def _items_panel(self, view: str, dev: dict) -> QWidget:
        panel = QWidget()
        panel.setObjectName("Transparent")
        pv = QVBoxLayout(panel)
        pv.setContentsMargins(self._DISCLOSE_W + 14, 2, 6, 10)
        pv.setSpacing(2)
        items = dev.get("items") or []
        limit = self._limits.get((view, dev["agent_id"]), tables.INV_ITEM_PAGE)
        shown = items[:limit]
        columns = tables.INVENTORY_ITEM_COLUMNS.get(view, ())
        head = QHBoxLayout()
        head.setSpacing(10)
        for title, width, _g in columns:
            lbl = _label(title, hint=True)
            if width:
                lbl.setFixedWidth(width)
                head.addWidget(lbl)
            else:
                head.addWidget(lbl, 1)
        pv.addLayout(head)
        line = QFrame()
        line.setObjectName("Divider")
        line.setFixedHeight(1)
        pv.addWidget(line)
        for item in shown:
            lh = QHBoxLayout()
            lh.setSpacing(10)
            for idx, (_title, width, getter) in enumerate(columns):
                try:
                    text = tables.cell_text(getter(item))
                except (AttributeError, TypeError, ValueError):
                    text = "—"
                lbl = _label(text, bold=idx == 0, hint=idx > 0)
                lbl.setToolTip(text)
                if width:
                    lh.addWidget(_fixed(lbl, width))
                else:
                    lbl.setSizePolicy(
                        QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Preferred
                    )
                    lh.addWidget(lbl, 1)
            pv.addLayout(lh)
        if len(items) > len(shown):
            more = QHBoxLayout()
            more.addWidget(
                _label(
                    self.t("inv_showing", shown=len(shown), total=len(items)), hint=True
                )
            )
            btn = QPushButton(
                self.t(
                    "inv_show_more",
                    n=min(tables.INV_ITEM_PAGE, len(items) - len(shown)),
                )
            )
            btn.setObjectName("Link")
            btn.setCursor(Qt.CursorShape.PointingHandCursor)
            btn.clicked.connect(lambda _=False, d=dev: self._show_more(view, d))
            more.addWidget(btn)
            more.addStretch(1)
            pv.addLayout(more)
        return panel


def not_available(store) -> bool:
    return store.api_unavailable()


__all__ = ["VulnerabilitiesTab", "EventsTab", "InventoryTab", "api", "not_available"]
