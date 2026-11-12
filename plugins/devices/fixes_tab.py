"""Devices page: the Fixes tab (vulnerabilities as things to do).

One row per package upgrade across the scoped devices (plugins/devices/
fixes.py), worst first, then the findings that are not package fixes
(failed CIS checks, an agent not reporting). Above them, the new
detections per day from the first-seen ledger. A row opens the fix's
detail page, which slides in over the Devices page like a mitigation.

Package names, versions and CVE ids come from the server and quote the
monitored systems: every label here is plain text.
"""

from __future__ import annotations

from datetime import date

from PyQt6.QtCore import Qt
from PyQt6.QtGui import QIcon
from PyQt6.QtWidgets import QLabel, QPushButton, QVBoxLayout, QWidget

from gui import theme
from gui.page_kit import (
    KVList,
    MenuRow,
    Page,
    PageHeader,
    RowList,
    back_link,
    line_icon,
    muted,
    section_heading,
)
from gui.qt_widgets import set_pill
from plugins.dashboard import mitigations
from plugins.dashboard.main import _DayStrip
from plugins.devices import fixes

_SEV_PILL = {
    "critical": "critical",
    "high": "error",
    "medium": "warning",
    "low": "info",
}
_MITIGATION_ICON = {
    "package_update": "package",
    "cis_checks": "shield-check",
    "agent_connection": "monitor",
}


def _plain(lbl: QLabel) -> QLabel:
    lbl.setTextFormat(Qt.TextFormat.PlainText)
    return lbl


def _sev_pill(sev: str) -> QLabel:
    lbl = QLabel()
    set_pill(lbl, _SEV_PILL.get(sev, "warning"), str(sev).capitalize())
    return lbl


def _with_pill(row: MenuRow, sev: str) -> MenuRow:
    """The severity pill between the row's text and its chevron."""
    row.layout().insertWidget(2, _sev_pill(sev), 0, Qt.AlignmentFlag.AlignVCenter)
    return row


class FixesTab:
    def __init__(self, ctx):
        self.ctx = ctx
        self.t = ctx.t
        self.widget = QWidget()
        self.widget.setObjectName("Transparent")
        self._col = QVBoxLayout(self.widget)
        self._col.setContentsMargins(0, 20, 0, 32)
        self._col.setSpacing(0)
        self.refresh()

    def set_scope(self) -> None:
        self.refresh()

    def refresh(self) -> None:
        """Rebuild the column (the data is ten items per device at most)."""
        while self._col.count():
            item = self._col.takeAt(0)
            if item.widget() is not None:
                item.widget().deleteLater()
        rows = self.ctx.scoped_rows()
        cards = [r["card"] for r in rows]
        names = {r["hostname"] for r in rows if r["this_machine"]}
        groups = fixes.group(cards, names)
        col = self._col

        led = fixes.ledger()
        days = fixes.detections(led, date.today())
        col.addWidget(section_heading(self.t("fix_section_new", days=fixes.LEDGER_DAYS)))
        col.addSpacing(10)
        new = sum(d["count"] for d in days)
        if led["since"] and (new or led["since"] < date.today().isoformat()):
            col.addWidget(_DayStrip(days))
            col.addSpacing(4)
            since = date.fromisoformat(led["since"])
            col.addWidget(_plain(muted(self.t("fix_new_total", n=new, day=f"{since.day} {since:%b}"))))
        else:
            col.addWidget(_plain(muted(self.t("fix_new_none"))))

        col.addSpacing(28)
        col.addWidget(section_heading(self.t("fix_section_fixes")))
        col.addSpacing(10)
        if groups:
            lst = RowList()
            for g in groups:
                lst.add_row(_with_pill(
                    MenuRow("package", fixes.title(g), fixes.hint(g),
                            on_click=lambda _g=g: self._open(_g)),
                    g["severity"]))
            col.addWidget(lst)
        else:
            scope = self.ctx.scope() or self.t("scope_all_lower")
            col.addWidget(_plain(muted(self.t("fix_nothing", scope=scope))))

        others = fixes.other_items(cards)
        if others:
            col.addSpacing(28)
            col.addWidget(section_heading(self.t("fix_section_other")))
            col.addSpacing(10)
            lst = RowList()
            for card, item in others:
                host = str(card.get("hostname") or card.get("agent_id") or "?")
                detail = mitigations.detail_line(item)
                lst.add_row(_with_pill(
                    MenuRow(_MITIGATION_ICON.get(item["kind"], "shield-check"), item["title"],
                            f"{host} · {detail}" if detail else host, chevron=False),
                    item["severity"]))
            col.addWidget(lst)

        col.addSpacing(16)
        col.addWidget(_plain(muted(self.t("fix_caveat"))))
        col.addStretch(1)

    # ---- detail ------------------------------------------------------------

    def _open(self, g: dict) -> None:
        led = fixes.ledger()
        page = Page()
        page.add(back_link(self.t("title"), self.ctx.pop))
        header = PageHeader(
            fixes.title(g),
            self.t("fix_detail_where", where=fixes.hint(g).rsplit(" · ", 1)[-1]),
            (_SEV_PILL.get(g["severity"], "warning"), g["severity"].capitalize()),
        )
        header.title.setTextFormat(Qt.TextFormat.PlainText)
        header.title.setWordWrap(True)
        header.subtitle.setTextFormat(Qt.TextFormat.PlainText)
        first = g["devices"][0]
        ask = QPushButton(self.t("ask_ai"))
        ask.setIcon(QIcon(line_icon("message-circle", theme.color("on_accent"), 18)))
        ask.setCursor(Qt.CursorShape.PointingHandCursor)
        ask.clicked.connect(lambda: self.ctx.ask_ai(
            mitigations.question(first["item"], first["hostname"], first["this_machine"],
                                 first["agent_id"])))
        header.add_control(ask)
        page.add(header)

        page.section(self.t("fix_section_machines"))
        machines = KVList()
        for d in g["devices"]:
            name = self.t("fix_this_machine", host=d["hostname"]) if d["this_machine"] else d["hostname"]
            state = self._state(d)
            seen = fixes.first_seen(led, d)
            machines.add(name, " · ".join(b for b in (d["version"], state, seen) if b))
        page.add(machines)

        page.section(self.t("fix_section_evidence"))
        ev = KVList()
        ev.add(self.t("fix_severity"), g["severity"].capitalize())
        worst = " · ".join(b for b in (
            self.t("fix_n_critical", n=g["critical"]) if g["critical"] else "",
            self.t("fix_n_high", n=g["high"]) if g["high"] else "") if b)
        if worst:
            ev.add(self.t("fix_worst"), worst)
        if g["fixed_version"]:
            ev.add(self.t("fix_fixed_in"), g["fixed_version"])
        if g["cves"]:
            ev.add(self.t("fix_cves"), ", ".join(g["cves"]))
        page.add(ev)

        steps = mitigations.fix_steps(first["item"])
        if steps:
            page.section(self.t("mitigation_fix"))
            lst = RowList()
            for i, step in enumerate(steps, 1):
                lst.add_row(self.ctx.step_row(i, step))
            page.add(lst)
        page.spacing(16)
        page.add(_plain(muted(self.t("fix_detail_caveat"))))
        page.stretch()
        self.ctx.push(page.widget)

    def _state(self, device: dict) -> str:
        """This machine's probe result for the item ('To fix', 'Fixed here,
        waiting for the next scan', ...); '' for other machines."""
        if not device["this_machine"]:
            return ""
        for row in self.ctx.rows():
            if row["this_machine"]:
                for item, state in mitigations.cached(row["card"], True):
                    if item["id"] == device["item"]["id"]:
                        return mitigations.state_text(state) if state else ""
        return ""
