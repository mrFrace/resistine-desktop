"""Devices page: the Responses tab (read-only Active Response visibility).

P0 of the Active Response feature (docs/active-response-P0.md): an operator
sees, but never changes, the AR state their account is allowed to see. Three
read-only sections built from the Phoenix API (plugins/devices/
active_response_api.py), all over ``api.phoenix.exposed`` — the app never
talks to Wazuh or the indexer:

  1. **AR policies** — the channels (``fetch_channels``), each with the monitor
     that fires it (``fetch_monitors`` -> ``destination_id`` == ``config_id``)
     and an ``affects_me`` badge.
  2. **Would run on this device** — for the device-scope selection, which
     channels would execute on it, derived from the channel ``location`` /
     ``agent_id`` against the device's ``agent_id``.
  3. **Recent executions** — the AR commands that ran, filtered to the
     selected device via ``fetch_executions(agent_id)``.

Nothing here creates, edits or fires anything (that is P2+). When the backend
routes are not deployed (404 -> NOT_AVAILABLE) or no channel is seeded yet, the
tab still loads and shows "No active responses configured yet". Everything the
server sends is untrusted text and is rendered as plain text.
"""

from __future__ import annotations

import threading
import time

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import QHBoxLayout, QLabel, QVBoxLayout, QWidget

from gui.page_kit import hairline, muted, section_heading
from gui.qt_widgets import Card, set_pill
from plugins.devices import active_response_api as ar
from plugins.devices.api import NOT_AVAILABLE

REFETCH_AFTER_S = 60


def _plain(lbl: QLabel) -> QLabel:
    lbl.setTextFormat(Qt.TextFormat.PlainText)
    return lbl


def _label(text, *, bold: bool = False, hint: bool = False, wrap: bool = False) -> QLabel:
    lbl = _plain(QLabel(str(text)))
    lbl.setObjectName("Hint" if hint else "RowTitle" if bold else "Val")
    lbl.setWordWrap(wrap)
    return lbl


def _stacked(top: str, bottom: str) -> QWidget:
    """A two-line cell: a bold title over a muted hint."""
    cell = QWidget()
    cell.setObjectName("Transparent")
    v = QVBoxLayout(cell)
    v.setContentsMargins(0, 0, 0, 0)
    v.setSpacing(0)
    v.addWidget(_label(top or "—", bold=True))
    if bottom:
        v.addWidget(_label(bottom, hint=True))
    return cell


def _pill_cell(kind: str, text: str) -> QWidget:
    """A status pill aligned to the left of its column."""
    cell = QWidget()
    cell.setObjectName("Transparent")
    h = QHBoxLayout(cell)
    h.setContentsMargins(0, 0, 0, 0)
    h.setSpacing(0)
    pill = QLabel()
    set_pill(pill, kind, text)
    h.addWidget(pill)
    h.addStretch(1)
    return cell


class ResponsesTab:
    """Read-only Active Response surface for the Devices page."""

    def __init__(self, ctx):
        self.ctx = ctx
        self.t = lambda key, **kw: ctx.t(f"responses_{key}", **kw)
        self.widget = QWidget()
        self.widget.setObjectName("Transparent")
        self._col = QVBoxLayout(self.widget)
        self._col.setContentsMargins(0, 20, 0, 32)
        self._col.setSpacing(0)
        self._channels: list | None = None
        self._monitors: list | None = None
        self._executions: list | None = None
        self._channels_err = None
        self._executions_err = None
        self._loading = False
        self._loaded_once = False
        self._loaded_at = 0.0
        self._render()
        self._fetch()

    # ---- scope -------------------------------------------------------------

    def _selected(self):
        """(agent_id, host) for the device-scope selection, or (None, None)
        when "All devices" is selected."""
        host = self.ctx.scope()
        if not host:
            return None, None
        for r in self.ctx.scoped_rows():
            return (r.get("agent_id") or None), (r.get("hostname") or host)
        return None, host

    def _ledger_device(self):
        """The device the consent ledger is about: the selected one, else this
        machine when "All" is selected, else (None, None)."""
        aid, host = self._selected()
        if host:
            return aid, host
        for r in self.ctx.rows():
            if r.get("this_machine"):
                return (r.get("agent_id") or None), r.get("hostname")
        return None, None

    # ---- data --------------------------------------------------------------

    def set_scope(self) -> None:
        """Scope changed: re-fetch the per-device executions and repaint
        (channels/monitors are global and stay cached)."""
        self._fetch(executions_only=True)

    def refresh(self) -> None:
        if time.monotonic() - self._loaded_at > REFETCH_AFTER_S:
            self._fetch()

    def _fetch(self, executions_only: bool = False) -> None:
        if self._loading:
            return
        self._loading = True
        agent_id, _ = self._selected()

        def work():
            channels = monitors = None
            channels_err = None
            if not executions_only:
                channels, channels_err = ar.fetch_channels()
                monitors, _merr = ar.fetch_monitors()
            executions, executions_err = ar.fetch_executions(agent_id)
            self.ctx.app.after(
                0,
                lambda: self._loaded(
                    executions_only, channels, channels_err, monitors,
                    executions, executions_err,
                ),
            )

        threading.Thread(target=work, daemon=True, name="devices-responses").start()

    def _loaded(self, executions_only, channels, channels_err, monitors,
                executions, executions_err) -> None:
        self._loading = False
        self._loaded_once = True
        self._loaded_at = time.monotonic()
        if not executions_only:
            if channels is not None:
                self._channels = channels
            if monitors is not None:
                self._monitors = monitors
            self._channels_err = channels_err
        if executions is not None:
            self._executions = executions
        self._executions_err = executions_err
        try:
            self._render()
        except RuntimeError:  # the page was torn down meanwhile
            pass

    # ---- render ------------------------------------------------------------

    def _clear(self) -> None:
        while self._col.count():
            item = self._col.takeAt(0)
            w = item.widget()
            if w is not None:
                w.hide()
                w.deleteLater()

    def _hard_error(self):
        """A real failure (not a not-yet-deployed 404) with nothing to show."""
        for err in (self._channels_err, self._executions_err):
            if err and err != NOT_AVAILABLE:
                return err
        return None

    def _render(self) -> None:
        self._clear()
        col = self._col
        channels = self._channels or []
        executions = self._executions or []

        if not self._loaded_once:
            col.addWidget(_plain(muted(self.t("loading"))))
            col.addStretch(1)
            return

        if not channels and not executions:
            err = self._hard_error()
            if err:
                col.addWidget(_plain(muted(self.t("error", error=err))))
            else:
                col.addWidget(_plain(muted(self.t("empty"))))
            col.addStretch(1)
            return

        err = self._hard_error()
        if err:
            col.addWidget(_plain(muted(self.t("stale", error=err))))
            col.addSpacing(12)

        self._section_policies(col, channels)
        col.addSpacing(28)
        self._section_ledger(col, channels)
        col.addSpacing(28)
        self._section_executions(col, executions)
        col.addStretch(1)

    def _table(self, columns, rows) -> QWidget:
        """A flat table in a Card. ``columns`` is ``(title, width, stretch)``;
        ``rows`` is a list of cells, each a QWidget or a string."""
        card = Card()
        card.body.setSpacing(2)
        head = QHBoxLayout()
        head.setContentsMargins(6, 0, 6, 4)
        head.setSpacing(12)
        for title, width, stretch in columns:
            lbl = _label(title, hint=True)
            if width:
                lbl.setFixedWidth(width)
            head.addWidget(lbl, stretch)
        card.body.addLayout(head)
        for row in rows:
            card.body.addWidget(hairline())
            wrap = QWidget()
            wrap.setObjectName("Transparent")
            rh = QHBoxLayout(wrap)
            rh.setContentsMargins(6, 8, 6, 8)
            rh.setSpacing(12)
            for (_title, width, stretch), cell in zip(columns, row):
                w = cell if isinstance(cell, QWidget) else _label(cell, wrap=True)
                if width:
                    w.setFixedWidth(width)
                rh.addWidget(w, stretch, Qt.AlignmentFlag.AlignTop)
            card.body.addWidget(wrap)
        return card

    # ---- section 1: AR policies -------------------------------------------

    def _section_policies(self, col, channels) -> None:
        col.addWidget(section_heading(self.t("section_policies")))
        col.addSpacing(10)
        if not channels:
            col.addWidget(_plain(muted(self.t("none_policies"))))
            return
        fired_by = ar.triggered_by(channels, self._monitors or [])
        columns = [
            (self.t("col_policy"), 0, 2),
            (self.t("col_location"), 90, 0),
            (self.t("col_type"), 120, 0),
            (self.t("col_affects"), 84, 0),
            (self.t("col_triggered_by"), 0, 2),
        ]
        rows = []
        for c in channels:
            name = c["name"]
            if not c["is_enabled"]:
                name = f"{name} ({self.t('disabled')})"
            policy = _stacked(name, c["executable"])
            type_text = c["type"] or "—"
            if c["stateful_timeout"]:
                type_text = self.t("type_timeout", type=c["type"] or "—",
                                    timeout=c["stateful_timeout"])
            affects = (
                _pill_cell("ok", self.t("affects_you"))
                if c["affects_me"]
                else _label("—", hint=True)
            )
            monitors = fired_by.get(c["config_id"]) or []
            triggered = ", ".join(m for m in monitors if m) if monitors else self.t("triggered_none")
            rows.append([
                policy,
                _label(c["location"] or "—"),
                _label(type_text),
                affects,
                _label(triggered, hint=not monitors, wrap=True),
            ])
        col.addWidget(self._table(columns, rows))

    # ---- section 2: consent ledger ----------------------------------------

    _RUN_PILL = {ar.RUNS_YES: ("ok", "run_yes"),
                 ar.RUNS_ON_TRIGGER: ("warning", "run_on_trigger"),
                 ar.RUNS_NO: ("info", "run_no")}

    def _section_ledger(self, col, channels) -> None:
        col.addWidget(section_heading(self.t("section_ledger")))
        col.addSpacing(10)
        aid, host = self._ledger_device()
        if not host:
            col.addWidget(_plain(muted(self.t("ledger_pick"))))
            return
        col.addWidget(_plain(muted(self.t("ledger_for", host=host))))
        col.addSpacing(8)
        if not channels:
            col.addWidget(_plain(muted(self.t("none_policies"))))
            return
        columns = [
            (self.t("col_policy"), 0, 2),
            (self.t("col_executable"), 0, 2),
            (self.t("col_would_run"), 110, 0),
        ]
        rows = []
        for c in channels:
            verdict = ar.channel_runs_on(c, aid)
            kind, key = self._RUN_PILL.get(verdict, ("info", "run_no"))
            rows.append([
                _label(c["name"], bold=True, wrap=True),
                _label(c["executable"] or "—", wrap=True),
                _pill_cell(kind, self.t(key)),
            ])
        col.addWidget(self._table(columns, rows))

    # ---- section 3: executions --------------------------------------------

    _CMD_PILL = {"enable": "error", "disable": "ok"}

    def _section_executions(self, col, executions) -> None:
        col.addWidget(section_heading(self.t("section_executions")))
        col.addSpacing(10)
        _, host = self._selected()
        if host:
            col.addWidget(_plain(muted(self.t("executions_for", host=host))))
            col.addSpacing(8)
        if not executions:
            key = "none_executions_device" if host else "none_executions"
            col.addWidget(_plain(muted(self.t(key))))
            return
        columns = [
            (self.t("col_agent"), 0, 2),
            (self.t("col_action"), 0, 2),
            (self.t("col_target"), 120, 0),
            (self.t("col_time"), 150, 0),
            (self.t("col_status"), 90, 0),
            (self.t("col_finding"), 0, 1),
        ]
        rows = []
        for e in executions:
            agent = _stacked(
                e["agent_name"] or e["agent_id"] or "—",
                self.t("agent_id", id=e["agent_id"]) if e["agent_id"] else "",
            )
            action = QWidget()
            action.setObjectName("Transparent")
            av = QVBoxLayout(action)
            av.setContentsMargins(0, 0, 0, 0)
            av.setSpacing(2)
            av.addWidget(_label(e["executable"] or "—", bold=True, wrap=True))
            if e["command"]:
                av.addWidget(_pill_cell(self._CMD_PILL.get(e["command"], "info"),
                                        e["command"]))
            status_kind = {
                "completed": "ok", "success": "ok", "done": "ok",
                "failed": "error", "error": "error",
                "pending": "warning", "staged": "warning",
                "acked": "info", "armed": "warning",
            }.get(e["status"].lower(), "info")
            rows.append([
                agent,
                action,
                _label(e["target"] or "—", wrap=True),
                _label(e["timestamp"] or "—", hint=True),
                _pill_cell(status_kind, e["status"] or "—"),
                _label(e["finding_id"] or "—", hint=True, wrap=True),
            ])
        col.addWidget(self._table(columns, rows))
