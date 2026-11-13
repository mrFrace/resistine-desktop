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

from PyQt6.QtCore import Qt, QTimer, pyqtSignal
from PyQt6.QtWidgets import (
    QComboBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)

from gui.page_kit import (
    KVList,
    Page,
    PageHeader,
    SettingRow,
    back_link,
    hairline,
    muted,
    section_heading,
)
from gui.qt_widgets import Card, set_pill
from plugins.devices import active_response_api as ar
from plugins.devices.api import NOT_AVAILABLE

REFETCH_AFTER_S = 60

# Hold-to-confirm: a state-changing AR write is never one careless click. The
# press must be held, longer the wider the blast radius (docs/active-
# response-P2.md AR-D3). Capped so a large fleet stays usable.
HOLD_BASE_MS = 1200
HOLD_PER_AGENT_MS = 400
HOLD_MAX_MS = 5000


def hold_duration_ms(n_agents: int) -> int:
    """How long the confirm must be held for ``n_agents`` in the blast radius."""
    n = max(1, int(n_agents or 1))
    return min(HOLD_MAX_MS, HOLD_BASE_MS + (n - 1) * HOLD_PER_AGENT_MS)


class HoldButton(QPushButton):
    """A button that fires ``confirmed`` only after being held down for its
    full duration; releasing early resets it. The label counts up so the
    operator sees the commitment they're making."""

    confirmed = pyqtSignal()

    def __init__(self, label: str, duration_ms: int = HOLD_BASE_MS):
        super().__init__(label)
        self._label = label
        self._duration_ms = max(200, int(duration_ms))
        self._elapsed = 0
        self._step = 50
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self._timer = QTimer(self)
        self._timer.setInterval(self._step)
        self._timer.timeout.connect(self._tick)
        self.pressed.connect(self._start)
        self.released.connect(self._reset)

    def set_duration_ms(self, duration_ms: int) -> None:
        self._duration_ms = max(200, int(duration_ms))

    def _start(self) -> None:
        if not self.isEnabled():
            return
        self._elapsed = 0
        self._timer.start()

    def _tick(self) -> None:
        self._elapsed += self._step
        pct = min(100, int(100 * self._elapsed / self._duration_ms))
        self.setText(f"{self._label}  ·  {pct}%")
        if self._elapsed >= self._duration_ms:
            self._timer.stop()
            self.setText(self._label)
            self.confirmed.emit()

    def _reset(self) -> None:
        self._timer.stop()
        self._elapsed = 0
        self.setText(self._label)


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
        self._refetch_pending = False
        self._fetched_for = None  # agent_id the in-flight executions fetch is for
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

    def _own_agent(self):
        """The caller's own agent a write would target: the ledger device when
        it carries an ``agent_id`` (a Desktop AR write is ``location=defined-
        agent``, D-2), else (None, host) so the UI can explain why it can't."""
        aid, host = self._ledger_device()
        return (aid, host) if aid else (None, host)

    # ---- data --------------------------------------------------------------

    def set_scope(self) -> None:
        """Scope changed: repaint at once from what is cached (the device
        filter is applied client-side), then re-fetch the executions
        (channels/monitors are global and stay cached)."""
        if self._loaded_once:
            try:
                self._render()
            except RuntimeError:
                pass
        self._fetch(executions_only=True)

    def refresh(self) -> None:
        if time.monotonic() - self._loaded_at > REFETCH_AFTER_S:
            self._fetch()

    def _fetch(self, executions_only: bool = False) -> None:
        if self._loading:
            # A scope change while a fetch is in flight is not lost: _loaded
            # runs one more executions fetch for the scope selected by then.
            self._refetch_pending = True
            return
        self._loading = True
        self._refetch_pending = False
        agent_id, _ = self._selected()
        self._fetched_for = agent_id

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
            return
        if self._refetch_pending or self._fetched_for != self._selected()[0]:
            self._fetch(executions_only=True)

    # ---- render ------------------------------------------------------------

    def _clear(self) -> None:
        while self._col.count():
            self._drop_item(self._col.takeAt(0))

    def _drop_item(self, item) -> None:
        """Hide+delete a layout item. A nested layout (e.g. a section header
        row added with addLayout) owns widgets that must be dropped too, or
        they stay parented to the tab and keep painting behind the next
        render."""
        if item is None:
            return
        w = item.widget()
        if w is not None:
            w.hide()
            w.deleteLater()
            return
        lay = item.layout()
        if lay is not None:
            while lay.count():
                self._drop_item(lay.takeAt(0))

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
        # The backend returns every execution of the caller's agents whatever
        # ?agent_id= says: the device scope is applied here.
        aid, host = self._selected()
        executions = ar.executions_for(self._executions or [], aid, host)

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

    def _section_header(self, title: str, button: QWidget | None = None) -> QWidget:
        """A section heading with an optional right-aligned action button, as a
        single widget so ``_clear`` removes it cleanly (a bare ``addLayout``
        row would leak its children)."""
        row = QWidget()
        row.setObjectName("Transparent")
        h = QHBoxLayout(row)
        h.setContentsMargins(0, 0, 0, 0)
        h.addWidget(section_heading(title))
        h.addStretch(1)
        if button is not None:
            h.addWidget(button)
        return row

    def _section_policies(self, col, channels) -> None:
        col.addWidget(self._section_header(self.t("section_policies"),
                                           self._new_policy_button()))
        col.addSpacing(4)
        col.addWidget(_plain(muted(self.t("gitops_note"))))
        col.addSpacing(10)
        if not channels:
            col.addWidget(_plain(muted(self.t("none_policies"))))
            return
        fired_by = ar.triggered_by(channels, self._monitors or [])
        columns = [
            (self.t("col_policy"), 0, 2),
            (self.t("col_location"), 130, 0),
            (self.t("col_type"), 120, 0),
            (self.t("col_affects"), 70, 0),
            (self.t("col_triggered_by"), 0, 2),
            (self.t("col_manage"), 180, 0),
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
                _label(c["location"] or "—", wrap=True),
                _label(type_text),
                affects,
                _label(triggered, hint=not monitors, wrap=True),
                self._manage_cell(c),
            ])
        col.addWidget(self._table(columns, rows))

    def _new_policy_button(self) -> QWidget:
        """The "New policy" affordance; disabled (with a reason) when no own
        agent is in scope, since a Desktop policy is always ``defined-agent``."""
        aid, host = self._own_agent()
        btn = QPushButton(self.t("new_policy"))
        btn.setObjectName("SurfaceBtn")
        btn.setCursor(Qt.CursorShape.PointingHandCursor)
        if aid:
            btn.setToolTip(self.t("new_policy_for", host=host or aid))
            btn.clicked.connect(lambda: self._open_policy_form(None))
        else:
            btn.setEnabled(False)
            btn.setToolTip(self.t("need_own_agent"))
        return btn

    def _manage_cell(self, channel) -> QWidget:
        """Edit/Delete buttons for a policy that carries a ``config_id``. The
        server re-checks per-user scope on the write; this only offers it."""
        cell = QWidget()
        cell.setObjectName("Transparent")
        h = QHBoxLayout(cell)
        h.setContentsMargins(0, 0, 0, 0)
        h.setSpacing(6)
        if not channel.get("config_id"):
            h.addWidget(_label("—", hint=True))
            h.addStretch(1)
            return cell
        edit = QPushButton(self.t("edit"))
        edit.setObjectName("SurfaceBtn")
        edit.setCursor(Qt.CursorShape.PointingHandCursor)
        # Size each button to its label (plus padding) so the text is never clipped to "di"/"le".
        edit.setMinimumWidth(edit.sizeHint().width() + 16)
        edit.clicked.connect(lambda _=False, c=channel: self._open_policy_form(c))
        delete = QPushButton(self.t("delete"))
        delete.setObjectName("SurfaceBtn")
        delete.setCursor(Qt.CursorShape.PointingHandCursor)
        delete.setMinimumWidth(delete.sizeHint().width() + 16)
        delete.clicked.connect(lambda _=False, c=channel: self._open_delete(c))
        h.addWidget(edit)
        h.addWidget(delete)
        h.addStretch(1)
        return cell

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
        mon_map = ar.monitors_by_channel(channels, self._monitors or [])
        rows = []
        for c in channels:
            # AR-D8a: a disabled channel (or one whose only monitors are all
            # disabled) would not run, whatever its location says.
            if not ar.policy_enabled(c, mon_map.get(c["config_id"])):
                kind, key = "info", "run_no_disabled"
            else:
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

    # A command whose effect is still in place and can be stopped early. The
    # empty command is excluded: a thin/aged-out row with no command is not a
    # live block to stop.
    _ACTIVE_CMDS = {"enable", "block", "blocked", "add", "fire"}
    # Statuses where the AR is no longer in effect (failed to apply, or already
    # reverted/expired): no Stop offered.
    _DONE_STATUS = {"failed", "error", "disabled", "reverted", "expired", "stopped"}

    def _section_executions(self, col, executions) -> None:
        col.addWidget(self._section_header(self.t("section_executions"),
                                           self._fire_now_button()))
        col.addSpacing(10)
        _, host = self._selected()
        if host:
            col.addWidget(_plain(muted(self.t("executions_for", host=host))))
            col.addSpacing(8)
        if not executions:
            key = "none_executions_device" if host else "none_executions"
            col.addWidget(_plain(muted(self.t(key))))
            return
        names = ar.channel_name_by_id(self._channels or [])
        # A thin AR record carries the agent id only; name it from the posture
        # rows (or a sibling record) so "004" and "francispc" read as one device.
        agent_names = ar.agent_names(self._executions or [], self.ctx.rows())
        columns = [
            (self.t("col_agent"), 0, 2),
            (self.t("col_action"), 0, 2),
            (self.t("col_target"), 120, 0),
            (self.t("col_time"), 150, 0),
            (self.t("col_status"), 90, 0),
            (self.t("col_manage"), 90, 0),
        ]
        rows = []
        for e in executions:
            agent = _stacked(
                ar.agent_display_name(e, agent_names),
                self.t("agent_id", id=e["agent_id"]) if e["agent_id"] else "",
            )
            action = QWidget()
            action.setObjectName("Transparent")
            av = QVBoxLayout(action)
            av.setContentsMargins(0, 0, 0, 0)
            av.setSpacing(2)
            # AR-D8c: lead with the executable, name the policy it came from.
            av.addWidget(_label(e["executable"] or "—", bold=True, wrap=True))
            channel = names.get(e["config_id"])
            if channel:
                av.addWidget(_label(channel, hint=True, wrap=True))
            if e["command"]:
                av.addWidget(_pill_cell(self._CMD_PILL.get(e["command"], "info"),
                                        e["command"]))
            # AR-D8c: the status badge is never empty.
            status_text = e["status"] or (e["command"] and self.t("status_active")) \
                or self.t("status_unknown")
            status_kind = {
                "completed": "ok", "success": "ok", "done": "ok",
                "failed": "error", "error": "error",
                "pending": "warning", "staged": "warning",
                "acked": "info", "armed": "warning",
            }.get(e["status"].lower(), "warning" if not e["status"] else "info")
            # AR-D8d: Target + the finding it came from (rule_title from the
            # event->finding join); keep the finding id reachable as a tooltip.
            target_cell = _stacked(e["target"] or "—", e["rule_title"])
            if e["finding_id"]:
                target_cell.setToolTip(self.t("finding_tooltip", id=e["finding_id"]))
            rows.append([
                agent,
                action,
                target_cell,
                _label(e["timestamp"] or "—", hint=True),
                _pill_cell(status_kind, status_text),
                self._exec_manage_cell(e),
            ])
        col.addWidget(self._table(columns, rows))

    def _fire_now_button(self) -> QWidget:
        """"Block an IP now" for the device in scope (AR-D7)."""
        aid, host = self._own_agent()
        btn = QPushButton(self.t("fire_now"))
        btn.setObjectName("SurfaceBtn")
        btn.setCursor(Qt.CursorShape.PointingHandCursor)
        if aid:
            btn.setToolTip(self.t("fire_now_for", host=host or aid))
            btn.clicked.connect(lambda: self._open_fire_form())
        else:
            btn.setEnabled(False)
            btn.setToolTip(self.t("need_own_agent"))
        return btn

    def _exec_manage_cell(self, e) -> QWidget:
        """A Stop button for an execution that is still in effect and that we
        can address (agent + executable + target known)."""
        cell = QWidget()
        cell.setObjectName("Transparent")
        h = QHBoxLayout(cell)
        h.setContentsMargins(0, 0, 0, 0)
        h.setSpacing(0)
        stoppable = (
            e["agent_id"] and e["target"]
            and e["executable"] in ar.EXECUTABLES
            and e["command"] in self._ACTIVE_CMDS
            and e["status"].lower() not in self._DONE_STATUS
        )
        if stoppable:
            stop = QPushButton(self.t("stop"))
            stop.setObjectName("SurfaceBtn")
            stop.setCursor(Qt.CursorShape.PointingHandCursor)
            stop.clicked.connect(lambda _=False, ex=e: self._open_stop(ex))
            h.addWidget(stop)
        else:
            h.addWidget(_label("—", hint=True))
        h.addStretch(1)
        return cell

    # ---- write flows: navigation + notification helpers -------------------

    def _push(self, page: QWidget) -> None:
        push = getattr(self.ctx, "push", None)
        if push is not None:
            push(page)

    def _pop(self) -> None:
        pop = getattr(self.ctx, "pop", None)
        if pop is not None:
            pop()

    def _after(self, fn) -> None:
        """Hop back to the UI thread (ctx.app.after), falling back to a direct
        call so the logic is still exercised under a synchronous test app."""
        app = getattr(self.ctx, "app", None)
        if app is not None and hasattr(app, "after"):
            app.after(0, fn)
        else:
            fn()

    def _notify(self, text: str) -> None:
        app = getattr(self.ctx, "app", None)
        notify = getattr(app, "show_notification", None)
        if notify is not None:
            notify(text, type="warning")

    def _reload(self) -> None:
        """Force the next refresh to re-fetch after a write changed state."""
        self._loaded_at = 0.0
        self._fetch()

    @staticmethod
    def _field(title: str, control: QWidget, hint: str = "") -> QWidget:
        return SettingRow(title, hint, control, stacked=True)

    # ---- write flows: the preview + self-test panel -----------------------

    def _fill_panel(self, panel: Card, data, err, loading: bool = False) -> None:
        """(Re)draw the blast-radius + mandatory self-test panel."""
        while panel.body.count():
            item = panel.body.takeAt(0)
            w = item.widget()
            if w is not None:
                w.deleteLater()
        if loading:
            panel.body.addWidget(_plain(muted(self.t("previewing"))))
            return
        if err:
            panel.body.addWidget(_plain(muted(self.t("preview_error", error=err))))
            return
        if not data:
            panel.body.addWidget(_plain(muted(self.t("preview_hint"))))
            return
        panel.body.addWidget(_label(self.t("blast_radius", n=data["count"]), bold=True))
        for a in data["included"][:50]:
            panel.body.addWidget(_label("•  " + (a["agent_name"] or a["agent_id"] or "—"),
                                        hint=True, wrap=True))
        if not data["included"]:
            panel.body.addWidget(_label(self.t("blast_none"), hint=True))
        if data["excluded"]:
            panel.body.addWidget(_label(self.t("excluded_head"), bold=True))
            for a in data["excluded"][:50]:
                who = a["agent_name"] or a["agent_id"] or "—"
                reason = a["reason"] or "—"
                panel.body.addWidget(_label(f"•  {who}: {reason}", hint=True, wrap=True))
        if data["refusals"]:
            panel.body.addWidget(_label(self.t("refusals_head"), bold=True))
            for r in data["refusals"][:50]:
                panel.body.addWidget(_label("•  " + r, wrap=True))
        panel.body.addWidget(hairline())
        st = data["self_test"]
        if not st["ran"]:
            panel.body.addWidget(_pill_cell("warning", self.t("selftest_missing")))
        elif st["would_fire_on_self"]:
            panel.body.addWidget(_pill_cell("error", self.t("selftest_fail")))
            for o in st["offending"][:50]:
                panel.body.addWidget(_label("•  " + o, hint=True, wrap=True))
        else:
            panel.body.addWidget(_pill_cell("ok", self.t("selftest_pass")))

    # ---- write flows: create / edit a Tier-1 policy (AR-D3) ---------------

    def _open_policy_form(self, channel) -> None:
        aid, host = self._own_agent()
        if not aid:
            self._notify(self.t("need_own_agent"))
            return
        editing = bool(channel and channel.get("config_id"))
        state = {"preview": None, "gen": 0}

        page = Page()
        page.add(back_link(self.ctx.t("title"), self._pop))
        page.add(PageHeader(
            self.t("edit_policy") if editing else self.t("new_policy"),
            self.t("policy_for", host=host or aid),
        ))

        page.section(self.t("form_details"))
        name = QLineEdit((channel or {}).get("name", "") if editing else "")
        name.setPlaceholderText(self.t("name_placeholder"))
        name.setMinimumHeight(34)
        page.add(self._field(self.t("field_name"), name))

        execu = QComboBox()
        for ex in ar.EXECUTABLES:
            execu.addItem(ex, ex)
        if editing:
            idx = execu.findData((channel or {}).get("executable"))
            if idx >= 0:
                execu.setCurrentIndex(idx)
        page.add(self._field(self.t("field_executable"), execu))

        trigger = QLineEdit()
        trigger.setPlaceholderText(self.t("trigger_placeholder"))
        trigger.setMinimumHeight(34)
        page.add(self._field(self.t("field_trigger"), trigger, hint=self.t("trigger_hint")))

        timeout = QSpinBox()
        timeout.setRange(1, 86400)
        timeout.setSuffix(" s")
        try:
            timeout.setValue(int((channel or {}).get("stateful_timeout") or 600))
        except (TypeError, ValueError):
            timeout.setValue(600)
        page.add(self._field(self.t("field_timeout"), timeout, hint=self.t("timeout_hint")))

        page.spacing(6)
        page.add(_plain(muted(self.t("location_note", host=host or aid, agent=aid))))
        page.add(_plain(muted(self.t("gitops_note"))))

        page.section(self.t("section_preview"))
        panel = Card()
        self._fill_panel(panel, None, None)
        page.add(panel)

        preview_btn = QPushButton(self.t("run_preview"))
        preview_btn.setObjectName("SurfaceBtn")
        preview_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        save = HoldButton(self.t("hold_save"))
        save.setEnabled(False)
        gate = _plain(muted(self.t("gate_run_first")))
        result = _plain(muted(""))
        result.hide()

        def build():
            return ar.build_policy(
                name=name.text(), executable=execu.currentData(),
                trigger=trigger.text(), stateful_timeout=timeout.value(),
                agent_id=aid,
                config_id=(channel or {}).get("config_id") if editing else None,
            )

        def invalidate(*_a):
            # A field changed: the shown preview no longer describes what would
            # be written. Bump the generation so an in-flight preview result is
            # ignored, and re-lock the save (TOCTOU on the self-test gate).
            state["gen"] += 1
            state["preview"] = None
            save.setEnabled(False)
            gate.setText(self.t("gate_rerun"))

        def do_preview():
            err = ar.validate_policy(
                name=name.text(), executable=execu.currentData(),
                trigger=trigger.text(), stateful_timeout=timeout.value(), agent_id=aid)
            if err:
                self._fill_panel(panel, None, err)
                save.setEnabled(False)
                gate.setText(self.t("gate_fix", error=err))
                return
            preview_btn.setEnabled(False)
            self._fill_panel(panel, None, None, loading=True)
            gate.setText(self.t("gate_previewing"))
            payload = build()
            gen = state["gen"]

            def work():
                data, perr = ar.preview(payload)
                self._after(lambda: done(data, perr, gen))

            threading.Thread(target=work, daemon=True, name="ar-preview").start()

        def done(data, perr, gen):
            try:
                preview_btn.setEnabled(True)
                if gen != state["gen"]:
                    return  # a field changed after this preview started: stale
                state["preview"] = data
                self._fill_panel(panel, data, perr)
                block = perr or ar.preview_blocks_save(data)
                save.setEnabled(not block)
                gate.setText(self.t("gate_blocked") if block else self.t("gate_ready"))
                if data:
                    save.set_duration_ms(hold_duration_ms(data.get("count", 1)))
            except RuntimeError:
                pass

        def commit():
            if ar.preview_blocks_save(state["preview"]):
                return
            save.setEnabled(False)
            preview_btn.setEnabled(False)
            result.setText(self.t("saving"))
            result.show()
            payload = build()

            def work():
                if editing:
                    _data, werr = ar.update_policy(channel["config_id"], payload)
                else:
                    _data, werr = ar.create_policy(payload)
                self._after(lambda: saved(werr))

            threading.Thread(target=work, daemon=True, name="ar-save").start()

        def saved(werr):
            if werr:
                try:
                    result.setText(self.t("save_failed", error=werr))
                    preview_btn.setEnabled(True)
                except RuntimeError:
                    pass
                return
            self._reload()
            self._pop()

        preview_btn.clicked.connect(do_preview)
        save.confirmed.connect(commit)
        name.textChanged.connect(invalidate)
        trigger.textChanged.connect(invalidate)
        execu.currentIndexChanged.connect(invalidate)
        timeout.valueChanged.connect(invalidate)

        actions = QHBoxLayout()
        actions.setSpacing(8)
        actions.addWidget(preview_btn)
        actions.addWidget(save)
        actions.addStretch(1)
        page.spacing(14)
        page.add_layout(actions)
        page.spacing(6)
        page.add(gate)
        page.spacing(10)
        page.add(result)
        page.stretch()
        self._push(page.widget)

    # ---- write flows: delete a policy -------------------------------------

    def _open_delete(self, channel) -> None:
        page = Page()
        page.add(back_link(self.ctx.t("title"), self._pop))
        page.add(PageHeader(self.t("delete_policy"), channel.get("name", "")))
        page.section(self.t("section_remove"))
        page.add(_plain(muted(self.t("delete_body", name=channel.get("name", "")))))
        page.spacing(12)
        confirm = HoldButton(self.t("hold_delete"))
        result = _plain(muted(""))
        result.hide()

        def commit():
            confirm.setEnabled(False)
            result.setText(self.t("deleting"))
            result.show()

            def work():
                _data, werr = ar.delete_policy(channel.get("config_id"))
                self._after(lambda: done(werr))

            threading.Thread(target=work, daemon=True, name="ar-delete").start()

        def done(werr):
            # NOT_AVAILABLE here is ambiguous (route undeployed vs config gone),
            # so it is surfaced as a failure rather than reported as a delete
            # that may not have happened. Only a clean 2xx counts as removed.
            if werr:
                try:
                    confirm.setEnabled(True)
                    reason = self.t("not_available_short") if werr == NOT_AVAILABLE else werr
                    result.setText(self.t("delete_failed", error=reason))
                except RuntimeError:
                    pass
                return
            self._reload()
            self._pop()

        confirm.confirmed.connect(commit)
        page.add(confirm)
        page.spacing(10)
        page.add(result)
        page.stretch()
        self._push(page.widget)

    # ---- write flows: fire an AR ad-hoc (AR-D7) ---------------------------

    def _open_fire_form(self, executable: str = "block-ip", target: str = "") -> None:
        aid, host = self._own_agent()
        if not aid:
            self._notify(self.t("need_own_agent"))
            return
        state = {"preview": None, "gen": 0}

        page = Page()
        page.add(back_link(self.ctx.t("title"), self._pop))
        page.add(PageHeader(self.t("fire_now"), self.t("fire_for", host=host or aid)))

        page.section(self.t("form_details"))
        execu = QComboBox()
        for ex in ar.EXECUTABLES:
            execu.addItem(ex, ex)
        idx = execu.findData(executable)
        if idx >= 0:
            execu.setCurrentIndex(idx)
        page.add(self._field(self.t("field_executable"), execu))

        target_field = QLineEdit(target)
        target_field.setMinimumHeight(34)
        page.add(self._field(self.t("field_target"), target_field))

        def target_hint():
            key = "target_user_hint" if execu.currentData() == "disable-account" \
                else "target_ip_hint"
            target_field.setPlaceholderText(self.t(key))

        target_hint()
        page.spacing(6)
        page.add(_plain(muted(self.t("location_note", host=host or aid, agent=aid))))

        page.section(self.t("section_preview"))
        panel = Card()
        self._fill_panel(panel, None, None)
        page.add(panel)

        preview_btn = QPushButton(self.t("run_preview"))
        preview_btn.setObjectName("SurfaceBtn")
        preview_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        fire_btn = HoldButton(self.t("hold_fire"))
        fire_btn.setEnabled(False)
        gate = _plain(muted(self.t("gate_run_first")))
        result = _plain(muted(""))
        result.hide()

        def invalidate(*_a):
            # The target/executable changed: the shown preview no longer
            # describes what would be fired. Re-lock and tell the user to
            # Preview again (so they aren't left holding a dead button).
            state["gen"] += 1
            state["preview"] = None
            fire_btn.setEnabled(False)
            gate.setText(self.t("gate_rerun"))

        def do_preview():
            err = ar.validate_fire(aid, execu.currentData(), target_field.text())
            if err:
                self._fill_panel(panel, None, err)
                fire_btn.setEnabled(False)
                gate.setText(self.t("gate_fix", error=err))
                return
            preview_btn.setEnabled(False)
            self._fill_panel(panel, None, None, loading=True)
            gate.setText(self.t("gate_previewing"))
            # build_fire already pins location=defined-agent, so the preview
            # and the fire below are the same payload shape.
            payload = ar.build_fire(aid, execu.currentData(), target_field.text())
            gen = state["gen"]

            def work():
                data, perr = ar.preview(payload)
                self._after(lambda: done(data, perr, gen))

            threading.Thread(target=work, daemon=True, name="ar-fire-preview").start()

        def done(data, perr, gen):
            try:
                preview_btn.setEnabled(True)
                if gen != state["gen"]:
                    return  # a field changed after this preview started: stale
                state["preview"] = data
                self._fill_panel(panel, data, perr)
                block = perr or ar.preview_blocks_save(data)
                fire_btn.setEnabled(not block)
                gate.setText(self.t("gate_blocked") if block else self.t("gate_ready"))
                if data:
                    fire_btn.set_duration_ms(hold_duration_ms(data.get("count", 1)))
            except RuntimeError:
                pass

        def commit():
            if ar.preview_blocks_save(state["preview"]):
                return
            fire_btn.setEnabled(False)
            preview_btn.setEnabled(False)
            result.setText(self.t("firing"))
            result.show()
            ex, tgt = execu.currentData(), target_field.text()

            def work():
                _data, werr = ar.fire(aid, ex, tgt)
                self._after(lambda: fired(werr))

            threading.Thread(target=work, daemon=True, name="ar-fire").start()

        def fired(werr):
            if werr:
                try:
                    result.setText(self.t("fire_failed", error=werr))
                    preview_btn.setEnabled(True)
                except RuntimeError:
                    pass
                return
            self._reload()
            self._pop()

        preview_btn.clicked.connect(do_preview)
        fire_btn.confirmed.connect(commit)
        execu.currentIndexChanged.connect(lambda *_: (target_hint(), invalidate()))
        target_field.textChanged.connect(invalidate)

        actions = QHBoxLayout()
        actions.setSpacing(8)
        actions.addWidget(preview_btn)
        actions.addWidget(fire_btn)
        actions.addStretch(1)
        page.spacing(14)
        page.add_layout(actions)
        page.spacing(6)
        page.add(gate)
        page.spacing(10)
        page.add(result)
        page.stretch()
        self._push(page.widget)

    # ---- write flows: stop an active AR (AR-D7) ---------------------------

    def _open_stop(self, e) -> None:
        page = Page()
        page.add(back_link(self.ctx.t("title"), self._pop))
        page.add(PageHeader(self.t("stop_title"), e.get("target", "")))
        page.section(self.t("section_remove"))
        kv = KVList()
        kv.add(self.t("field_target"), e.get("target") or "—")
        kv.add(self.t("field_executable"), e.get("executable") or "—")
        kv.add(self.t("col_agent"), e.get("agent_name") or e.get("agent_id") or "—")
        for lbl in kv.findChildren(QLabel):
            lbl.setTextFormat(Qt.TextFormat.PlainText)
        page.add(kv)
        page.spacing(12)
        confirm = HoldButton(self.t("hold_stop"))
        result = _plain(muted(""))
        result.hide()

        def commit():
            confirm.setEnabled(False)
            result.setText(self.t("stopping"))
            result.show()

            def work():
                _data, werr = ar.stop(e.get("agent_id"), e.get("executable"),
                                      e.get("target"))
                self._after(lambda: done(werr))

            threading.Thread(target=work, daemon=True, name="ar-stop").start()

        def done(werr):
            if werr:
                try:
                    confirm.setEnabled(True)
                    result.setText(self.t("stop_failed", error=werr))
                except RuntimeError:
                    pass
                return
            self._reload()
            self._pop()

        confirm.confirmed.connect(commit)
        page.add(confirm)
        page.spacing(10)
        page.add(result)
        page.stretch()
        self._push(page.widget)
