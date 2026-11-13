"""Devices → Responses tab (plugins/devices/responses_tab.py), offscreen."""

import pytest

pytest.importorskip("PyQt6")

from PyQt6.QtCore import Qt  # noqa: E402
from PyQt6.QtWidgets import QApplication, QLabel  # noqa: E402

from plugins.devices import active_response_api as ar  # noqa: E402
from plugins.devices import responses_tab  # noqa: E402
from plugins.devices.api import NOT_AVAILABLE  # noqa: E402

pytestmark = pytest.mark.unit

CHANNELS = [
    {"config_id": "cfg-1", "name": "ar-smoke-test", "executable": "firewall-drop",
     "location": "all", "agent_id": "", "type": "stateful", "stateful_timeout": "600",
     "is_enabled": True, "affects_me": True},
    {"config_id": "cfg-2", "name": "disable-bad-user", "executable": "disable-account",
     "location": "009", "agent_id": "009", "type": "stateless", "stateful_timeout": "",
     "is_enabled": True, "affects_me": False},
]
MONITORS = [
    {"monitor_id": "mon-1", "name": "ar_monitor_bruteforce", "enabled": True,
     "indices": [], "queries": [], "trigger_condition": "", "destination_id": "cfg-1"},
]
EXECS = [
    {"agent_id": "004", "agent_name": "lab-host", "executable": "firewall-drop",
     "command": "enable", "target": "203.0.113.7", "timestamp": "2026-11-13T10:00:00Z",
     "status": "completed", "finding_id": "fnd-abc", "rule_title": "SSH brute force",
     "monitor_id": "mon-1", "config_id": "cfg-1"},
]

ROWS = [
    {"agent_id": "004", "hostname": "lab-host", "this_machine": True},
    {"agent_id": "009", "hostname": "win-box", "this_machine": False},
]


@pytest.fixture(scope="module")
def qapp():
    return QApplication.instance() or QApplication(["test"])


class _App:
    def after(self, ms, fn, *a):
        fn(*a)


class _SyncThread:
    def __init__(self, target, **kw):
        self.target = target

    def start(self):
        self.target()


class _Ctx:
    def __init__(self, scope=None):
        self.app = _App()
        self._scope = scope
        self.pushed = []
        self.notes = []

    @staticmethod
    def t(key, **fmt):
        from plugins.devices.main import _t
        return _t(key, **fmt)

    def scope(self):
        return self._scope

    def rows(self):
        return list(ROWS)

    def scoped_rows(self):
        if self._scope is None:
            return list(ROWS)
        return [r for r in ROWS if r["hostname"] == self._scope]

    def push(self, page):
        self.pushed.append(page)

    def pop(self):
        if self.pushed:
            self.pushed.pop()


# make the test app able to raise a notification (used by write flows)
_App.show_notification = lambda self, text, type=None: None


@pytest.fixture
def tab(qapp, monkeypatch):
    def build(channels=CHANNELS, monitors=MONITORS, execs=EXECS,
              channels_err=None, execs_err=None, scope=None):
        exec_calls = []

        def fetch_execs(agent_id=None):
            exec_calls.append(agent_id)
            return (execs if execs is not None else None), execs_err

        monkeypatch.setattr(ar, "fetch_channels",
                            lambda: ((channels if channels is not None else None), channels_err))
        monkeypatch.setattr(ar, "fetch_monitors", lambda: (monitors or [], None))
        monkeypatch.setattr(ar, "fetch_executions", fetch_execs)
        monkeypatch.setattr(responses_tab.threading, "Thread", _SyncThread)
        t = responses_tab.ResponsesTab(_Ctx(scope))
        t._exec_calls = exec_calls
        return t
    return build


def _labels(widget):
    return [lbl.text() for lbl in widget.findChildren(QLabel)]


def _headings(widget):
    return [lbl.text() for lbl in widget.findChildren(QLabel)
            if lbl.objectName() == "Section"]


def test_three_sections_render_with_data(tab):
    t = tab()
    assert _headings(t.widget) == [
        t.t("section_policies").upper(),
        t.t("section_ledger").upper(),
        t.t("section_executions").upper(),
    ]
    labels = _labels(t.widget)
    assert "ar-smoke-test" in labels and "firewall-drop" in labels
    # "triggered by" provenance resolved from the monitor's destination_id
    assert "ar_monitor_bruteforce" in labels


def test_affects_me_badge_shown(tab):
    t = tab()
    assert t.t("affects_you") in _labels(t.widget)


def test_empty_state_when_nothing_configured(tab):
    t = tab(channels=[], monitors=[], execs=[])
    assert t.t("empty") in _labels(t.widget)
    assert _headings(t.widget) == []


def test_not_available_degrades_to_empty_state(tab):
    t = tab(channels=None, channels_err=NOT_AVAILABLE, execs=None, execs_err=NOT_AVAILABLE)
    assert t.t("empty") in _labels(t.widget)


def test_hard_error_with_no_data_is_shown(tab):
    t = tab(channels=None, channels_err="http 503", execs=None, execs_err="http 503")
    assert any("http 503" in x for x in _labels(t.widget))


def test_executions_unfiltered_when_scope_is_all(tab):
    t = tab(scope=None)
    assert t._exec_calls == [None]


def test_executions_filtered_by_selected_device(tab):
    t = tab(scope="win-box")
    assert t._exec_calls == ["009"]


def test_consent_ledger_verdict_for_selected_device(tab):
    # cfg-2 is pinned to agent 009; selecting win-box (009) makes it "Yes",
    # cfg-1 (location all) is always "Yes".
    t = tab(scope="win-box")
    labels = _labels(t.widget)
    assert t.t("ledger_for", host="win-box") in labels
    assert t.t("run_yes") in labels


def test_set_scope_refetches_executions_only(tab):
    t = tab(scope=None)
    assert t._exec_calls == [None]
    t.ctx._scope = "lab-host"
    t.set_scope()
    assert t._exec_calls == [None, "004"]


def test_server_strings_are_plain_text(tab):
    t = tab()
    name = next(lbl for lbl in t.widget.findChildren(QLabel) if lbl.text() == "ar-smoke-test")
    assert name.textFormat() == Qt.TextFormat.PlainText


# ---- P2 additions ---------------------------------------------------------

DISABLED_CHANNELS = [
    {"config_id": "cfg-off", "name": "off-policy", "executable": "block-ip",
     "location": "all", "agent_id": "", "type": "stateful", "stateful_timeout": "600",
     "is_enabled": False, "affects_me": True},
]


def test_hold_duration_scales_with_blast_radius():
    assert responses_tab.hold_duration_ms(1) == responses_tab.HOLD_BASE_MS
    assert responses_tab.hold_duration_ms(5) > responses_tab.hold_duration_ms(1)
    assert responses_tab.hold_duration_ms(10_000) == responses_tab.HOLD_MAX_MS


def test_ledger_disabled_policy_shows_no(tab):
    # AR-D8a: a disabled channel (location=all) must read "No (off)", not Yes.
    t = tab(channels=DISABLED_CHANNELS, monitors=[], execs=[], scope="lab-host")
    labels = _labels(t.widget)
    assert t.t("run_no_disabled") in labels
    assert t.t("run_yes") not in labels


def test_new_policy_and_fire_buttons_present(tab):
    from PyQt6.QtWidgets import QPushButton
    t = tab(scope="lab-host")
    btns = [b.text() for b in t.widget.findChildren(QPushButton)]
    assert t.t("new_policy") in btns
    assert t.t("fire_now") in btns
    assert t.t("gitops_note") in _labels(t.widget)


def test_new_policy_disabled_without_own_agent(qapp, monkeypatch):
    from PyQt6.QtWidgets import QPushButton
    # a scope whose row carries no agent_id -> cannot create a defined-agent policy
    rows = [{"agent_id": "", "hostname": "no-agent", "this_machine": False}]
    monkeypatch.setattr(responses_tab.threading, "Thread", _SyncThread)
    monkeypatch.setattr(ar, "fetch_channels", lambda: (CHANNELS, None))
    monkeypatch.setattr(ar, "fetch_monitors", lambda: (MONITORS, None))
    monkeypatch.setattr(ar, "fetch_executions", lambda agent_id=None: (EXECS, None))

    class C(_Ctx):
        def rows(self):
            return list(rows)

        def scoped_rows(self):
            return [r for r in rows if r["hostname"] == self._scope]

    t = responses_tab.ResponsesTab(C("no-agent"))
    new_btn = next(b for b in t.widget.findChildren(QPushButton)
                   if b.text() == t.t("new_policy"))
    assert new_btn.isEnabled() is False


def test_open_policy_form_pushes_a_form(tab):
    t = tab(scope="lab-host")
    t._open_policy_form(None)
    assert t.ctx.pushed, "the create form should be pushed onto the stack"
    form = t.ctx.pushed[-1]
    labels = _labels(form)
    assert t.t("field_executable") in labels
    assert t.t("field_timeout") in labels
    # the self-test gate starts blocked: no hold-to-save until a clean preview
    saves = [w for w in form.findChildren(responses_tab.HoldButton)
             if w.text().startswith(t.t("hold_save"))]
    assert saves and saves[0].isEnabled() is False


def test_fill_panel_blocks_save_on_self_hit(tab):
    t = tab(scope="lab-host")
    card = responses_tab.Card()
    failed = ar.parse_preview({
        "count": 1, "included": [{"agent_id": "004"}],
        "self_test": {"would_fire_on_self": True, "offending": ["10.42.10.252"]},
    })
    t._fill_panel(card, failed, None)
    labels = [lbl.text() for lbl in card.findChildren(QLabel)]
    assert t.t("selftest_fail") in labels
    assert ar.preview_blocks_save(failed) is not None


def test_open_fire_form_pushes_a_form(tab):
    t = tab(scope="lab-host")
    t._open_fire_form()
    assert t.ctx.pushed
    labels = _labels(t.ctx.pushed[-1])
    assert t.t("field_target") in labels


def _find(form, cls, pred=lambda w: True):
    return next(w for w in form.findChildren(cls) if pred(w))


def _gate_label(t, form):
    from PyQt6.QtWidgets import QLabel
    gate_texts = {t.t(k) for k in ("gate_run_first", "gate_rerun", "gate_previewing",
                                   "gate_ready", "gate_blocked")}
    # gate_fix carries a placeholder, so match by prefix too
    return next(l for l in form.findChildren(QLabel)
                if l.text() in gate_texts or l.text().startswith(t.t("gate_fix", error="")[:10]))


def test_fire_gate_unlocks_on_clean_preview_and_relocks_on_edit(tab, monkeypatch):
    from PyQt6.QtWidgets import QLineEdit, QPushButton
    good = ar.parse_preview({"count": 1, "included": [{"agent_id": "004"}],
                             "self_test": {"would_fire_on_self": False, "offending": []}})
    monkeypatch.setattr(ar, "preview", lambda payload: (good, None))

    t = tab(scope="lab-host")
    t._open_fire_form()
    form = t.ctx.pushed[-1]
    target = _find(form, QLineEdit)
    preview_btn = _find(form, QPushButton, lambda b: b.text() == t.t("run_preview"))
    fire_btn = _find(form, responses_tab.HoldButton)
    gate = _gate_label(t, form)

    # initial: locked, told to preview
    assert fire_btn.isEnabled() is False
    assert gate.text() == t.t("gate_run_first")

    # a clean preview unlocks the hold-to-fire
    target.setText("203.0.113.7")
    preview_btn.click()
    assert fire_btn.isEnabled() is True
    assert gate.text() == t.t("gate_ready")

    # editing the target re-locks it and tells the user to preview again (the
    # live-tested bug: fire must not stay armed against an un-previewed target)
    target.setText("203.0.113.8")
    assert fire_btn.isEnabled() is False
    assert gate.text() == t.t("gate_rerun")


def test_fire_gate_stays_locked_when_self_test_would_fire(tab, monkeypatch):
    from PyQt6.QtWidgets import QLineEdit, QPushButton
    bad = ar.parse_preview({"count": 1, "included": [{"agent_id": "004"}],
                            "self_test": {"would_fire_on_self": True, "offending": ["10.42.10.252"]}})
    monkeypatch.setattr(ar, "preview", lambda payload: (bad, None))
    t = tab(scope="lab-host")
    t._open_fire_form()
    form = t.ctx.pushed[-1]
    _find(form, QLineEdit).setText("10.42.10.252")
    _find(form, QPushButton, lambda b: b.text() == t.t("run_preview")).click()
    assert _find(form, responses_tab.HoldButton).isEnabled() is False
    assert _gate_label(t, form).text() == t.t("gate_blocked")


def test_sections_do_not_leak_widgets_on_rerender(tab):
    from PyQt6.QtWidgets import QLabel
    t = tab(scope="lab-host")

    def live_headings():
        return sum(1 for l in t.widget.findChildren(QLabel)
                   if l.objectName() == "Section" and l.isVisibleTo(t.widget))

    assert live_headings() == 3
    t._render()
    t._render()
    # the AR-D3 section headers were added via addLayout; _clear must still
    # drop them, or stale headers/buttons pile up and paint behind the tables
    assert live_headings() == 3
