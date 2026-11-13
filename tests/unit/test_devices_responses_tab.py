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
     "status": "completed", "finding_id": "fnd-abc", "monitor_id": "mon-1", "config_id": "cfg-1"},
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
