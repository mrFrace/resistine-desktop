"""Devices → Sessions tab (plugins/devices/sessions_tab.py), offscreen."""

import time
from datetime import datetime, timedelta, timezone

import pytest

pytest.importorskip("PyQt6")

from PyQt6.QtWidgets import QApplication, QLabel  # noqa: E402

from gui.page_kit import MenuRow  # noqa: E402
from plugins.devices import sessions_api, sessions_tab  # noqa: E402
from plugins.login import cross_signing as cs  # noqa: E402

pytestmark = pytest.mark.unit


def _iso(delta: timedelta) -> str:
    return (datetime.now(timezone.utc) - delta).strftime("%Y-%m-%dT%H:%M:%SZ")


ROWS = {"devices": [
    {"device_id": "PHX_QS3ZBL42VSZ6YQAJ", "current": True, "kind": "phoenix",
     "session": {"client_name": "Phoenix Desktop", "last_active_at": _iso(timedelta(0))},
     "vpn": {"hostname": "drake-laptop", "address": "10.42.20.14"},
     "agent": {"agent_id": "017", "agent_name": "drake-laptop-ab12", "linked": False}},
    {"device_id": "PHX_BBBBBBBBBBBBBBBB", "current": False, "kind": "phoenix",
     "session": {"client_name": "Phoenix Desktop", "last_active_at": _iso(timedelta(days=20))},
     "vpn": {"hostname": "<b>win-box</b>", "address": "10.42.20.7"},
     "agent": {"agent_id": "021", "agent_name": "win-box", "linked": False}},
    {"device_id": "ABCDEFGHIJ", "current": False, "kind": "matrix",
     "session": {"client_name": "Element X", "user_agent": "Element X/26.11 (iPhone15,2; iOS 18)",
                 "last_active_at": _iso(timedelta(minutes=3))}},
    {"device_id": "PHX_AAAAAAAAAAAAAAAA", "current": False, "kind": "phoenix",
     "session": None, "vpn": {"hostname": "old-box", "address": "10.42.20.9"}},
]}


@pytest.fixture(scope="module")
def qapp():
    return QApplication.instance() or QApplication(["test"])


class _App:
    def after(self, ms, fn, *a):
        fn(*a)


class _Ctx:
    def __init__(self):
        self.app = _App()
        self.pushed = []
        self.popped = 0

    @staticmethod
    def t(key, **fmt):
        from plugins.devices.main import _t
        return _t(key, **fmt)

    def push(self, page):
        self.pushed.append(page)

    def pop(self):
        self.popped += 1


@pytest.fixture
def tab(qapp, monkeypatch):
    def build(status=cs.UNVERIFIED, rows=ROWS, error=None):
        monkeypatch.setattr(sessions_api, "list_devices",
                            lambda: (sessions_api.parse_devices(rows) if rows else None, error))
        monkeypatch.setattr(cs, "query_own_keys", lambda: None)
        monkeypatch.setattr(cs, "device_status", lambda own, dev: status)
        monkeypatch.setattr(sessions_tab.threading, "Thread", _SyncThread)
        return sessions_tab.SessionsTab(_Ctx())
    return build


class _SyncThread:
    def __init__(self, target, **kw):
        self.target = target

    def start(self):
        self.target()


def _rows(widget):
    return [r for r in widget.findChildren(MenuRow)]


def _titles(widget):
    return [r.text() for r in _rows(widget)]


def test_grouping_and_order(tab):
    t = tab()
    titles = _titles(t.widget)
    assert titles[0] == "drake-laptop (this device)"
    assert titles[1] == t.t("verify")
    assert titles[2:] == ["<b>win-box</b>", "Element X · iPhone", "old-box", t.t("manage_browser")]
    headings = [lbl.text() for lbl in t.widget.findChildren(QLabel) if lbl.objectName() == "Section"]
    assert headings == [t.t(f"group_{k}").upper() for k in ("this", "phoenix", "apps", "gone", "more")]


def test_server_strings_are_plain_text(tab):
    t = tab()
    row = next(r for r in _rows(t.widget) if r.text() == "<b>win-box</b>")
    from PyQt6.QtCore import Qt
    assert row._title.textFormat() == Qt.TextFormat.PlainText


def test_this_device_has_no_remove_and_others_open_a_page(tab):
    t = tab()
    this = _rows(t.widget)[0]
    this.clicked.emit()
    assert t.ctx.pushed == []
    other = next(r for r in _rows(t.widget) if r.text() == "<b>win-box</b>")
    other.clicked.emit()
    [page] = t.ctx.pushed
    assert any(r.text() == t.t("remove") for r in page.findChildren(MenuRow))


def test_verify_row_only_when_unverified(tab):
    assert t_has_verify(tab(status=cs.VERIFIED)) is False
    assert t_has_verify(tab(status=cs.UNVERIFIED)) is True
    no_cs = tab(status=cs.NO_CROSS_SIGNING)
    assert t_has_verify(no_cs) is False
    texts = [lbl.text() for lbl in no_cs.widget.findChildren(QLabel)]
    assert no_cs.t("no_cross_signing") in texts


def t_has_verify(t):
    return t.t("verify") in _titles(t.widget)


def test_removal_text_names_what_goes(tab):
    t = tab()
    rows = {r.device_id: r for r in t._rows}
    phx = t.removal_text(rows["PHX_BBBBBBBBBBBBBBBB"])
    assert "10.42.20.7" in phx and "021" in phx and "<b>win-box</b>" in phx
    gone = t.removal_text(rows["PHX_AAAAAAAAAAAAAAAA"])
    assert "already signed out" in gone and "10.42.20.9" in gone


def test_recent_session_warning_only_for_other_apps(tab):
    t = tab()
    rows = {r.device_id: r for r in t._rows}
    warn = t.recent_warning(rows["ABCDEFGHIJ"])
    assert "Element X · iPhone" in warn and "3 min ago" in warn
    assert t.recent_warning(rows["PHX_BBBBBBBBBBBBBBBB"]) == ""
    old = sessions_api.DeviceRow("OLDPHONE", session=sessions_api.Session(
        client_name="Element", last_active_at=_iso(timedelta(days=30))))
    assert t.recent_warning(old) == ""


def test_remove_refreshes_and_pops(tab, monkeypatch):
    t = tab()
    removed = []
    monkeypatch.setattr(sessions_api, "remove_device",
                        lambda dev: (removed.append(dev), (True, None))[1])
    next(r for r in _rows(t.widget) if r.text() == "old-box").clicked.emit()
    page = t.ctx.pushed[-1]
    next(r for r in page.findChildren(MenuRow) if r.text() == t.t("remove")).clicked.emit()
    assert removed == ["PHX_AAAAAAAAAAAAAAAA"]
    assert t.ctx.popped == 1


def test_remove_failure_keeps_the_page(tab, monkeypatch):
    t = tab()
    monkeypatch.setattr(sessions_api, "remove_device",
                        lambda dev: (False, "the VPN server is unavailable, try again later"))
    next(r for r in _rows(t.widget) if r.text() == "old-box").clicked.emit()
    page = t.ctx.pushed[-1]
    next(r for r in page.findChildren(MenuRow) if r.text() == t.t("remove")).clicked.emit()
    assert t.ctx.popped == 0
    assert any("VPN server is unavailable" in lbl.text() for lbl in page.findChildren(QLabel))
    assert "old-box" in _titles(t.widget)


def test_not_available_and_error_states(tab):
    from plugins.devices.api import NOT_AVAILABLE

    t = tab(rows=None, error=NOT_AVAILABLE)
    texts = [lbl.text() for lbl in t.widget.findChildren(QLabel)]
    assert t.t("not_available") in texts
    t = tab(rows=None, error="http 500")
    assert any("http 500" in lbl.text() for lbl in t.widget.findChildren(QLabel))


def test_verify_page_clears_the_field_and_maps_errors(tab, monkeypatch):
    from PyQt6.QtWidgets import QLineEdit, QPushButton

    t = tab()
    seen = []

    def verify(secret):
        seen.append(secret)
        raise cs.VerificationError("wrong_key")

    monkeypatch.setattr(cs, "verify_this_device", verify)
    t._open_verify()
    page = t.ctx.pushed[-1]
    field = page.findChild(QLineEdit)
    assert field.echoMode() == QLineEdit.EchoMode.Password
    field.setText("EsTE s92N")
    page.findChild(QPushButton).click()
    assert seen == ["EsTE s92N"]
    assert field.text() == ""
    assert any(lbl.text() == t.t("err_wrong_key") for lbl in page.findChildren(QLabel))


def test_every_verification_error_code_has_text(tab):
    t = tab()
    for code in ("not_a_recovery_key", "wrong_key", "no_cross_signing", "identity_mismatch",
                 "no_device_keys", "not_connected", "device_key_mismatch", "upload_failed",
                 "server", "network", "not_signed_in", "unsupported", "unknown"):
        assert t.verify_error(code) != t.t("err_unknown") or code == "unknown"
    assert t.verify_error("<script>") == t.t("err_unknown")
    assert t.verify_error("made_up_code") == t.t("err_unknown")


def test_os_and_ago_helpers():
    assert sessions_tab.os_of("Element X/26.11 (iPhone15,2; iOS 18)") == "iPhone"
    assert sessions_tab.os_of("Mozilla/5.0 (Windows NT 10.0)") == "Windows"
    assert sessions_tab.os_of("") == ""
    now = time.time()
    assert sessions_tab.seconds_since("not a date") is None
    assert 0 <= sessions_tab.seconds_since(_iso(timedelta(minutes=5)), now) - 300 < 5
