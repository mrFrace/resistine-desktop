"""Signed-in devices API client (plugins/devices/sessions_api.py)."""

from unittest.mock import MagicMock

import pytest

from plugins.devices import sessions_api as sa
from plugins.devices.api import NOT_AVAILABLE

pytestmark = pytest.mark.unit

FULL = {"devices": [
    {"device_id": "PHX_QS3ZBL42VSZ6YQAJ", "current": True, "kind": "phoenix",
     "session": {"client_name": "Phoenix Desktop", "user_agent": "Phoenix-Desktop/2026.11.06 (Linux)",
                 "created_at": "2026-11-11T19:02:29Z", "last_active_at": "2026-11-12T14:20:00Z",
                 "last_active_ip": "2603:6080::1"},
     "vpn": {"hostname": "drake-laptop", "address": "10.42.20.14"},
     "agent": {"agent_id": "017", "agent_name": "drake-laptop-ab12", "linked": False}},
    {"device_id": "ABCDEFGHIJ", "current": False, "kind": "matrix",
     "session": {"client_name": "Element X", "user_agent": "Element X/26.11.0 (iPhone15,2; iOS 18.1)"},
     "vpn": None, "agent": None},
    {"device_id": "PHX_AAAAAAAAAAAAAAAA", "current": False, "kind": "phoenix",
     "session": None, "vpn": {"hostname": "old-box", "address": "10.42.20.9"},
     "agent": {"agent_id": "009", "agent_name": "old-box", "linked": True}},
]}


def resp(status, body=None):
    r = MagicMock()
    r.status_code = status
    if isinstance(body, Exception):
        r.json.side_effect = body
    else:
        r.json.return_value = body if body is not None else {}
    return r


@pytest.fixture
def http(monkeypatch):
    from plugins.vpn import provisioning

    calls = []
    answers = []

    def fake(method, path, **kw):
        calls.append((method, path))
        a = answers.pop(0)
        if isinstance(a, Exception):
            raise a
        return a

    monkeypatch.setattr(provisioning, "_authorized_request", fake)
    return calls, answers


def test_parse_full():
    rows = sa.parse_devices(FULL)
    assert [r.device_id for r in rows] == ["PHX_QS3ZBL42VSZ6YQAJ", "ABCDEFGHIJ", "PHX_AAAAAAAAAAAAAAAA"]
    this, phone, gone = rows
    assert this.current and this.phoenix and this.signed_in
    assert this.vpn.address == "10.42.20.14" and this.agent.agent_id == "017"
    assert this.agent.linked is False
    assert not phone.phoenix and phone.vpn is None and phone.session.client_name == "Element X"
    assert not gone.signed_in and gone.agent.linked is True


def test_parse_minimal_and_garbage():
    rows = sa.parse_devices({"devices": [
        {"device_id": "XYZ"},
        {"device_id": "../../etc"},           # not an id: dropped
        {"device_id": 5}, "junk", None,
        {"device_id": "PHX_short", "kind": "phoenix"},   # claims phoenix, isn't: matrix
        {"device_id": "ABC", "current": "yes", "session": "x", "agent": {"linked": "true"}},
    ]})
    assert [r.device_id for r in rows] == ["XYZ", "PHX_short", "ABC"]
    assert rows[1].kind == "matrix"
    assert rows[2].current is False and rows[2].session is None
    assert rows[2].agent.linked is False
    assert sa.parse_devices("nope") == [] and sa.parse_devices({"devices": {}}) == []


def test_parse_strips_control_chars_and_caps_length():
    [row] = sa.parse_devices({"devices": [{"device_id": "A", "session": {
        "client_name": "Ele\x1bment" + "x" * 500, "user_agent": "u" * 1000}}]})
    assert "\x1b" not in row.session.client_name
    assert len(row.session.client_name) <= 120 and len(row.session.user_agent) <= 300


def test_list_ok(http):
    calls, answers = http
    answers.append(resp(200, FULL))
    rows, err = sa.list_devices()
    assert err is None and len(rows) == 3
    assert calls == [("GET", "/v1/devices")]


def test_list_not_deployed(http):
    http[1].append(resp(404))
    assert sa.list_devices() == (None, NOT_AVAILABLE)


def test_list_server_detail_and_bad_json(http):
    http[1].append(resp(503, {"detail": "device management is not configured"}))
    assert sa.list_devices() == (None, "device management is not configured")
    http[1].append(resp(200, ValueError("x")))
    assert sa.list_devices() == (None, "bad json")


def test_list_signed_out(http):
    from plugins.vpn.provisioning import ProvisioningError

    http[1].append(ProvisioningError("You're not signed in to Phoenix. Sign in again."))
    rows, err = sa.list_devices()
    assert rows is None and "not signed in" in err


@pytest.mark.parametrize("status,body,expected", [
    (204, None, (True, None)),
    (404, {"detail": "no such device"}, (False, "gone")),
    (409, {"detail": "this is the device you are using: sign out instead"},
     (False, "this is the device you are using: sign out instead")),
    (503, {"detail": "the VPN server is unavailable, try again later"},
     (False, "the VPN server is unavailable, try again later")),
])
def test_remove_statuses(http, status, body, expected):
    http[1].append(resp(status, body))
    assert sa.remove_device("ABCDEFGHIJ") == expected
    assert http[0] == [("DELETE", "/v1/devices/ABCDEFGHIJ")]


@pytest.mark.parametrize("bad", ["", "a/b", "../x", "a b", "x" * 65, "PHX_?", None])
def test_remove_validates_the_id_before_any_request(http, bad):
    assert sa.remove_device(bad) == (False, "invalid device id")
    assert http[0] == []
