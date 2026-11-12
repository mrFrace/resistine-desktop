"""Element session name for this install (plugins/login/device_name.py)."""

import pytest

from plugins.login import cross_signing as cs
from plugins.login import device_name as dn

pytestmark = pytest.mark.unit


def test_display_name():
    assert dn.display_name("drake-laptop", "Linux") == "Phoenix Desktop · drake-laptop (Linux)"
    assert dn.display_name("mac", "Darwin") == "Phoenix Desktop · mac (macOS)"
    assert dn.display_name("", "Plan9") == "Phoenix Desktop"
    name = dn.display_name("evil\x1b[31m\n" + "x" * 200, "Windows")
    assert "\x1b" not in name and "\n" not in name and len(name) < 100


@pytest.fixture
def hs(monkeypatch):
    calls = []
    state = {"name": "Phoenix Desktop on Unknown device", "error": None}

    def fake(method, path, body=None):
        calls.append((method, path, body))
        if state["error"]:
            raise state["error"]
        return 200, ({"display_name": state["name"]} if method == "GET" else {})

    monkeypatch.setattr(cs, "_request", fake)
    monkeypatch.setattr(dn.settings, "get", lambda ns, k, d=None: "PHX_AAAAAAAAAAAAAAAA"
                        if (ns, k) == ("auth", "device_id") else d)
    return calls, state


def test_sets_the_name_when_it_differs(hs):
    calls, _ = hs
    assert dn.name_this_device() is True
    assert calls[-1] == ("PUT", "/_matrix/client/v3/devices/PHX_AAAAAAAAAAAAAAAA",
                         {"display_name": dn.display_name()})


def test_no_write_when_already_named(hs):
    calls, state = hs
    state["name"] = dn.display_name()
    assert dn.name_this_device() is True
    assert [c[0] for c in calls] == ["GET"]


def test_failure_is_quiet(hs):
    _, state = hs
    state["error"] = cs.VerificationError("server", "HTTP 403")
    assert dn.name_this_device() is False
    state["error"] = RuntimeError("boom")
    assert dn.name_this_device() is False


def test_no_device_no_request(monkeypatch):
    monkeypatch.setattr(dn.settings, "get", lambda *a, **k: None)
    monkeypatch.setattr(cs, "_request", lambda *a, **k: pytest.fail("no request"))
    assert dn.name_this_device() is False
