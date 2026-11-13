"""Active Response API client (plugins/devices/active_response_api.py)."""

from unittest.mock import MagicMock

import pytest

from plugins.devices import active_response_api as ar
from plugins.devices.api import NOT_AVAILABLE

pytestmark = pytest.mark.unit

CHANNELS = {"active_responses": [
    {"config_id": "cfg-1", "name": "ar-smoke-test", "executable": "firewall-drop",
     "location": "local", "agent_id": "", "type": "stateful", "stateful_timeout": 600,
     "is_enabled": True, "affects_me": True},
    {"config_id": "cfg-2", "name": "disable-bad-user", "executable": "disable-account",
     "location": "004", "agent_id": "004", "type": "stateless", "stateful_timeout": None,
     "is_enabled": False, "affects_me": False},
]}

MONITORS = {"monitors": [
    {"monitor_id": "mon-1", "name": "ar_monitor_bruteforce", "enabled": True,
     "indices": ["wazuh-findings-v5-*"], "queries": ["rule.id:5710"],
     "trigger_condition": "ctx.results[0].hits.total.value > 0", "destination_id": "cfg-1"},
]}

EXECS = {"executions": [
    {"agent_id": "004", "agent_name": "lab-host", "executable": "firewall-drop",
     "command": "enable", "target": {"ip": "203.0.113.7"}, "@timestamp": "2026-11-13T10:00:00Z",
     "status": "completed", "finding_id": "fnd-abc", "monitor_id": "mon-1", "config_id": "cfg-1"},
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
        calls.append((method, path, kw.get("params")))
        a = answers.pop(0)
        if isinstance(a, Exception):
            raise a
        return a

    monkeypatch.setattr(provisioning, "_authorized_request", fake)
    return calls, answers


# ---- parsers --------------------------------------------------------------


def test_parse_channel_full_and_coercion():
    c = ar.parse_channel(CHANNELS["active_responses"][0])
    assert c["config_id"] == "cfg-1" and c["name"] == "ar-smoke-test"
    assert c["executable"] == "firewall-drop" and c["location"] == "local"
    assert c["stateful_timeout"] == "600" and c["is_enabled"] is True
    assert c["affects_me"] is True
    disabled = ar.parse_channel(CHANNELS["active_responses"][1])
    assert disabled["is_enabled"] is False and disabled["affects_me"] is False
    assert disabled["stateful_timeout"] == ""


def test_parse_channel_rejects_garbage_and_strips():
    assert ar.parse_channel("nope") is None
    assert ar.parse_channel({}) is None  # no id and no name
    c = ar.parse_channel({"name": "Ev\x1bil" + "x" * 500, "config_id": "c"})
    assert "\x1b" not in c["name"] and len(c["name"]) <= 120


def test_parse_monitor_and_execution():
    m = ar.parse_monitor(MONITORS["monitors"][0])
    assert m["monitor_id"] == "mon-1" and m["destination_id"] == "cfg-1"
    assert m["indices"] == ["wazuh-findings-v5-*"] and m["enabled"] is True
    e = ar.parse_execution(EXECS["executions"][0])
    assert e["agent_id"] == "004" and e["command"] == "enable"
    assert e["target"] == "203.0.113.7" and e["timestamp"] == "2026-11-13T10:00:00Z"
    assert e["status"] == "completed" and e["finding_id"] == "fnd-abc"


def test_execution_target_variants():
    assert ar.parse_execution({"target": {"user": "mallory"}})["target"] == "mallory"
    assert ar.parse_execution({"target": "198.51.100.9"})["target"] == "198.51.100.9"
    assert ar.parse_execution({"ip": "198.51.100.1"})["target"] == "198.51.100.1"
    assert ar.parse_execution({})["target"] == ""


# ---- fetch ----------------------------------------------------------------


def test_fetch_channels_ok(http):
    calls, answers = http
    answers.append(resp(200, CHANNELS))
    data, err = ar.fetch_channels()
    assert err is None and [c["config_id"] for c in data] == ["cfg-1", "cfg-2"]
    assert calls == [("GET", "/v1/me/active-response", None)]


def test_fetch_monitors_ok(http):
    http[1].append(resp(200, MONITORS))
    data, err = ar.fetch_monitors()
    assert err is None and data[0]["monitor_id"] == "mon-1"
    assert http[0][0][1] == "/v1/me/active-response/monitors"


def test_fetch_executions_passes_agent_id(http):
    http[1].append(resp(200, EXECS))
    data, err = ar.fetch_executions("004")
    assert err is None and data[0]["agent_id"] == "004"
    assert http[0] == [("GET", "/v1/me/active-response/executions", {"agent_id": "004"})]


def test_fetch_executions_no_filter(http):
    http[1].append(resp(200, EXECS))
    ar.fetch_executions()
    assert http[0][0][2] is None


def test_404_maps_to_not_available(http):
    http[1].append(resp(404))
    assert ar.fetch_channels() == (None, NOT_AVAILABLE)


def test_other_errors(http):
    http[1].append(resp(503))
    assert ar.fetch_monitors() == (None, "http 503")
    http[1].append(resp(200, ValueError("x")))
    assert ar.fetch_executions() == (None, "bad json")


def test_signed_out_is_an_error_string(http):
    from plugins.vpn.provisioning import ProvisioningError

    http[1].append(ProvisioningError("You're not signed in to Phoenix. Sign in again."))
    data, err = ar.fetch_channels()
    assert data is None and "not signed in" in err


# ---- pure helpers ---------------------------------------------------------


def test_channel_runs_on_by_location():
    assert ar.channel_runs_on({"location": "all"}, "004") == ar.RUNS_YES
    assert ar.channel_runs_on({"location": "server"}, "004") == ar.RUNS_NO
    assert ar.channel_runs_on({"location": "local"}, "004") == ar.RUNS_ON_TRIGGER
    pinned = {"location": "004", "agent_id": "004"}
    assert ar.channel_runs_on(pinned, "004") == ar.RUNS_YES
    assert ar.channel_runs_on(pinned, "009") == ar.RUNS_NO
    # Blank location falls back to the backend's own affects_me verdict.
    assert ar.channel_runs_on({"location": "", "affects_me": True}, None) == ar.RUNS_YES
    assert ar.channel_runs_on({"location": "", "affects_me": False}, None) == ar.RUNS_NO


def test_triggered_by_maps_monitors_to_channels():
    channels = [ar.parse_channel(c) for c in CHANNELS["active_responses"]]
    monitors = [ar.parse_monitor(m) for m in MONITORS["monitors"]]
    fired = ar.triggered_by(channels, monitors)
    assert fired == {"cfg-1": ["ar_monitor_bruteforce"]}
    assert ar.triggered_by(channels, []) == {}
