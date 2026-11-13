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


# ---- AR-D8a: a disabled policy would not run ------------------------------


def test_policy_enabled_accounts_for_channel_and_monitor_flags():
    live = {"is_enabled": True}
    off = {"is_enabled": False}
    assert ar.policy_enabled(live, None) is True
    assert ar.policy_enabled(off, None) is False  # disabled channel -> No
    # channel on, but its only monitor is disabled -> No
    assert ar.policy_enabled(live, [{"enabled": False}]) is False
    # one enabled monitor is enough
    assert ar.policy_enabled(live, [{"enabled": False}, {"enabled": True}]) is True


def test_channel_name_by_id_and_monitors_by_channel():
    channels = [ar.parse_channel(c) for c in CHANNELS["active_responses"]]
    assert ar.channel_name_by_id(channels)["cfg-1"] == "ar-smoke-test"
    monitors = [ar.parse_monitor(m) for m in MONITORS["monitors"]]
    by_chan = ar.monitors_by_channel(channels, monitors)
    assert [m["monitor_id"] for m in by_chan["cfg-1"]] == ["mon-1"]


# ---- builders / validators (pure) -----------------------------------------


def test_build_policy_is_always_defined_agent():
    p = ar.build_policy(name=" x ", executable="block-ip", trigger=" rule.id:5710 ",
                        stateful_timeout="600", agent_id="004")
    assert p["location"] == "defined-agent" and p["agent_id"] == "004"
    assert p["type"] == "stateful" and p["stateful_timeout"] == 600
    assert p["name"] == "x" and p["trigger"] == "rule.id:5710"
    assert "config_id" not in p
    assert ar.build_policy(name="x", executable="block-ip", trigger="t",
                           stateful_timeout=5, agent_id="004",
                           config_id="cfg-9")["config_id"] == "cfg-9"


def test_build_fire_keys_target_by_executable():
    assert ar.build_fire("004", "block-ip", "203.0.113.7")["target"] == {"ip": "203.0.113.7"}
    assert ar.build_fire("004", "disable-account", "mallory")["target"] == {"user": "mallory"}


def test_build_fire_pins_location_defined_agent():
    # The preview and the actual fire share this builder, so the fired blast
    # radius matches what was self-tested (never an unpinned, wider fire).
    assert ar.build_fire("004", "block-ip", "1.2.3.4")["location"] == "defined-agent"


def test_validate_policy_rules():
    ok = dict(name="n", executable="block-ip", trigger="t", stateful_timeout=600, agent_id="004")
    assert ar.validate_policy(**ok) is None
    assert ar.validate_policy(**{**ok, "name": "  "})
    assert ar.validate_policy(**{**ok, "executable": "rm-rf"})
    assert ar.validate_policy(**{**ok, "trigger": ""})
    assert ar.validate_policy(**{**ok, "agent_id": ""})
    assert ar.validate_policy(**{**ok, "stateful_timeout": 0})
    assert ar.validate_policy(**{**ok, "stateful_timeout": "x"})


def test_validate_fire_rules():
    assert ar.validate_fire("004", "block-ip", "1.2.3.4") is None
    assert ar.validate_fire("", "block-ip", "1.2.3.4")
    assert ar.validate_fire("004", "nope", "1.2.3.4")
    assert ar.validate_fire("004", "block-ip", "  ")


# ---- preview parsing + save gate ------------------------------------------

PREVIEW = {
    "count": 1,
    "included": [{"agent_id": "004", "agent_name": "lab-host"}],
    "excluded": [{"agent_id": "250", "reason": "self-infra"}],
    "refusals": [],
    "self_test": {"would_fire_on_self": False, "offending": []},
}


def test_parse_preview_normalises_shape():
    p = ar.parse_preview(PREVIEW)
    assert p["count"] == 1
    assert p["included"][0] == {"agent_id": "004", "agent_name": "lab-host", "reason": ""}
    assert p["excluded"][0]["reason"] == "self-infra"
    assert p["self_test"] == {"ran": True, "would_fire_on_self": False, "offending": []}
    # count falls back to len(included) when absent/garbage
    assert ar.parse_preview({"included": [1, 2]})["count"] == 2
    # a missing self_test block is marked not-run
    assert ar.parse_preview({})["self_test"]["ran"] is False
    # an EMPTY self_test object is not a passed test — it must not open the gate
    empty = ar.parse_preview({"count": 1, "self_test": {}})
    assert empty["self_test"]["ran"] is False
    assert ar.preview_blocks_save(empty) is not None


def test_preview_blocks_save_gate():
    assert ar.preview_blocks_save(None)                      # nothing yet
    assert ar.preview_blocks_save({"self_test": {"ran": False}})  # no self-test
    assert ar.preview_blocks_save(
        {"self_test": {"ran": True, "would_fire_on_self": True}, "refusals": []})
    assert ar.preview_blocks_save(
        {"self_test": {"ran": True, "would_fire_on_self": False}, "refusals": ["x"]})
    assert ar.preview_blocks_save(ar.parse_preview(PREVIEW)) is None  # clear


# ---- write endpoints ------------------------------------------------------


@pytest.fixture
def rw(monkeypatch):
    """Capture the full request (method, path, params, json) and feed answers."""
    from plugins.vpn import provisioning

    calls, answers = [], []

    def fake(method, path, **kw):
        calls.append({"method": method, "path": path,
                      "params": kw.get("params"), "json": kw.get("json")})
        a = answers.pop(0)
        if isinstance(a, Exception):
            raise a
        return a

    monkeypatch.setattr(provisioning, "_authorized_request", fake)
    return calls, answers


def test_create_policy_posts_body(rw):
    calls, answers = rw
    answers.append(resp(201, {"config_id": "cfg-new"}))
    payload = ar.build_policy(name="n", executable="block-ip", trigger="t",
                              stateful_timeout=600, agent_id="004")
    data, err = ar.create_policy(payload)
    assert err is None and data == {"config_id": "cfg-new"}
    assert calls[0]["method"] == "POST"
    assert calls[0]["path"] == "/v1/me/active-response"
    assert calls[0]["json"]["location"] == "defined-agent"


def test_create_policy_refuses_location_all_without_a_call(rw):
    calls, _ = rw
    data, err = ar.create_policy({"location": "all"})
    assert data is None and "gitops" in err
    assert calls == []  # never hit the wire


def test_update_and_delete_policy(rw):
    calls, answers = rw
    answers.append(resp(200, {"config_id": "cfg-1"}))
    ar.update_policy("cfg-1", {"name": "x"})
    assert calls[-1]["method"] == "PUT"
    assert calls[-1]["path"] == "/v1/me/active-response/cfg-1"
    answers.append(resp(204))
    data, err = ar.delete_policy("cfg-1")
    assert err is None and data == {}
    assert calls[-1]["method"] == "DELETE"


def test_update_delete_require_config_id(rw):
    calls, _ = rw
    assert ar.update_policy("", {})[0] is None
    assert ar.delete_policy("")[0] is None
    assert calls == []


def test_fire_and_stop(rw):
    calls, answers = rw
    answers.append(resp(200, {"execution_id": "e1"}))
    data, err = ar.fire("004", "block-ip", "203.0.113.7")
    assert err is None and data == {"execution_id": "e1"}
    assert calls[-1]["path"] == "/v1/me/active-response/fire"
    assert calls[-1]["json"]["target"] == {"ip": "203.0.113.7"}
    answers.append(resp(200, {"ok": True}))
    ar.stop("004", "disable-account", "mallory")
    assert calls[-1]["path"] == "/v1/me/active-response/stop"
    assert calls[-1]["json"]["target"] == {"user": "mallory"}


def test_preview_endpoint_parses(rw):
    _calls, answers = rw
    answers.append(resp(200, PREVIEW))
    data, err = ar.preview({"executable": "block-ip"})
    assert err is None and data["count"] == 1 and data["self_test"]["ran"] is True


def test_write_error_surfaces_server_detail(rw):
    _calls, answers = rw
    answers.append(resp(403, {"detail": "agent 250 is not yours"}))
    data, err = ar.create_policy(ar.build_policy(
        name="n", executable="block-ip", trigger="t", stateful_timeout=1, agent_id="250"))
    assert data is None and "not yours" in err


def test_write_404_is_not_available(rw):
    _calls, answers = rw
    answers.append(resp(404))
    assert ar.fire("004", "block-ip", "1.2.3.4") == (None, NOT_AVAILABLE)


def test_fetch_inventory(rw):
    calls, answers = rw
    answers.append(resp(200, {"agents": [{"agent_id": "004", "agent_name": "lab-host"},
                                         {"id": "009", "hostname": "win-box"}]}))
    data, err = ar.fetch_inventory()
    assert err is None
    assert data[0] == {"agent_id": "004", "agent_name": "lab-host"}
    assert data[1] == {"agent_id": "009", "agent_name": "win-box"}
    assert calls[-1]["path"] == "/v1/me/inventory"
