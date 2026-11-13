"""Each plugin's fixes() reads cached state only and run_fix() goes
through the plugin's own function; unknown ids are refused."""

from unittest.mock import MagicMock, patch

import pytest

from plugins.base_plugin import BasePlugin

pytestmark = pytest.mark.unit


def test_base_plugin_offers_nothing():
    p = MagicMock()
    assert BasePlugin.fixes(p) == [] and BasePlugin.run_fix(p, "x") == (False, "not offered")


def _wazuh(monkeypatch, state, conn="connected", installed=True):
    from plugins.wazuh import main as wz
    with patch("plugins.wazuh.main._platform_supported", True), \
         patch("plugins.wazuh.main.get_agent_status", return_value=state), \
         patch("plugins.wazuh.main.is_agent_installed", return_value=installed), \
         patch("plugins.wazuh.main.needs_reenrollment", return_value=False), \
         patch("plugins.wazuh.main.get_agent_name", return_value="test-host"), \
         patch("plugins.wazuh.main.get_agent_group", return_value="g"), \
         patch("plugins.wazuh.main.get_agent_connection", return_value=conn), \
         patch("plugins.wazuh.main.restore_client_key_if_needed"):
        app = MagicMock()
        app.after = lambda ms, fn, *a: fn(*a)
        p = wz.Plugin(app)
    monkeypatch.setattr(wz, "is_agent_installed", lambda: installed)
    p._cached_state, p._cached_conn = state, conn
    p._refresh_screen = MagicMock()
    return p, wz


def test_wazuh_fixes_and_run(monkeypatch):
    monkeypatch.setattr("utils.fixes.this_host", lambda: "box")
    p, wz = _wazuh(monkeypatch, "Stopped")
    [f] = p.fixes()
    assert (f.id, f.host, f.needs_admin) == ("agent_start", "box", True)
    monkeypatch.setattr(wz, "start_agent", lambda: True)
    assert p.run_fix("agent_start") == (True, "agent started")
    p, wz = _wazuh(monkeypatch, "Running", conn="disconnected")
    assert [f.id for f in p.fixes()] == ["agent_reconnect"]
    monkeypatch.setattr(wz, "reenroll_agent", lambda: (False, "manager unreachable"))
    assert p.run_fix("agent_reconnect") == (False, "manager unreachable") and p._reconnecting is False
    assert p.run_fix("rm") == (False, "not offered")
    p._installing = True
    assert p.fixes() == []
    p, _ = _wazuh(monkeypatch, "Running")
    assert p.fixes() == []


def test_antivirus_fixes_and_run(monkeypatch, isolated_settings):
    from plugins.antivirus import main as av
    monkeypatch.setattr("utils.fixes.this_host", lambda: "box")
    p = av.Plugin.__new__(av.Plugin)
    p.app = MagicMock()
    p.app.after = lambda ms, fn, *a: fn(*a)
    p.get_name = lambda: "Antivirus"
    p._refresh_db_info = MagicMock()
    p._last_state = "protected"
    assert [f.id for f in p.fixes()] == ["av_signatures"]  # never updated
    isolated_settings.set("antivirus", "last_sig_update_ts", __import__("time").time())
    assert p.fixes() == []
    p._last_state = "not_installed"
    isolated_settings.set("antivirus", "last_sig_update_ts", 0)
    assert p.fixes() == []
    monkeypatch.setattr(av.clamav, "run_freshclam", lambda: (True, "database updated"))
    assert p.run_fix("av_signatures") == (True, "database updated")
    assert isolated_settings.get("antivirus", "last_sig_update_ts") > 0
    assert p.run_fix("x") == (False, "not offered")


def test_vpn_switched_off_by_hand_is_not_a_fix(monkeypatch, isolated_settings):
    from plugins.vpn import main as vpn
    monkeypatch.setattr("utils.fixes.this_host", lambda: "box")
    monkeypatch.setattr(vpn, "_phoenix_signed_in", lambda: True)
    monkeypatch.setattr(vpn, "my_vpn_status", "Stopped")
    monkeypatch.setattr(vpn.threading, "Thread", lambda **kw: MagicMock())
    p = vpn.Plugin.__new__(vpn.Plugin)
    p._toggle_busy = False
    p.vpn_toggle_switch = None
    p.get_name = lambda: "VPN"
    p.get_selected_conf_file_name = lambda: "drake-laptop"
    assert [f.id for f in p.fixes()] == ["vpn_connect"]
    p.request_toggle(0)                      # the user switches it off
    assert isolated_settings.get("vpn", "user_disconnected") is True
    p._toggle_busy = False
    assert p.fixes() == []                   # their call, not a fault
    p.request_toggle(1)                      # and on again, by hand
    assert isolated_settings.get("vpn", "user_disconnected") is False
    p._toggle_busy = False
    assert [f.id for f in p.fixes()] == ["vpn_connect"]


def test_vpn_fixes_and_run(monkeypatch, isolated_settings):
    from plugins.vpn import main as vpn
    monkeypatch.setattr("utils.fixes.this_host", lambda: "box")
    monkeypatch.setattr(vpn, "_phoenix_signed_in", lambda: True)
    monkeypatch.setattr(vpn, "my_vpn_status", "Stopped")
    p = vpn.Plugin.__new__(vpn.Plugin)
    p._toggle_busy = False
    p.get_name = lambda: "VPN"
    [f] = p.fixes()
    assert (f.id, f.needs_admin) == ("vpn_connect", True)
    monkeypatch.setattr(vpn, "_phoenix_signed_in", lambda: False)
    assert p.fixes() == []
    monkeypatch.setattr(vpn, "_phoenix_signed_in", lambda: True)
    monkeypatch.setattr(vpn, "my_vpn_status", "Running")
    assert p.fixes() == []

    def connect(value):
        assert value == 1 and p._toggle_busy
        monkeypatch.setattr(vpn, "my_vpn_status", "Running")
        p._toggle_busy = False
    p._provision_then_connect = connect
    monkeypatch.setattr(vpn, "my_vpn_status", "Stopped")
    assert p.run_fix("vpn_connect") == (True, "VPN connected")
    p._toggle_busy = True
    assert p.run_fix("vpn_connect") == (False, "the VPN is busy")
    assert p.run_fix("x") == (False, "not offered")


def test_devices_fixes_and_run(monkeypatch):
    from plugins.devices import main as dv
    from plugins.devices import sessions_api
    monkeypatch.setattr("utils.fixes.this_host", lambda: "old-box")
    monkeypatch.setattr(dv.socket, "gethostname", lambda: "old-box")
    rows = sessions_api.parse_devices({"devices": [
        {"device_id": "PHX_QS3ZBL42VSZ6YQAJ", "current": True, "kind": "phoenix", "vpn": {"hostname": "old-box"}},
        {"device_id": "PHX_AAAAAAAAAAAAAAAA", "kind": "phoenix", "vpn": {"hostname": "old-box"}},
        {"device_id": "PHX_BBBBBBBBBBBBBBBB", "kind": "phoenix", "vpn": {"hostname": "other"}}]})
    tab = MagicMock(_rows=rows, _loaded_at=99.0)
    p = dv.Plugin.__new__(dv.Plugin)
    p._destroyed = False
    p._tabs = {"sessions": tab}
    p.get_name = lambda: "Devices"
    [f] = p.fixes()
    assert f.id == "stale_installs" and f.why == "1 earlier install of this machine still signed in"
    removed = []
    monkeypatch.setattr(sessions_api, "remove_device", lambda d: (removed.append(d), (True, None))[1])
    assert p.run_fix("stale_installs") == (True, "1 removed") and removed == ["PHX_AAAAAAAAAAAAAAAA"]
    assert tab._loaded_at == 0.0
    p._tabs = {}
    assert p.fixes() == [] and p.run_fix("stale_installs") == (True, "0 removed")
    assert p.run_fix("x") == (False, "not offered")
