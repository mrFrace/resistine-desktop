"""Undo of a job (BasePlugin.undo): a closed set of actions per plugin,
the argument re-validated, the same path as the forward action."""

from unittest.mock import MagicMock, patch

import pytest

from plugins.base_plugin import BasePlugin
from utils import jobs

pytestmark = pytest.mark.unit


@pytest.fixture(autouse=True)
def fresh(isolated_settings):
    jobs._reset_for_tests()
    yield
    jobs._reset_for_tests()


def test_base_plugin_offers_nothing():
    assert BasePlugin.undo(MagicMock(), "anything") is False


def test_vpn_undo_goes_through_request_toggle_for_the_selected_config_only():
    from plugins.vpn import main as vpn
    p = vpn.Plugin.__new__(vpn.Plugin)
    p._toggle_busy = False
    p.get_selected_conf_file_name = lambda: "drake-laptop"
    p.request_toggle = MagicMock()
    assert p.undo("vpn_disconnect", "drake-laptop") is True
    p.request_toggle.assert_called_once_with(0)
    assert p.undo("vpn_connect", "drake-laptop") is True
    p.request_toggle.assert_called_with(1)
    assert p.undo("vpn_disconnect", "other-box") is False     # not what is selected now
    assert p.undo("vpn_disconnect", "") is False
    assert p.undo("rm -rf", "drake-laptop") is False           # not an action
    p._toggle_busy = True
    assert p.undo("vpn_disconnect", "drake-laptop") is False
    assert p.request_toggle.call_count == 2


def test_vpn_toggle_declares_its_undo(monkeypatch):
    from plugins.vpn import main as vpn
    p = vpn.Plugin.__new__(vpn.Plugin)
    p.id = "vpn"
    p.app = MagicMock()
    p.get_name = lambda: "VPN"
    p.update_plugin = MagicMock()
    monkeypatch.setattr(vpn, "IS_WINDOWS", False)
    monkeypatch.setattr(vpn, "my_vpn_status", "Running")
    p._toggle_posix = lambda value, conf: None
    p._toggle_busy = True
    p._toggle_worker(1, "drake-laptop")
    [job] = jobs.recent()
    assert job["status"] == "done" and job["undo"] == {
        "label": "Disconnect", "plugin": "VPN", "action": "vpn_disconnect", "arg": "drake-laptop"}
    monkeypatch.setattr(vpn, "my_vpn_status", "Stopped")
    p._toggle_busy = True
    p._toggle_worker(0, "drake-laptop")
    assert jobs.recent()[0]["undo"]["action"] == "vpn_connect"


def test_wazuh_undo_removes_the_agent_as_a_job(monkeypatch):
    from plugins.wazuh import main as wz
    removed = []
    with patch("plugins.wazuh.main._platform_supported", True), \
         patch("plugins.wazuh.main.get_agent_status", return_value="Running"), \
         patch("plugins.wazuh.main.is_agent_installed", return_value=True), \
         patch("plugins.wazuh.main.needs_reenrollment", return_value=False), \
         patch("plugins.wazuh.main.get_agent_name", return_value="test-host"), \
         patch("plugins.wazuh.main.get_agent_group", return_value="test.group"), \
         patch("plugins.wazuh.main.get_agent_connection", return_value="connected"), \
         patch("plugins.wazuh.main.restore_client_key_if_needed"):
        app = MagicMock()
        app.after = lambda ms, fn, *a: fn(*a)
        p = wz.Plugin(app)
    monkeypatch.setattr(wz, "_PLATFORM", "Linux")
    monkeypatch.setattr("plugins.wazuh.agent.wazuh_functions_linux.remove_agent",
                        lambda wipe_keys=False: removed.append(wipe_keys) or True)
    monkeypatch.setattr(wz.threading, "Thread", lambda target, **kw: MagicMock(start=target))
    p._refresh_screen = MagicMock()
    assert p.undo("remove_agent") is True
    assert removed == [False]                   # never the identity wipe
    [job] = jobs.recent()
    assert job["title"] == "Endpoint agent removal" and job["status"] == "done"
    assert p._installing is False
    app.show_notification.assert_called_with("Endpoint agent removed", type="info")
    assert p.undo("wipe_everything") is False
    p._installing = True
    assert p.undo("remove_agent") is False
    assert p._install_undo()["plugin"] == p.get_name()
