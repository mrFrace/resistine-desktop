"""Tests for plugins.dashboard.main — Dashboard Plugin logic.

Covers: initialization, destroy cleanup, applying collected card data,
and the card data builders.
"""

from unittest.mock import MagicMock, patch

import pytest

from plugins.dashboard.main import Plugin


@pytest.fixture()
def dashboard_plugin():
    app = MagicMock()
    app.plugin_list = []
    return Plugin(app)


@pytest.mark.unit
class TestDashboardInit:
    def test_attributes(self, dashboard_plugin):
        assert dashboard_plugin.get_name() == "Dashboard"
        assert dashboard_plugin.order == 1
        assert dashboard_plugin.uninstall_enabled is False

    def test_id(self, dashboard_plugin):
        assert dashboard_plugin.id == "001"


@pytest.mark.unit
class TestDestroy:
    def test_cancels_resize_timer(self, dashboard_plugin):
        dashboard_plugin._resize_after_id = 42
        dashboard_plugin._resize_handler_id = None
        dashboard_plugin.destroy()
        dashboard_plugin.app.after_cancel.assert_called_with(42)

    def test_unbinds_resize_handler(self, dashboard_plugin):
        dashboard_plugin._resize_after_id = None
        dashboard_plugin._resize_handler_id = "handler_123"
        dashboard_plugin.destroy()
        dashboard_plugin.app.unbind.assert_called_with(
            "<Configure>", "handler_123",
        )

    def test_destroy_no_resize_state(self, dashboard_plugin):
        # No _resize_after_id or _resize_handler_id — should not raise
        dashboard_plugin.destroy()

    def test_destroy_handles_cancel_error(self, dashboard_plugin):
        dashboard_plugin._resize_after_id = 42
        dashboard_plugin._resize_handler_id = None
        dashboard_plugin.app.after_cancel.side_effect = RuntimeError("gone")
        dashboard_plugin.destroy()  # Should not raise


@pytest.mark.unit
class TestApply:
    def test_updates_pill_and_values(self, dashboard_plugin):
        dashboard_plugin.main_frame = MagicMock()
        pill = MagicMock()
        value = MagicMock()
        empty = MagicMock()
        dashboard_plugin._pills = {"endpoint": pill}
        dashboard_plugin._value_labels = {
            ("endpoint", "Service"): value,
            ("endpoint", "Connection"): empty,
        }
        dashboard_plugin._collecting = True

        dashboard_plugin._apply({
            "endpoint": (("Running", "ok"),
                         {"Service": "Running", "Connection": None}),
        })

        assert dashboard_plugin._collecting is False
        assert "Running" in pill.configure.call_args.kwargs["text"]
        value.configure.assert_called_with(text="Running")
        empty.configure.assert_called_with(text="\u2014")

    def test_card_without_pill(self, dashboard_plugin):
        dashboard_plugin.main_frame = MagicMock()
        label = MagicMock()
        dashboard_plugin._pills = {}
        dashboard_plugin._value_labels = {("system", "Device"): label}

        dashboard_plugin._apply({"system": ((None, None), {"Device": "box"})})

        label.configure.assert_called_with(text="box")

    def test_skips_when_screen_destroyed(self, dashboard_plugin):
        dashboard_plugin.main_frame = MagicMock()
        dashboard_plugin.main_frame.winfo_exists.return_value = False
        label = MagicMock()
        dashboard_plugin._value_labels = {("system", "Device"): label}

        dashboard_plugin._apply({"system": ((None, None), {"Device": "box"})})

        label.configure.assert_not_called()


@pytest.mark.unit
class TestAssistantData:
    def test_matrix_transport_skips_probe(self):
        from plugins.dashboard import main as dash

        with patch.object(dash.chat_endpoint, "get_transport",
                          return_value=dash.chat_endpoint.TRANSPORT_MATRIX), \
                patch.object(dash.chat_endpoint, "probe") as probe, \
                patch.object(dash, "_vpn_connected", return_value=False):
            (pill, values) = dash._assistant_data("model")

        probe.assert_not_called()
        assert pill == ("Matrix", "neutral")
        assert values["Server"] == dash.chat_endpoint.get_assistant_mxid()
        assert values["Access"].startswith("Locked")

    def test_offline_endpoint(self):
        from plugins.dashboard import main as dash

        result = {"online": False, "models": None, "latency_ms": None,
                  "error": "boom"}
        with patch.object(dash.chat_endpoint, "get_transport",
                          return_value=dash.chat_endpoint.TRANSPORT_OPENAI), \
                patch.object(dash.chat_endpoint, "get_base_url",
                             return_value="https://host.example:8002/v1"), \
                patch.object(dash.chat_endpoint, "probe", return_value=result), \
                patch.object(dash, "_vpn_connected", return_value=True):
            (pill, values) = dash._assistant_data("m")

        assert pill == ("Offline", "error")
        assert values["Server"] == "host.example:8002"
        assert values["Models"] is None and values["Latency"] is None


@pytest.mark.unit
class TestEndpointData:
    def test_system_managed_install_is_labelled(self):
        from plugins.dashboard import main as dash
        import plugins.wazuh.main as wazuh

        module = MagicMock()
        module.get_install_info.return_value = {
            "path": "/opt/resistine", "system_managed": True}
        with patch.object(wazuh, "_platform_supported", True), \
                patch.object(wazuh, "get_agent_status", return_value="Running"), \
                patch.object(wazuh, "get_agent_name", return_value="host-1"), \
                patch.object(wazuh, "get_agent_group", return_value="default"), \
                patch.object(dash.importlib, "import_module", return_value=module):
            (pill, values) = dash._endpoint_data()

        assert pill == ("Running", "ok")
        assert values["Install"] == "/opt/resistine (system-managed)"
        assert values["Agent name"] == "host-1"
