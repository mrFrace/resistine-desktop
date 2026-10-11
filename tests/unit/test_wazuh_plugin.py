"""Tests for plugins.wazuh.main — Wazuh/Endpoint Plugin logic.

Covers: check_status, _toggle_agent, _start_installation guards,
destroy, status polling lifecycle, and config module.
"""

from unittest.mock import MagicMock, patch

import pytest

from plugins.wazuh import config as wazuh_config


# ---------------------------------------------------------------------------
# Config module tests
# ---------------------------------------------------------------------------

@pytest.mark.unit
class TestWazuhConfig:
    def test_version_format(self):
        assert "-" in wazuh_config.WAZUH_VERSION  # e.g., "4.14.2-1"

    def test_arch_map_has_known_archs(self):
        assert "arm64" in wazuh_config.WAZUH_PKG_ARCH_MAP
        assert "x86_64" in wazuh_config.WAZUH_PKG_ARCH_MAP

    def test_manager_is_set(self):
        assert wazuh_config.WAZUH_MANAGER
        assert "." in wazuh_config.WAZUH_MANAGER

    def test_linux_deb_url_has_placeholder(self):
        assert "{arch}" in wazuh_config.LINUX_WAZUH_DEB_URL

    def test_linux_rpm_url_has_placeholder(self):
        assert "{arch}" in wazuh_config.LINUX_WAZUH_RPM_URL

    def test_linux_arch_maps(self):
        assert wazuh_config.LINUX_PKG_ARCH_MAP_DEB["x86_64"] == "amd64"
        assert wazuh_config.LINUX_PKG_ARCH_MAP_RPM["x86_64"] == "x86_64"

    def test_paths_are_absolute(self):
        assert wazuh_config.WAZUH_INSTALL_DIR.startswith("/")
        assert wazuh_config.WAZUH_LAUNCHD_PLIST.startswith("/")


# ---------------------------------------------------------------------------
# Plugin logic tests
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def qapp():
    from PyQt6.QtWidgets import QApplication
    return QApplication.instance() or QApplication([])


@pytest.fixture()
def wazuh_plugin():
    """Create a Wazuh Plugin with mocked platform functions."""
    with patch("plugins.wazuh.main._platform_supported", True), \
         patch("plugins.wazuh.main.get_agent_status", return_value="Running"), \
         patch("plugins.wazuh.main.is_agent_installed", return_value=True), \
         patch("plugins.wazuh.main.needs_reenrollment", return_value=False), \
         patch("plugins.wazuh.main.get_agent_name", return_value="test-host"), \
         patch("plugins.wazuh.main.get_agent_group", return_value="test.group"), \
         patch("plugins.wazuh.main.is_vpn_connected", return_value=True), \
         patch("plugins.wazuh.main.start_agent", return_value=True), \
         patch("plugins.wazuh.main.stop_agent", return_value=True), \
         patch("plugins.wazuh.main.get_agent_connection", return_value="connected"), \
         patch("plugins.wazuh.main.restore_client_key_if_needed"):
        app = MagicMock()
        from plugins.wazuh.main import Plugin
        p = Plugin(app)
        yield p


@pytest.mark.unit
class TestCheckStatus:
    """check_status() is non-blocking: it reads the poll-maintained cache
    (_cached_state / _cached_conn) rather than calling get_agent_status()."""

    def test_running_connected_returns_ok(self, wazuh_plugin):
        wazuh_plugin._cached_state = "Running"
        wazuh_plugin._cached_conn = "connected"
        assert wazuh_plugin.check_status() == "OK"

    def test_running_unknown_connection_is_not_downgraded(self, wazuh_plugin):
        wazuh_plugin._cached_state = "Running"
        wazuh_plugin._cached_conn = "unknown"
        assert wazuh_plugin.check_status() == "OK"

    def test_running_but_disconnected_returns_warning(self, wazuh_plugin):
        wazuh_plugin._cached_state = "Running"
        wazuh_plugin._cached_conn = "disconnected"
        assert wazuh_plugin.check_status() == "Warning"

    def test_running_without_cached_conn_reads_live_once(self, wazuh_plugin):
        wazuh_plugin._cached_state = "Running"
        wazuh_plugin._cached_conn = None
        with patch("plugins.wazuh.main.get_agent_connection",
                   return_value="disconnected") as conn:
            assert wazuh_plugin.check_status() == "Warning"
            assert wazuh_plugin._cached_conn == "disconnected"
            wazuh_plugin.check_status()
            conn.assert_called_once()

    def test_live_connection_read_error_treated_as_unknown(self, wazuh_plugin):
        wazuh_plugin._cached_state = "Running"
        wazuh_plugin._cached_conn = None
        with patch("plugins.wazuh.main.get_agent_connection",
                   side_effect=RuntimeError("fail")):
            assert wazuh_plugin.check_status() == "OK"
        assert wazuh_plugin._cached_conn == "unknown"

    def test_stopped_returns_error(self, wazuh_plugin):
        wazuh_plugin._cached_state = "Stopped"
        assert wazuh_plugin.check_status() == "Error"

    def test_not_installed_returns_warning(self, wazuh_plugin):
        wazuh_plugin._cached_state = "Not Installed"
        assert wazuh_plugin.check_status() == "Warning"

    def test_unpopulated_cache_returns_warning(self, wazuh_plugin):
        wazuh_plugin._cached_state = None
        assert wazuh_plugin.check_status() == "Warning"

    def test_does_not_call_get_agent_status(self, wazuh_plugin):
        wazuh_plugin._cached_state = "Stopped"
        with patch("plugins.wazuh.main.get_agent_status") as gas:
            wazuh_plugin.check_status()
        gas.assert_not_called()

    def test_poll_result_updates_status(self, wazuh_plugin):
        wazuh_plugin._cached_state = "Running"
        wazuh_plugin._cached_conn = "connected"
        wazuh_plugin._on_poll_result("Stopped", "unknown")
        assert wazuh_plugin.status == "Error"
        wazuh_plugin.app.update_plugin.assert_called_with(wazuh_plugin.id)

    def test_unsupported_platform_returns_none(self, wazuh_plugin):
        with patch("plugins.wazuh.main._platform_supported", False):
            assert wazuh_plugin.check_status() is None


@pytest.mark.unit
class TestStartInstallation:
    def test_blocks_double_install(self, wazuh_plugin):
        wazuh_plugin._installing = True
        wazuh_plugin._install_btn = MagicMock()
        # Should return immediately without touching the button
        wazuh_plugin._start_installation()
        wazuh_plugin._install_btn.configure.assert_not_called()


@pytest.mark.unit
class TestToggleAgent:
    def test_no_op_when_already_in_desired_state(self, wazuh_plugin):
        """Switching to current state should do nothing."""
        wazuh_plugin._agent_toggle = MagicMock()
        with patch("plugins.wazuh.main.get_agent_status", return_value="Running"), \
             patch("plugins.wazuh.main.threading.Thread") as thread:
            wazuh_plugin._toggle_agent(True)  # Want start, already running
            # Should not disable toggle or start thread
            wazuh_plugin._agent_toggle.setEnabled.assert_not_called()
            thread.assert_not_called()

    @pytest.mark.parametrize("platform_name", ["Linux", "Windows"])
    def test_start_requires_vpn(self, wazuh_plugin, qapp, platform_name):
        """On Linux/Windows, starting the agent without VPN shows an error and
        flips the toggle back off without re-firing the toggled handler."""
        from plugins.vpn.qt_toggle import ToggleSwitch

        toggle = ToggleSwitch()
        toggle.setChecked(True)  # user just flipped it on
        handler = MagicMock()
        toggle.toggled.connect(handler)
        wazuh_plugin._agent_toggle = toggle
        with patch("plugins.wazuh.main._PLATFORM", platform_name), \
             patch("plugins.wazuh.main.get_agent_status", return_value="Stopped"), \
             patch("plugins.wazuh.main.is_vpn_connected", return_value=False), \
             patch("plugins.wazuh.main.start_agent") as start:
            wazuh_plugin._toggle_agent(True)
        wazuh_plugin.app.show_notification.assert_called_once()
        assert "VPN" in wazuh_plugin.app.show_notification.call_args[0][0]
        assert toggle.isChecked() is False
        handler.assert_not_called()
        assert toggle.isEnabled()
        start.assert_not_called()

    def test_darwin_start_skips_vpn_gate(self, wazuh_plugin, qapp):
        """macOS has no VPN gate: start proceeds (toggle disabled while busy)."""
        from plugins.vpn.qt_toggle import ToggleSwitch

        toggle = ToggleSwitch()
        wazuh_plugin._agent_toggle = toggle
        with patch("plugins.wazuh.main._PLATFORM", "Darwin"), \
             patch("plugins.wazuh.main.get_agent_status", return_value="Stopped"), \
             patch("plugins.wazuh.main.is_vpn_connected", return_value=False), \
             patch("plugins.wazuh.main.threading.Thread") as thread:
            wazuh_plugin._toggle_agent(True)
        wazuh_plugin.app.show_notification.assert_not_called()
        assert toggle.isEnabled() is False
        thread.return_value.start.assert_called_once()


@pytest.mark.unit
class TestStatusPolling:
    def test_stop_cancels_poll(self, wazuh_plugin):
        wazuh_plugin._status_poll_id = 42
        wazuh_plugin._stop_status_polling()
        wazuh_plugin.app.after_cancel.assert_called_with(42)
        assert wazuh_plugin._status_poll_id is None

    def test_stop_noop_when_not_polling(self, wazuh_plugin):
        wazuh_plugin._status_poll_id = None
        wazuh_plugin._stop_status_polling()  # Should not raise
        wazuh_plugin.app.after_cancel.assert_not_called()


@pytest.mark.unit
class TestDestroy:
    def test_stops_polling(self, wazuh_plugin):
        wazuh_plugin._status_poll_id = 99
        wazuh_plugin.destroy()
        assert wazuh_plugin._status_poll_id is None

    def test_destroy_when_not_polling(self, wazuh_plugin):
        wazuh_plugin._status_poll_id = None
        wazuh_plugin.destroy()  # Should not raise
