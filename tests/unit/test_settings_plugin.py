"""Tests for plugins.settings.main — Settings Plugin logic (PyQt6).

Covers: save_api_key (OpenAI transport), save_animation_setting,
change_appearance_mode / _apply_appearance_mode, _get_app_version,
_handle_logout / _handle_login, _handle_uninstall, _check_for_updates,
_disconnect_vpn, _remove_wazuh_agent, _revoke_session, _clear_user_data.

The Matrix-transport side of the API card is covered in
tests/unit/test_chat_matrix_transport.py::TestSettingsTransportCard.
"""

import os
from unittest.mock import MagicMock, call, patch

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtWidgets import QApplication, QMessageBox  # noqa: E402

_YES = QMessageBox.StandardButton.Yes
_NO = QMessageBox.StandardButton.No


@pytest.fixture(scope="module")
def qapp():
    return QApplication.instance() or QApplication([])


@pytest.fixture()
def settings_plugin(isolated_settings):
    """A Settings Plugin with a mocked app and no screen built."""
    from plugins.settings.main import Plugin

    app = MagicMock()
    app.plugins = []
    app.plugin_list = []
    return Plugin(app)


@pytest.fixture()
def built_plugin(settings_plugin, qapp):
    """A Settings Plugin whose full main screen (real Qt widgets) is built."""
    settings_plugin._test_page = settings_plugin.create_main_screen()  # keep alive
    return settings_plugin


def _login_plugin():
    login = MagicMock()
    login.id = "007"
    return login


# ---------------------------------------------------------------------------
# Screen construction
# ---------------------------------------------------------------------------

@pytest.mark.unit
class TestScreenConstruction:
    def test_logged_out_shows_log_in_button(self, built_plugin):
        assert built_plugin.logout_button.text() == "Log In"

    def test_logged_in_shows_log_out_button(self, settings_plugin, qapp, isolated_settings):
        isolated_settings.set("auth", "logged_in", True)
        settings_plugin._test_page = settings_plugin.create_main_screen()
        assert settings_plugin.logout_button.text() == "Log Out"

    def test_fields_prefilled_from_settings(self, settings_plugin, qapp, isolated_settings):
        isolated_settings.set_secret("chat", "openai_api_key", "sk-existing")
        isolated_settings.set("chat", "openai_base_url", "http://local/v1")
        isolated_settings.set("chat", "disable_animation", True)
        isolated_settings.set("ui", "appearance_mode", "Dark")
        settings_plugin._test_page = settings_plugin.create_main_screen()
        assert settings_plugin.api_key_entry.text() == "sk-existing"
        assert settings_plugin.api_base_entry.text() == "http://local/v1"
        assert settings_plugin.disable_animation_checkbox.isChecked() is True
        assert settings_plugin.appearance_combo.currentText() == "Dark"

    def test_defaults_to_openai_transport(self, built_plugin):
        from utils.chat_config import DEFAULT_BASE_URL
        assert built_plugin.transport_combo.currentData() == "openai"
        assert built_plugin.api_base_entry.text() == DEFAULT_BASE_URL
        assert DEFAULT_BASE_URL == "https://dashboard.phoenix.exposed:8002/v1"
        assert not built_plugin.api_key_entry.isHidden()
        assert built_plugin.matrix_bot_entry.isHidden()


# ---------------------------------------------------------------------------
# save_api_key (OpenAI transport)
# ---------------------------------------------------------------------------

@pytest.mark.unit
class TestSaveApiKey:
    def test_saves_key_and_base_url(self, built_plugin, isolated_settings):
        built_plugin.api_key_entry.setText("sk-test-key")
        built_plugin.api_base_entry.setText("http://localhost:11434/v1")

        built_plugin.save_api_key()

        assert isolated_settings.get_secret("chat", "openai_api_key") == "sk-test-key"
        assert isolated_settings.get("chat", "openai_base_url") == "http://localhost:11434/v1"
        assert isolated_settings.get("chat", "transport") == "openai"
        from plugins.settings.main import _t
        assert built_plugin.status_label.text() == _t(
            "settings.apikey.saved_success", "Saved")
        # status line is cleared later via app.after
        assert built_plugin.app.after.call_args[0][0] == 2500

    def test_empty_key_and_base_saves_nothing(self, built_plugin, isolated_settings):
        built_plugin.api_key_entry.setText("   ")
        built_plugin.api_base_entry.setText("")

        built_plugin.save_api_key()

        assert isolated_settings.get_secret("chat", "openai_api_key") is None
        assert isolated_settings.get("chat", "openai_base_url") is None

    def test_clears_base_url_when_empty(self, built_plugin, isolated_settings):
        isolated_settings.set("chat", "openai_base_url", "http://old.url")
        built_plugin.api_key_entry.setText("sk-key")
        built_plugin.api_base_entry.setText("")

        built_plugin.save_api_key()

        assert isolated_settings.get("chat", "openai_base_url") is None
        assert isolated_settings.get_secret("chat", "openai_api_key") == "sk-key"

    def test_reinitializes_chat_plugin(self, built_plugin):
        mock_chat = MagicMock()
        mock_chat.get_name.return_value = "Chat"
        built_plugin.app.plugin_list = [mock_chat]
        built_plugin.api_key_entry.setText("sk-key")

        built_plugin.save_api_key()

        mock_chat.reinitialize_client.assert_called_once()

    def test_save_failure_shows_error(self, built_plugin):
        built_plugin.api_key_entry.setText("sk-key")
        with patch("plugins.settings.main.settings.set_secret", return_value=False):
            built_plugin.save_api_key()
        from plugins.settings.main import _t
        assert built_plugin.status_label.text() == _t(
            "settings.apikey.saved_error", "Save failed")
        built_plugin.app.after.assert_not_called()


# ---------------------------------------------------------------------------
# save_animation_setting
# ---------------------------------------------------------------------------

@pytest.mark.unit
class TestSaveAnimationSetting:
    def test_toggle_on_saves_true(self, built_plugin, isolated_settings):
        built_plugin.disable_animation_checkbox.setChecked(True)  # fires toggled
        assert isolated_settings.get("chat", "disable_animation") is True

    def test_toggle_off_saves_false(self, built_plugin, isolated_settings):
        built_plugin.disable_animation_checkbox.setChecked(True)
        built_plugin.disable_animation_checkbox.setChecked(False)
        assert isolated_settings.get("chat", "disable_animation") is False

    def test_applies_to_chat_plugin(self, built_plugin):
        mock_chat = MagicMock()
        mock_chat.get_name.return_value = "Chat"
        built_plugin.app.plugin_list = [mock_chat]
        built_plugin.disable_animation_checkbox.setChecked(True)
        mock_chat.apply_animation_setting.assert_called_once()


# ---------------------------------------------------------------------------
# change_appearance_mode
# ---------------------------------------------------------------------------

@pytest.mark.unit
class TestChangeAppearanceMode:
    def test_persists_and_defers_restyle(self, settings_plugin, isolated_settings):
        settings_plugin.change_appearance_mode("Dark")

        assert isolated_settings.get("ui", "appearance_mode") == "Dark"
        settings_plugin.app.set_appearance_mode.assert_not_called()
        delay, callback = settings_plugin.app.after.call_args[0]
        assert delay == 0
        callback()
        settings_plugin.app.set_appearance_mode.assert_called_once_with("Dark")

    def test_apply_swallows_errors(self, settings_plugin):
        settings_plugin.app.set_appearance_mode.side_effect = RuntimeError("boom")
        settings_plugin._apply_appearance_mode("Light")  # must not raise
        settings_plugin.app.set_appearance_mode.assert_called_once_with("Light")


# ---------------------------------------------------------------------------
# _get_app_version
# ---------------------------------------------------------------------------

@pytest.mark.unit
class TestGetAppVersion:
    def test_frozen_reads_plist(self, settings_plugin, monkeypatch, tmp_path):
        monkeypatch.setattr("sys.frozen", True, raising=False)
        macos_dir = tmp_path / "Contents" / "MacOS"
        macos_dir.mkdir(parents=True)
        monkeypatch.setattr("sys.executable", str(macos_dir / "Resistine"))

        import plistlib
        plist_path = tmp_path / "Contents" / "Info.plist"
        with open(plist_path, "wb") as f:
            plistlib.dump({"CFBundleShortVersionString": "2.5.1"}, f)

        assert settings_plugin._get_app_version() == "2.5.1"

    def test_source_mode_fallback(self, settings_plugin, monkeypatch):
        monkeypatch.setattr("sys.frozen", False, raising=False)
        with patch("utils.updates.version.get_current_version", return_value="3.0.0"):
            assert settings_plugin._get_app_version() == "3.0.0"

    def test_ultimate_fallback(self, settings_plugin, monkeypatch):
        monkeypatch.setattr("sys.frozen", False, raising=False)
        with patch("utils.updates.version.get_current_version", side_effect=ImportError):
            assert settings_plugin._get_app_version() == "1.0.0"


# ---------------------------------------------------------------------------
# _handle_logout / _handle_login
# ---------------------------------------------------------------------------

_LOGOUT_STEPS = ("_disconnect_vpn", "_remove_wazuh_agent",
                 "_revoke_session", "_clear_user_data")


@pytest.mark.unit
class TestHandleLogout:
    def _patch_steps(self, plugin, manager):
        patches = []
        for name in _LOGOUT_STEPS:
            m = getattr(manager, name)
            patches.append(patch.object(plugin, name, m))
        return patches

    def test_user_cancels(self, settings_plugin):
        settings_plugin.app.plugin_list = [_login_plugin()]
        manager = MagicMock()
        with patch("plugins.settings.main.QMessageBox.question",
                   return_value=_NO) as q:
            for p in self._patch_steps(settings_plugin, manager):
                p.start()
            try:
                settings_plugin._handle_logout()
            finally:
                patch.stopall()
        q.assert_called_once()
        assert manager.mock_calls == []
        settings_plugin.app.show_login.assert_not_called()

    def test_refuses_when_login_plugin_uninstalled(self, settings_plugin):
        """Without the Login plugin installed the user can't sign back in,
        so logout must short-circuit with a user-facing notification."""
        settings_plugin.app.plugin_list = []  # login absent
        with patch("plugins.settings.main.QMessageBox.question") as q:
            settings_plugin._handle_logout()
        q.assert_not_called()
        settings_plugin.app.show_notification.assert_called_once()
        msg = settings_plugin.app.show_notification.call_args[0][0]
        assert "Login plugin" in msg and "Store" in msg

    def test_confirm_runs_cleanup_in_order_then_shows_login(self, settings_plugin):
        settings_plugin.app.plugin_list = [_login_plugin()]
        manager = MagicMock()
        manager.attach_mock(settings_plugin.app.show_login, "show_login")
        with patch("plugins.settings.main.QMessageBox.question", return_value=_YES):
            for p in self._patch_steps(settings_plugin, manager):
                p.start()
            try:
                settings_plugin._handle_logout()
            finally:
                patch.stopall()
        assert manager.mock_calls == [
            call._disconnect_vpn(), call._remove_wazuh_agent(),
            call._revoke_session(), call._clear_user_data(), call.show_login(),
        ]

    def test_clears_auth_and_removes_agent_on_confirm(
        self, settings_plugin, isolated_settings,
    ):
        """End-to-end through the real helpers with OS-level effects mocked."""
        isolated_settings.set("auth", "logged_in", True)
        isolated_settings.set("auth", "email", "alice@example.com")
        settings_plugin.app.plugin_list = [_login_plugin()]
        mock_mgr = MagicMock()
        mock_mgr.get_active_config_path.return_value = None
        with patch("plugins.settings.main.QMessageBox.question", return_value=_YES), \
             patch("platform.system", return_value="Darwin"), \
             patch("plugins.vpn.wireguard.vpn_functions_darwin.stop_vpn", create=True), \
             patch(
                 "plugins.vpn.wireguard.vpn_functions_darwin.get_writable_wireguard_dir",
                 return_value="/nonexistent/wg",
                 create=True,
             ), \
             patch("plugins.vpn.config_manager.VPNConfigManager", return_value=mock_mgr), \
             patch(
                 "plugins.wazuh.agent.wazuh_functions_darwin.remove_agent",
                 return_value=True,
                 create=True,
             ) as mock_remove, \
             patch("plugins.login.oidc.revoke") as mock_revoke:
            settings_plugin._handle_logout()
        mock_remove.assert_called_once_with(wipe_keys=True)
        mock_revoke.assert_called_once()
        assert isolated_settings.get("auth", "logged_in") is None
        assert isolated_settings.get("auth", "email") is None
        settings_plugin.app.show_login.assert_called_once()

    def test_show_login_failure_notifies(self, settings_plugin):
        settings_plugin.app.plugin_list = [_login_plugin()]
        settings_plugin.app.show_login.side_effect = RuntimeError("no screen")
        manager = MagicMock()
        with patch("plugins.settings.main.QMessageBox.question", return_value=_YES):
            for p in self._patch_steps(settings_plugin, manager):
                p.start()
            try:
                settings_plugin._handle_logout()
            finally:
                patch.stopall()
        args, kwargs = settings_plugin.app.show_notification.call_args
        assert "Logout failed" in args[0] and kwargs["type"] == "error"


@pytest.mark.unit
class TestHandleLogin:
    def test_shows_login_without_clearing(self, settings_plugin, isolated_settings):
        isolated_settings.set("chat", "openai_base_url", "http://keep")
        settings_plugin.app.plugin_list = [_login_plugin()]
        settings_plugin._handle_login()
        settings_plugin.app.show_login.assert_called_once()
        assert isolated_settings.get("chat", "openai_base_url") == "http://keep"

    def test_refuses_without_login_plugin(self, settings_plugin):
        settings_plugin._handle_login()
        settings_plugin.app.show_login.assert_not_called()
        assert "Login plugin" in settings_plugin.app.show_notification.call_args[0][0]

    def test_login_plugin_detected_via_app_plugins(self, settings_plugin):
        settings_plugin.app.plugins = [_login_plugin()]
        assert settings_plugin._login_plugin_installed() is True
        settings_plugin.app.plugins = []
        settings_plugin.app.plugin_list = []
        assert settings_plugin._login_plugin_installed() is False


# ---------------------------------------------------------------------------
# _revoke_session
# ---------------------------------------------------------------------------

@pytest.mark.unit
class TestRevokeSession:
    def test_calls_oidc_revoke(self, settings_plugin):
        with patch("plugins.login.oidc.revoke") as mock_revoke:
            settings_plugin._revoke_session()
        mock_revoke.assert_called_once_with()

    def test_revoke_failure_does_not_raise(self, settings_plugin):
        with patch("plugins.login.oidc.revoke", side_effect=OSError("offline")):
            settings_plugin._revoke_session()  # best effort


# ---------------------------------------------------------------------------
# _handle_uninstall
# ---------------------------------------------------------------------------

@pytest.mark.unit
class TestHandleUninstall:
    def test_user_cancels(self, built_plugin):
        with patch("plugins.settings.main.QMessageBox.question", return_value=_NO), \
             patch("utils.uninstall.run_uninstall") as mock_run:
            built_plugin._handle_uninstall()
        mock_run.assert_not_called()
        assert built_plugin.uninstall_button.isEnabled()

    def test_success_closes_app_and_quits_on_linux(self, built_plugin, monkeypatch):
        monkeypatch.setattr("sys.platform", "linux")
        fake_qapp = MagicMock()
        with patch("plugins.settings.main.QMessageBox.question", return_value=_YES), \
             patch("utils.uninstall.run_uninstall", return_value=(True, "ok")) as mock_run, \
             patch.object(QApplication, "instance", return_value=fake_qapp):
            built_plugin._handle_uninstall()
        mock_run.assert_called_once()
        assert mock_run.call_args[0][0] is built_plugin.app
        built_plugin.app.close.assert_called_once()
        fake_qapp.quit.assert_called_once()
        assert "Uninstalled" in built_plugin.uninstall_status_label.text()

    def test_success_on_darwin_schedules_hard_exit(self, built_plugin, monkeypatch):
        monkeypatch.setattr("sys.platform", "darwin")
        with patch("plugins.settings.main.QMessageBox.question", return_value=_YES), \
             patch("utils.uninstall.run_uninstall", return_value=(True, "ok")), \
             patch("threading.Timer") as mock_timer:
            built_plugin._handle_uninstall()
        built_plugin.app.close.assert_called_once()
        assert mock_timer.call_args[0][0] == 0.3
        mock_timer.return_value.start.assert_called_once()

    def test_failure_shows_message_and_reenables(self, built_plugin):
        with patch("plugins.settings.main.QMessageBox.question", return_value=_YES), \
             patch("utils.uninstall.run_uninstall", return_value=(False, "denied")):
            built_plugin._handle_uninstall()
        built_plugin.app.close.assert_not_called()
        assert built_plugin.uninstall_button.isEnabled()
        assert built_plugin.uninstall_status_label.text() == "denied"

    def test_exception_shows_error_and_reenables(self, built_plugin):
        with patch("plugins.settings.main.QMessageBox.question", return_value=_YES), \
             patch("utils.uninstall.run_uninstall", side_effect=RuntimeError("boom")):
            built_plugin._handle_uninstall()
        assert built_plugin.uninstall_button.isEnabled()
        assert built_plugin.uninstall_status_label.text() == "Error: boom"


# ---------------------------------------------------------------------------
# _check_for_updates
# ---------------------------------------------------------------------------

@pytest.mark.unit
class TestCheckForUpdates:
    def test_updates_not_available(self, built_plugin):
        with patch("utils.updates.is_available", return_value=False), \
             patch("utils.updates.check_for_updates") as mock_check:
            built_plugin._check_for_updates()
        mock_check.assert_not_called()
        assert "not available" in built_plugin.update_status_label.text().lower()

    def test_check_success(self, built_plugin):
        with patch("utils.updates.is_available", return_value=True), \
             patch("utils.updates.check_for_updates", return_value=True):
            built_plugin._check_for_updates()
        assert "checking" in built_plugin.update_status_label.text().lower()

    def test_check_error_result(self, built_plugin):
        with patch("utils.updates.is_available", return_value=True), \
             patch("utils.updates.check_for_updates", return_value="error"):
            built_plugin._check_for_updates()
        assert built_plugin.update_status_label.text() == "Update check failed"

    def test_check_exception(self, built_plugin):
        with patch("utils.updates.is_available", side_effect=RuntimeError("boom")):
            built_plugin._check_for_updates()
        assert built_plugin.update_status_label.text() == "Error: boom"


# ---------------------------------------------------------------------------
# _disconnect_vpn
# ---------------------------------------------------------------------------

@pytest.mark.unit
class TestDisconnectVpn:
    def test_darwin(self, settings_plugin):
        mock_mgr = MagicMock()
        mock_mgr.get_active_config_path.return_value = "/tmp/resistine.conf"
        with patch("platform.system", return_value="Darwin"), \
             patch(
                 "plugins.vpn.wireguard.vpn_functions_darwin.stop_vpn",
                 create=True,
             ) as mock_stop, \
             patch(
                 "plugins.vpn.wireguard.vpn_functions_darwin.get_writable_wireguard_dir",
                 return_value="/nonexistent/wg",
                 create=True,
             ), \
             patch(
                 "plugins.vpn.config_manager.VPNConfigManager",
                 return_value=mock_mgr,
             ):
            settings_plugin._disconnect_vpn()
            mock_stop.assert_called_once_with("/tmp/resistine.conf")

    def test_darwin_no_active_config_still_stops(self, settings_plugin):
        """If no config is registered, still call stop_vpn with a sentinel
        so the tunnel is forcibly torn down rather than silently skipped."""
        mock_mgr = MagicMock()
        mock_mgr.get_active_config_path.return_value = None
        with patch("platform.system", return_value="Darwin"), \
             patch(
                 "plugins.vpn.wireguard.vpn_functions_darwin.stop_vpn",
                 create=True,
             ) as mock_stop, \
             patch(
                 "plugins.vpn.wireguard.vpn_functions_darwin.get_writable_wireguard_dir",
                 return_value="/nonexistent/wg",
                 create=True,
             ), \
             patch(
                 "plugins.vpn.config_manager.VPNConfigManager",
                 return_value=mock_mgr,
             ):
            settings_plugin._disconnect_vpn()
            mock_stop.assert_called_once_with("")

    def test_windows(self, settings_plugin):
        with patch("platform.system", return_value="Windows"), \
             patch(
                 "plugins.vpn.wireguard.vpn_windows_client.disconnect",
                 create=True,
             ) as mock_disc:
            settings_plugin._disconnect_vpn()
            mock_disc.assert_called_once_with("resistine")

    def test_linux(self, settings_plugin):
        mock_mgr = MagicMock()
        mock_mgr.get_active_config_path.return_value = "/tmp/resistine.conf"
        with patch("platform.system", return_value="Linux"), \
             patch(
                 "plugins.vpn.wireguard.vpn_functions_linux.stop_vpn",
                 create=True,
             ) as mock_stop, \
             patch(
                 "plugins.vpn.wireguard.vpn_functions_linux.get_writable_wireguard_dir",
                 return_value="/nonexistent/wg",
                 create=True,
             ), \
             patch(
                 "plugins.vpn.config_manager.VPNConfigManager",
                 return_value=mock_mgr,
             ):
            settings_plugin._disconnect_vpn()
            mock_stop.assert_called_once_with("/tmp/resistine.conf")

    def test_failure_logs_warning(self, settings_plugin):
        with patch("platform.system", side_effect=RuntimeError("boom")):
            settings_plugin._disconnect_vpn()  # should not raise


# ---------------------------------------------------------------------------
# _remove_wazuh_agent
# ---------------------------------------------------------------------------

@pytest.mark.unit
class TestRemoveWazuhAgent:
    def test_darwin_calls_remove_agent_with_wipe_keys(self, settings_plugin):
        with patch("platform.system", return_value="Darwin"), \
             patch(
                 "plugins.wazuh.agent.wazuh_functions_darwin.remove_agent",
                 return_value=True,
                 create=True,
             ) as mock_remove:
            settings_plugin._remove_wazuh_agent()
            mock_remove.assert_called_once_with(wipe_keys=True)

    def test_linux_calls_remove_agent_with_wipe_keys(self, settings_plugin):
        with patch("platform.system", return_value="Linux"), \
             patch(
                 "plugins.wazuh.agent.wazuh_functions_linux.remove_agent",
                 return_value=True,
                 create=True,
             ) as mock_remove:
            settings_plugin._remove_wazuh_agent()
            mock_remove.assert_called_once_with(wipe_keys=True)

    def test_windows_calls_remove_agent_with_wipe_keys(self, settings_plugin):
        with patch("platform.system", return_value="Windows"), \
             patch(
                 "plugins.wazuh.agent.wazuh_functions_windows.remove_agent",
                 return_value=True,
                 create=True,
             ) as mock_remove:
            settings_plugin._remove_wazuh_agent()
            mock_remove.assert_called_once_with(wipe_keys=True)

    def test_remove_failure_does_not_raise(self, settings_plugin):
        """remove_agent() returning False (e.g. user cancels admin prompt)
        must not break the logout flow."""
        with patch("platform.system", return_value="Darwin"), \
             patch(
                 "plugins.wazuh.agent.wazuh_functions_darwin.remove_agent",
                 return_value=False,
                 create=True,
             ):
            settings_plugin._remove_wazuh_agent()  # should not raise

    def test_remove_exception_does_not_raise(self, settings_plugin):
        with patch("platform.system", side_effect=RuntimeError("boom")):
            settings_plugin._remove_wazuh_agent()  # should not raise


# ---------------------------------------------------------------------------
# _clear_user_data
# ---------------------------------------------------------------------------

@pytest.mark.unit
class TestClearUserData:
    def test_clears_auth_namespace(self, settings_plugin, isolated_settings):
        isolated_settings.set("auth", "email", "alice@example.com")
        isolated_settings.set("auth", "logged_in", True)

        with patch("platform.system", return_value="Darwin"), \
             patch(
                 "plugins.vpn.wireguard.vpn_functions_darwin.get_writable_wireguard_dir",
                 return_value="/nonexistent/wg",
                 create=True,
             ):
            settings_plugin._clear_user_data()

        assert isolated_settings.get("auth", "email") is None
        assert isolated_settings.get("auth", "logged_in") is None

    def test_clears_wireguard_keys_darwin(self, settings_plugin, isolated_settings):
        isolated_settings.set_secret("wireguard", "private_key", "wg-priv")
        isolated_settings.set("wireguard", "public_key", "wg-pub")

        with patch("platform.system", return_value="Darwin"), \
             patch(
                 "plugins.vpn.wireguard.vpn_functions_darwin.get_writable_wireguard_dir",
                 return_value="/nonexistent/wg",
                 create=True,
             ):
            settings_plugin._clear_user_data()

        assert isolated_settings.get("wireguard", "private_key") is None
        assert isolated_settings.get("wireguard", "public_key") is None

    def test_clears_vpn_keys_windows(self, settings_plugin, isolated_settings):
        """Windows stores WG keys in the 'vpn' namespace — cleared via clear_namespace."""
        isolated_settings.set_secret("vpn", "private_key", "vpn-priv")
        isolated_settings.set("vpn", "public_key", "vpn-pub")

        with patch("platform.system", return_value="Darwin"), \
             patch(
                 "plugins.vpn.wireguard.vpn_functions_darwin.get_writable_wireguard_dir",
                 return_value="/nonexistent/wg",
                 create=True,
             ):
            settings_plugin._clear_user_data()

        assert isolated_settings.get("vpn", "private_key") is None
        assert isolated_settings.get("vpn", "public_key") is None

    def test_clears_vpn_namespace(self, settings_plugin, isolated_settings):
        isolated_settings.set("vpn", "active_config", "resistine")
        isolated_settings.set("vpn", "onboarding_complete", True)

        with patch("platform.system", return_value="Darwin"), \
             patch(
                 "plugins.vpn.wireguard.vpn_functions_darwin.get_writable_wireguard_dir",
                 return_value="/nonexistent/wg",
                 create=True,
             ):
            settings_plugin._clear_user_data()

        assert isolated_settings.get("vpn", "active_config") is None
        assert isolated_settings.get("vpn", "onboarding_complete") is None

    def test_removes_conf_files(self, settings_plugin, isolated_settings, tmp_path):
        wg_dir = tmp_path / "wireguard"
        wg_dir.mkdir()
        (wg_dir / "resistine.conf").write_text("[Interface]")
        (wg_dir / "custom.conf").write_text("[Interface]")
        (wg_dir / "keepme.txt").write_text("not a conf")

        with patch("platform.system", return_value="Darwin"), \
             patch(
                 "plugins.vpn.wireguard.vpn_functions_darwin.get_writable_wireguard_dir",
                 return_value=str(wg_dir),
                 create=True,
             ):
            settings_plugin._clear_user_data()

        assert not (wg_dir / "resistine.conf").exists()
        assert not (wg_dir / "custom.conf").exists()
        assert (wg_dir / "keepme.txt").exists()

    def test_clears_chat_history(self, settings_plugin, isolated_settings):
        isolated_settings.set("chat_history", "index", [{"id": "s1"}])
        isolated_settings.set("chat_history", "msg_s1", [{"role": "user"}])

        with patch("platform.system", return_value="Darwin"), \
             patch(
                 "plugins.vpn.wireguard.vpn_functions_darwin.get_writable_wireguard_dir",
                 return_value="/nonexistent/wg",
                 create=True,
             ):
            settings_plugin._clear_user_data()

        assert isolated_settings.get("chat_history", "index") is None

    def test_clears_chat_api_key(self, settings_plugin, isolated_settings):
        isolated_settings.set_secret("chat", "openai_api_key", "sk-secret")
        isolated_settings.set("chat", "openai_base_url", "http://localhost")

        with patch("platform.system", return_value="Darwin"), \
             patch(
                 "plugins.vpn.wireguard.vpn_functions_darwin.get_writable_wireguard_dir",
                 return_value="/nonexistent/wg",
                 create=True,
             ):
            settings_plugin._clear_user_data()

        assert isolated_settings.get_secret("chat", "openai_api_key") is None
        assert isolated_settings.get("chat", "openai_base_url") is None

    def test_clears_wazuh_namespace(self, settings_plugin, isolated_settings):
        isolated_settings.set("wazuh", "enrolled_email", "alice@example.com")
        isolated_settings.set("wazuh", "install_state", "installed")
        isolated_settings.set("wazuh", "retry_count", 2)

        with patch("platform.system", return_value="Darwin"), \
             patch(
                 "plugins.vpn.wireguard.vpn_functions_darwin.get_writable_wireguard_dir",
                 return_value="/nonexistent/wg",
                 create=True,
             ):
            settings_plugin._clear_user_data()

        assert isolated_settings.get("wazuh", "enrolled_email") is None
        assert isolated_settings.get("wazuh", "install_state") is None
        assert isolated_settings.get("wazuh", "retry_count") is None

    def test_preserves_device_scoped_settings(
        self, settings_plugin, isolated_settings,
    ):
        isolated_settings.set("chat", "disable_animation", True)
        isolated_settings.set("antivirus", "auto_update_enabled", True)

        with patch("platform.system", return_value="Darwin"), \
             patch(
                 "plugins.vpn.wireguard.vpn_functions_darwin.get_writable_wireguard_dir",
                 return_value="/nonexistent/wg",
                 create=True,
             ):
            settings_plugin._clear_user_data()

        assert isolated_settings.get("chat", "disable_animation") is True
        assert isolated_settings.get("antivirus", "auto_update_enabled") is True
