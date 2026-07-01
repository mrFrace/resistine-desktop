"""Tests for plugins.settings.main — Settings Plugin logic.

Covers: save_api_key, save_animation_setting, change_appearance_mode,
_effective_appearance_mode, _apply_theme_refresh, _get_app_version,
_handle_logout guard, _handle_uninstall guard, _check_for_updates.
"""

import sys
from unittest.mock import MagicMock, patch

import pytest

# Ensure tkinter.messagebox is stubbed (conftest stubs tkinter as MagicMock,
# but "import tkinter.messagebox" inside methods fails because it tries to
# load a submodule of a MagicMock).
if "tkinter.messagebox" not in sys.modules:
    sys.modules["tkinter.messagebox"] = MagicMock()


@pytest.fixture()
def settings_plugin(isolated_settings):
    """Create a Settings Plugin with mocked app."""
    app = MagicMock()
    from plugins.settings.main import Plugin
    return Plugin(app)


# ---------------------------------------------------------------------------
# save_api_key
# ---------------------------------------------------------------------------

@pytest.mark.unit
class TestSaveApiKey:
    def test_saves_key_and_base_url(self, settings_plugin, isolated_settings):
        settings_plugin.api_key_entry = MagicMock()
        settings_plugin.api_key_entry.get.return_value = "sk-test-key"
        settings_plugin.api_base_entry = MagicMock()
        settings_plugin.api_base_entry.get.return_value = "http://localhost:11434/v1"
        settings_plugin.status_label = MagicMock()
        settings_plugin.app.plugin_list = []

        settings_plugin.save_api_key()

        assert isolated_settings.get_secret("chat", "openai_api_key") == "sk-test-key"
        assert isolated_settings.get("chat", "openai_base_url") == "http://localhost:11434/v1"

    def test_empty_key_does_nothing(self, settings_plugin, isolated_settings):
        settings_plugin.api_key_entry = MagicMock()
        settings_plugin.api_key_entry.get.return_value = "   "
        settings_plugin.api_base_entry = MagicMock()
        settings_plugin.api_base_entry.get.return_value = ""
        settings_plugin.status_label = MagicMock()

        settings_plugin.save_api_key()

        assert isolated_settings.get_secret("chat", "openai_api_key") is None

    def test_clears_base_url_when_empty(self, settings_plugin, isolated_settings):
        isolated_settings.set("chat", "openai_base_url", "http://old.url")

        settings_plugin.api_key_entry = MagicMock()
        settings_plugin.api_key_entry.get.return_value = "sk-key"
        settings_plugin.api_base_entry = MagicMock()
        settings_plugin.api_base_entry.get.return_value = ""
        settings_plugin.status_label = MagicMock()
        settings_plugin.app.plugin_list = []

        settings_plugin.save_api_key()

        assert isolated_settings.get("chat", "openai_base_url") is None

    def test_reinitializes_chat_plugin(self, settings_plugin, isolated_settings):
        mock_chat = MagicMock()
        mock_chat.get_name.return_value = "Chat"
        settings_plugin.app.plugin_list = [mock_chat]

        settings_plugin.api_key_entry = MagicMock()
        settings_plugin.api_key_entry.get.return_value = "sk-key"
        settings_plugin.api_base_entry = MagicMock()
        settings_plugin.api_base_entry.get.return_value = ""
        settings_plugin.status_label = MagicMock()

        settings_plugin.save_api_key()

        mock_chat.reinitialize_client.assert_called_once()


# ---------------------------------------------------------------------------
# save_animation_setting
# ---------------------------------------------------------------------------

@pytest.mark.unit
class TestSaveAnimationSetting:
    def test_saves_true(self, settings_plugin, isolated_settings):
        settings_plugin.disable_animation_var = MagicMock()
        settings_plugin.disable_animation_var.get.return_value = True
        settings_plugin.save_animation_setting()
        assert isolated_settings.get("chat", "disable_animation") is True

    def test_saves_false(self, settings_plugin, isolated_settings):
        settings_plugin.disable_animation_var = MagicMock()
        settings_plugin.disable_animation_var.get.return_value = False
        settings_plugin.save_animation_setting()
        assert isolated_settings.get("chat", "disable_animation") is False


# ---------------------------------------------------------------------------
# change_appearance_mode
# ---------------------------------------------------------------------------

@pytest.mark.unit
class TestChangeAppearanceMode:
    def test_calls_set_appearance_mode(self, settings_plugin):
        import customtkinter
        settings_plugin.change_appearance_mode("Dark")
        customtkinter.set_appearance_mode.assert_called_with("Dark")

    def test_applies_theme_refresh(self, settings_plugin):
        with patch.object(settings_plugin, "_apply_theme_refresh") as mock_refresh:
            settings_plugin.change_appearance_mode("Light")
            mock_refresh.assert_called_once()


# ---------------------------------------------------------------------------
# _effective_appearance_mode
# ---------------------------------------------------------------------------

@pytest.mark.unit
class TestEffectiveAppearanceMode:
    def test_returns_mode_when_not_system(self, settings_plugin):
        import customtkinter
        customtkinter.get_appearance_mode.return_value = "Dark"
        assert settings_plugin._effective_appearance_mode() == "Dark"

    def test_system_mode_darwin_dark(self, settings_plugin, monkeypatch):
        import customtkinter
        customtkinter.get_appearance_mode.return_value = "System"
        monkeypatch.setattr("sys.platform", "darwin")

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="Dark")
            result = settings_plugin._effective_appearance_mode()
            assert result == "Dark"

    def test_system_mode_darwin_light(self, settings_plugin, monkeypatch):
        import customtkinter
        customtkinter.get_appearance_mode.return_value = "System"
        monkeypatch.setattr("sys.platform", "darwin")

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stdout="")
            result = settings_plugin._effective_appearance_mode()
            assert result == "Light"

    def test_system_mode_non_darwin(self, settings_plugin, monkeypatch):
        import customtkinter
        customtkinter.get_appearance_mode.return_value = "System"
        monkeypatch.setattr("sys.platform", "linux")
        result = settings_plugin._effective_appearance_mode()
        assert result == "Light"


# ---------------------------------------------------------------------------
# _apply_theme_refresh
# ---------------------------------------------------------------------------

@pytest.mark.unit
class TestApplyThemeRefresh:
    def test_calls_refresh_ui_theme(self, settings_plugin):
        settings_plugin.app.refresh_ui_theme = MagicMock()
        settings_plugin._apply_theme_refresh()
        settings_plugin.app.refresh_ui_theme.assert_called_once()

    def test_falls_back_to_update_idletasks(self, settings_plugin):
        settings_plugin.app.refresh_ui_theme = MagicMock(side_effect=RuntimeError("fail"))
        settings_plugin._apply_theme_refresh()
        settings_plugin.app.update_idletasks.assert_called()

    def test_no_refresh_method(self, settings_plugin):
        del settings_plugin.app.refresh_ui_theme
        settings_plugin._apply_theme_refresh()
        settings_plugin.app.update_idletasks.assert_called()


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
# _handle_logout
# ---------------------------------------------------------------------------

@pytest.mark.unit
class TestHandleLogout:
    def _set_messagebox(self, return_value):
        """Set tkinter.messagebox.askyesno on the mock tkinter parent."""
        tk = sys.modules["tkinter"]
        tk.messagebox.askyesno = MagicMock(return_value=return_value)

    def test_user_cancels(self, settings_plugin):
        self._set_messagebox(False)
        mock_login = MagicMock(); mock_login.id = "007"
        settings_plugin.app.plugin_list = [mock_login]
        settings_plugin._handle_logout()

    def test_refuses_when_login_plugin_uninstalled(self, settings_plugin):
        """Without the Login plugin installed the user can't sign back in,
        so logout must short-circuit with a user-facing notification."""
        settings_plugin.app.plugin_list = []  # login absent
        settings_plugin.app.show_notification = MagicMock()
        # askyesno would normally be the user-visible step; assert we never
        # got that far.
        self._set_messagebox(True)
        settings_plugin._handle_logout()
        settings_plugin.app.show_notification.assert_called_once()
        msg = settings_plugin.app.show_notification.call_args[0][0]
        assert "Login plugin" in msg and "Store" in msg

    def test_clears_auth_on_confirm(self, settings_plugin, isolated_settings):
        isolated_settings.set("auth", "logged_in", True)
        isolated_settings.set("auth", "email", "alice@example.com")
        self._set_messagebox(True)
        # Logout is gated on the Login plugin being installed.
        mock_login = MagicMock(); mock_login.id = "007"
        settings_plugin.app.plugin_list = [mock_login]
        mock_mgr = MagicMock()
        mock_mgr.get_active_config_path.return_value = None
        with patch("platform.system", return_value="Darwin"), \
             patch("plugins.vpn.wireguard.vpn_functions_darwin.stop_vpn", create=True), \
             patch(
                 "plugins.vpn.wireguard.vpn_functions_darwin.get_writable_wireguard_dir",
                 return_value="/tmp/wg",
                 create=True,
             ), \
             patch("plugins.vpn.config_manager.VPNConfigManager", return_value=mock_mgr), \
             patch(
                 "plugins.wazuh.agent.wazuh_functions_darwin.remove_agent",
                 return_value=True,
                 create=True,
             ), \
             patch("plugins.login.main.Plugin"):
            settings_plugin._handle_logout()
        # auth namespace is fully cleared on logout
        assert isolated_settings.get("auth", "logged_in") is None
        assert isolated_settings.get("auth", "email") is None

    def test_handle_logout_invokes_wazuh_removal(self, settings_plugin):
        """_handle_logout must call _remove_wazuh_agent so the service is
        stopped and enrollment keys are wiped, not just settings cleared."""
        self._set_messagebox(True)
        mock_login = MagicMock(); mock_login.id = "007"
        settings_plugin.app.plugin_list = [mock_login]
        mock_mgr = MagicMock()
        mock_mgr.get_active_config_path.return_value = None
        with patch("platform.system", return_value="Darwin"), \
             patch("plugins.vpn.wireguard.vpn_functions_darwin.stop_vpn", create=True), \
             patch(
                 "plugins.vpn.wireguard.vpn_functions_darwin.get_writable_wireguard_dir",
                 return_value="/tmp/wg",
                 create=True,
             ), \
             patch("plugins.vpn.config_manager.VPNConfigManager", return_value=mock_mgr), \
             patch(
                 "plugins.wazuh.agent.wazuh_functions_darwin.remove_agent",
                 return_value=True,
                 create=True,
             ) as mock_remove, \
             patch("plugins.login.main.Plugin"):
            settings_plugin._handle_logout()
        mock_remove.assert_called_once_with(wipe_keys=True)


# ---------------------------------------------------------------------------
# _handle_uninstall
# ---------------------------------------------------------------------------

@pytest.mark.unit
class TestHandleUninstall:
    def _set_messagebox(self, return_value):
        tk = sys.modules["tkinter"]
        tk.messagebox.askyesno = MagicMock(return_value=return_value)

    def test_user_cancels(self, settings_plugin):
        self._set_messagebox(False)
        settings_plugin._handle_uninstall()

    def test_uninstall_success_destroys_app(self, settings_plugin):
        settings_plugin.uninstall_button = MagicMock()
        settings_plugin.uninstall_status_label = MagicMock()
        self._set_messagebox(True)

        with patch("utils.uninstall.run_uninstall", return_value=(True, "ok")):
            settings_plugin._handle_uninstall()
            settings_plugin.app.destroy.assert_called_once()

    def test_uninstall_failure_shows_error(self, settings_plugin):
        settings_plugin.uninstall_button = MagicMock()
        settings_plugin.uninstall_status_label = MagicMock()
        self._set_messagebox(True)

        with patch("utils.uninstall.run_uninstall", return_value=(False, "denied")):
            settings_plugin._handle_uninstall()
            settings_plugin.app.destroy.assert_not_called()
            settings_plugin.uninstall_button.configure.assert_called()


# ---------------------------------------------------------------------------
# _check_for_updates
# ---------------------------------------------------------------------------

@pytest.mark.unit
class TestCheckForUpdates:
    def test_updates_not_available(self, settings_plugin):
        settings_plugin.update_status_label = MagicMock()
        with patch("utils.updates.is_available", return_value=False):
            settings_plugin._check_for_updates()
        last_call = settings_plugin.update_status_label.configure.call_args
        assert "not available" in last_call.kwargs["text"].lower()

    def test_check_success(self, settings_plugin):
        settings_plugin.update_status_label = MagicMock()
        with patch("utils.updates.is_available", return_value=True), \
             patch("utils.updates.check_for_updates", return_value=True):
            settings_plugin._check_for_updates()
        last_call = settings_plugin.update_status_label.configure.call_args
        assert "checking" in last_call.kwargs["text"].lower()

    def test_check_exception(self, settings_plugin):
        settings_plugin.update_status_label = MagicMock()
        with patch("utils.updates.is_available", side_effect=RuntimeError("boom")):
            settings_plugin._check_for_updates()
        last_call = settings_plugin.update_status_label.configure.call_args
        assert "error" in last_call.kwargs["text"].lower()


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
                 return_value="/tmp/wg",
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
                 return_value="/tmp/wg",
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
                 return_value="/tmp/wg",
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
                 return_value="/tmp/wg",
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
                 return_value="/tmp/wg",
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
                 return_value="/tmp/wg",
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
                 return_value="/tmp/wg",
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
                 return_value="/tmp/wg",
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
                 return_value="/tmp/wg",
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
                 return_value="/tmp/wg",
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
                 return_value="/tmp/wg",
                 create=True,
             ):
            settings_plugin._clear_user_data()

        assert isolated_settings.get("chat", "disable_animation") is True
        assert isolated_settings.get("antivirus", "auto_update_enabled") is True

    def test_removes_legacy_email_file(
        self, settings_plugin, isolated_settings, tmp_path,
    ):
        # _clear_user_data builds the path as:
        #   dirname(dirname(dirname(realpath(__file__)))) / "utils" / "email-settings.txt"
        # So we need realpath to point 3 levels deep under a root that
        # contains utils/email-settings.txt.
        fake_root = tmp_path / "root"
        utils_dir = fake_root / "utils"
        utils_dir.mkdir(parents=True)
        email_file = utils_dir / "email-settings.txt"
        email_file.write_text("alice@example.com")

        fake_module = fake_root / "plugins" / "settings" / "main.py"

        with patch("platform.system", return_value="Darwin"), \
             patch(
                 "plugins.vpn.wireguard.vpn_functions_darwin.get_writable_wireguard_dir",
                 return_value="/tmp/wg",
                 create=True,
             ), \
             patch(
                 "plugins.settings.main.os.path.realpath",
                 return_value=str(fake_module),
             ):
            settings_plugin._clear_user_data()

        assert not email_file.exists()
