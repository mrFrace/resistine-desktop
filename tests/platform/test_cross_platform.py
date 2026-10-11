"""
Cross-platform compatibility tests.

These tests verify that the platform-abstracted code behaves correctly
on all supported platforms (macOS, Windows, Linux).

All subprocess calls are mocked — safe to run anywhere.
"""
import platform
import os
import pytest
from unittest.mock import MagicMock, patch


# ===========================================================================
# Settings: correct config dir per platform
# ===========================================================================
class TestConfigDirPerPlatform:
    def test_darwin_config_dir(self):
        with patch("utils.settings.platform.system", return_value="Darwin"):
            from utils.settings import get_config_dir
            path = get_config_dir()
        assert "Library/Application Support/Phoenix" in path

    def test_windows_config_dir(self):
        with patch("utils.settings.platform.system", return_value="Windows"):
            with patch.dict(os.environ, {"APPDATA": r"C:\Users\Test\AppData\Roaming"}):
                from utils.settings import get_config_dir
                path = get_config_dir()
        assert "Phoenix" in path

    def test_linux_config_dir(self):
        with patch("utils.settings.platform.system", return_value="Linux"):
            from utils.settings import get_config_dir
            path = get_config_dir()
        assert ".config/phoenix" in path

    def test_darwin_path_is_absolute(self):
        with patch("utils.settings.platform.system", return_value="Darwin"):
            from utils.settings import get_config_dir
            path = get_config_dir()
        assert os.path.isabs(path), f"Non-absolute path for Darwin: {path}"

    def test_linux_path_is_absolute(self):
        with patch("utils.settings.platform.system", return_value="Linux"):
            from utils.settings import get_config_dir
            path = get_config_dir()
        assert os.path.isabs(path), f"Non-absolute path for Linux: {path}"


# ===========================================================================
# Settings: cross-platform get/set/secret
# ===========================================================================
class TestSettingsCrossPlatform:
    def test_get_set_works(self, isolated_settings):
        isolated_settings.set("test_ns", "key", "value")
        assert isolated_settings.get("test_ns", "key") == "value"

    def test_secrets_work(self, isolated_settings):
        isolated_settings.set_secret("test_ns", "secret_key", "secret_value")
        result = isolated_settings.get_secret("test_ns", "secret_key")
        assert result == "secret_value"

    def test_namespace_cleared(self, isolated_settings):
        isolated_settings.set("ns", "x", 1)
        isolated_settings.clear_namespace("ns")
        assert isolated_settings.list_keys("ns") == []


# ===========================================================================
# VPN config manager: cross-platform filesystem behavior
# ===========================================================================
class TestVPNConfigManagerCrossPlatform:
    def test_import_and_list_config(self, wireguard_dir, isolated_settings, sample_wireguard_conf):
        from plugins.vpn.config_manager import VPNConfigManager
        mgr = VPNConfigManager(str(wireguard_dir))
        ok, name = mgr.import_config("corp.conf", sample_wireguard_conf)
        assert ok is True
        names = [c["name"] for c in mgr.list_configs()]
        assert name in names

    def test_sanitize_filename_no_path_sep(self, wireguard_dir, isolated_settings):
        from plugins.vpn.config_manager import VPNConfigManager
        mgr = VPNConfigManager(str(wireguard_dir))
        # Path separators must be stripped
        result = mgr.sanitize_filename("../../evil.conf")
        assert os.sep not in result
        assert "/" not in result
        assert "\\" not in result


# ===========================================================================
# Wazuh: architecture mapping
# ===========================================================================
class TestWazuhArchMapping:
    @pytest.mark.parametrize("machine,expected_arch", [
        ("arm64", "arm64"),
        ("x86_64", "intel64"),
        ("unknown", "arm64"),  # fallback
    ])
    @patch("plugins.wazuh.agent.wazuh_functions_darwin.platform.machine")
    def test_package_url_arch(self, mock_machine, machine, expected_arch):
        mock_machine.return_value = machine
        from plugins.wazuh.agent.wazuh_functions_darwin import get_package_url
        url = get_package_url()
        assert expected_arch in url


# ===========================================================================
# LoginAPI: works regardless of OS
# ===========================================================================
class TestLoginAPICrossPlatform:
    @patch("plugins.login.api.requests.post")
    def test_send_otp_cross_platform(self, mock_post):
        mock_post.return_value = MagicMock(
            ok=True,
            status_code=200,
            json=lambda: {"status": "success"},
            text='{"status": "success"}',
        )
        from plugins.login.api import LoginAPI
        api = LoginAPI("https://test.resistine.work")
        ok, msg, data = api.send_otp("user@example.com")
        assert ok is True

    @patch("plugins.login.api.requests.post")
    def test_verify_otp_uses_real_hostname(self, mock_post):
        """hostname in payload should be the actual machine hostname, not hardcoded."""
        import socket
        mock_post.return_value = MagicMock(
            ok=True,
            status_code=200,
            json=lambda: {"status": "success"},
            text='{"status": "success"}',
        )
        from plugins.login.api import LoginAPI
        api = LoginAPI("https://test.resistine.work")
        api.verify_otp("user@example.com", "123456", "pubkey")
        payload = mock_post.call_args[1]["json"]
        assert payload["hostname"] == socket.gethostname()


# ===========================================================================
# WireGuard key generation: cross-platform cryptography
# ===========================================================================
class TestWireguardKeyCrossPlatform:
    def test_key_generation_works(self):
        from plugins.vpn.wireguard.vpn_functions_darwin import generate_wireguard_keys
        result = generate_wireguard_keys()
        assert result is not None
        assert len(result["private_key"]) == 44
        assert len(result["public_key"]) == 44

    def test_key_generation_uses_x25519(self):
        """Keys must be X25519 — 32 raw bytes, 44 chars base64-encoded."""
        import base64
        from plugins.vpn.wireguard.vpn_functions_darwin import generate_wireguard_keys
        result = generate_wireguard_keys()
        priv_raw = base64.b64decode(result["private_key"])
        pub_raw = base64.b64decode(result["public_key"])
        assert len(priv_raw) == 32
        assert len(pub_raw) == 32


# ===========================================================================
# Encryption: Fernet keys are cross-platform
# ===========================================================================
class TestFernetCrossPlatform:
    def test_encrypt_decrypt_same_python(self, isolated_settings):
        """Fernet encrypt/decrypt in the same Python process must round-trip."""
        isolated_settings.set_secret("ns", "payload", "cross_platform_value")
        result = isolated_settings.get_secret("ns", "payload")
        assert result == "cross_platform_value"

    def test_fernet_key_is_44_bytes_base64(self, mock_keyring):
        """Fernet.generate_key() must always produce a 44-char base64 key."""
        from cryptography.fernet import Fernet
        key = Fernet.generate_key()
        assert len(key) == 44


# ===========================================================================
# Agent name + group: no platform-specific chars required
# ===========================================================================
class TestAgentIdentityCrossPlatform:
    @patch("plugins.wazuh.agent.wazuh_functions_darwin.subprocess.run")
    @patch("plugins.wazuh.agent.wazuh_functions_darwin.socket.gethostname", return_value="test-machine")
    def test_agent_name_is_ascii(self, mock_host, mock_run, isolated_settings, monkeypatch):
        monkeypatch.setattr(
            "plugins.wazuh.agent.wazuh_functions_darwin.settings", isolated_settings
        )
        mock_run.return_value = MagicMock(stdout="", returncode=1)
        from plugins.wazuh.agent.wazuh_functions_darwin import get_agent_name
        name = get_agent_name()
        name.encode("ascii")  # Should not raise

    def test_agent_group_is_ascii(self, isolated_settings, monkeypatch):
        monkeypatch.setattr(
            "plugins.wazuh.agent.wazuh_functions_darwin.settings", isolated_settings
        )
        isolated_settings.set("auth", "email", "user@example.com")
        from plugins.wazuh.agent.wazuh_functions_darwin import get_agent_group
        group = get_agent_group()
        group.encode("ascii")  # Should not raise


# ===========================================================================
# Wazuh platform modules are importable on any host
#
# Earlier versions of this codebase used NotImplementedError stubs for the
# non-native platform modules. Those stubs are gone — every platform module
# has a real implementation. These tests verify only that the modules import
# cleanly and expose the expected symbols, without invoking any function
# that would touch the real system (start_agent/stop_agent would call
# NET STOP / sudo against the host).
#
# NOTE: the previous version of this section was a pair of
# TestWazuhWindowsStubs/TestWazuhLinuxStubs classes that called
# start_agent/stop_agent/full_install directly and expected
# NotImplementedError. Those tests were from when the platform modules
# were stubs. By the time the tests became relevant, the implementations
# had been filled in and the tests were attempting to run NET STOP
# WazuhSvc, Stop-Service -Force, pkexec, and sudo commands on my real
# system during every suite run. The symbol check shape chosen below is
# intentionally defensive... it confirms the functions exist without
# actually invoking them. If you ever add a test that needs to call
# these functions going forward please make sure it's inside a
# subprocess-mocking context (or uses the allow_subprocess if truly
# necessary), otherwise you'll run into the same "real commands" issue
# described above. - Austin
# ===========================================================================
class TestWazuhPlatformModulesImportable:
    @pytest.mark.parametrize("func_name", [
        "get_agent_name",
        "get_agent_group",
        "get_package_url",
        "is_agent_installed",
        "get_agent_status",
        "start_agent",
        "stop_agent",
        "full_install",
    ])
    def test_windows_module_exposes_symbol(self, func_name):
        from plugins.wazuh.agent import wazuh_functions_windows as wfw
        assert callable(getattr(wfw, func_name)), f"{func_name} missing from wazuh_functions_windows"

    @pytest.mark.parametrize("func_name", [
        "get_agent_name",
        "get_agent_group",
        "get_package_url",
        "is_agent_installed",
        "get_agent_status",
        "start_agent",
        "stop_agent",
        "full_install",
    ])
    def test_linux_module_exposes_symbol(self, func_name):
        from plugins.wazuh.agent import wazuh_functions_linux as wfl
        assert callable(getattr(wfl, func_name)), f"{func_name} missing from wazuh_functions_linux"

    def test_darwin_module_exposes_symbol(self):
        from plugins.wazuh.agent import wazuh_functions_darwin as wfd
        assert callable(getattr(wfd, "get_agent_status"))
