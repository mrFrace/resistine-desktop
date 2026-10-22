"""
Unit tests for plugins/vpn/wireguard/vpn_functions_darwin.py (macOS VPN).

All subprocess calls and settings I/O are mocked.
Tests run on any platform.

Covers:
- generate_wireguard_keys — key shape and independence
- save / get / delete / exists wireguard keys
- setup_vpn_keys — full flow
- parse_and_create_vpn_config — valid config, missing fields, invalid JSON
- save_vpn_configuration — delegates to parse_and_create
- start_vpn / stop_vpn — CLI helper delegation
- check_service_status — Running / Stopped
- is_extension_enabled — parsing systemextensionsctl output
- check_wireguard_installed — always True on macOS
- VPNConfigManager — active config path
"""
import base64
import json
import os
import pytest
from unittest.mock import MagicMock, patch


# ---------------------------------------------------------------------------
# Setup: patch settings + CLI helper for all tests
# ---------------------------------------------------------------------------
@pytest.fixture(autouse=True)
def patch_vpn_settings(isolated_settings, monkeypatch):
    monkeypatch.setattr("plugins.vpn.wireguard.vpn_functions_darwin.settings", isolated_settings)


@pytest.fixture(autouse=True)
def disable_cli_detection(monkeypatch):
    """Prevent HelperToolManager from scanning the real filesystem."""
    monkeypatch.setattr(
        "plugins.vpn.wireguard.vpn_functions_darwin.HelperToolManager._find_cli_path",
        lambda self: "/fake/resistine-vpn-cli",
    )
    # Also patch helper.is_available
    from plugins.vpn.wireguard import vpn_functions_darwin as vfd
    vfd.helper.cli_path = "/fake/resistine-vpn-cli"
    vfd.helper.is_available = True


# ===========================================================================
# generate_wireguard_keys
# ===========================================================================
@pytest.mark.unit
class TestGenerateWireguardKeys:
    def test_returns_dict_with_keys(self):
        from plugins.vpn.wireguard.vpn_functions_darwin import generate_wireguard_keys
        result = generate_wireguard_keys()
        assert result is not None
        assert "private_key" in result
        assert "public_key" in result

    def test_keys_are_base64_encoded(self):
        from plugins.vpn.wireguard.vpn_functions_darwin import generate_wireguard_keys
        result = generate_wireguard_keys()
        # Should be valid base64
        for key_name in ("private_key", "public_key"):
            decoded = base64.b64decode(result[key_name])
            assert len(decoded) == 32  # X25519 raw key = 32 bytes

    def test_each_call_produces_unique_keys(self):
        from plugins.vpn.wireguard.vpn_functions_darwin import generate_wireguard_keys
        r1 = generate_wireguard_keys()
        r2 = generate_wireguard_keys()
        assert r1["private_key"] != r2["private_key"]
        assert r1["public_key"] != r2["public_key"]

    def test_private_and_public_keys_differ(self):
        from plugins.vpn.wireguard.vpn_functions_darwin import generate_wireguard_keys
        result = generate_wireguard_keys()
        assert result["private_key"] != result["public_key"]


# ===========================================================================
# save / get / delete wireguard keys
# ===========================================================================
@pytest.mark.unit
class TestWireguardKeyStorage:
    def test_save_and_get_private_key(self, isolated_settings):
        from plugins.vpn.wireguard.vpn_functions_darwin import (
            save_wireguard_keys,
            get_wireguard_private_key,
        )
        save_wireguard_keys("my_private_key", "my_public_key")
        assert get_wireguard_private_key() == "my_private_key"

    def test_save_and_get_public_key(self, isolated_settings):
        from plugins.vpn.wireguard.vpn_functions_darwin import (
            save_wireguard_keys,
            get_wireguard_public_key,
        )
        save_wireguard_keys("my_private_key", "my_public_key")
        assert get_wireguard_public_key() == "my_public_key"

    def test_keys_stored_as_secrets(self, isolated_settings, tmp_config_dir):
        from plugins.vpn.wireguard.vpn_functions_darwin import save_wireguard_keys
        save_wireguard_keys("secret_priv", "secret_pub")
        # Secrets must not be stored in plaintext
        wg_file = tmp_config_dir / "wireguard.json"
        if wg_file.exists():
            raw = wg_file.read_text()
            assert "secret_priv" not in raw
            assert "secret_pub" not in raw

    def test_delete_wireguard_keys(self, isolated_settings):
        from plugins.vpn.wireguard.vpn_functions_darwin import (
            save_wireguard_keys,
            delete_wireguard_keys,
            wireguard_keys_exist,
        )
        save_wireguard_keys("priv", "pub")
        delete_wireguard_keys()
        assert not wireguard_keys_exist()

    def test_wireguard_keys_exist_false_initially(self, isolated_settings):
        from plugins.vpn.wireguard.vpn_functions_darwin import wireguard_keys_exist
        assert wireguard_keys_exist() is False

    def test_wireguard_keys_exist_true_after_save(self, isolated_settings):
        from plugins.vpn.wireguard.vpn_functions_darwin import (
            save_wireguard_keys,
            wireguard_keys_exist,
        )
        save_wireguard_keys("priv", "pub")
        assert wireguard_keys_exist() is True


# ===========================================================================
# setup_vpn_keys
# ===========================================================================
@pytest.mark.unit
class TestSetupVpnKeys:
    def test_returns_public_key_string(self, isolated_settings):
        from plugins.vpn.wireguard.vpn_functions_darwin import setup_vpn_keys
        pub_key = setup_vpn_keys()
        assert pub_key is not None
        assert isinstance(pub_key, str)
        assert len(pub_key) > 0

    def test_public_key_is_valid_base64(self, isolated_settings):
        from plugins.vpn.wireguard.vpn_functions_darwin import setup_vpn_keys
        pub_key = setup_vpn_keys()
        decoded = base64.b64decode(pub_key)
        assert len(decoded) == 32

    def test_deletes_old_keys_first(self, isolated_settings):
        from plugins.vpn.wireguard.vpn_functions_darwin import (
            save_wireguard_keys,
            setup_vpn_keys,
            get_wireguard_private_key,
        )
        save_wireguard_keys("old_priv", "old_pub")
        setup_vpn_keys()
        new_priv = get_wireguard_private_key()
        assert new_priv != "old_priv"

    def test_stores_both_keys(self, isolated_settings):
        from plugins.vpn.wireguard.vpn_functions_darwin import (
            setup_vpn_keys,
            wireguard_keys_exist,
        )
        setup_vpn_keys()
        assert wireguard_keys_exist()


# ===========================================================================
# parse_and_create_vpn_config
# ===========================================================================
@pytest.mark.unit
class TestParseAndCreateVpnConfig:
    def test_creates_config_file(self, tmp_path, isolated_settings, sample_vpn_config_json):
        from plugins.vpn.wireguard.vpn_functions_darwin import (
            save_wireguard_keys,
            parse_and_create_vpn_config,
        )
        save_wireguard_keys("my_priv_key", "my_pub_key")

        with patch("plugins.vpn.wireguard.vpn_functions_darwin.get_writable_wireguard_dir",
                   return_value=str(tmp_path)):
            path = parse_and_create_vpn_config(sample_vpn_config_json, "test_config")

        assert path is not None
        assert os.path.exists(path)

    def test_config_contains_interface_section(self, tmp_path, isolated_settings, sample_vpn_config_json):
        from plugins.vpn.wireguard.vpn_functions_darwin import (
            save_wireguard_keys,
            parse_and_create_vpn_config,
        )
        save_wireguard_keys("my_priv_key", "my_pub_key")
        with patch("plugins.vpn.wireguard.vpn_functions_darwin.get_writable_wireguard_dir",
                   return_value=str(tmp_path)):
            path = parse_and_create_vpn_config(sample_vpn_config_json, "test_config")
        content = open(path).read()
        assert "[Interface]" in content
        assert "[Peer]" in content

    def test_config_contains_client_address(self, tmp_path, isolated_settings, sample_vpn_config_json):
        from plugins.vpn.wireguard.vpn_functions_darwin import (
            save_wireguard_keys,
            parse_and_create_vpn_config,
        )
        save_wireguard_keys("my_priv_key", "my_pub_key")
        with patch("plugins.vpn.wireguard.vpn_functions_darwin.get_writable_wireguard_dir",
                   return_value=str(tmp_path)):
            path = parse_and_create_vpn_config(sample_vpn_config_json, "test_config")
        content = open(path).read()
        assert "10.0.0.2" in content

    def test_config_contains_server_endpoint(self, tmp_path, isolated_settings, sample_vpn_config_json):
        from plugins.vpn.wireguard.vpn_functions_darwin import (
            save_wireguard_keys,
            parse_and_create_vpn_config,
        )
        save_wireguard_keys("my_priv_key", "my_pub_key")
        with patch("plugins.vpn.wireguard.vpn_functions_darwin.get_writable_wireguard_dir",
                   return_value=str(tmp_path)):
            path = parse_and_create_vpn_config(sample_vpn_config_json, "test_config")
        content = open(path).read()
        assert "vpn.example.com:51820" in content

    def test_uses_private_key_from_storage(self, tmp_path, isolated_settings, sample_vpn_config_json):
        from plugins.vpn.wireguard.vpn_functions_darwin import (
            save_wireguard_keys,
            parse_and_create_vpn_config,
        )
        save_wireguard_keys("STORED_PRIVATE_KEY_VALUE", "pub")
        with patch("plugins.vpn.wireguard.vpn_functions_darwin.get_writable_wireguard_dir",
                   return_value=str(tmp_path)):
            path = parse_and_create_vpn_config(sample_vpn_config_json, "test_config")
        content = open(path).read()
        assert "STORED_PRIVATE_KEY_VALUE" in content

    def test_returns_none_when_no_private_key(self, tmp_path, isolated_settings, sample_vpn_config_json):
        from plugins.vpn.wireguard.vpn_functions_darwin import parse_and_create_vpn_config
        with patch("plugins.vpn.wireguard.vpn_functions_darwin.get_writable_wireguard_dir",
                   return_value=str(tmp_path)):
            path = parse_and_create_vpn_config(sample_vpn_config_json, "test_config")
        assert path is None

    def test_returns_none_for_invalid_json(self, tmp_path, isolated_settings):
        from plugins.vpn.wireguard.vpn_functions_darwin import parse_and_create_vpn_config
        with patch("plugins.vpn.wireguard.vpn_functions_darwin.get_writable_wireguard_dir",
                   return_value=str(tmp_path)):
            path = parse_and_create_vpn_config("not valid json {{{{", "test_config")
        assert path is None

    def test_accepts_dict_input(self, tmp_path, isolated_settings, sample_vpn_config_json):
        from plugins.vpn.wireguard.vpn_functions_darwin import (
            save_wireguard_keys,
            parse_and_create_vpn_config,
        )
        save_wireguard_keys("priv", "pub")
        with patch("plugins.vpn.wireguard.vpn_functions_darwin.get_writable_wireguard_dir",
                   return_value=str(tmp_path)):
            path = parse_and_create_vpn_config(sample_vpn_config_json, "test_config")
        assert path is not None

    def test_accepts_json_string_input(self, tmp_path, isolated_settings, sample_vpn_config_json):
        from plugins.vpn.wireguard.vpn_functions_darwin import (
            save_wireguard_keys,
            parse_and_create_vpn_config,
        )
        save_wireguard_keys("priv", "pub")
        with patch("plugins.vpn.wireguard.vpn_functions_darwin.get_writable_wireguard_dir",
                   return_value=str(tmp_path)):
            path = parse_and_create_vpn_config(json.dumps(sample_vpn_config_json), "test_config")
        assert path is not None

    def test_config_file_permissions_600(self, tmp_path, isolated_settings, sample_vpn_config_json):
        import platform
        import stat
        if platform.system() == "Windows":
            pytest.skip("POSIX-only")
        from plugins.vpn.wireguard.vpn_functions_darwin import (
            save_wireguard_keys,
            parse_and_create_vpn_config,
        )
        save_wireguard_keys("priv", "pub")
        with patch("plugins.vpn.wireguard.vpn_functions_darwin.get_writable_wireguard_dir",
                   return_value=str(tmp_path)):
            path = parse_and_create_vpn_config(sample_vpn_config_json, "test_config")
        mode = oct(stat.S_IMODE(os.stat(path).st_mode))
        assert mode == oct(0o600)


# ===========================================================================
# start_vpn / stop_vpn
# ===========================================================================
@pytest.mark.unit
class TestStartStopVpn:
    @patch("plugins.vpn.wireguard.vpn_functions_darwin.subprocess.run")
    def test_start_vpn_success(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0, stdout="Connected\n", stderr="")
        with patch("plugins.vpn.wireguard.vpn_functions_darwin.VPNHelper.activate_extension", return_value=True):
            from plugins.vpn.wireguard.vpn_functions_darwin import start_vpn
            result = start_vpn("/path/to/config.conf")
        assert result is True

    @patch("plugins.vpn.wireguard.vpn_functions_darwin.subprocess.run")
    def test_start_vpn_failure(self, mock_run):
        mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="error")
        with patch("plugins.vpn.wireguard.vpn_functions_darwin.VPNHelper.activate_extension", return_value=True):
            from plugins.vpn.wireguard.vpn_functions_darwin import start_vpn
            result = start_vpn("/path/to/config.conf")
        assert result is False

    @patch("plugins.vpn.wireguard.vpn_functions_darwin.subprocess.run")
    def test_stop_vpn_success(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0, stdout="Stopped\n", stderr="")
        from plugins.vpn.wireguard.vpn_functions_darwin import stop_vpn
        result = stop_vpn("/path/to/config.conf")
        assert result is True

    @patch("plugins.vpn.wireguard.vpn_functions_darwin.subprocess.run")
    def test_stop_vpn_failure(self, mock_run):
        mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="failed")
        from plugins.vpn.wireguard.vpn_functions_darwin import stop_vpn
        result = stop_vpn("/path/to/config.conf")
        assert result is False

    def test_start_vpn_without_cli_returns_false(self):
        from plugins.vpn.wireguard import vpn_functions_darwin as vfd
        original = vfd.helper.cli_path
        vfd.helper.cli_path = None
        vfd.helper.is_available = False
        try:
            result = vfd.start_vpn("/path/to/config.conf")
        finally:
            vfd.helper.cli_path = original
            vfd.helper.is_available = True
        assert result is False


# ===========================================================================
# check_service_status
# ===========================================================================
@pytest.mark.unit
class TestCheckServiceStatus:
    @patch("plugins.vpn.wireguard.vpn_functions_darwin.subprocess.run")
    def test_returns_running(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0, stdout="Connected\n", stderr="")
        from plugins.vpn.wireguard.vpn_functions_darwin import check_service_status
        assert check_service_status("wg0") == "Running"

    @patch("plugins.vpn.wireguard.vpn_functions_darwin.subprocess.run")
    def test_returns_stopped(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0, stdout="Disconnected\n", stderr="")
        from plugins.vpn.wireguard.vpn_functions_darwin import check_service_status
        assert check_service_status("wg0") == "Stopped"

    @patch("plugins.vpn.wireguard.vpn_functions_darwin.subprocess.run")
    def test_exception_returns_stopped(self, mock_run):
        mock_run.side_effect = Exception("cli crashed")
        from plugins.vpn.wireguard.vpn_functions_darwin import check_service_status
        assert check_service_status("wg0") == "Stopped"


# ===========================================================================
# is_extension_enabled
# ===========================================================================
@pytest.mark.unit
class TestIsExtensionEnabled:
    @patch("plugins.vpn.wireguard.vpn_functions_darwin.subprocess.run")
    def test_enabled_when_activated_enabled(self, mock_run, monkeypatch):
        from plugins.vpn.wireguard import vpn_functions_darwin as vfd
        # Reset cache
        vfd._extension_cache["timestamp"] = 0

        output = (
            "2  com.resistine.desktop.network-extension "
            "[activated enabled]\n"
        )
        mock_run.return_value = MagicMock(stdout=output, stderr="", returncode=0)
        result = vfd.is_extension_enabled()
        assert result is True

    @patch("plugins.vpn.wireguard.vpn_functions_darwin.subprocess.run")
    def test_disabled_when_not_enabled(self, mock_run):
        from plugins.vpn.wireguard import vpn_functions_darwin as vfd
        vfd._extension_cache["timestamp"] = 0

        output = (
            "2  com.resistine.desktop.network-extension "
            "[activated waiting for user]\n"
        )
        mock_run.return_value = MagicMock(stdout=output, stderr="", returncode=0)
        result = vfd.is_extension_enabled()
        assert result is False

    @patch("plugins.vpn.wireguard.vpn_functions_darwin.subprocess.run")
    def test_false_when_extension_not_listed(self, mock_run):
        from plugins.vpn.wireguard import vpn_functions_darwin as vfd
        vfd._extension_cache["timestamp"] = 0
        mock_run.return_value = MagicMock(stdout="No extensions installed\n", stderr="", returncode=0)
        result = vfd.is_extension_enabled()
        assert result is False

    @patch("plugins.vpn.wireguard.vpn_functions_darwin.subprocess.run")
    def test_false_on_subprocess_exception(self, mock_run):
        from plugins.vpn.wireguard import vpn_functions_darwin as vfd
        vfd._extension_cache["timestamp"] = 0
        mock_run.side_effect = Exception("systemextensionsctl not found")
        result = vfd.is_extension_enabled()
        assert result is False

    @patch("plugins.vpn.wireguard.vpn_functions_darwin.subprocess.run")
    def test_caches_result(self, mock_run):
        from plugins.vpn.wireguard import vpn_functions_darwin as vfd
        vfd._extension_cache["timestamp"] = 0
        mock_run.return_value = MagicMock(stdout="[activated enabled]\n", stderr="", returncode=0)
        vfd.is_extension_enabled()
        vfd.is_extension_enabled()
        # Should only call subprocess once due to cache
        assert mock_run.call_count == 1


# ===========================================================================
# check_wireguard_installed
# ===========================================================================
@pytest.mark.unit
def test_check_wireguard_installed_always_true():
    from plugins.vpn.wireguard.vpn_functions_darwin import check_wireguard_installed
    assert check_wireguard_installed() is True


# ===========================================================================
# Builds without the VPN (unsigned test builds)
# ===========================================================================
@pytest.mark.unit
class TestVpnAvailability:
    def test_bundled_build_is_available(self, monkeypatch, tmp_path):
        from plugins.vpn.wireguard import vpn_functions_darwin as vfd
        monkeypatch.setattr(vfd, "get_writable_wireguard_dir", lambda: str(tmp_path))
        assert vfd.vpn_bundled() and vfd.vpn_unavailable_reason() is None

    def test_no_cli_means_no_vpn_and_no_extension_request(self, monkeypatch):
        from plugins.vpn.wireguard import vpn_functions_darwin as vfd
        monkeypatch.setattr(vfd.helper, "cli_path", None)
        assert vfd.vpn_unavailable_reason() == vfd.NOT_BUNDLED
        with patch.dict("sys.modules", {"plugins.vpn.wireguard.extension_activator": None}):
            assert vfd.VPNHelper.activate_extension() is False  # returns before importing PyObjC

    def test_blocked_app_group_folder(self, monkeypatch):
        from plugins.vpn.wireguard import vpn_functions_darwin as vfd

        def blocked():
            raise PermissionError(1, "Operation not permitted")
        monkeypatch.setattr(vfd, "get_writable_wireguard_dir", blocked)
        assert "blocked Phoenix" in vfd.vpn_unavailable_reason()

    def test_activation_error_comes_from_the_delegate(self, monkeypatch):
        from plugins.vpn.wireguard import vpn_functions_darwin as vfd
        monkeypatch.setattr(vfd.VPNHelper, "_activator_ref", None)
        assert vfd.VPNHelper.activation_error() is None
        monkeypatch.setattr(vfd.VPNHelper, "_activator_ref", MagicMock(error="Missing entitlement"))
        assert vfd.VPNHelper.activation_error() == "Missing entitlement"
