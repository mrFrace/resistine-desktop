"""
Windows-specific platform tests.

Mirrors test_darwin_specific.py but for Windows paths, registry access,
service management, and privilege escalation patterns.

All subprocess, registry, and ctypes calls are mocked — safe to run anywhere.
"""
import json
import os
import sys
import socket
import pytest
from unittest.mock import MagicMock, patch, mock_open, call


# ===========================================================================
# W1: Windows config directory
# ===========================================================================
@pytest.mark.platform_windows
class TestWindowsConfigDir:
    def test_windows_uses_appdata(self):
        """Config dir must live under %APPDATA%\\Phoenix."""
        with patch("utils.settings.platform.system", return_value="Windows"):
            with patch.dict(os.environ, {"APPDATA": r"C:\Users\Test\AppData\Roaming"}):
                from utils.settings import get_config_dir
                path = get_config_dir()
        assert path == r"C:\Users\Test\AppData\Roaming\Phoenix"

    def test_windows_fallback_when_appdata_missing(self):
        """If APPDATA is not set, fall back to home directory."""
        env = {k: v for k, v in os.environ.items() if k != "APPDATA"}
        with patch("utils.settings.platform.system", return_value="Windows"):
            with patch.dict(os.environ, env, clear=True):
                from utils.settings import get_config_dir
                path = get_config_dir()
        assert "Phoenix" in path
        assert os.path.isabs(path)

    def test_windows_path_is_absolute(self):
        with patch("utils.settings.platform.system", return_value="Windows"):
            with patch.dict(os.environ, {"APPDATA": r"C:\Users\Test\AppData\Roaming"}):
                from utils.settings import get_config_dir
                path = get_config_dir()
        assert os.path.isabs(path)


# ===========================================================================
# W2: Windows VPN paths
# ===========================================================================
@pytest.mark.platform_windows
class TestWindowsVPNPaths:
    def test_wireguard_dir_under_config(self):
        # NOTE: the patch target is the local binding in
        # plugins.vpn.wireguard.vpn_functions_windows, not
        # utils.settings.get_config_dir. The vpn_functions_windows module
        # imports get_config_dir by name at import time, so once it's
        # loaded patching the source in utils.settings has no effect on
        # the already-resolved reference. I originally tried to patch the
        # source module and it silently passed on a completely wrong
        # path, which was difficult to track down. If you write more
        # tests that need to swap out a helper imported this way please
        # be sure that you're patching where it's used, not where it's
        # defined, otherwise you'll get a test that technically passes
        # while still exercising the wrong code path. - Austin
        with patch("plugins.vpn.wireguard.vpn_functions_windows.get_config_dir",
                   return_value=r"C:\Users\Test\AppData\Roaming\Resistine"):
            with patch("os.makedirs"):
                from plugins.vpn.wireguard.vpn_functions_windows import get_writable_wireguard_dir
                wg_dir = get_writable_wireguard_dir()
        assert wg_dir == r"C:\Users\Test\AppData\Roaming\Resistine\wireguard"

    def test_config_path_includes_tunnel_name(self):
        with patch("plugins.vpn.wireguard.vpn_functions_windows.get_config_dir",
                   return_value=r"C:\Users\Test\AppData\Roaming\Resistine"):
            with patch("os.makedirs"):
                from plugins.vpn.wireguard.vpn_functions_windows import get_config_path
                path = get_config_path("my_tunnel")
        assert path.endswith("my_tunnel.conf")
        assert "wireguard" in path


# ===========================================================================
# W3: WireGuard executable detection
# ===========================================================================
@pytest.mark.platform_windows
class TestWireGuardDetection:
    def test_finds_program_files_64bit(self):
        from plugins.vpn.wireguard.vpn_functions_windows import find_wireguard_exe
        with patch("os.path.exists", side_effect=lambda p: p == r"C:\Program Files\WireGuard\wireguard.exe"):
            result = find_wireguard_exe()
        assert result == r"C:\Program Files\WireGuard\wireguard.exe"

    def test_finds_program_files_x86(self):
        """Fallback to 32-bit Program Files."""
        from plugins.vpn.wireguard.vpn_functions_windows import find_wireguard_exe
        with patch("os.path.exists", side_effect=lambda p: p == r"C:\Program Files (x86)\WireGuard\wireguard.exe"):
            result = find_wireguard_exe()
        assert result == r"C:\Program Files (x86)\WireGuard\wireguard.exe"

    def test_returns_none_when_not_installed(self):
        from plugins.vpn.wireguard.vpn_functions_windows import find_wireguard_exe
        with patch("os.path.exists", return_value=False):
            result = find_wireguard_exe()
        assert result is None

    def test_check_wireguard_installed_true(self):
        from plugins.vpn.wireguard.vpn_functions_windows import check_wireguard_installed
        with patch("plugins.vpn.wireguard.vpn_functions_windows.find_wireguard_exe",
                   return_value=r"C:\Program Files\WireGuard\wireguard.exe"):
            assert check_wireguard_installed() is True

    def test_check_wireguard_installed_false(self):
        from plugins.vpn.wireguard.vpn_functions_windows import check_wireguard_installed
        with patch("plugins.vpn.wireguard.vpn_functions_windows.find_wireguard_exe",
                   return_value=None):
            assert check_wireguard_installed() is False

    def test_find_wg_cli_adjacent_to_wireguard(self):
        """wg.exe lives in the same directory as wireguard.exe."""
        from plugins.vpn.wireguard.vpn_functions_windows import find_wg_cli
        with patch("plugins.vpn.wireguard.vpn_functions_windows.find_wireguard_exe",
                   return_value=r"C:\Program Files\WireGuard\wireguard.exe"):
            with patch("os.path.exists", side_effect=lambda p: p == r"C:\Program Files\WireGuard\wg.exe"):
                result = find_wg_cli()
        assert result == r"C:\Program Files\WireGuard\wg.exe"

    def test_find_wg_cli_missing(self):
        from plugins.vpn.wireguard.vpn_functions_windows import find_wg_cli
        with patch("plugins.vpn.wireguard.vpn_functions_windows.find_wireguard_exe",
                   return_value=None):
            assert find_wg_cli() is None


# ===========================================================================
# W4: Windows key management
# ===========================================================================
@pytest.mark.platform_windows
class TestWindowsKeyManagement:
    def test_generate_keys_via_wg_exe(self):
        """When wg.exe is available, use it for key generation."""
        from plugins.vpn.wireguard.vpn_functions_windows import generate_wireguard_keys
        with patch("plugins.vpn.wireguard.vpn_functions_windows.find_wg_cli",
                   return_value=r"C:\Program Files\WireGuard\wg.exe"):
            with patch("subprocess.check_output", side_effect=[
                "cHJpdmF0ZWtleWRhdGFiYXNlNjRlbmNvZGVkZGF0YQ==\n",  # genkey
                "cHVibGlja2V5ZGF0YWJhc2U2NGVuY29kZWRkYXRhYWE=\n",  # pubkey
            ]):
                result = generate_wireguard_keys()
        assert result is not None
        assert "private_key" in result
        assert "public_key" in result

    def test_generate_keys_fallback_to_python(self):
        """When wg.exe is missing, fall back to Python cryptography."""
        from plugins.vpn.wireguard.vpn_functions_windows import generate_wireguard_keys
        with patch("plugins.vpn.wireguard.vpn_functions_windows.find_wg_cli",
                   return_value=None):
            result = generate_wireguard_keys()
        assert result is not None
        assert len(result["private_key"]) == 44  # base64 of 32 bytes
        assert len(result["public_key"]) == 44

    def test_generate_keys_wg_exe_failure_falls_back(self):
        """If wg.exe fails, fall back to Python."""
        import subprocess
        from plugins.vpn.wireguard.vpn_functions_windows import generate_wireguard_keys
        with patch("plugins.vpn.wireguard.vpn_functions_windows.find_wg_cli",
                   return_value=r"C:\Program Files\WireGuard\wg.exe"):
            with patch("subprocess.check_output",
                       side_effect=subprocess.CalledProcessError(1, "wg")):
                result = generate_wireguard_keys()
        assert result is not None  # Should still succeed via fallback

    def test_save_keys_uses_encrypted_storage(self, isolated_settings, monkeypatch):
        """Private key must be stored encrypted (ENC: prefix), public key plaintext."""
        monkeypatch.setattr("plugins.vpn.wireguard.vpn_functions_windows._settings", isolated_settings)
        from plugins.vpn.wireguard.vpn_functions_windows import save_wireguard_keys
        result = save_wireguard_keys("my_private_key", "my_public_key")
        assert result is True
        # Private key should be encrypted
        raw = isolated_settings.get("vpn", "private_key")
        assert raw.startswith("ENC:")
        # Public key should be plaintext
        assert isolated_settings.get("vpn", "public_key") == "my_public_key"

    def test_get_private_key_decrypts(self, isolated_settings, monkeypatch):
        """get_wireguard_private_key must decrypt the stored value."""
        monkeypatch.setattr("plugins.vpn.wireguard.vpn_functions_windows._settings", isolated_settings)
        isolated_settings.set_secret("vpn", "private_key", "test_secret_key")
        from plugins.vpn.wireguard.vpn_functions_windows import get_wireguard_private_key
        result = get_wireguard_private_key()
        assert result == "test_secret_key"

    def test_delete_keys_removes_both(self, isolated_settings, monkeypatch):
        monkeypatch.setattr("plugins.vpn.wireguard.vpn_functions_windows._settings", isolated_settings)
        isolated_settings.set_secret("vpn", "private_key", "pk")
        isolated_settings.set("vpn", "public_key", "pubk")
        from plugins.vpn.wireguard.vpn_functions_windows import delete_wireguard_keys
        assert delete_wireguard_keys() is True
        assert isolated_settings.get("vpn", "private_key") is None
        assert isolated_settings.get("vpn", "public_key") is None

    def test_setup_vpn_keys_returns_public_key(self, isolated_settings, monkeypatch):
        """setup_vpn_keys must generate, save, and return the public key."""
        monkeypatch.setattr("plugins.vpn.wireguard.vpn_functions_windows._settings", isolated_settings)
        from plugins.vpn.wireguard.vpn_functions_windows import setup_vpn_keys
        pub = setup_vpn_keys()
        assert pub is not None
        assert len(pub) == 44  # base64


# ===========================================================================
# W5: Windows VPN config creation
# ===========================================================================
@pytest.mark.platform_windows
class TestWindowsVPNConfigCreation:
    def test_creates_valid_conf_file(self, tmp_path, isolated_settings, monkeypatch):
        """parse_and_create_vpn_config must write a valid WireGuard .conf."""
        monkeypatch.setattr("plugins.vpn.wireguard.vpn_functions_windows._settings", isolated_settings)
        monkeypatch.setattr(
            "plugins.vpn.wireguard.vpn_functions_windows.get_writable_wireguard_dir",
            lambda: str(tmp_path),
        )
        # Pre-save a private key
        isolated_settings.set_secret("vpn", "private_key", "testPrivateKey123456789012345678901234=")

        from plugins.vpn.wireguard.vpn_functions_windows import parse_and_create_vpn_config
        config_json = json.dumps({
            "Interface": {"Address": "10.0.0.2", "DNS": ["10.0.0.1"]},
            "Peer": {
                "PublicKey": "serverPubKey=",
                "AllowedIPs": ["10.0.0.0/24"],
                "Endpoint": "vpn.example.com:51820",
            },
        })
        path = parse_and_create_vpn_config(config_json, "test_tunnel")
        assert path is not None
        assert os.path.exists(path)

        content = open(path).read()
        assert "[Interface]" in content
        assert "[Peer]" in content
        assert "PrivateKey" in content
        assert "serverPubKey=" in content

    def test_injects_private_key_when_missing(self, tmp_path, isolated_settings, monkeypatch):
        """If server response has no PrivateKey, inject from encrypted storage."""
        monkeypatch.setattr("plugins.vpn.wireguard.vpn_functions_windows._settings", isolated_settings)
        monkeypatch.setattr(
            "plugins.vpn.wireguard.vpn_functions_windows.get_writable_wireguard_dir",
            lambda: str(tmp_path),
        )
        isolated_settings.set_secret("vpn", "private_key", "injectedKey=")

        from plugins.vpn.wireguard.vpn_functions_windows import parse_and_create_vpn_config
        config_json = json.dumps({
            "Interface": {"Address": "10.0.0.2", "PrivateKey": ""},
            "Peer": {"PublicKey": "srv=", "AllowedIPs": ["0.0.0.0/0"], "Endpoint": "1.2.3.4:51820"},
        })
        path = parse_and_create_vpn_config(config_json)
        content = open(path).read()
        assert "injectedKey=" in content

    def test_empty_config_returns_none(self, isolated_settings, monkeypatch):
        monkeypatch.setattr("plugins.vpn.wireguard.vpn_functions_windows._settings", isolated_settings)
        from plugins.vpn.wireguard.vpn_functions_windows import parse_and_create_vpn_config
        assert parse_and_create_vpn_config("") is None
        assert parse_and_create_vpn_config(None) is None

    def test_invalid_json_returns_none(self, isolated_settings, monkeypatch):
        monkeypatch.setattr("plugins.vpn.wireguard.vpn_functions_windows._settings", isolated_settings)
        from plugins.vpn.wireguard.vpn_functions_windows import parse_and_create_vpn_config
        assert parse_and_create_vpn_config("{not valid json}") is None

    def test_missing_interface_or_peer_returns_none(self, isolated_settings, monkeypatch):
        monkeypatch.setattr("plugins.vpn.wireguard.vpn_functions_windows._settings", isolated_settings)
        from plugins.vpn.wireguard.vpn_functions_windows import parse_and_create_vpn_config
        # Missing Peer
        assert parse_and_create_vpn_config(json.dumps({"Interface": {"Address": "10.0.0.1"}})) is None
        # Missing Interface
        assert parse_and_create_vpn_config(json.dumps({"Peer": {"PublicKey": "key="}})) is None

    def test_conf_uses_unix_line_endings(self, tmp_path, isolated_settings, monkeypatch):
        """WireGuard .conf must use LF, not CRLF, even on Windows."""
        monkeypatch.setattr("plugins.vpn.wireguard.vpn_functions_windows._settings", isolated_settings)
        monkeypatch.setattr(
            "plugins.vpn.wireguard.vpn_functions_windows.get_writable_wireguard_dir",
            lambda: str(tmp_path),
        )
        isolated_settings.set_secret("vpn", "private_key", "pk=")

        from plugins.vpn.wireguard.vpn_functions_windows import parse_and_create_vpn_config
        config_json = json.dumps({
            "Interface": {"Address": "10.0.0.2"},
            "Peer": {"PublicKey": "srv=", "AllowedIPs": ["0.0.0.0/0"], "Endpoint": "1.2.3.4:51820"},
        })
        path = parse_and_create_vpn_config(config_json)
        # Read in binary to check line endings
        raw = open(path, "rb").read()
        assert b"\r\n" not in raw, "WireGuard config must use LF line endings, not CRLF"

    def test_list_values_comma_separated(self, tmp_path, isolated_settings, monkeypatch):
        """DNS and AllowedIPs lists must be comma-separated in the .conf."""
        monkeypatch.setattr("plugins.vpn.wireguard.vpn_functions_windows._settings", isolated_settings)
        monkeypatch.setattr(
            "plugins.vpn.wireguard.vpn_functions_windows.get_writable_wireguard_dir",
            lambda: str(tmp_path),
        )
        isolated_settings.set_secret("vpn", "private_key", "pk=")

        from plugins.vpn.wireguard.vpn_functions_windows import parse_and_create_vpn_config
        config_json = json.dumps({
            "Interface": {"Address": "10.0.0.2", "DNS": ["8.8.8.8", "8.8.4.4"]},
            "Peer": {
                "PublicKey": "srv=",
                "AllowedIPs": ["10.0.0.0/24", "192.168.0.0/16"],
                "Endpoint": "1.2.3.4:51820",
            },
        })
        path = parse_and_create_vpn_config(config_json)
        content = open(path).read()
        assert "8.8.8.8, 8.8.4.4" in content
        assert "10.0.0.0/24, 192.168.0.0/16" in content


# ===========================================================================
# W6: Windows service status wrappers
# ===========================================================================
@pytest.mark.platform_windows
class TestWindowsServiceStatusWrappers:
    def test_check_service_status_running(self):
        from plugins.vpn.wireguard.vpn_functions_windows import check_service_status
        with patch("plugins.vpn.wireguard.vpn_functions_windows.get_status",
                   return_value={"status": "ok", "state": "Running"}):
            assert check_service_status("wg0") == "Running"

    def test_check_service_status_stopped(self):
        from plugins.vpn.wireguard.vpn_functions_windows import check_service_status
        with patch("plugins.vpn.wireguard.vpn_functions_windows.get_status",
                   return_value={"status": "ok", "state": "Stopped"}):
            assert check_service_status("wg0") == "Stopped"

    def test_check_service_status_exception_returns_stopped(self):
        """If IPC fails, status must default to Stopped."""
        from plugins.vpn.wireguard.vpn_functions_windows import check_service_status
        with patch("plugins.vpn.wireguard.vpn_functions_windows.get_status",
                   side_effect=ConnectionRefusedError()):
            assert check_service_status("wg0") == "Stopped"

    def test_check_service_status_empty_tunnel_returns_stopped(self):
        from plugins.vpn.wireguard.vpn_functions_windows import check_service_status
        assert check_service_status("") == "Stopped"
        assert check_service_status(None) == "Stopped"

    def test_start_vpn_returns_bool(self):
        from plugins.vpn.wireguard.vpn_functions_windows import start_vpn
        with patch("plugins.vpn.wireguard.vpn_functions_windows.connect",
                   return_value={"status": "ok", "state": "Running"}):
            assert start_vpn("wg0") is True

    def test_start_vpn_failure(self):
        from plugins.vpn.wireguard.vpn_functions_windows import start_vpn
        with patch("plugins.vpn.wireguard.vpn_functions_windows.connect",
                   return_value={"status": "error", "message": "No config"}):
            assert start_vpn("wg0") is False

    def test_stop_vpn_returns_bool(self):
        from plugins.vpn.wireguard.vpn_functions_windows import stop_vpn
        with patch("plugins.vpn.wireguard.vpn_functions_windows.disconnect",
                   return_value={"status": "ok", "state": "Stopped"}):
            assert stop_vpn("wg0") is True


# ===========================================================================
# W7: Windows settings — no chmod on Windows
# ===========================================================================
@pytest.mark.platform_windows
class TestWindowsSettingsPermissions:
    def test_no_chmod_on_windows(self, isolated_settings, monkeypatch):
        """On Windows, _save_json and _get_file_path must NOT call os.chmod."""
        monkeypatch.setattr("utils.settings.platform.system", lambda: "Windows")
        with patch("os.chmod") as mock_chmod:
            isolated_settings.set("test_ns", "key", "value")
        mock_chmod.assert_not_called()

    def test_master_key_fallback_file_still_created(self, tmp_config_dir, mock_keyring, monkeypatch):
        """Fallback master key file must be created even on Windows."""
        import utils.settings as s
        monkeypatch.setattr("utils.settings.platform.system", lambda: "Windows")

        # Force keyring failure to trigger fallback
        mock_kr, store = mock_keyring
        mock_kr.set_password.side_effect = Exception("Keyring unavailable")
        mock_kr.get_password.return_value = None

        key = s._get_master_key()
        key_file = os.path.join(str(tmp_config_dir), ".master.key")
        assert os.path.exists(key_file)


# ===========================================================================
# W8: Bug-hunting — VPN config edge cases
# ===========================================================================
@pytest.mark.platform_windows
class TestVPNConfigEdgeCases:
    """Tests likely to expose bugs in PrivateKey injection logic.

    NOTE: the two tests below cover a subtle case sensitivity issue I
    encountered while working on this. The server-side WireGuard config
    can legitimately come back with a different casing for the PrivateKey
    field ("PrivateKey", "privatekey", "PRIVATEKEY", etc.), and the
    Windows injection code will match it case-insensitively before
    deciding whether to overwrite. If you ever rework
    parse_and_create_vpn_config please make sure that both a real
    server-provided key is never overwritten by the stored one and also
    that the rendered .conf never ends up with two PrivateKey lines in
    different casings, because WireGuard will refuse to load that config
    and the tunnel will silently fail to install, causing hard to debug
    "dead VPN" reports. - Austin
    """

    def test_lowercase_privatekey_with_value_not_overwritten(self, tmp_path, isolated_settings, monkeypatch):
        """If the server sends 'privatekey' (lowercase) with a real value,
        the code must NOT overwrite it from encrypted storage."""
        monkeypatch.setattr("plugins.vpn.wireguard.vpn_functions_windows._settings", isolated_settings)
        monkeypatch.setattr(
            "plugins.vpn.wireguard.vpn_functions_windows.get_writable_wireguard_dir",
            lambda: str(tmp_path),
        )
        isolated_settings.set_secret("vpn", "private_key", "stored_key=")

        from plugins.vpn.wireguard.vpn_functions_windows import parse_and_create_vpn_config
        # Server sends lowercase 'privatekey' with REAL value
        config_json = json.dumps({
            "Interface": {"privatekey": "server_provided_key=", "Address": "10.0.0.2"},
            "Peer": {"PublicKey": "srv=", "AllowedIPs": ["0.0.0.0/0"], "Endpoint": "1.2.3.4:51820"},
        })
        path = parse_and_create_vpn_config(config_json)
        content = open(path).read()

        # The server-provided key should be preserved, NOT replaced with stored_key
        assert "server_provided_key=" in content
        # The stored key should NOT have been injected
        assert "stored_key=" not in content

    def test_no_duplicate_privatekey_in_output(self, tmp_path, isolated_settings, monkeypatch):
        """When the server sends an empty 'privatekey' placeholder, the code
        injects the real key as 'PrivateKey'. The output must not contain BOTH
        keys — that would make WireGuard reject the config."""
        monkeypatch.setattr("plugins.vpn.wireguard.vpn_functions_windows._settings", isolated_settings)
        monkeypatch.setattr(
            "plugins.vpn.wireguard.vpn_functions_windows.get_writable_wireguard_dir",
            lambda: str(tmp_path),
        )
        isolated_settings.set_secret("vpn", "private_key", "real_key=")

        from plugins.vpn.wireguard.vpn_functions_windows import parse_and_create_vpn_config
        # Server sends empty lowercase placeholder
        config_json = json.dumps({
            "Interface": {"privatekey": "", "Address": "10.0.0.2"},
            "Peer": {"PublicKey": "srv=", "AllowedIPs": ["0.0.0.0/0"], "Endpoint": "1.2.3.4:51820"},
        })
        path = parse_and_create_vpn_config(config_json)
        content = open(path).read().lower()

        # Count occurrences of 'privatekey' (case-insensitive) — must be exactly 1
        privatekey_count = content.count("privatekey")
        assert privatekey_count == 1, (
            f"Found {privatekey_count} 'privatekey' lines in conf — duplicate "
            "keys will cause WireGuard to reject the config:\n" + content
        )

    def test_disk_full_returns_none(self, tmp_path, isolated_settings, monkeypatch):
        """If disk write fails (ENOSPC, etc.), parse_and_create_vpn_config
        must return None instead of raising or writing partial config."""
        monkeypatch.setattr("plugins.vpn.wireguard.vpn_functions_windows._settings", isolated_settings)
        monkeypatch.setattr(
            "plugins.vpn.wireguard.vpn_functions_windows.get_writable_wireguard_dir",
            lambda: str(tmp_path),
        )
        isolated_settings.set_secret("vpn", "private_key", "pk=")

        from plugins.vpn.wireguard.vpn_functions_windows import parse_and_create_vpn_config
        config_json = json.dumps({
            "Interface": {"Address": "10.0.0.2"},
            "Peer": {"PublicKey": "srv=", "AllowedIPs": ["0.0.0.0/0"], "Endpoint": "1.2.3.4:51820"},
        })

        original_open = open
        def failing_open(path, *args, **kwargs):
            if str(path).endswith(".conf"):
                raise OSError(28, "No space left on device")
            return original_open(path, *args, **kwargs)

        with patch("builtins.open", side_effect=failing_open):
            result = parse_and_create_vpn_config(config_json)
        assert result is None, "Disk-full failure must return None, not raise"
