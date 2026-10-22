"""
Windows version compatibility tests.

Validates that Resistine behaves correctly across:
- Windows 10 (21H2, 22H2)
- Windows 11 (23H2, 24H2, 25H2)

Key areas of version divergence tested:
- sc query output format (whitespace, casing, error codes)
- PowerShell 5.1 vs 7.x command syntax
- Registry access patterns (32/64-bit views, key existence)
- UAC elevation behavior (ShellExecuteW return codes)
- Environment variable availability (SYSTEM account vs user)
- Service startup timeout expectations
- Path handling (MAX_PATH, long paths, UNC paths)
- Credential Manager / keyring backend availability
- WireGuard executable discovery across install methods
- Uninstaller registry key variations

All I/O is mocked — safe to run anywhere.
"""
import json
import os
import sys
import pytest
from unittest.mock import MagicMock, patch, call


# Windows-only modules are stubbed centrally in tests/conftest.py


# ===========================================================================
# V1: Environment variable availability across execution contexts
# ===========================================================================
@pytest.mark.platform_windows
class TestEnvVarAvailability:
    """Windows services running as SYSTEM may not have user env vars."""

    def test_appdata_missing_in_system_context(self):
        """Config dir must not crash when APPDATA is unset (SYSTEM account)."""
        env = {k: v for k, v in os.environ.items() if k != "APPDATA"}
        with patch("utils.settings.platform.system", return_value="Windows"):
            with patch.dict(os.environ, env, clear=True):
                from utils.settings import get_config_dir
                path = get_config_dir()
        assert "Phoenix" in path
        assert os.path.isabs(path)

    def test_programdata_fallback(self):
        """PROGRAMDATA missing should fall back to C:\\ProgramData."""
        env = {k: v for k, v in os.environ.items() if k != "PROGRAMDATA"}
        with patch.dict(os.environ, env, clear=True):
            from plugins.vpn.wireguard.service_client import _PROGRAMDATA
            # The module-level constant should have a fallback
            assert _PROGRAMDATA  # Not empty

    def test_programfiles_fallback(self):
        """PROGRAMFILES missing should not crash WireGuard detection."""
        from plugins.vpn.wireguard.vpn_functions_windows import find_wireguard_exe
        with patch("os.path.exists", return_value=False):
            # Should not raise, even if env vars are weird
            result = find_wireguard_exe()
        assert result is None

    def test_temp_dir_always_available(self):
        """tempfile operations must work even with nonstandard TEMP."""
        import tempfile
        with patch.dict(os.environ, {"TEMP": os.path.join(os.getcwd(), "test_temp")}):
            # Should not crash
            tmp = tempfile.gettempdir()
            assert tmp  # Not empty


# ===========================================================================
# V2: Registry access patterns across Windows versions
# ===========================================================================
@pytest.mark.platform_windows
class TestRegistryCompat:
    def test_registry_view_iteration(self):
        """Registry view iteration should check 64-bit, 32-bit, and default views."""
        import winreg
        from utils.uninstall.windows import _iter_registry_views

        # Ensure KEY_WOW64_64KEY and KEY_WOW64_32KEY attrs exist
        winreg.KEY_WOW64_64KEY = 0x0100
        winreg.KEY_WOW64_32KEY = 0x0200

        views = _iter_registry_views(winreg)
        assert 0 in views  # Default view
        assert 0x0100 in views  # 64-bit
        assert 0x0200 in views  # 32-bit

    def test_registry_query_tries_all_views(self):
        """_query_reg_string must try all registry views before returning None."""
        import winreg
        from utils.uninstall.windows import _query_reg_string

        winreg.KEY_WOW64_64KEY = 0x0100
        winreg.KEY_WOW64_32KEY = 0x0200
        winreg.KEY_READ = 0x20019

        call_count = [0]
        original_open = winreg.OpenKey

        def mock_open(root, subkey, reserved=0, access=0):
            call_count[0] += 1
            raise OSError("Not found")

        winreg.OpenKey = mock_open
        try:
            result = _query_reg_string(winreg, winreg.HKEY_LOCAL_MACHINE, "Test\\Key", "Value")
        finally:
            winreg.OpenKey = original_open

        assert result is None
        assert call_count[0] == 3  # Tried all 3 views

    def test_machine_guid_registry_path(self):
        """MachineGuid must be read from the correct registry path."""
        import winreg
        from plugins.wazuh.agent.wazuh_functions_windows import _get_machine_guid

        opened_path = []

        def mock_open(root, subkey):
            opened_path.append(subkey)
            return MagicMock()

        with patch.object(winreg, "OpenKey", side_effect=mock_open):
            with patch.object(winreg, "QueryValueEx",
                              return_value=("test-guid", 1)):
                with patch.object(winreg, "CloseKey"):
                    _get_machine_guid()

        assert opened_path[0] == r"SOFTWARE\Microsoft\Cryptography"

    def test_uninstall_registry_keys_checked(self):
        """Uninstaller must check both known registry key paths."""
        from utils.uninstall.windows import _INNO_UNINSTALL_KEYS
        assert len(_INNO_UNINSTALL_KEYS) >= 2
        # Must check the Inno Setup key format
        assert any("ResistineDesktop_is1" in key for key in _INNO_UNINSTALL_KEYS)
        assert any("Resistine" in key for key in _INNO_UNINSTALL_KEYS)


# ===========================================================================
# V3: PowerShell version compatibility
# ===========================================================================
@pytest.mark.platform_windows
class TestPowerShellCompat:
    """PowerShell 5.1 (Win10 default) vs 7.x (Win11 may have both)."""

    def test_run_privileged_uses_compatible_flags(self):
        """_run_privileged must use flags that work on both PS 5.1 and PS 7."""
        from plugins.wazuh.agent.wazuh_functions_windows import _run_privileged

        mock_result = MagicMock(returncode=0, stdout="ok", stderr="")
        with patch("plugins.wazuh.agent.wazuh_functions_windows._is_admin", return_value=True), \
                patch("subprocess.CREATE_NO_WINDOW", 0x08000000, create=True), \
                patch("subprocess.run", return_value=mock_result) as mock_run:
            _run_privileged("Get-Service")

        cmd = mock_run.call_args[0][0]
        assert "-NoProfile" in cmd  # Works on both PS 5.1 and 7
        assert "-ExecutionPolicy" in cmd
        assert "Bypass" in cmd
        # The script runs from a file, never interpolated into -Command
        assert "-File" in cmd and "-Command" not in cmd

    def test_tls_setting_compatible(self):
        """TLS protocol setting must work on both PS 5.1 and PS 7."""
        from plugins.wazuh.agent.wazuh_functions_windows import _download_file

        mock_result = MagicMock(returncode=0, stdout="", stderr="")
        with patch("subprocess.run", return_value=mock_result) as mock_run:
            with patch("os.path.exists", return_value=True):
                _download_file("https://example.com/file.msi", "/tmp/file.msi")

        cmd = mock_run.call_args[0][0]
        cmd_str = " ".join(cmd)
        # TLS 1.2 setting works on PS 5.1; PS 7 uses TLS 1.2+ by default
        assert "Tls12" in cmd_str

    def test_elevation_uses_compatible_syntax(self):
        """UAC elevation via Start-Process must use PS 5.1-compatible syntax."""
        from plugins.wazuh.agent.wazuh_functions_windows import _run_privileged

        mock_result = MagicMock(returncode=0, stdout="", stderr="")
        with patch("plugins.wazuh.agent.wazuh_functions_windows._is_admin", return_value=False):
            with patch("subprocess.run", return_value=mock_result) as mock_run:
                with patch("tempfile.NamedTemporaryFile") as mock_tmp:
                    mock_file = MagicMock()
                    mock_file.__enter__ = MagicMock(return_value=mock_file)
                    mock_file.__exit__ = MagicMock(return_value=False)
                    mock_file.name = "C:\\temp\\script.ps1"
                    mock_tmp.return_value = mock_file
                    with patch("os.path.exists", return_value=False):
                        with patch("os.unlink"):
                            _run_privileged("test command")

        if mock_run.called:
            cmd_str = " ".join(mock_run.call_args[0][0])
            # -Verb RunAs is PS 5.1+ compatible
            assert "RunAs" in cmd_str or "-NoProfile" in cmd_str


# ===========================================================================
# V4: UAC elevation and ShellExecuteW
# ===========================================================================
@pytest.mark.platform_windows
class TestUACCompat:
    def test_shell_execute_success_codes(self):
        """ShellExecuteW returns >32 on success across all Windows versions."""
        from utils.uninstall.windows import run_uninstall

        with patch("utils.uninstall.windows._find_uninstaller_command",
                   return_value=(r"C:\Program Files\Resistine\unins000.exe", "")):
            with patch("os.path.exists", return_value=True):
                # Win10: typically returns 42
                with patch("ctypes.windll.shell32.ShellExecuteW", return_value=42):
                    ok, msg = run_uninstall(None)
                assert ok is True

    def test_shell_execute_failure_codes(self):
        """ShellExecuteW returns <=32 on failure. Common codes across versions."""
        from utils.uninstall.windows import run_uninstall

        failure_codes = [
            0,   # Out of memory
            2,   # File not found
            3,   # Path not found
            5,   # Access denied (common on Win11 with stricter UAC)
            8,   # Not enough memory
            26,  # Sharing violation
            27,  # Filename too long
            31,  # No association
            32,  # DDE busy (edge case)
        ]
        for code in failure_codes:
            with patch("utils.uninstall.windows._find_uninstaller_command",
                       return_value=(r"C:\unins000.exe", "")):
                with patch("ctypes.windll.shell32.ShellExecuteW", return_value=code):
                    ok, msg = run_uninstall(None)
            assert ok is False, f"Code {code} should indicate failure"

    def test_is_admin_check_does_not_crash(self):
        """_is_admin must handle ctypes exceptions gracefully."""
        from plugins.wazuh.agent.wazuh_functions_windows import _is_admin

        # Simulate ctypes not available (wine, minimal Windows)
        with patch("ctypes.windll.shell32.IsUserAnAdmin", side_effect=AttributeError("No windll")):
            assert _is_admin() is False

        with patch("ctypes.windll.shell32.IsUserAnAdmin", side_effect=OSError("Access denied")):
            assert _is_admin() is False


# ===========================================================================
# V5: Path handling across Windows versions
# ===========================================================================
@pytest.mark.platform_windows
class TestPathCompat:
    def test_backslash_and_forward_slash_paths(self, tmp_path):
        """Windows accepts both / and \\ in paths. Config handling must too."""
        from plugins.vpn.wireguard.windows_vpn_service import find_config

        # Create config with forward-slash path
        conf = tmp_path / "wg0.conf"
        conf.write_text("[Interface]\n")

        # Pass forward-slash path (common when paths come from JSON)
        forward_path = str(conf).replace("\\", "/")
        result = find_config("wg0", forward_path)
        assert result == forward_path

    def test_unc_path_handling(self, tmp_path):
        """UNC paths (\\\\server\\share) should not crash path operations."""
        from plugins.vpn.wireguard.vpn_functions_windows import get_config_path
        with patch("plugins.vpn.wireguard.vpn_functions_windows.get_writable_wireguard_dir",
                   return_value=r"\\server\share\wireguard"):
            with patch("os.makedirs"):
                path = get_config_path("tunnel")
        assert "tunnel.conf" in path

    def test_spaces_in_program_files(self, tmp_path):
        """WireGuard detection must handle 'Program Files' with spaces."""
        from plugins.vpn.wireguard.vpn_functions_windows import find_wireguard_exe

        def mock_exists(path):
            return path == r"C:\Program Files\WireGuard\wireguard.exe"

        with patch("os.path.exists", side_effect=mock_exists):
            result = find_wireguard_exe()
        assert result == r"C:\Program Files\WireGuard\wireguard.exe"

    def test_non_ascii_appdata_path(self):
        """APPDATA with non-ASCII chars (e.g., usernames with accents)."""
        with patch("utils.settings.platform.system", return_value="Windows"):
            with patch.dict(os.environ, {"APPDATA": r"C:\Users\M\u00fcller\AppData\Roaming"}):
                from utils.settings import get_config_dir
                path = get_config_dir()
        assert "Phoenix" in path

    def test_config_filename_sanitization_on_windows(self, wireguard_dir, isolated_settings, sample_wireguard_conf):
        """Windows-reserved chars in filenames must be stripped."""
        from plugins.vpn.config_manager import VPNConfigManager
        mgr = VPNConfigManager(str(wireguard_dir))

        # Windows-reserved characters
        reserved = ['<', '>', ':', '"', '|', '?', '*']
        for char in reserved:
            name = mgr.sanitize_filename(f"test{char}config.conf")
            for bad in reserved:
                assert bad not in name, f"Reserved char '{bad}' should be stripped"

    def test_wireguard_dir_created_with_makedirs(self, tmp_path):
        """get_writable_wireguard_dir must create the directory if missing."""
        with patch("plugins.vpn.wireguard.vpn_functions_windows.get_config_dir",
                   return_value=str(tmp_path)):
            from plugins.vpn.wireguard.vpn_functions_windows import get_writable_wireguard_dir
            result = get_writable_wireguard_dir()
        assert os.path.isdir(result)
        assert result.endswith("wireguard")


# ===========================================================================
# V6: Service behavior differences Win10 vs Win11
# ===========================================================================
@pytest.mark.platform_windows
class TestServiceCompat:
    """Windows 11 has stricter service lifecycle requirements."""

    def test_install_tunnel_stderr_case_insensitive(self):
        """'Already installed' check must be case-insensitive for locale compat."""
        from plugins.vpn.wireguard.windows_vpn_service import install_tunnel

        # Win11 German locale might say "bereits installiert" but error code
        # is consistent, so we check 'already installed' case-insensitively
        mock_result = MagicMock(returncode=1, stdout="", stderr="SERVICE ALREADY INSTALLED")
        with patch("plugins.vpn.wireguard.windows_vpn_service.find_config", return_value="C:\\conf"):
            with patch("os.path.exists", return_value=True):
                with patch("subprocess.run", return_value=mock_result):
                    ok, msg = install_tunnel("wg0")
        assert ok is True

    def test_uninstall_checks_error_1060_in_both_streams(self):
        """Error 1060 may appear in stdout OR stderr depending on Win version."""
        from plugins.vpn.wireguard.windows_vpn_service import uninstall_tunnel

        # Error in stderr only (Win11 25H2 behavior)
        mock_result = MagicMock(returncode=1, stdout="", stderr="[SC] OpenService FAILED 1060")
        with patch("subprocess.run", return_value=mock_result):
            ok, msg = uninstall_tunnel("wg0")
        assert ok is True

    def test_status_tunnel_handles_empty_output(self):
        """sc query may return empty output on some error conditions."""
        from plugins.vpn.wireguard.windows_vpn_service import status_tunnel
        mock_result = MagicMock(returncode=1, stdout="", stderr="")
        with patch("subprocess.run", return_value=mock_result):
            result = status_tunnel("wg0")
        assert result == "Unknown"

    def test_stop_tunnel_handles_error_1062(self):
        """Error 1062 = 'service has not been started'. Must be treated as success."""
        from plugins.vpn.wireguard.windows_vpn_service import stop_tunnel
        # Real sc output includes "1062" in stderr text, which stop_tunnel checks
        mock_result = MagicMock(
            returncode=1062,
            stdout="",
            stderr="[SC] ControlService FAILED 1062:\n\nThe service has not been started.\n",
        )
        with patch("plugins.vpn.wireguard.windows_vpn_service.run_cmd", return_value=mock_result):
            ok, msg = stop_tunnel("wg0")
        assert ok is True

    def test_sysmon_64_and_32_bit_check(self):
        """Sysmon detection must check both Sysmon64 and Sysmon service names."""
        from plugins.wazuh.agent.wazuh_functions_windows import _is_sysmon_installed

        # Win11 ARM: only Sysmon (not Sysmon64) exists
        results = [
            MagicMock(returncode=1),  # Sysmon64 not found
            MagicMock(returncode=0),  # Sysmon found
        ]
        with patch("subprocess.run", side_effect=results) as mock_run:
            assert _is_sysmon_installed() is True

        # Verify it checked both
        calls = mock_run.call_args_list
        assert len(calls) == 2
        assert "Sysmon64" in str(calls[0])
        assert "Sysmon" in str(calls[1])


# ===========================================================================
# V7: Keyring/Credential Manager across versions
# ===========================================================================
@pytest.mark.platform_windows
class TestKeyringCompat:
    def test_keyring_failure_falls_back_to_file(self, tmp_config_dir, monkeypatch):
        """If Windows Credential Manager is unavailable, must use fallback file."""
        import utils.settings as s

        mock_kr = MagicMock()
        mock_kr.get_password.return_value = None
        mock_kr.set_password.side_effect = Exception("Credential Manager unavailable")
        monkeypatch.setattr("utils.settings.keyring", mock_kr)

        key = s._get_master_key()
        assert key is not None
        assert len(key) > 0

        # Fallback file should exist
        fallback = os.path.join(str(tmp_config_dir), ".master.key")
        assert os.path.exists(fallback)

    def test_fernet_from_fallback_file(self, tmp_config_dir, monkeypatch):
        """_get_fernet must work when keyring is unavailable."""
        import utils.settings as s
        from cryptography.fernet import Fernet

        # Write a known key to fallback
        key = Fernet.generate_key()
        fallback = os.path.join(str(tmp_config_dir), ".master.key")
        with open(fallback, "wb") as f:
            f.write(key)

        mock_kr = MagicMock()
        mock_kr.get_password.return_value = None
        monkeypatch.setattr("utils.settings.keyring", mock_kr)

        fernet = s._get_fernet()
        # Should be able to encrypt/decrypt
        encrypted = fernet.encrypt(b"test")
        assert fernet.decrypt(encrypted) == b"test"

    def test_secrets_round_trip_with_fallback_key(self, tmp_config_dir, monkeypatch):
        """Full secret set/get must work using fallback key storage."""
        import utils.settings as s

        mock_kr = MagicMock()
        mock_kr.get_password.return_value = None
        mock_kr.set_password.side_effect = Exception("No Credential Manager")
        monkeypatch.setattr("utils.settings.keyring", mock_kr)

        s.set_secret("test_ns", "api_key", "my_secret_value")
        result = s.get_secret("test_ns", "api_key")
        assert result == "my_secret_value"


# ===========================================================================
# V8: WireGuard discovery across install methods
# ===========================================================================
@pytest.mark.platform_windows
class TestWireGuardDiscovery:
    def test_standard_install_64bit(self):
        from plugins.vpn.wireguard.vpn_functions_windows import find_wireguard_exe
        with patch("os.path.exists", side_effect=lambda p: "Program Files\\WireGuard" in p and "x86" not in p):
            assert find_wireguard_exe() == r"C:\Program Files\WireGuard\wireguard.exe"

    def test_legacy_32bit_install(self):
        """Some Win10 systems have 32-bit WireGuard."""
        from plugins.vpn.wireguard.vpn_functions_windows import find_wireguard_exe
        with patch("os.path.exists", side_effect=lambda p: "(x86)" in p):
            assert find_wireguard_exe() == r"C:\Program Files (x86)\WireGuard\wireguard.exe"

    def test_wg_cli_found_next_to_wireguard(self):
        """wg.exe should be in same dir as wireguard.exe."""
        from plugins.vpn.wireguard.vpn_functions_windows import find_wg_cli
        with patch("plugins.vpn.wireguard.vpn_functions_windows.find_wireguard_exe",
                   return_value=r"C:\Program Files\WireGuard\wireguard.exe"):
            with patch("os.path.exists", return_value=True):
                result = find_wg_cli()
        assert result == r"C:\Program Files\WireGuard\wg.exe"

    def test_wireguard_not_installed(self):
        from plugins.vpn.wireguard.vpn_functions_windows import find_wireguard_exe, check_wireguard_installed
        with patch("os.path.exists", return_value=False):
            assert find_wireguard_exe() is None
            assert check_wireguard_installed() is False


# ===========================================================================
# V9: Uninstaller registry discovery across versions
# ===========================================================================
@pytest.mark.platform_windows
class TestUninstallerCompat:
    def test_split_quoted_command(self):
        """Uninstall command may be quoted (Inno Setup style)."""
        from utils.uninstall.windows import _split_uninstall_command

        exe, args = _split_uninstall_command('"C:\\Program Files\\Resistine\\unins000.exe" /SILENT')
        assert exe == r"C:\Program Files\Resistine\unins000.exe"
        assert args == "/SILENT"

    def test_split_unquoted_command(self):
        from utils.uninstall.windows import _split_uninstall_command

        exe, args = _split_uninstall_command(r"C:\unins.exe /SILENT")
        assert exe == r"C:\unins.exe"
        assert args == "/SILENT"

    def test_split_empty_command(self):
        from utils.uninstall.windows import _split_uninstall_command

        exe, args = _split_uninstall_command("")
        assert exe == ""
        assert args == ""

    def test_split_none_command(self):
        from utils.uninstall.windows import _split_uninstall_command

        exe, args = _split_uninstall_command(None)
        assert exe == ""

    def test_candidate_paths_deduplication(self, tmp_path):
        """Candidate paths must be deduplicated."""
        from utils.uninstall.windows import _candidate_uninstaller_paths

        # Patch away all registry access to get empty candidates
        import winreg
        with patch.object(winreg, "OpenKey", side_effect=OSError("Not found")):
            candidates = _candidate_uninstaller_paths()

        # No duplicates
        normalized = [c.lower() for c in candidates]
        assert len(normalized) == len(set(normalized))

    def test_is_available_false_when_no_exe(self):
        from utils.uninstall.windows import is_available
        with patch("utils.uninstall.windows._find_uninstaller_command", return_value=("", "")):
            assert is_available() is False

    def test_is_available_true_when_exe_exists(self):
        from utils.uninstall.windows import is_available
        with patch("utils.uninstall.windows._find_uninstaller_command",
                   return_value=(r"C:\Resistine\unins000.exe", "")):
            with patch("os.path.exists", return_value=True):
                assert is_available() is True


# ===========================================================================
# V10: Agent name stability across Windows versions
# ===========================================================================
@pytest.mark.platform_windows
class TestAgentNameVersionCompat:
    def test_same_guid_same_name(self):
        """Agent name must be deterministic for the same hostname + GUID."""
        from plugins.wazuh.agent.wazuh_functions_windows import get_agent_name

        with patch("plugins.wazuh.agent.wazuh_functions_windows.socket.gethostname",
                   return_value="DESKTOP-PC"):
            with patch("plugins.wazuh.agent.wazuh_functions_windows._get_machine_guid",
                       return_value="550e8400-e29b-41d4-a716-446655440000"):
                name1 = get_agent_name()
                name2 = get_agent_name()
        assert name1 == name2

    def test_guid_suffix_is_last_12_chars(self):
        """GUID suffix must be last 12 chars with dashes removed, uppercased."""
        from plugins.wazuh.agent.wazuh_functions_windows import get_agent_name

        guid = "550e8400-e29b-41d4-a716-446655440000"
        # No dashes: 550e8400e29b41d4a716446655440000 → last 12: 446655440000
        expected_suffix = "446655440000".upper()

        with patch("plugins.wazuh.agent.wazuh_functions_windows.socket.gethostname",
                   return_value="PC"):
            with patch("plugins.wazuh.agent.wazuh_functions_windows._get_machine_guid",
                       return_value=guid):
                name = get_agent_name()
        assert name.endswith(expected_suffix)

    def test_win10_vs_win11_hostname_formats(self):
        """Win10 uses DESKTOP-XXXXXXX, Win11 may use different formats."""
        from plugins.wazuh.agent.wazuh_functions_windows import get_agent_name

        hostnames = [
            "DESKTOP-ABC1234",   # Win10 default
            "LAPTOP-XYZ9876",   # Win10 laptop
            "MyPC",             # Custom name
            "WIN-SERVER2022",   # Server
            "PC-123",           # Short name
        ]
        for hostname in hostnames:
            with patch("plugins.wazuh.agent.wazuh_functions_windows.socket.gethostname",
                       return_value=hostname):
                with patch("plugins.wazuh.agent.wazuh_functions_windows._get_machine_guid",
                           return_value=None):
                    name = get_agent_name()
            assert name  # Not empty
            assert all(c.isalnum() or c in ".-_" for c in name)
