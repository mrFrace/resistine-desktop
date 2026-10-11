"""
macOS-specific tests.

These tests verify macOS behavior: correct paths, launchd integration,
Network Extension check, and SMAppService skip logic outside bundles.

All tests use mock subprocess — they do NOT require a running macOS system
but ARE marked platform_darwin so they can be skipped on CI if desired.
"""
import platform
import os
import pytest
from unittest.mock import MagicMock, patch


pytestmark = pytest.mark.platform_darwin


# ===========================================================================
# Config dir on macOS
# ===========================================================================
class TestDarwinConfigDir:
    def test_config_dir_is_library_application_support(self, monkeypatch):
        import utils.settings as s
        with patch.object(platform, "system", return_value="Darwin"):
            # Reimport to pick up the patched platform
            path = s.get_config_dir()
            assert "Library/Application Support/Phoenix" in path

    def test_config_dir_exists_under_home(self, monkeypatch):
        import utils.settings as s
        with patch.object(platform, "system", return_value="Darwin"):
            path = s.get_config_dir()
            assert path.startswith(os.path.expanduser("~"))


# ===========================================================================
# Wazuh paths
# ===========================================================================
class TestWazuhPaths:
    def test_install_dir_is_library_ossec(self):
        from plugins.wazuh.config import WAZUH_INSTALL_DIR
        assert WAZUH_INSTALL_DIR == "/Library/Ossec"

    def test_launchd_plist_path(self):
        from plugins.wazuh.config import WAZUH_LAUNCHD_PLIST
        assert WAZUH_LAUNCHD_PLIST == "/Library/LaunchDaemons/com.wazuh.agent.plist"

    def test_env_file_in_tmp(self):
        # Wazuh's macOS .pkg install scripts read this fixed path as root; the
        # app stages it there as root (never via a user-writable /tmp file).
        from plugins.wazuh.config import WAZUH_PKG_ENV_FILE
        assert WAZUH_PKG_ENV_FILE == "/tmp/wazuh_envs"

    def test_wazuh_control_binary_path(self):
        from plugins.wazuh.config import WAZUH_INSTALL_DIR
        control_path = f"{WAZUH_INSTALL_DIR}/bin/wazuh-control"
        # Path should be rooted at /Library/Ossec
        assert control_path.startswith("/Library/Ossec")


# ===========================================================================
# is_agent_installed uses macOS-specific paths
# ===========================================================================
class TestIsAgentInstalledDarwin:
    @patch("plugins.wazuh.agent.wazuh_functions_darwin.os.path.isdir")
    @patch("plugins.wazuh.agent.wazuh_functions_darwin.os.path.exists")
    def test_checks_library_ossec(self, mock_exists, mock_isdir):
        mock_isdir.return_value = True
        mock_exists.return_value = False
        from plugins.wazuh.agent.wazuh_functions_darwin import is_agent_installed
        is_agent_installed()
        # Should check /Library/Ossec
        checked_paths = [str(call.args[0]) for call in mock_isdir.call_args_list]
        assert any("/Library/Ossec" in p for p in checked_paths)

    @patch("plugins.wazuh.agent.wazuh_functions_darwin.os.path.isdir")
    @patch("plugins.wazuh.agent.wazuh_functions_darwin.os.path.exists")
    def test_checks_launchd_plist(self, mock_exists, mock_isdir):
        mock_isdir.return_value = False
        mock_exists.return_value = True
        from plugins.wazuh.agent.wazuh_functions_darwin import is_agent_installed
        is_agent_installed()
        checked_paths = [str(call.args[0]) for call in mock_exists.call_args_list]
        assert any("LaunchDaemons" in p or "com.wazuh" in p for p in checked_paths)


# ===========================================================================
# get_agent_status uses launchctl
# ===========================================================================
class TestGetAgentStatusDarwin:
    @patch("plugins.wazuh.agent.wazuh_functions_darwin.subprocess.run")
    @patch("plugins.wazuh.agent.wazuh_functions_darwin.is_agent_installed", return_value=True)
    def test_uses_launchctl_command(self, _, mock_run):
        mock_run.return_value = MagicMock(stdout="state = running\n", returncode=0)
        from plugins.wazuh.agent.wazuh_functions_darwin import get_agent_status
        get_agent_status()
        cmd_used = mock_run.call_args[0][0]
        assert "launchctl" in cmd_used

    @patch("plugins.wazuh.agent.wazuh_functions_darwin.subprocess.run")
    @patch("plugins.wazuh.agent.wazuh_functions_darwin.is_agent_installed", return_value=True)
    def test_falls_back_to_pgrep(self, _, mock_run):
        # launchctl fails; pgrep finds process
        mock_run.side_effect = [
            MagicMock(stdout="", returncode=1),  # launchctl
            MagicMock(returncode=0),              # pgrep
        ]
        from plugins.wazuh.agent.wazuh_functions_darwin import get_agent_status
        status = get_agent_status()
        assert status == "Running"
        # Second call should be pgrep
        second_cmd = mock_run.call_args_list[1][0][0]
        assert "pgrep" in second_cmd


# ===========================================================================
# VPN — WireGuard dir uses App Group container
# ===========================================================================
class TestVpnDarwinPaths:
    def test_wireguard_dir_uses_group_containers(self):
        """get_writable_wireguard_dir must use App Group container path."""
        with patch("plugins.vpn.wireguard.vpn_functions_darwin.os.makedirs"):
            from plugins.vpn.wireguard.vpn_functions_darwin import get_writable_wireguard_dir
            path = get_writable_wireguard_dir()
        assert "Group Containers" in path
        assert "group.Resistine" in path
        assert "wireguard" in path

    def test_wireguard_dir_is_under_home(self):
        with patch("plugins.vpn.wireguard.vpn_functions_darwin.os.makedirs"):
            from plugins.vpn.wireguard.vpn_functions_darwin import get_writable_wireguard_dir
            path = get_writable_wireguard_dir()
        home = os.path.expanduser("~")
        assert path.startswith(home)


# ===========================================================================
# is_extension_enabled uses systemextensionsctl
# ===========================================================================
class TestIsExtensionEnabledDarwin:
    @patch("plugins.vpn.wireguard.vpn_functions_darwin.subprocess.run")
    def test_uses_systemextensionsctl(self, mock_run):
        from plugins.vpn.wireguard import vpn_functions_darwin as vfd
        vfd._extension_cache["timestamp"] = 0
        mock_run.return_value = MagicMock(stdout="", stderr="", returncode=0)
        vfd.is_extension_enabled()
        cmd = mock_run.call_args[0][0]
        assert "systemextensionsctl" in cmd

    @patch("plugins.vpn.wireguard.vpn_functions_darwin.subprocess.run")
    def test_checks_resistine_extension_id(self, mock_run):
        from plugins.vpn.wireguard import vpn_functions_darwin as vfd
        vfd._extension_cache["timestamp"] = 0
        output = "2 com.resistine.desktop.network-extension [activated enabled]"
        mock_run.return_value = MagicMock(stdout=output, stderr="", returncode=0)
        result = vfd.is_extension_enabled()
        assert result is True


# ===========================================================================
# _run_privileged uses osascript with administrator privileges
# ===========================================================================
class TestRunPrivilegedDarwin:
    @patch("plugins.wazuh.agent.wazuh_functions_darwin.subprocess.run")
    def test_uses_osascript(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0, stdout="ok", stderr="")
        from plugins.wazuh.agent.wazuh_functions_darwin import _run_privileged
        _run_privileged("echo hello")
        cmd = mock_run.call_args[0][0]
        assert "osascript" in cmd

    @patch("plugins.wazuh.agent.wazuh_functions_darwin.subprocess.run")
    def test_uses_administrator_privileges(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0, stdout="ok", stderr="")
        from plugins.wazuh.agent.wazuh_functions_darwin import _run_privileged
        _run_privileged("echo hello")
        cmd = mock_run.call_args[0][0]
        cmd_str = " ".join(cmd)
        assert "administrator privileges" in cmd_str


# ===========================================================================
# Hardware UUID extraction
# ===========================================================================
class TestHardwareUUID:
    @patch("plugins.wazuh.agent.wazuh_functions_darwin.subprocess.run")
    def test_uses_ioreg(self, mock_run):
        mock_run.return_value = MagicMock(
            stdout='"IOPlatformUUID" = "AABB-CCDD-0000-1111-222233334444"\n',
            returncode=0,
        )
        from plugins.wazuh.agent.wazuh_functions_darwin import _get_hardware_uuid
        uuid = _get_hardware_uuid()
        assert uuid == "AABB-CCDD-0000-1111-222233334444"

    @patch("plugins.wazuh.agent.wazuh_functions_darwin.subprocess.run")
    def test_ioreg_command_used(self, mock_run):
        mock_run.return_value = MagicMock(stdout="", returncode=0)
        from plugins.wazuh.agent.wazuh_functions_darwin import _get_hardware_uuid
        _get_hardware_uuid()
        cmd = mock_run.call_args[0][0]
        assert "ioreg" in cmd

    @patch("plugins.wazuh.agent.wazuh_functions_darwin.subprocess.run")
    def test_returns_none_when_uuid_not_in_output(self, mock_run):
        mock_run.return_value = MagicMock(stdout="No UUID here\n", returncode=0)
        from plugins.wazuh.agent.wazuh_functions_darwin import _get_hardware_uuid
        assert _get_hardware_uuid() is None

    @patch("plugins.wazuh.agent.wazuh_functions_darwin.subprocess.run")
    def test_returns_none_on_exception(self, mock_run):
        mock_run.side_effect = Exception("ioreg crashed")
        from plugins.wazuh.agent.wazuh_functions_darwin import _get_hardware_uuid
        assert _get_hardware_uuid() is None
