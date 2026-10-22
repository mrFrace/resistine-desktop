"""
Unit tests for the Windows VPN Service IPC handler and tunnel management.

Covers services/windows_vpn_service.py:
- IPC token initialization
- handle_request: auth, command dispatch, tunnel lifecycle
- find_config: priority resolution (explicit path > ProgramData)
- install_tunnel / uninstall_tunnel / start_tunnel / stop_tunnel / status_tunnel
- wg_service_name formatting
- Allowed command validation
- Edge cases: missing tunnel, bad token, unknown command

All subprocess and filesystem calls are mocked — safe to run anywhere.
"""
import json
import os
import socket
import secrets
import pytest
from unittest.mock import MagicMock, patch, mock_open, call


# win32 modules are stubbed centrally in tests/conftest.py


@pytest.fixture(autouse=True)
def _windows_subprocess_constants():
    """Provide Windows-only subprocess.CREATE_NO_WINDOW when running off Windows.

    The service's run_cmd() passes creationflags=subprocess.CREATE_NO_WINDOW,
    which only exists on Windows. Patch it in (create=True) so the real
    command-dispatch / output-parsing logic can be exercised on Linux CI.
    """
    with patch("subprocess.CREATE_NO_WINDOW", 0x08000000, create=True):
        yield


# ===========================================================================
# IPC Token
# ===========================================================================
@pytest.mark.unit
class TestIPCToken:
    def test_init_reads_existing_token(self, tmp_path):
        token_file = tmp_path / "ipc_token"
        # Token must be >= 32 chars or _get_or_create_ipc_token regenerates it
        existing = "a" * 64
        token_file.write_text(existing)

        with patch("plugins.vpn.wireguard.windows_vpn_service.IPC_TOKEN_FILE", str(token_file)):
            from plugins.vpn.wireguard.windows_vpn_service import _get_or_create_ipc_token
            token = _get_or_create_ipc_token()
        assert token == existing

    def test_init_generates_new_token_when_missing(self, tmp_path):
        token_file = tmp_path / "subdir" / "ipc_token"
        with patch("plugins.vpn.wireguard.windows_vpn_service.IPC_TOKEN_FILE", str(token_file)):
            from plugins.vpn.wireguard.windows_vpn_service import _get_or_create_ipc_token
            token = _get_or_create_ipc_token()
        assert len(token) == 64  # hex(32 bytes)
        assert token_file.exists()
        assert token_file.read_text() == token

    def test_init_generates_new_token_when_empty(self, tmp_path):
        token_file = tmp_path / "ipc_token"
        token_file.write_text("")

        with patch("plugins.vpn.wireguard.windows_vpn_service.IPC_TOKEN_FILE", str(token_file)):
            from plugins.vpn.wireguard.windows_vpn_service import _get_or_create_ipc_token
            token = _get_or_create_ipc_token()
        assert len(token) == 64

    def test_init_handles_permission_error(self, tmp_path):
        """If token cannot be written, function should still return a token.

        Replicates real failure mode: makedirs OK but open() fails (e.g. ACL on file).
        """
        bad_path = str(tmp_path / "subdir" / "token")
        original_open = open

        def failing_open(path, *args, **kwargs):
            if path == bad_path:
                raise OSError("Access denied (simulated ACL)")
            return original_open(path, *args, **kwargs)

        with patch("plugins.vpn.wireguard.windows_vpn_service.IPC_TOKEN_FILE", bad_path):
            with patch("builtins.open", side_effect=failing_open):
                from plugins.vpn.wireguard.windows_vpn_service import _get_or_create_ipc_token
                token = _get_or_create_ipc_token()
        assert len(token) == 64  # Generated in memory even if write fails
        # Token is hex chars only (no garbage from failed read attempts)
        assert all(c in "0123456789abcdef" for c in token)

    def test_two_inits_with_existing_file_return_same_token(self, tmp_path):
        """Token must be persistent: two calls with existing file → same token.

        If this fails, every service restart would invalidate all client tokens.
        """
        token_file = tmp_path / "ipc_token"
        with patch("plugins.vpn.wireguard.windows_vpn_service.IPC_TOKEN_FILE", str(token_file)):
            from plugins.vpn.wireguard.windows_vpn_service import _get_or_create_ipc_token
            t1 = _get_or_create_ipc_token()
            t2 = _get_or_create_ipc_token()
        assert t1 == t2, "Token must persist across calls when file exists"


# ===========================================================================
# wg_service_name
# ===========================================================================
@pytest.mark.unit
class TestWgServiceName:
    def test_format(self):
        from plugins.vpn.wireguard.windows_vpn_service import wg_service_name
        assert wg_service_name("resistine_default") == "WireGuardTunnel$resistine_default"
        assert wg_service_name("wg0") == "WireGuardTunnel$wg0"


# ===========================================================================
# find_config — path priority resolution
# ===========================================================================
@pytest.mark.unit
class TestFindConfig:
    def test_explicit_path_takes_priority(self, tmp_path):
        """If an explicit config_path is provided and exists, use it."""
        conf = tmp_path / "user_appdata" / "wg0.conf"
        conf.parent.mkdir()
        conf.write_text("[Interface]\n")

        from plugins.vpn.wireguard.windows_vpn_service import find_config
        result = find_config("wg0", str(conf))
        assert result == str(conf)

    def test_falls_back_to_programdata(self, tmp_path):
        from plugins.vpn.wireguard.windows_vpn_service import find_config
        pd_conf = tmp_path / "wg0.conf"
        pd_conf.write_text("[Interface]\n")

        with patch("plugins.vpn.wireguard.windows_vpn_service.CONFIG_BASE", str(tmp_path)):
            result = find_config("wg0")
        assert result == str(pd_conf)

    def test_explicit_path_nonexistent_falls_back(self, tmp_path):
        """If explicit path doesn't exist, try ProgramData."""
        # NOTE: importing find_config locally inside the test (rather than at
        # the top of the module) is intentional. The other tests above
        # imported it at the module level and ran fine, but both of these
        # caused a NameError the first time I ran them because the
        # module-level name was unbound once I started patching CONFIG_BASE.
        # If you move this import out of the function body for whatever
        # reason please make sure both falls_back cases still resolve
        # find_config correctly. - Austin
        from plugins.vpn.wireguard.windows_vpn_service import find_config as _find_config

        pd_conf = tmp_path / "wg0.conf"
        pd_conf.write_text("[Interface]\n")

        with patch("plugins.vpn.wireguard.windows_vpn_service.CONFIG_BASE", str(tmp_path)):
            result = _find_config("wg0", "/nonexistent/wg0.conf")
        assert result == str(pd_conf)

    def test_returns_none_when_no_config_found(self, tmp_path):
        from plugins.vpn.wireguard.windows_vpn_service import find_config as _find_config

        with patch("plugins.vpn.wireguard.windows_vpn_service.CONFIG_BASE", str(tmp_path)):
            result = _find_config("wg0")
        assert result is None


# ===========================================================================
# install_tunnel
# ===========================================================================
@pytest.mark.unit
class TestInstallTunnel:
    def test_success(self, tmp_path):
        conf = tmp_path / "wg0.conf"
        conf.write_text("[Interface]\n")

        from plugins.vpn.wireguard.windows_vpn_service import install_tunnel

        mock_result = MagicMock(returncode=0, stdout="", stderr="")
        with patch("plugins.vpn.wireguard.windows_vpn_service.find_config", return_value=str(conf)):
            with patch("os.path.exists", return_value=True):
                with patch("subprocess.run", return_value=mock_result):
                    with patch("time.sleep"):
                        ok, msg = install_tunnel("wg0")
        assert ok is True

    def test_already_installed(self, tmp_path):
        conf = tmp_path / "wg0.conf"
        conf.write_text("[Interface]\n")

        from plugins.vpn.wireguard.windows_vpn_service import install_tunnel

        mock_result = MagicMock(returncode=1, stdout="", stderr="Service already installed")
        with patch("plugins.vpn.wireguard.windows_vpn_service.find_config", return_value=str(conf)):
            with patch("os.path.exists", return_value=True):
                with patch("subprocess.run", return_value=mock_result):
                    ok, msg = install_tunnel("wg0")
        assert ok is True
        assert "Already installed" in msg

    def test_config_not_found(self):
        from plugins.vpn.wireguard.windows_vpn_service import install_tunnel
        with patch("plugins.vpn.wireguard.windows_vpn_service.find_config", return_value=None):
            ok, msg = install_tunnel("wg0")
        assert ok is False
        assert "not found" in msg.lower()

    def test_wireguard_exe_missing(self, tmp_path):
        conf = tmp_path / "wg0.conf"
        conf.write_text("[Interface]\n")

        from plugins.vpn.wireguard.windows_vpn_service import install_tunnel
        with patch("plugins.vpn.wireguard.windows_vpn_service.find_config", return_value=str(conf)):
            with patch("os.path.exists", return_value=False):
                ok, msg = install_tunnel("wg0")
        assert ok is False
        assert "not installed" in msg.lower()


# ===========================================================================
# start_tunnel / stop_tunnel / status_tunnel
# ===========================================================================
@pytest.mark.unit
class TestTunnelOperations:
    def test_start_tunnel_success(self):
        from plugins.vpn.wireguard.windows_vpn_service import start_tunnel
        mock_result = MagicMock(returncode=0, stdout="", stderr="")
        with patch("subprocess.run", return_value=mock_result):
            ok, msg = start_tunnel("wg0")
        assert ok is True

    def test_start_tunnel_already_running(self):
        from plugins.vpn.wireguard.windows_vpn_service import start_tunnel
        mock_result = MagicMock(returncode=1, stdout="already running", stderr="")
        with patch("subprocess.run", return_value=mock_result):
            ok, msg = start_tunnel("wg0")
        assert ok is True
        assert "Already running" in msg

    def test_start_tunnel_start_pending(self):
        from plugins.vpn.wireguard.windows_vpn_service import start_tunnel
        mock_result = MagicMock(returncode=1056, stdout="START_PENDING", stderr="")
        with patch("subprocess.run", return_value=mock_result):
            ok, msg = start_tunnel("wg0")
        assert ok is True

    def test_stop_tunnel_success(self):
        from plugins.vpn.wireguard.windows_vpn_service import stop_tunnel
        mock_result = MagicMock(returncode=0, stdout="stopped", stderr="")
        with patch("subprocess.run", return_value=mock_result):
            ok, msg = stop_tunnel("wg0")
        assert ok is True

    def test_stop_tunnel_already_stopped(self):
        from plugins.vpn.wireguard.windows_vpn_service import stop_tunnel
        mock_result = MagicMock(returncode=1, stdout="not started", stderr="")
        with patch("subprocess.run", return_value=mock_result):
            ok, msg = stop_tunnel("wg0")
        assert ok is True
        assert "Already stopped" in msg

    @pytest.mark.parametrize("output,expected", [
        ("STATE: 4  RUNNING", "Running"),
        ("STATE: 1  STOPPED", "Stopped"),
        ("STATE: 2  START_PENDING", "Starting"),
        ("STATE: 3  STOP_PENDING", "Stopping"),
        ("1060 does not exist", "Not Installed"),
        ("something else entirely", "Unknown"),
    ])
    def test_status_tunnel_states(self, output, expected):
        from plugins.vpn.wireguard.windows_vpn_service import status_tunnel
        mock_result = MagicMock(returncode=0, stdout=output, stderr="")
        with patch("subprocess.run", return_value=mock_result):
            assert status_tunnel("wg0") == expected

    def test_uninstall_tunnel_not_installed(self):
        from plugins.vpn.wireguard.windows_vpn_service import uninstall_tunnel
        mock_result = MagicMock(returncode=1, stdout="1060", stderr="")
        with patch("subprocess.run", return_value=mock_result):
            ok, msg = uninstall_tunnel("wg0")
        assert ok is True
        assert "Not installed" in msg


# ===========================================================================
# handle_request — IPC dispatcher
# ===========================================================================
@pytest.mark.unit
class TestHandleRequest:
    def _request(self, command, tunnel="wg0", token=None, config_path=None):
        from plugins.vpn.wireguard.windows_vpn_service import handle_request, IPC_TOKEN
        req = {
            "token": token or IPC_TOKEN,
            "command": command,
            "tunnel": tunnel,
        }
        if config_path:
            req["config_path"] = config_path
        return handle_request(req)

    def test_unauthorized_token_rejected(self):
        result = self._request("status", token="wrong_token")
        assert result["status"] == "error"
        assert "unauthorized" in result["message"].lower()

    def test_invalid_command_rejected(self):
        result = self._request("hack_the_planet")
        assert result["status"] == "error"
        assert "invalid command" in result["message"].lower()

    def test_missing_tunnel_rejected(self):
        from plugins.vpn.wireguard.windows_vpn_service import handle_request, IPC_TOKEN
        result = handle_request({"token": IPC_TOKEN, "command": "status", "tunnel": ""})
        assert result["status"] == "error"
        assert "missing tunnel" in result["message"].lower()

    def test_status_command(self):
        with patch("plugins.vpn.wireguard.windows_vpn_service.status_tunnel", return_value="Running"):
            result = self._request("status")
        assert result["status"] == "ok"
        assert result["state"] == "Running"

    def test_connect_when_not_installed(self):
        """connect must install + start if tunnel is Not Installed."""
        with patch("plugins.vpn.wireguard.windows_vpn_service.status_tunnel",
                   side_effect=["Not Installed", "Running", "Running"]):
            with patch("plugins.vpn.wireguard.windows_vpn_service.install_tunnel",
                       return_value=(True, "Installed")):
                with patch("plugins.vpn.wireguard.windows_vpn_service.start_tunnel",
                           return_value=(True, "Started")):
                    result = self._request("connect")
        assert result["status"] == "ok"
        assert result["state"] == "Running"

    def test_connect_already_running(self):
        with patch("plugins.vpn.wireguard.windows_vpn_service.status_tunnel", return_value="Running"):
            result = self._request("connect")
        assert result["status"] == "ok"
        assert "Already running" in result.get("message", "")

    def test_disconnect_already_stopped(self):
        with patch("plugins.vpn.wireguard.windows_vpn_service.status_tunnel", return_value="Stopped"):
            result = self._request("disconnect")
        assert result["status"] == "ok"

    def test_disconnect_running(self):
        with patch("plugins.vpn.wireguard.windows_vpn_service.status_tunnel",
                   side_effect=["Running", "Stopped"]):
            with patch("plugins.vpn.wireguard.windows_vpn_service.stop_tunnel",
                       return_value=(True, "Stopped")):
                result = self._request("disconnect")
        assert result["status"] == "ok"

    def test_health_command(self):
        with patch("plugins.vpn.wireguard.windows_vpn_service.status_tunnel", return_value="Running"):
            result = self._request("health")
        assert result["status"] == "ok"
        assert result["service"] == "running"
        assert result["wireguard"] == "Running"

    def test_restart_command(self):
        with patch("plugins.vpn.wireguard.windows_vpn_service.stop_tunnel", return_value=(True, "Stopped")):
            with patch("plugins.vpn.wireguard.windows_vpn_service.start_tunnel", return_value=(True, "Started")):
                with patch("plugins.vpn.wireguard.windows_vpn_service.status_tunnel", return_value="Running"):
                    result = self._request("restart")
        assert result["status"] == "ok"
        assert result["state"] == "Running"

    def test_stop_command(self):
        with patch("plugins.vpn.wireguard.windows_vpn_service.stop_tunnel", return_value=(True, "Stopped")):
            result = self._request("stop")
        assert result["status"] == "ok"

    def test_exception_in_handler_returns_error(self):
        with patch("plugins.vpn.wireguard.windows_vpn_service.status_tunnel",
                   side_effect=RuntimeError("Boom")):
            result = self._request("status")
        assert result["status"] == "error"
        assert "Boom" in result["message"]

    @pytest.mark.parametrize("cmd", [
        "status", "start", "connect", "disconnect", "stop", "restart", "health"
    ])
    def test_all_allowed_commands_accepted(self, cmd):
        """Every command in ALLOWED_COMMANDS must not return 'Invalid command'."""
        with patch("plugins.vpn.wireguard.windows_vpn_service.status_tunnel", return_value="Stopped"):
            with patch("plugins.vpn.wireguard.windows_vpn_service.install_tunnel", return_value=(True, "ok")):
                with patch("plugins.vpn.wireguard.windows_vpn_service.start_tunnel", return_value=(True, "ok")):
                    with patch("plugins.vpn.wireguard.windows_vpn_service.stop_tunnel", return_value=(True, "ok")):
                        result = self._request(cmd)
        assert "invalid command" not in result.get("message", "").lower()

    def test_connect_passes_config_path(self):
        """connect must forward config_path to install_tunnel."""
        with patch("plugins.vpn.wireguard.windows_vpn_service.status_tunnel",
                   side_effect=["Not Installed", "Running", "Running"]):
            with patch("plugins.vpn.wireguard.windows_vpn_service.install_tunnel",
                       return_value=(True, "Installed")) as mock_install:
                with patch("plugins.vpn.wireguard.windows_vpn_service.start_tunnel",
                           return_value=(True, "Started")):
                    self._request("connect", config_path="/user/appdata/wg0.conf")
        mock_install.assert_called_once_with("wg0", "/user/appdata/wg0.conf")


# ===========================================================================
# SC QUERY OUTPUT PARSING — WINDOWS VERSION COMPATIBILITY
# ===========================================================================
@pytest.mark.unit
class TestScQueryVersionCompat:
    """sc query output format varies across Windows 10/11 builds and locales.

    These tests verify that status_tunnel handles all known output variations
    without relying on exact formatting, whitespace, or locale-specific strings.
    """

    @pytest.mark.parametrize("output", [
        # Win10 English
        "SERVICE_NAME: WireGuardTunnel$wg0\r\n        TYPE               : 10  WIN32_OWN_PROCESS\r\n        STATE              : 4  RUNNING\r\n",
        # Win11 22H2+ English — extra whitespace
        "SERVICE_NAME: WireGuardTunnel$wg0\n    TYPE     : 10  WIN32_OWN_PROCESS\n    STATE    : 4  RUNNING \n",
        # Lowercase (some localized builds)
        "state: 4  running",
        # Mixed case with extra info
        "STATE              : 4  RUNNING\r\n                        (STOPPABLE, NOT_PAUSABLE, ACCEPTS_SHUTDOWN)",
        # Win11 25H2 compact format (observed in some builds)
        "RUNNING",
    ])
    def test_running_detected(self, output):
        from plugins.vpn.wireguard.windows_vpn_service import status_tunnel
        mock_result = MagicMock(returncode=0, stdout=output, stderr="")
        with patch("subprocess.run", return_value=mock_result):
            assert status_tunnel("wg0") == "Running"

    @pytest.mark.parametrize("output", [
        "STATE              : 1  STOPPED\r\n",
        "state: 1  stopped",
        "STOPPED",
        "STATE    : 1  STOPPED \r\n                        (NOT_STOPPABLE, NOT_PAUSABLE, IGNORES_SHUTDOWN)",
    ])
    def test_stopped_detected(self, output):
        from plugins.vpn.wireguard.windows_vpn_service import status_tunnel
        mock_result = MagicMock(returncode=0, stdout=output, stderr="")
        with patch("subprocess.run", return_value=mock_result):
            assert status_tunnel("wg0") == "Stopped"

    @pytest.mark.parametrize("output", [
        # Win10 error 1060
        "[SC] EnumQueryServicesStatus:OpenService FAILED 1060:\r\nThe specified service does not exist as an installed service.",
        # Win11 shortened error
        "FAILED 1060",
        # Error in stderr instead of stdout
        "",  # empty stdout
    ])
    def test_not_installed_detected(self, output):
        from plugins.vpn.wireguard.windows_vpn_service import status_tunnel
        stderr = "1060" if not output else ""
        mock_result = MagicMock(returncode=1, stdout=output, stderr=stderr)
        with patch("subprocess.run", return_value=mock_result):
            assert status_tunnel("wg0") == "Not Installed"

    @pytest.mark.parametrize("output", [
        "STATE: 2  START_PENDING",
        "start_pending",
    ])
    def test_starting_detected(self, output):
        from plugins.vpn.wireguard.windows_vpn_service import status_tunnel
        mock_result = MagicMock(returncode=0, stdout=output, stderr="")
        with patch("subprocess.run", return_value=mock_result):
            assert status_tunnel("wg0") == "Starting"

    @pytest.mark.parametrize("output", [
        "STATE: 3  STOP_PENDING",
        "stop_pending",
    ])
    def test_stopping_detected(self, output):
        from plugins.vpn.wireguard.windows_vpn_service import status_tunnel
        mock_result = MagicMock(returncode=0, stdout=output, stderr="")
        with patch("subprocess.run", return_value=mock_result):
            assert status_tunnel("wg0") == "Stopping"

    def test_start_tunnel_win10_error_1056(self):
        """Error 1056 = service already running. Win10 returns this as rc."""
        # NOTE: the parameterized stop_tunnel cases below caught a real bug
        # in source code the first time I ran them. stop_tunnel was only
        # checking for the substring "not started", but the real Windows 10
        # error 1062 message is "The service has not been started." which
        # contains "not been started" (not "not started"). The output
        # wording isn't always the same across Windows versions, so if you
        # add any more error code paths do your research and make sure the
        # substring check matches whatever phrasing you expect on every
        # applicable version, otherwise we'll run into version-specific
        # errors. - Austin
        from plugins.vpn.wireguard.windows_vpn_service import start_tunnel
        # Win10: returncode=1056, stderr has the message
        mock_result = MagicMock(returncode=1056, stdout="", stderr="An instance of the service is already running.")
        with patch("subprocess.run", return_value=mock_result):
            ok, msg = start_tunnel("wg0")
        assert ok is True

    def test_start_tunnel_win11_error_already_running_in_stdout(self):
        """Win11 may put 'already running' in stdout instead of using error code."""
        from plugins.vpn.wireguard.windows_vpn_service import start_tunnel
        mock_result = MagicMock(returncode=0, stdout="The service is already running.", stderr="")
        with patch("subprocess.run", return_value=mock_result):
            ok, msg = start_tunnel("wg0")
        # Should succeed (service IS running, which is what we wanted)
        assert ok is True

    def test_stop_tunnel_win10_not_started(self):
        """Win10 says 'not been started' when service isn't running."""
        from plugins.vpn.wireguard.windows_vpn_service import stop_tunnel
        mock_result = MagicMock(
            returncode=1,
            stdout="",
            stderr="[SC] ControlService FAILED 1062:\n\nThe service has not been started.\n",
        )
        with patch("plugins.vpn.wireguard.windows_vpn_service.run_cmd", return_value=mock_result):
            ok, msg = stop_tunnel("wg0")
        assert ok is True
        assert "Already stopped" in msg


# ===========================================================================
# WAZUH SC QUERY — Windows version differences
# ===========================================================================
@pytest.mark.unit
class TestWazuhScQueryCompat:
    """Wazuh service status parsing across Windows versions."""

    @pytest.mark.parametrize("stdout_text", [
        # Win10 standard
        "SERVICE_NAME: WazuhSvc\r\n        TYPE               : 10  WIN32_OWN_PROCESS\r\n        STATE              : 4  RUNNING\r\n",
        # Win11 with extra metadata
        "STATE              : 4  RUNNING\r\n                        (STOPPABLE, NOT_PAUSABLE, ACCEPTS_SHUTDOWN)\r\n        WIN32_EXIT_CODE    : 0  (0x0)",
        # Minimal
        "RUNNING",
    ])
    def test_running_detected(self, stdout_text):
        from plugins.wazuh.agent.wazuh_functions_windows import get_agent_status
        mock_result = MagicMock(stdout=stdout_text, stderr="")
        with patch("plugins.wazuh.agent.wazuh_functions_windows.is_agent_installed", return_value=True):
            with patch("subprocess.run", return_value=mock_result):
                assert get_agent_status() == "Running"

    @pytest.mark.parametrize("stdout_text", [
        "STATE              : 1  STOPPED\r\n",
        "STOPPED",
        "STATE    : 1  STOPPED \r\n                        (NOT_STOPPABLE)",
    ])
    def test_stopped_detected(self, stdout_text):
        from plugins.wazuh.agent.wazuh_functions_windows import get_agent_status
        mock_result = MagicMock(stdout=stdout_text, stderr="")
        with patch("plugins.wazuh.agent.wazuh_functions_windows.is_agent_installed", return_value=True):
            with patch("subprocess.run", return_value=mock_result):
                assert get_agent_status() == "Stopped"
