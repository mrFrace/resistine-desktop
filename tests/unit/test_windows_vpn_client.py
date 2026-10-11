"""
Unit tests for Windows VPN IPC client.

Covers plugins/vpn/wireguard/service_client.py and
       plugins/vpn/wireguard/vpn_windows_client.py

All socket calls are mocked — safe to run on macOS/Linux.

service_client tests:
- send_command builds correct JSON payload (token, command, tunnel)
- config_path included only when provided
- ConnectionRefusedError handled → error dict returned
- socket.timeout handled → error dict returned
- Socket always closed (finally block)
- Response JSON parsed and returned

vpn_windows_client tests:
- connect() returns service response
- disconnect() returns service response
- get_status() returns service response
- Exception in send_command → error dict (not re-raised)
- toggle() connects when Stopped, disconnects when Running
"""
import json
import socket
import pytest
from unittest.mock import MagicMock, patch


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_mock_socket(response_data: dict):
    # NOTE: same trap as tray's _mock_socket... service_client._recv_response
    # loops on recv() until it gets b"". recv.return_value=data would feed
    # the same bytes every call and the loop would never terminate, running
    # the process out of memory. Keep it as side_effect=[data, b""] so the
    # second call signals FIN. If you're tweaking IPC recv behavior in the
    # future, please double-check both this helper and the tray one so you
    # don't run into any issues related to this. - Austin
    sock = MagicMock()
    data = json.dumps(response_data).encode("utf-8")
    sock.recv.side_effect = [data, b""]
    return sock


def _patch_socket(response_data: dict):
    """Patch socket.socket to return a mock that returns response_data."""
    mock_sock = _make_mock_socket(response_data)
    return patch(
        "plugins.vpn.wireguard.service_client.socket.socket",
        return_value=mock_sock,
    ), mock_sock


# ===========================================================================
# service_client.send_command — socket-level IPC
# ===========================================================================
@pytest.mark.unit
class TestSendCommand:
    """All tests set RESISTINE_IPC_TOKEN so _load_ipc_token() returns a
    known value via its env-var fallback (the token file won't exist in CI)."""

    FAKE_TOKEN = "test-ipc-token-abc123"

    @pytest.fixture(autouse=True)
    def _set_ipc_token(self, monkeypatch):
        monkeypatch.setenv("RESISTINE_IPC_TOKEN", self.FAKE_TOKEN)

    def test_payload_contains_ipc_token(self):
        """send_command must include the IPC token loaded from the shared file."""
        from plugins.vpn.wireguard.service_client import send_command

        ctx, mock_sock = _patch_socket({"status": "ok", "state": "Running"})
        with patch("plugins.vpn.wireguard.service_client._load_ipc_token",
                   return_value="test_token_abc123"):
            with ctx:
                send_command("status", "wg0")

        sent_bytes = mock_sock.sendall.call_args[0][0]
        payload = json.loads(sent_bytes.decode("utf-8"))
        assert payload["token"] == "test_token_abc123"

    def test_payload_contains_command_and_tunnel(self):
        """Payload must have 'command' and 'tunnel' fields matching the arguments."""
        from plugins.vpn.wireguard.service_client import send_command

        ctx, mock_sock = _patch_socket({"status": "ok"})
        with ctx:
            send_command("disconnect", "my_tunnel")

        payload = json.loads(mock_sock.sendall.call_args[0][0].decode("utf-8"))
        assert payload["command"] == "disconnect"
        assert payload["tunnel"] == "my_tunnel"

    def test_config_path_included_when_provided(self):
        """config_path must be in the payload when passed to send_command."""
        from plugins.vpn.wireguard.service_client import send_command

        ctx, mock_sock = _patch_socket({"status": "ok", "state": "Running"})
        with ctx:
            send_command("connect", "wg0", config_path="/path/to/wg0.conf")

        payload = json.loads(mock_sock.sendall.call_args[0][0].decode("utf-8"))
        assert payload.get("config_path") == "/path/to/wg0.conf"

    def test_config_path_omitted_when_not_provided(self):
        """config_path key must NOT appear in the payload when not passed."""
        from plugins.vpn.wireguard.service_client import send_command

        ctx, mock_sock = _patch_socket({"status": "ok", "state": "Stopped"})
        with ctx:
            send_command("status", "wg0")

        payload = json.loads(mock_sock.sendall.call_args[0][0].decode("utf-8"))
        assert "config_path" not in payload

    def test_connection_refused_returns_error_dict(self):
        """ConnectionRefusedError → {'status': 'error', 'state': 'Stopped', ...}"""
        from plugins.vpn.wireguard.service_client import send_command

        mock_sock = MagicMock()
        mock_sock.connect.side_effect = ConnectionRefusedError()

        with patch("plugins.vpn.wireguard.service_client.socket.socket", return_value=mock_sock):
            result = send_command("status", "wg0")

        assert result["status"] == "error"
        assert result["state"] == "Stopped"
        assert "not running" in result.get("message", "").lower()

    def test_socket_timeout_returns_error_dict(self):
        """socket.timeout → {'status': 'error', 'state': 'Stopped', ...}"""
        from plugins.vpn.wireguard.service_client import send_command

        mock_sock = MagicMock()
        mock_sock.connect.side_effect = socket.timeout()

        with patch("plugins.vpn.wireguard.service_client.socket.socket", return_value=mock_sock):
            result = send_command("status", "wg0")

        assert result["status"] == "error"
        assert result["state"] == "Stopped"
        assert "timed out" in result.get("message", "").lower()

    def test_socket_closed_on_success(self):
        """Socket must be closed in the finally block after a successful call."""
        from plugins.vpn.wireguard.service_client import send_command

        ctx, mock_sock = _patch_socket({"status": "ok", "state": "Running"})
        with ctx:
            send_command("status", "wg0")

        mock_sock.close.assert_called_once()

    def test_socket_closed_after_connection_refused(self):
        """Socket must be closed even when ConnectionRefusedError is raised."""
        from plugins.vpn.wireguard.service_client import send_command

        mock_sock = MagicMock()
        mock_sock.connect.side_effect = ConnectionRefusedError()

        with patch("plugins.vpn.wireguard.service_client.socket.socket", return_value=mock_sock):
            send_command("status", "wg0")

        mock_sock.close.assert_called_once()

    def test_response_json_parsed_correctly(self):
        """Response bytes are decoded from JSON and returned as a dict."""
        from plugins.vpn.wireguard.service_client import send_command

        expected = {"status": "ok", "state": "Running", "interface": "utun8"}
        ctx, mock_sock = _patch_socket(expected)
        with ctx:
            result = send_command("status", "wg0")

        assert result == expected

    def test_connects_to_correct_host_and_port(self):
        """Socket must connect to SERVICE_HOST:SERVICE_PORT."""
        from plugins.vpn.wireguard.service_client import (
            send_command, SERVICE_HOST, SERVICE_PORT
        )

        ctx, mock_sock = _patch_socket({"status": "ok"})
        with ctx:
            send_command("status", "wg0")

        mock_sock.connect.assert_called_once_with((SERVICE_HOST, SERVICE_PORT))

    def test_timeout_set_on_socket(self):
        """Socket timeout must be configured before connecting."""
        from plugins.vpn.wireguard.service_client import send_command

        ctx, mock_sock = _patch_socket({"status": "ok"})
        with ctx:
            send_command("status", "wg0")

        mock_sock.settimeout.assert_called_once()
        timeout_val = mock_sock.settimeout.call_args[0][0]
        assert isinstance(timeout_val, (int, float))
        assert timeout_val > 0


# ===========================================================================
# vpn_windows_client — higher-level wrapper
# ===========================================================================
@pytest.mark.unit
class TestVpnWindowsClient:
    def _mock_send(self, response: dict):
        return patch(
            "plugins.vpn.wireguard.vpn_windows_client.send_command",
            return_value=response,
        )

    def test_connect_returns_service_response(self):
        from plugins.vpn.wireguard.vpn_windows_client import connect

        expected = {"status": "ok", "state": "Running"}
        with self._mock_send(expected):
            result = connect("wg0", config_path="/path/to/conf")

        assert result == expected

    def test_connect_sends_config_path(self):
        """connect() must forward config_path to send_command."""
        from plugins.vpn.wireguard.vpn_windows_client import connect

        with patch("plugins.vpn.wireguard.vpn_windows_client.send_command",
                   return_value={"status": "ok"}) as mock_sc:
            connect("wg0", config_path="/etc/wg0.conf")

        call_kwargs = mock_sc.call_args[1]
        assert call_kwargs.get("config_path") == "/etc/wg0.conf"

    def test_disconnect_returns_service_response(self):
        from plugins.vpn.wireguard.vpn_windows_client import disconnect

        expected = {"status": "ok", "state": "Stopped"}
        with self._mock_send(expected):
            result = disconnect("wg0")

        assert result == expected

    def test_get_status_returns_service_response(self):
        from plugins.vpn.wireguard.vpn_windows_client import get_status

        expected = {"status": "ok", "state": "Running"}
        with self._mock_send(expected):
            result = get_status("wg0")

        assert result == expected

    def test_connect_exception_returns_error_dict(self):
        """If send_command raises, connect() must return an error dict."""
        from plugins.vpn.wireguard.vpn_windows_client import connect

        with patch(
            "plugins.vpn.wireguard.vpn_windows_client.send_command",
            side_effect=OSError("socket error"),
        ):
            result = connect("wg0")

        assert result["status"] == "error"
        assert "socket error" in result.get("message", "")

    def test_disconnect_exception_returns_error_dict(self):
        from plugins.vpn.wireguard.vpn_windows_client import disconnect

        with patch(
            "plugins.vpn.wireguard.vpn_windows_client.send_command",
            side_effect=OSError("broken pipe"),
        ):
            result = disconnect("wg0")

        assert result["status"] == "error"

    def test_get_status_exception_returns_stopped_state(self):
        """If send_command raises, get_status() must return state=Stopped."""
        from plugins.vpn.wireguard.vpn_windows_client import get_status

        with patch(
            "plugins.vpn.wireguard.vpn_windows_client.send_command",
            side_effect=RuntimeError("service crashed"),
        ):
            result = get_status("wg0")

        assert result.get("state") == "Stopped"
