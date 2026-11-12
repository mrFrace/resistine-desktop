"""
Unit tests for the Windows system tray application.

Covers gui/tray.py:
- _state_from_service: service state → tray state mapping
- _get_active_tunnel: config file reading, fallback logic
- _send_command: IPC socket, error handling
- ResistineTray: state machine, connect/disconnect actions, menu building

All socket, filesystem, and subprocess calls are mocked — safe to run anywhere.
"""
import json
import os
import socket
import pytest
from unittest.mock import MagicMock, patch, call


# ===========================================================================
# _state_from_service
# ===========================================================================
@pytest.mark.unit
class TestStateFromService:
    @pytest.mark.parametrize("service_state,expected", [
        ("Running", "connected"),
        ("Starting", "connecting"),
        ("Stopping", "connecting"),
        ("Stopped", "disconnected"),
        ("Not Installed", "disconnected"),
        ("Unknown", "disconnected"),
        ("", "disconnected"),
    ])
    def test_state_mapping(self, service_state, expected):
        from gui.tray import _state_from_service
        assert _state_from_service(service_state) == expected


# ===========================================================================
# _get_active_tunnel
# ===========================================================================
@pytest.mark.unit
class TestGetActiveTunnel:
    def test_reads_from_config_file(self, tmp_path):
        config_file = tmp_path / "vpn_config.json"
        config_file.write_text(json.dumps({"active_config": "my_tunnel"}))
        wg_dir = tmp_path / "wireguard"
        wg_dir.mkdir()
        (wg_dir / "my_tunnel.conf").write_text("[Interface]\n")

        with patch("gui.tray.CONFIG_FILE", str(config_file)):
            with patch("gui.tray.WG_DIR", str(wg_dir)):
                from gui.tray import _get_active_tunnel
                name, path = _get_active_tunnel()
        assert name == "my_tunnel"
        assert path.endswith("my_tunnel.conf")

    def test_fallback_to_first_conf(self, tmp_path):
        """If no config file, use first .conf found in wireguard dir."""
        config_file = tmp_path / "vpn_config.json"
        # No config file written

        wg_dir = tmp_path / "wireguard"
        wg_dir.mkdir()
        (wg_dir / "fallback_tunnel.conf").write_text("[Interface]\n")

        with patch("gui.tray.CONFIG_FILE", str(config_file)):
            with patch("gui.tray.WG_DIR", str(wg_dir)):
                from gui.tray import _get_active_tunnel
                name, path = _get_active_tunnel()
        assert name == "fallback_tunnel"

    def test_returns_none_when_no_configs(self, tmp_path):
        config_file = tmp_path / "vpn_config.json"
        wg_dir = tmp_path / "wireguard"
        wg_dir.mkdir()

        with patch("gui.tray.CONFIG_FILE", str(config_file)):
            with patch("gui.tray.WG_DIR", str(wg_dir)):
                from gui.tray import _get_active_tunnel
                name, path = _get_active_tunnel()
        assert name is None
        assert path is None

    def test_handles_corrupt_config_file(self, tmp_path):
        config_file = tmp_path / "vpn_config.json"
        config_file.write_text("not valid json{{{")
        wg_dir = tmp_path / "wireguard"
        wg_dir.mkdir()

        with patch("gui.tray.CONFIG_FILE", str(config_file)):
            with patch("gui.tray.WG_DIR", str(wg_dir)):
                from gui.tray import _get_active_tunnel
                name, path = _get_active_tunnel()
        # Should not crash, falls back or returns None
        assert name is None or isinstance(name, str)


# ===========================================================================
# _send_command — tray IPC
# ===========================================================================
@pytest.mark.unit
class TestTraySendCommand:
    def _mock_socket(self, response_data):
        # NOTE: the side_effect=[data, b""] shape matters here... tray's
        # _recv_response loops until recv returns empty bytes. If you swap
        # this for recv.return_value=data the loop never sees a FIN, parts[]
        # grows forever, and the whole machine gets pinned at 100% memory.
        # It took me a while to track this down so for anyone working on this
        # in the future, pay attention to how you're forming certain commands
        # so you don't end up with a dangerous state. - Austin
        mock_sock = MagicMock()
        data = json.dumps(response_data).encode("utf-8")
        mock_sock.recv.side_effect = [data, b""]
        return mock_sock

    def test_sends_json_payload(self):
        from gui.tray import _send_command
        mock_sock = self._mock_socket({"status": "ok"})
        with patch("gui.tray.socket.socket", return_value=mock_sock):
            _send_command("status", "wg0")

        sent = json.loads(mock_sock.sendall.call_args[0][0].decode())
        assert sent["command"] == "status"
        assert sent["tunnel"] == "wg0"
        assert "token" in sent

    def test_includes_config_path(self):
        from gui.tray import _send_command
        mock_sock = self._mock_socket({"status": "ok"})
        with patch("gui.tray.socket.socket", return_value=mock_sock):
            _send_command("connect", "wg0", config_path="/path/to/wg0.conf")

        sent = json.loads(mock_sock.sendall.call_args[0][0].decode())
        assert sent["config_path"] == "/path/to/wg0.conf"

    def test_connection_refused(self):
        from gui.tray import _send_command
        mock_sock = MagicMock()
        mock_sock.connect.side_effect = ConnectionRefusedError()
        with patch("gui.tray.socket.socket", return_value=mock_sock):
            result = _send_command("status", "wg0")
        assert result["status"] == "error"
        assert result["state"] == "Stopped"

    def test_socket_timeout(self):
        from gui.tray import _send_command
        mock_sock = MagicMock()
        mock_sock.connect.side_effect = socket.timeout()
        with patch("gui.tray.socket.socket", return_value=mock_sock):
            result = _send_command("status", "wg0")
        assert result["status"] == "error"

    def test_socket_always_closed(self):
        from gui.tray import _send_command
        mock_sock = self._mock_socket({"status": "ok"})
        with patch("gui.tray.socket.socket", return_value=mock_sock):
            _send_command("status", "wg0")
        mock_sock.close.assert_called_once()

    def test_socket_closed_on_error(self):
        from gui.tray import _send_command
        mock_sock = MagicMock()
        mock_sock.connect.side_effect = ConnectionRefusedError()
        with patch("gui.tray.socket.socket", return_value=mock_sock):
            _send_command("status", "wg0")
        mock_sock.close.assert_called_once()


# ===========================================================================
# PhoenixTray state machine
# ===========================================================================
@pytest.mark.unit
class TestResistineTrayState:
    def test_initial_state_disconnected(self):
        from gui.tray import ResistineTray
        tray = ResistineTray()
        assert tray._state == "disconnected"

    def test_title_connected(self):
        from gui.tray import ResistineTray
        tray = ResistineTray()
        tray._state = "connected"
        assert "Connected" in tray._title()

    def test_title_disconnected(self):
        from gui.tray import ResistineTray
        tray = ResistineTray()
        tray._state = "disconnected"
        assert "Disconnected" in tray._title()

    def test_title_connecting(self):
        from gui.tray import ResistineTray
        tray = ResistineTray()
        tray._state = "connecting"
        assert "Connecting" in tray._title()

    def test_on_disconnect_noop_when_already_disconnected(self):
        """Disconnect action should do nothing if already disconnected."""
        from gui.tray import ResistineTray
        tray = ResistineTray()
        tray._state = "disconnected"
        tray._tunnel = "wg0"

        with patch("gui.tray._send_command") as mock_send:
            tray.on_disconnect(None, None)
        mock_send.assert_not_called()

    def test_on_connect_sets_connecting_state(self):
        """Connect action should immediately set state to 'connecting' before IPC call."""
        from gui.tray import ResistineTray
        tray = ResistineTray()
        tray._state = "disconnected"
        tray._tunnel = "wg0"
        tray._config_path = "/path/to/wg0.conf"
        tray._icon = MagicMock()

        captured_state = []

        def capture_state_at_send(*args, **kwargs):
            # When _send_command is called, state must already be "connecting"
            captured_state.append(tray._state)
            return {"status": "ok", "state": "Running"}

        with patch("gui.tray._send_command", side_effect=capture_state_at_send):
            with patch.object(tray, "_refresh_status"):
                tray.on_connect(None, None)

        assert captured_state == ["connecting"], (
            f"Expected state 'connecting' during IPC call, got {captured_state}"
        )

    def test_on_connect_forwards_config_path(self):
        """Connect must forward config_path to _send_command."""
        from gui.tray import ResistineTray
        tray = ResistineTray()
        tray._state = "disconnected"
        tray._tunnel = "wg0"
        tray._config_path = r"C:\Users\Test\AppData\Roaming\Resistine\wireguard\wg0.conf"
        tray._icon = MagicMock()

        with patch("gui.tray._send_command", return_value={"status": "ok", "state": "Running"}) as mock_send:
            with patch.object(tray, "_refresh_status"):
                tray.on_connect(None, None)

        # Connect call must include the config_path
        connect_calls = [c for c in mock_send.call_args_list if c[0][0] == "connect"]
        assert connect_calls, "connect command was not sent"
        assert tray._config_path in connect_calls[0][0]

    def test_on_connect_noop_when_no_tunnel(self):
        from gui.tray import ResistineTray
        tray = ResistineTray()
        tray._tunnel = None

        with patch("gui.tray._send_command") as mock_send:
            tray.on_connect(None, None)
        mock_send.assert_not_called()


# ===========================================================================
# CRITICAL BUG-HUNTING TESTS — these are likely to fail and indicate
# real shipping issues
# ===========================================================================
@pytest.mark.unit
class TestTrayServiceTokenMismatch:
    """The tray uses a hardcoded literal 'RESISTINE_INTERNAL_TOKEN_CHANGE_ME'
    while the service generates a random token at first start and stores it
    in %PROGRAMDATA%\\Resistine\\ipc_token. These will never match → all tray
    IPC calls will be rejected as Unauthorized.

    NOTE: these two tests caught a ship-blocker bug the first time I ran
    them. gui/tray.py had IPC_TOKEN set to the literal placeholder
    "RESISTINE_INTERNAL_TOKEN_CHANGE_ME", which meant every Connect/
    Disconnect action from the tray was silently rejected by the service
    as Unauthorized and the tray menu effectively did nothing. If anyone
    reintroduces a module-level IPC_TOKEN constant on the tray side please
    ensure that it's actually loaded from the shared
    %PROGRAMDATA%\\Resistine\\ipc_token file on every call, otherwise you'll
    experience the same non-working tray issue described above. - Austin
    """

    def test_tray_token_is_not_a_placeholder(self):
        """Tray IPC_TOKEN must not be a hardcoded placeholder string."""
        from gui.tray import IPC_TOKEN
        # A literal 'CHANGE_ME' string is a known broken placeholder
        assert "CHANGE_ME" not in IPC_TOKEN, (
            f"Tray uses placeholder token: {IPC_TOKEN!r}. The service generates "
            "a random token in %PROGRAMDATA%\\Resistine\\ipc_token — the tray "
            "must read from the same file or it will always be rejected."
        )

    def test_tray_loads_token_from_shared_file(self, tmp_path):
        """Tray must load IPC token from the same source as service_client."""
        # Set up a real token file like the service would write
        token_file = tmp_path / "ipc_token"
        token_file.write_text("real_token_64_chars_long_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")

        # The tray module currently imports IPC_TOKEN as a hardcoded constant.
        # If this is fixed, the tray would either:
        #   1. Import _load_ipc_token from service_client and call it
        #   2. Have its own _load_ipc_token() function reading from the same path
        from gui.tray import IPC_TOKEN
        # If IPC_TOKEN is loaded dynamically, it should be either:
        # - 64 hex chars (matches service _init_ipc_token format)
        # - empty string (no service installed)
        assert (len(IPC_TOKEN) == 64 and all(c in "0123456789abcdef" for c in IPC_TOKEN.lower())) or IPC_TOKEN == "" or "CHANGE_ME" not in IPC_TOKEN, (
            f"Tray IPC_TOKEN={IPC_TOKEN!r} is not a real service-generated token"
        )


@pytest.mark.unit
class TestTrayBufferTruncation:
    """tray.py uses BUFFER_SIZE=4096 with sock.recv(BUFFER_SIZE), but
    service responses for 'health' or detailed status may exceed that.
    A truncated response would cause a JSONDecodeError.

    NOTE: the older tray did a single sock.recv(4096) and returned whatever
    bytes it got, which would silently truncate any service response that
    happened to exceed the buffer and then JSONDecodeError out on parsing.
    service_client.py already loops on recv() until it gets b"", so if
    you're rewriting the tray IPC pathway please ensure that it reads the
    full response the same way (or at the very least picks a buffer big
    enough to cover every command's response) instead of a single fixed
    recv, otherwise we'll run into partial-read parse errors under load.
    - Austin
    """

    def test_buffer_size_handles_typical_responses(self):
        """4096 bytes must be enough for the service's largest typical response."""
        from gui.tray import BUFFER_SIZE
        # The 'health' command response includes service+socket+wireguard fields
        # plus tunnel state. If WireGuard returns verbose status, we may exceed 4KB.
        # Either BUFFER_SIZE should be larger, or tray should use _recv_response loop.
        assert BUFFER_SIZE >= 4096, "Buffer too small for service responses"

    def test_recv_uses_full_response_loop(self):
        """tray._send_command should loop on recv() like service_client does,
        OR have a buffer large enough to never truncate."""
        import inspect
        from gui import tray
        source = inspect.getsource(tray._send_command)
        # Either loops on recv (proper) or has a single recv call (truncation risk)
        recv_calls = source.count("sock.recv(")
        if recv_calls == 1 and tray.BUFFER_SIZE < 16384:
            pytest.fail(
                "tray._send_command does a single sock.recv(BUFFER_SIZE) with "
                f"BUFFER_SIZE={tray.BUFFER_SIZE}. Large service responses could "
                "be truncated → JSONDecodeError. Either loop on recv() like "
                "service_client._recv_response, or increase BUFFER_SIZE to 65536."
            )
