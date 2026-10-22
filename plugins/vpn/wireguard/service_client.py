"""
IPC client for the ResistineVPN Windows service.
Authors: Merhawi
Copyright (c) Resistine 2025
"""
import json
import os
import socket

from utils.logger import logger

SERVICE_HOST = "127.0.0.1"
SERVICE_PORT = 51888

# Token file is written by the service on first start and shared via ProgramData.
# Both the service (SYSTEM) and the GUI (current user) can access ProgramData.
# IMPORTANT: this path must match IPC_TOKEN_FILE in
# plugins/vpn/wireguard/windows_vpn_service.py — the service writes to
# %PROGRAMDATA%\Resistine\wireguard\.ipc_token (dot-prefixed, inside the
# wireguard/ subdirectory). The client reads from that same location so
# both sides authenticate against the same token value.
_PROGRAMDATA = os.environ.get("PROGRAMDATA", r"C:\ProgramData")
_IPC_TOKEN_FILE = os.path.join(_PROGRAMDATA, "Resistine", "wireguard", ".ipc_token")


def _load_ipc_token() -> str:
    """Load the IPC authentication token from the shared token file."""
    try:
        with open(_IPC_TOKEN_FILE, "r") as fh:
            token = fh.read().strip()
        if token:
            return token
        logger.error("IPC token file is empty")
    except FileNotFoundError:
        logger.warning(f"IPC token file not found at {_IPC_TOKEN_FILE} — is the VPN service installed?")
    except OSError as e:
        logger.error(f"Failed to load IPC token: {e}")
    # Fallback: allow override via environment (useful for CI / testing)
    return os.environ.get("RESISTINE_IPC_TOKEN", "")


def _recv_response(sock: socket.socket) -> bytes:
    """Read the full response.

    The service closes the connection after sending its reply, so we read
    until we receive an empty chunk (TCP FIN) rather than guessing a fixed
    buffer size.  This handles arbitrarily-sized responses correctly.
    """
    parts = []
    while True:
        chunk = sock.recv(65536)
        if not chunk:
            break
        parts.append(chunk)
    return b"".join(parts)


def send_command(command: str, tunnel: str, config_path: str = None) -> dict:
    """Send a command to the ResistineVPN service via IPC socket.

    Args:
        command: The command to send (status, connect, disconnect, etc.)
        tunnel: The tunnel name.
        config_path: Full path to the .conf file (optional, used for connect).
    Returns:
        dict with at minimum a 'status' key.
    """
    token = _load_ipc_token()
    if not token:
        return {"status": "error", "state": "Stopped", "message": "IPC token unavailable — VPN service not installed"}

    payload = {
        "token": token,
        "command": command,
        "tunnel": tunnel,
    }
    if config_path:
        payload["config_path"] = config_path

    logger.debug(f"VPN IPC → command={command} tunnel={tunnel}")
    if config_path:
        logger.debug(f"VPN IPC   config_path={config_path}")

    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((SERVICE_HOST, SERVICE_PORT))
        sock.sendall(json.dumps(payload).encode("utf-8"))

        data = _recv_response(sock)
        response = json.loads(data.decode("utf-8"))
        logger.debug(f"VPN IPC ← {response}")
        return response

    except ConnectionRefusedError:
        logger.error("VPN service is not running (connection refused)")
        return {"status": "error", "state": "Stopped", "message": "VPN service not running"}
    except socket.timeout:
        logger.error("VPN service timed out")
        return {"status": "error", "state": "Stopped", "message": "VPN service timed out"}
    except Exception as e:
        logger.exception("Unexpected error communicating with VPN service")
        return {"status": "error", "state": "Stopped", "message": str(e)}
    finally:
        if sock:
            try:
                sock.close()
            except Exception:
                pass