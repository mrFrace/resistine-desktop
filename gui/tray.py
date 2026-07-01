# tray.py
"""
Resistine VPN System Tray Icon — standalone, no project imports.
Authors: Merhawi and the Resistine Team
Copyright (c) Resistine 2025
Licensed under the GNU General Public License v2 or later
"""

import threading
import os
import sys
import time
import json
import socket
import logging
import subprocess

try:
    import pystray
    from pystray import MenuItem as item
    from PIL import Image, ImageDraw
except ImportError:
    print("ERROR: pip install pystray pillow")
    sys.exit(1)


# ---- Paths ----
BASE_DIR    = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # project root (up from gui/)
ASSETS_DIR  = os.path.join(BASE_DIR, "resources", "icons")
ICON_PATH   = os.path.join(ASSETS_DIR, "icon.ico")
APPDATA_DIR = os.path.join(os.environ.get("APPDATA", ""), "Resistine")
WG_DIR      = os.path.join(APPDATA_DIR, "wireguard")
CONFIG_FILE = os.path.join(APPDATA_DIR, "vpn_config.json")
LOG_FILE    = os.path.join(APPDATA_DIR, "tray.log")
MAIN_SCRIPT = os.path.join(BASE_DIR, "main.py")


# ---- Logging (minimal) ----
os.makedirs(APPDATA_DIR, exist_ok=True)
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.WARNING,
    format="%(asctime)s | %(levelname)s | %(message)s",
)
logger = logging.getLogger("ResistineTray")


# ---- IPC (inline, no service_client import) ----
SERVICE_HOST = "127.0.0.1"
SERVICE_PORT = 51888
BUFFER_SIZE  = 65536
POLL_INTERVAL = 5

# Token is written by the ResistineVPN service on first start and shared via
# %PROGRAMDATA%\Resistine\wireguard\.ipc_token. Path must match IPC_TOKEN_FILE
# in plugins/vpn/wireguard/windows_vpn_service.py.
_IPC_TOKEN_FILE = os.path.join(
    os.environ.get("PROGRAMDATA", r"C:\ProgramData"),
    "Resistine",
    "wireguard",
    ".ipc_token",
)


def _restrict_token_acl(token_path: str) -> None:
    """Re-apply restrictive ACL on the IPC token file (Windows only).

    The service writes the token first, but if the file was created before
    the hardening shipped (or somehow inherited broader perms), reading from
    the GUI side gives us another chance to lock it down. Best-effort:
    failures are swallowed so notification/IPC keeps working.
    """
    if sys.platform != "win32":
        return
    try:
        import getpass

        user = os.environ.get("USERNAME") or getpass.getuser()
        subprocess.run(
            [
                "icacls", token_path,
                "/inheritance:r",
                "/grant", "SYSTEM:F",
                "/grant", "Administrators:F",
                "/grant", f"{user}:R",
            ],
            check=False,
            capture_output=True,
            timeout=5,
            # Suppress the console window: this runs on every IPC call
            # (token is re-loaded per request), so without it a cmd window
            # flashes on the desktop each time the GUI is windowless.
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except Exception:
        pass


def _load_ipc_token() -> str:
    try:
        with open(_IPC_TOKEN_FILE, "r") as fh:
            token = fh.read().strip()
        if token:
            # Best-effort harden the file's ACL each time we read it.
            _restrict_token_acl(_IPC_TOKEN_FILE)
            return token
    except FileNotFoundError:
        pass
    except OSError as e:
        logger.error(f"Failed to load IPC token: {e}")
    # Test/dev override
    return os.environ.get("RESISTINE_IPC_TOKEN", "")


# IPC_TOKEN kept as a module attribute for backward compatibility, but
# it is re-loaded on every IPC call via _load_ipc_token().
IPC_TOKEN = _load_ipc_token()

DOT_COLORS = {
    "connected":    (30,  142,  62, 255),   # green
    "disconnected": (197,  34,  31, 255),   # red
    "connecting":   (230, 160,   0, 255),   # yellow
}


def _recv_response(sock: socket.socket) -> bytes:
    """Read until the service closes the connection (TCP FIN)."""
    parts = []
    while True:
        chunk = sock.recv(BUFFER_SIZE)
        if not chunk:
            break
        parts.append(chunk)
    return b"".join(parts)


def _send_command(command: str, tunnel: str, config_path: str = None) -> dict:
    token = _load_ipc_token()
    if not token:
        return {"status": "error", "state": "Stopped",
                "message": "IPC token unavailable — VPN service not installed"}

    payload = {
        "token":   token,
        "command": command,
        "tunnel":  tunnel,
    }
    if config_path:
        payload["config_path"] = config_path

    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((SERVICE_HOST, SERVICE_PORT))
        sock.sendall(json.dumps(payload).encode("utf-8"))
        data = _recv_response(sock)
        return json.loads(data.decode("utf-8"))
    except ConnectionRefusedError:
        return {"status": "error", "state": "Stopped", "message": "Service not running"}
    except socket.timeout:
        return {"status": "error", "state": "Stopped", "message": "Service timed out"}
    except Exception as e:
        logger.error(f"IPC error: {e}")
        return {"status": "error", "state": "Stopped", "message": str(e)}
    finally:
        if sock:
            try:
                sock.close()
            except Exception:
                pass


# ---- Active tunnel (read config file directly) ----

def _get_active_tunnel() -> tuple:
    """Returns (tunnel_name, config_path) or (None, None)."""
    try:
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE, "r") as f:
                data = json.load(f)
                name = data.get("active_config")
                if name:
                    path = os.path.join(WG_DIR, f"{name}.conf")
                    return name, path

        # Fallback: first .conf found in wireguard dir
        if os.path.exists(WG_DIR):
            confs = [f for f in os.listdir(WG_DIR) if f.endswith(".conf")]
            if confs:
                name = confs[0].replace(".conf", "")
                return name, os.path.join(WG_DIR, confs[0])

    except Exception as e:
        logger.error(f"Failed to get active tunnel: {e}")

    return None, None


# ---- Icon builder ----

def _build_icon(state: str) -> Image.Image:
    """App icon with a colored status dot in the bottom-right corner."""
    size = 64

    if os.path.exists(ICON_PATH):
        base = Image.open(ICON_PATH).convert("RGBA")
        base = base.resize((size, size), Image.LANCZOS)
    else:
        # Fallback: plain blue square
        base = Image.new("RGBA", (size, size), (60, 120, 200, 255))

    draw = ImageDraw.Draw(base)

    # Dot position — bottom-right corner
    dot_r  = 10
    margin = 2
    x0 = size - (dot_r * 2) - margin
    y0 = size - (dot_r * 2) - margin
    x1 = size - margin
    y1 = size - margin

    # White ring so dot is visible on any background
    ring = 2
    draw.ellipse(
        [x0 - ring, y0 - ring, x1 + ring, y1 + ring],
        fill=(255, 255, 255, 255),
    )

    # Colored dot
    draw.ellipse(
        [x0, y0, x1, y1],
        fill=DOT_COLORS.get(state, DOT_COLORS["disconnected"]),
    )

    return base


def _state_from_service(service_state: str) -> str:
    if service_state == "Running":
        return "connected"
    if service_state in ("Starting", "Stopping"):
        return "connecting"
    return "disconnected"


# ---- Tray App ----

class ResistineTray:
    def __init__(self):
        self._icon       = None
        self._tunnel     = None
        self._config_path = None
        self._state      = "disconnected"
        self._lock       = threading.Lock()

    def _refresh_status(self):
        tunnel, config_path = _get_active_tunnel()
        if not tunnel:
            return

        try:
            result    = _send_command("status", tunnel)
            new_state = _state_from_service(result.get("state", "Stopped"))

            with self._lock:
                changed           = new_state != self._state
                self._tunnel      = tunnel
                self._config_path = config_path
                self._state       = new_state

            if self._icon:
                self._icon.title = self._title()
                self._icon.update_menu()
                if changed:
                    self._icon.icon = _build_icon(new_state)
                    logger.warning(f"VPN state changed: {new_state}")

        except Exception as e:
            logger.error(f"Status poll failed: {e}")

    def _poll_loop(self):
        while True:
            self._refresh_status()
            time.sleep(POLL_INTERVAL)

    def _title(self) -> str:
        return {
            "connected":    "Resistine VPN — Connected",
            "disconnected": "Resistine VPN — Disconnected",
            "connecting":   "Resistine VPN — Connecting...",
        }.get(self._state, "Resistine VPN")

    # ---- Actions ----

    def on_connect(self, icon, item):
        with self._lock:
            tunnel      = self._tunnel
            config_path = self._config_path
        if not tunnel:
            return

        # Immediate yellow feedback
        with self._lock:
            self._state = "connecting"
        if self._icon:
            self._icon.icon  = _build_icon("connecting")
            self._icon.title = self._title()
            self._icon.update_menu()

        result = _send_command("connect", tunnel, config_path)
        if result.get("status") != "ok" and \
           result.get("state") not in ("Starting", "Running"):
            logger.error(f"Connect failed: {result.get('message', '')}")

        self._refresh_status()
    
    def on_disconnect(self, icon, item):
        with self._lock:
            if self._state == "disconnected":
                return
            tunnel = self._tunnel
        if not tunnel:
            return
        result = _send_command("disconnect", tunnel)
        if result.get("status") != "ok":
            logger.error(f"Disconnect failed: {result.get('message', '')}")
        self._refresh_status()

    def on_open_app(self, icon, item):
        """Open the main Resistine window — focus existing instance or launch new."""
        # Check if main.py is already running by looking for its process
        try:
            import ctypes
            import ctypes.wintypes

            # Find window by title prefix — main.py sets the window title to "Resistine"
            hwnd = ctypes.windll.user32.FindWindowW(None, "Resistine")
            if hwnd:
                # Window exists — bring it to foreground
                SW_RESTORE = 9
                ctypes.windll.user32.ShowWindow(hwnd, SW_RESTORE)
                ctypes.windll.user32.SetForegroundWindow(hwnd)
                return
        except Exception:
            pass

        # No existing window found — launch a new instance
        subprocess.Popen(
            [sys.executable, MAIN_SCRIPT],
            cwd=BASE_DIR,
        )

    def on_quit(self, icon, item):
        icon.stop()

    # ---- Menu ----

    def _build_menu(self):
        with self._lock:
            state = self._state

        is_connected  = state == "connected"
        is_connecting = state == "connecting"

        status_label = {
            "connected":    "● Connected",
            "disconnected": "● Disconnected",
            "connecting":   "● Connecting...",
        }.get(state, "● Unknown")

        return pystray.Menu(
            item(status_label,     None,               enabled=False),
            pystray.Menu.SEPARATOR,
            item("Connect",        self.on_connect,
                 enabled=not is_connected and not is_connecting),
            item("Disconnect",     self.on_disconnect, enabled=is_connected),
            pystray.Menu.SEPARATOR,
            item("Open Resistine", self.on_open_app, default=True),
            item("Quit",           self.on_quit),
        )

    # ---- Run ----

    def run(self):
        tunnel, config_path = _get_active_tunnel()
        if tunnel:
            try:
                result            = _send_command("status", tunnel)
                self._state       = _state_from_service(result.get("state", "Stopped"))
                self._tunnel      = tunnel
                self._config_path = config_path
            except Exception:
                self._state = "disconnected"

        self._icon = pystray.Icon(
            name="ResistineVPN",
            icon=_build_icon(self._state),
            title=self._title(),
            menu=pystray.Menu(lambda: self._build_menu()),
        )

        threading.Thread(target=self._poll_loop, daemon=True).start()
        self._icon.run()


if __name__ == "__main__":
    ResistineTray().run()