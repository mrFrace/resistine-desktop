"""
Windows Service to manage WireGuard VPN tunnels for Phoenix VPN.
Authors: Merhawi
Copyright (c) Resistine 2025
This service listens for commands from the GUI and manages WireGuard tunnels
accordingly. It also auto-starts a default tunnel if present in ProgramData.
"""

from __future__ import annotations

import win32serviceutil
import win32service
import win32event
import servicemanager
import win32con

import secrets as _secrets
import socket
import threading
import json
import subprocess
import os
import logging
import time
import sys
import shutil


# ---------------- Configuration ----------------

SERVICE_NAME         = "ResistineVPN"
SERVICE_DISPLAY_NAME = "Phoenix VPN Service"
SERVICE_DESCRIPTION  = "Manages WireGuard tunnels for Phoenix VPN"

SERVICE_HOST = "127.0.0.1"
SERVICE_PORT = 51888
RECV_BUFFER  = 65536

ALLOWED_COMMANDS = {
    "status", "connect", "disconnect",
    "start", "stop", "restart", "health"
}

PROGRAMDATA = os.environ.get("PROGRAMDATA", r"C:\ProgramData")
CONFIG_BASE = os.path.join(PROGRAMDATA, "Resistine", "wireguard")

# IPC token — generated once on first service start and shared via ProgramData
# so the GUI client (running as the current user) can authenticate requests.
IPC_TOKEN_FILE = os.path.join(CONFIG_BASE, ".ipc_token")

# Populated by _init_runtime() when the service / CLI actually starts.
# Module import (e.g. by pytest collecting tests on macOS/Linux) must not
# touch the filesystem or create files in %PROGRAMDATA%.
IPC_TOKEN: str = ""


def _restrict_token_acl(token_path: str) -> None:
    """Restrict the IPC token file's ACL on Windows via icacls.

    Grants SYSTEM:F, Administrators:F, and read-only to the current user.
    Disables inheritance so other users cannot read the token. A no-op on
    non-Windows platforms; failures are swallowed so a flaky icacls run
    cannot break the service or GUI.
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
            # Suppress the console window so icacls doesn't flash a cmd
            # window when the service runs in a user session (debug mode).
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except Exception:
        # Best-effort hardening — never fail the caller on ACL issues.
        pass


def _get_or_create_ipc_token() -> str:
    """Return the IPC auth token, generating and persisting it if needed."""
    if os.path.exists(IPC_TOKEN_FILE):
        try:
            with open(IPC_TOKEN_FILE, "r") as fh:
                token = fh.read().strip()
            if len(token) >= 32:
                # Re-apply ACL on every read to heal any inherited perms.
                _restrict_token_acl(IPC_TOKEN_FILE)
                return token
        except OSError:
            pass

    token = _secrets.token_hex(32)
    try:
        os.makedirs(os.path.dirname(IPC_TOKEN_FILE), exist_ok=True)
        with open(IPC_TOKEN_FILE, "w") as fh:
            fh.write(token)
        _restrict_token_acl(IPC_TOKEN_FILE)
    except OSError as e:
        logging.getLogger("ResistineVPN").error("Could not persist IPC token: %s", e)
    return token


def _find_wireguard_exe() -> str:
    """Locate the WireGuard executable, checking both Program Files paths."""
    candidates = [
        r"C:\Program Files\WireGuard\wireguard.exe",
        r"C:\Program Files (x86)\WireGuard\wireguard.exe",
    ]
    for path in candidates:
        if os.path.exists(path):
            return path
    # Fallback to PATH lookup
    found = shutil.which("wireguard")
    if found:
        return found
    # Return the default path so error messages are meaningful
    return candidates[0]


WIREGUARD_EXE = _find_wireguard_exe()


# ---------------- Logging ----------------

def _get_log_file() -> str:
    """
    Use ProgramData if writable (service/admin context).
    Fall back to AppData when running as regular user (debug mode).
    """
    programdata_log = os.path.join(PROGRAMDATA, "Resistine", "vpn_service.log")
    try:
        os.makedirs(os.path.dirname(programdata_log), exist_ok=True)
        with open(programdata_log, "a"):
            pass
        return programdata_log
    except PermissionError:
        appdata_log = os.path.join(
            os.environ.get("APPDATA", ""), "Phoenix", "vpn_service.log"
        )
        os.makedirs(os.path.dirname(appdata_log), exist_ok=True)
        return appdata_log


TRACE = 5
logging.addLevelName(TRACE, "TRACE")


def _trace(self, message, *args, **kwargs):
    if self.isEnabledFor(TRACE):
        self._log(TRACE, message, args, **kwargs)


logging.Logger.trace = _trace

# Populated by _init_runtime(); module import must not touch the filesystem.
LOG_FILE: str = ""
logger = logging.getLogger("ResistineVPN")


def _init_runtime() -> None:
    """Initialize on-disk state (config dir, IPC token, log handlers).

    Called from SvcDoRun() and the __main__ guard — *never* at import time
    so this module remains safe to import on macOS/Linux (e.g. by tests).
    Safe to call multiple times.
    """
    global IPC_TOKEN, LOG_FILE

    try:
        os.makedirs(CONFIG_BASE, exist_ok=True)
    except OSError:
        pass

    if not IPC_TOKEN:
        IPC_TOKEN = _get_or_create_ipc_token()

    if not LOG_FILE:
        LOG_FILE = _get_log_file()
        # Only attach a file handler once.
        if not any(
            isinstance(h, logging.FileHandler)
            and getattr(h, "baseFilename", None) == LOG_FILE
            for h in logger.handlers
        ):
            handler = logging.FileHandler(LOG_FILE)
            handler.setFormatter(
                logging.Formatter(
                    "%(asctime)s | %(levelname)s | %(funcName)s:%(lineno)d | %(message)s",
                ),
            )
            logger.addHandler(handler)
            logger.setLevel(logging.DEBUG)
            logger.info(f"Service module loaded. Logging to: {LOG_FILE}")


# ---------------- Helpers ----------------

def run_cmd(cmd: list, timeout: int = 30) -> subprocess.CompletedProcess:
    return subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=timeout,
        creationflags=subprocess.CREATE_NO_WINDOW,
    )


def wg_service_name(tunnel: str) -> str:
    return f"WireGuardTunnel${tunnel}"


def _flush_dns_cache() -> None:
    """Flush the Windows DNS resolver cache after tunnel state changes."""
    def _flush():
        try:
            subprocess.run(
                ["ipconfig", "/flushdns"],
                capture_output=True, timeout=10,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
            logger.debug("DNS cache flushed")
        except Exception:
            logger.debug("DNS cache flush failed (non-critical)")
    threading.Thread(target=_flush, daemon=True).start()


# ---------------- Config discovery ----------------

def find_config(tunnel: str, config_path: str = None) -> str | None:
    """
    Find tunnel config file.
    Priority:
    1. Explicit path from GUI (user AppData)
    2. ProgramData fallback
    """
    if config_path and os.path.exists(config_path):
        logger.info(f"Using provided config: {config_path}")
        return config_path

    fallback = os.path.join(CONFIG_BASE, f"{tunnel}.conf")
    if os.path.exists(fallback):
        logger.info(f"Using ProgramData config: {fallback}")
        return fallback

    logger.warning(f"No config found for tunnel '{tunnel}'")
    return None


def find_default_tunnel() -> str | None:
    """
    Discover default tunnel from ProgramData.
    Prefers 'phoenix' (then the pre-rebrand 'resistine'), otherwise first .conf found.
    """
    if not os.path.exists(CONFIG_BASE):
        return None

    confs = [f for f in os.listdir(CONFIG_BASE) if f.endswith(".conf")]
    if not confs:
        logger.warning(f"No .conf files in {CONFIG_BASE}")
        return None

    for preferred in ("phoenix", "resistine"):
        if f"{preferred}.conf" in confs:
            return preferred

    name = confs[0].replace(".conf", "")
    logger.info(f"Auto-detected tunnel: {name}")
    return name


# ---------------- WireGuard helpers ----------------

def uninstall_tunnel(tunnel: str):
    svc = wg_service_name(tunnel)
    result = run_cmd(["sc", "query", svc])
    if "1060" in (result.stdout + result.stderr):
        return True, "Not installed"

    run_cmd(["sc", "stop", svc])
    time.sleep(1)

    result = run_cmd([WIREGUARD_EXE, "/uninstalltunnelservice", tunnel])
    logger.info(f"Uninstall '{tunnel}': returncode={result.returncode}")
    time.sleep(1)
    return True, "Uninstalled"


def _ensure_system_config(tunnel: str, source_conf: str) -> str:
    """
    Copy the config to ProgramData so the SYSTEM-level WireGuard tunnel
    service can read it, regardless of where the GUI stored the original.

    WireGuard's /installtunnelservice registers a service that runs as
    SYSTEM.  SYSTEM has no access to any user's %APPDATA%, so if the .conf
    lives there the tunnel silently fails to start.  Copying to ProgramData
    (CONFIG_BASE) fixes this while keeping the user's copy untouched.

    Returns the path that should be passed to /installtunnelservice.
    """
    system_conf = os.path.join(CONFIG_BASE, f"{tunnel}.conf")

    # Already in ProgramData — nothing to do
    if os.path.abspath(source_conf) == os.path.abspath(system_conf):
        return system_conf

    try:
        os.makedirs(CONFIG_BASE, exist_ok=True)
        shutil.copy2(source_conf, system_conf)
        logger.info(
            f"Copied config for '{tunnel}' to ProgramData: {system_conf}"
        )
    except Exception as e:
        # Non-fatal: try the original path and let WireGuard report the error
        logger.warning(
            f"Could not copy config to ProgramData, using original path. "
            f"Error: {e}"
        )
        return source_conf

    return system_conf


def install_tunnel(tunnel: str, config_path: str = None):
    conf = find_config(tunnel, config_path)
    if not conf:
        return False, f"Config not found for tunnel: {tunnel}"

    if not os.path.exists(WIREGUARD_EXE):
        return False, f"WireGuard not installed at {WIREGUARD_EXE}"

    # FIX (VPN not starting): WireGuard tunnel services run as SYSTEM and
    # cannot read files from a user's %APPDATA%.  Always install from a
    # ProgramData copy so the SYSTEM account can access the config.
    conf = _ensure_system_config(tunnel, conf)

    uninstall_tunnel(tunnel)

    result = run_cmd([WIREGUARD_EXE, "/installtunnelservice", conf])
    logger.debug(f"Install '{tunnel}': returncode={result.returncode}")
    logger.debug(f"stdout: {result.stdout.strip()}")
    logger.debug(f"stderr: {result.stderr.strip()}")

    if "already installed" in result.stderr.lower():
        return True, "Already installed"

    if result.returncode == 0:
        logger.info(f"Tunnel '{tunnel}' installed")
        time.sleep(1)
        return True, "Installed"

    logger.error(f"Failed to install '{tunnel}': {result.stderr}")
    return False, result.stderr.strip()


def start_tunnel(tunnel: str):
    svc = wg_service_name(tunnel)
    logger.info(f"Starting: {svc}")

    result = run_cmd(["sc", "start", svc])
    combined = (result.stdout + result.stderr).lower()

    if "already running" in combined:
        return True, "Already running"
    if "start_pending" in combined or result.returncode == 1056:
        return True, "Starting"
    if result.returncode == 0:
        return True, "Started"

    logger.error(f"Failed to start '{tunnel}': {result.stderr}")
    return False, result.stderr.strip()


def stop_tunnel(tunnel: str):
    result = run_cmd(["sc", "stop", wg_service_name(tunnel)])
    combined = (result.stdout + result.stderr).lower()

    if "not started" in combined or "1062" in combined:
        return True, "Already stopped"

    return result.returncode == 0, combined.strip()


def status_tunnel(tunnel: str) -> str:
    result = run_cmd(["sc", "query", wg_service_name(tunnel)])
    out = (result.stdout + result.stderr).lower()

    if "1060" in out or "does not exist" in out:
        return "Not Installed"
    if "running" in out:
        return "Running"
    if "start_pending" in out:
        return "Starting"
    if "stop_pending" in out:
        return "Stopping"
    if "stopped" in out:
        return "Stopped"

    logger.warning(f"Unknown status for '{tunnel}': {out.strip()}")
    return "Unknown"


# ---------------- IPC Handler ----------------

def handle_request(request: dict) -> dict:
    if request.get("token") != IPC_TOKEN:
        return {"status": "error", "message": "Unauthorized"}

    cmd         = request.get("command")
    tunnel      = request.get("tunnel")
    config_path = request.get("config_path")

    if cmd not in ALLOWED_COMMANDS:
        return {"status": "error", "message": f"Invalid command: {cmd}"}

    if not tunnel:
        return {"status": "error", "message": "Missing tunnel"}

    try:
        if cmd == "status":
            return {"status": "ok", "state": status_tunnel(tunnel)}

        if cmd == "connect":
            state = status_tunnel(tunnel)
            if state == "Running":
                return {"status": "ok", "state": "Running", "message": "Already running"}

            # Always reinstall before starting — even if the tunnel service
            # exists in "Stopped" state. A stopped WireGuardTunnel$ service
            # means it previously failed (often exit code 2 = config not found
            # because SYSTEM couldn't read AppData). Reinstalling copies the
            # config to ProgramData via _ensure_system_config so SYSTEM can
            # access it. Skipping install for "Stopped" is the root cause of
            # the default/first config silently failing to connect.
            ok, msg = install_tunnel(tunnel, config_path)
            if not ok:
                return {"status": "error", "state": status_tunnel(tunnel), "message": msg}

            ok, msg = start_tunnel(tunnel)
            actual_state = status_tunnel(tunnel)
            if actual_state in ("Running", "Starting"):
                _flush_dns_cache()
                return {"status": "ok", "state": actual_state, "message": msg}
            return {"status": "error", "state": actual_state, "message": msg}

        if cmd == "disconnect":
            state = status_tunnel(tunnel)
            if state in ("Stopped", "Not Installed"):
                return {"status": "ok", "state": "Stopped", "message": "Already stopped"}
            ok, msg = stop_tunnel(tunnel)
            actual_state = status_tunnel(tunnel)
            if ok:
                _flush_dns_cache()
            return {"status": "ok" if ok else "error", "state": actual_state, "message": msg}

        if cmd == "start":
            ok, msg = start_tunnel(tunnel)
            return {"status": "ok" if ok else "error", "message": msg}

        if cmd == "stop":
            ok, msg = stop_tunnel(tunnel)
            return {"status": "ok" if ok else "error", "message": msg}

        if cmd == "restart":
            stop_tunnel(tunnel)
            time.sleep(1)
            ok, msg = start_tunnel(tunnel)
            actual_state = status_tunnel(tunnel)
            return {"status": "ok" if ok else "error", "state": actual_state, "message": "Restarted"}

        if cmd == "health":
            return {
                "status":    "ok",
                "service":   "running",
                "socket":    "listening",
                "wireguard": status_tunnel(tunnel),
            }

    except Exception as e:
        logger.exception(f"Error handling '{cmd}': {e}")
        return {"status": "error", "message": str(e)}

    return {"status": "error", "message": "Unhandled command"}


# ---------------- Socket Server ----------------

def _handle_connection(conn: socket.socket) -> None:
    """Handle a single IPC connection in its own thread."""
    try:
        data = conn.recv(RECV_BUFFER)
        if not data:
            return
        request = json.loads(data.decode("utf-8"))
        response = handle_request(request)
        conn.sendall(json.dumps(response).encode("utf-8"))
    except Exception as e:
        logger.error(f"Request error: {e}")
        try:
            conn.sendall(
                json.dumps({"status": "error", "message": str(e)}).encode("utf-8")
            )
        except Exception:
            pass
    finally:
        conn.close()


def socket_server(stop_event):
    servicemanager.LogInfoMsg("IPC socket thread starting")
    time.sleep(0.2)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        sock.bind((SERVICE_HOST, SERVICE_PORT))
        sock.listen(5)
        sock.settimeout(1.0)
        servicemanager.LogInfoMsg(f"IPC listening on {SERVICE_HOST}:{SERVICE_PORT}")
    except Exception as e:
        servicemanager.LogErrorMsg(f"Socket bind failed: {e}")
        logger.error(f"Socket bind failed: {e}")
        return

    while win32event.WaitForSingleObject(stop_event, 0) != win32con.WAIT_OBJECT_0:
        try:
            conn, _ = sock.accept()
        except socket.timeout:
            continue
        except Exception as e:
            logger.error(f"Accept error: {e}")
            break

        threading.Thread(
            target=_handle_connection, args=(conn,), daemon=True
        ).start()

    sock.close()
    servicemanager.LogInfoMsg("IPC socket thread stopped")


def run_socket_server(stop_event):
    try:
        socket_server(stop_event)
    except Exception as e:
        servicemanager.LogErrorMsg(f"Socket server crashed: {repr(e)}")
        logger.exception("Socket server crashed")


# ---------------- Windows Service ----------------

class ResistineVPNService(win32serviceutil.ServiceFramework):
    _svc_name_         = SERVICE_NAME
    _svc_display_name_ = SERVICE_DISPLAY_NAME
    _svc_description_  = SERVICE_DESCRIPTION

    def __init__(self, args):
        win32serviceutil.ServiceFramework.__init__(self, args)
        self.hWaitStop = win32event.CreateEvent(None, 0, 0, None)

    def SvcStop(self):
        servicemanager.LogInfoMsg("ResistineVPN stopping")
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        win32event.SetEvent(self.hWaitStop)

    def SvcDoRun(self):
        # Defer all filesystem / token / log-handler setup until the service
        # actually runs. Keeping it out of module import means the module is
        # safe to import on non-Windows platforms (and in tests).
        _init_runtime()

        servicemanager.LogInfoMsg("ResistineVPN starting")

        # Report RUNNING immediately — SCM requires response within 30s
        self.ReportServiceStatus(win32service.SERVICE_RUNNING)
        servicemanager.LogInfoMsg("ResistineVPN reported RUNNING")

        # Start IPC socket in background
        threading.Thread(
            target=run_socket_server,
            args=(self.hWaitStop,),
            daemon=True,
        ).start()
        servicemanager.LogInfoMsg("IPC thread started")

        # Block until stop signal
        win32event.WaitForSingleObject(self.hWaitStop, win32event.INFINITE)

        # Graceful shutdown
        servicemanager.LogInfoMsg("Shutting down")
        try:
            tunnel = find_default_tunnel()
            if tunnel:
                stop_tunnel(tunnel)
        except Exception as e:
            servicemanager.LogWarningMsg(f"Shutdown error: {e}")

        servicemanager.LogInfoMsg("ResistineVPN stopped")


if __name__ == "__main__":
    _init_runtime()
    win32serviceutil.HandleCommandLine(ResistineVPNService)