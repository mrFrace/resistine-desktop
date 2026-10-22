"""ClamAV backend — shared (platform-agnostic) logic.

Binary discovery dispatch, config generation, daemon management,
scanning (socket + fallback), quarantine, whitelist, and signature DB.

Platform-specific functions (binary paths, daemon registration, FDA checks,
etc.) live in clamav_platform_{darwin,linux,windows}.py and are accessed
via the _get_platform() late-import helper.

Author: Resistine Team
Copyright (c) Resistine 2025
Licensed under the GNU General Public License v2 or later
"""
from __future__ import annotations

import glob
import json
import os
import platform
import re
import shutil
import socket
import struct
import subprocess
import tempfile
import threading
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed

from utils.logger import logger
from utils.settings import get_config_dir

# ── Timeout constants ─────────────────────────────────────
SOCKET_PING_TIMEOUT = 2          # seconds: zPING handshake timeout
SOCKET_SCAN_TIMEOUT = 120        # seconds: per-file CONTSCAN timeout
CLAMD_START_TIMEOUT_POLLS = 60   # iterations × 0.5s = 30s max wait for clamd
CLAMD_STOP_TIMEOUT_POLLS = 10    # iterations × 0.5s = 5s max wait for clamd stop
SCAN_CANCEL_WAIT_TIMEOUT = 10    # seconds: wait for cancelled clamscan to exit
SCAN_PROC_WAIT_TIMEOUT = 30      # seconds: wait for clamscan to finish
SCAN_KILL_WAIT_TIMEOUT = 5       # seconds: wait after killing clamscan
GH_API_FETCH_TIMEOUT = 15        # seconds: CVD cert auto-fetch from GitHub

# ── Paths ────────────────────────────────────────────────

_CLAMAV_DATA_DIR = os.path.join(get_config_dir(), "clamav")
_DB_DIR = os.path.join(_CLAMAV_DATA_DIR, "db")
_LOG_DIR = os.path.join(_CLAMAV_DATA_DIR, "log")
_RUN_DIR = os.path.join(_CLAMAV_DATA_DIR, "run")
_QUARANTINE_DIR = os.path.join(_CLAMAV_DATA_DIR, "quarantine")
_CLAMD_CONF = os.path.join(_CLAMAV_DATA_DIR, "clamd.conf")
_FRESHCLAM_CONF = os.path.join(_CLAMAV_DATA_DIR, "freshclam.conf")
_CLAMD_SOCKET = os.path.join(_RUN_DIR, "clamd.sock")
_CLAMD_PID = os.path.join(_RUN_DIR, "clamd.pid")
_WHITELIST_FILE = os.path.join(_CLAMAV_DATA_DIR, "whitelist.txt")
_EXCLUSIONS_FILE = os.path.join(_CLAMAV_DATA_DIR, "exclusions.json")


def _ensure_dirs():
    for d in (_DB_DIR, _LOG_DIR, _RUN_DIR, _QUARANTINE_DIR):
        os.makedirs(d, exist_ok=True)


def _dir_has_db(db_dir: str) -> bool:
    """Return True if *db_dir* contains at least one CVD/CLD file."""
    return bool(
        glob.glob(os.path.join(db_dir, "*.cvd"))
        or glob.glob(os.path.join(db_dir, "*.cld"))
    )


def _effective_db_dir(*, writable: bool = False) -> str:
    """Return the best DB directory: system if available, else user.

    When *writable* is True (for freshclam writes), requires write access.
    When False (for reading/checking), prefers whichever directory actually
    contains signature files — avoids returning an empty system dir when
    the user dir has valid databases (e.g. after reinstall with leftover
    system dirs).
    """
    plat = _get_platform()
    if writable:
        sys_db = plat.system_db_dir_writable()
        return sys_db if sys_db else _DB_DIR

    # For reading: prefer whichever directory has actual DB files.
    sys_db = plat.system_db_dir()
    if sys_db:
        if _dir_has_db(sys_db):
            return sys_db
        # System dir exists but empty — fall back to user dir if it has files
        if _dir_has_db(_DB_DIR):
            return _DB_DIR
        return sys_db
    return _DB_DIR


# ── Platform dispatch ─────────────────────────────────────


def _get_platform():
    """Late-import the active platform module to avoid circular imports."""
    import platform as _platform

    system = _platform.system()
    if system == "Darwin":
        from plugins.antivirus import clamav_platform_darwin as mod
    elif system == "Linux":
        from plugins.antivirus import clamav_platform_linux as mod
    elif system == "Windows":
        from plugins.antivirus import defender_windows as mod
    else:
        raise RuntimeError(f"Unsupported platform: {system}")
    return mod


# ── Engine identity ──────────────────────────────────────


def engine_name() -> str:
    """Return the human-readable name of the antivirus engine."""
    return "ClamAV"


# ── Binary discovery (delegates to platform) ──────────────


def get_binaries() -> dict[str, str | None]:
    """Return dict of binary name → path (or None)."""
    plat = _get_platform()
    names = ("clamscan", "clamdscan", "clamd", "freshclam", "clamonacc")
    return {n: plat.find_binary(n) for n in names}


def is_available() -> bool:
    """True if at least clamscan is found."""
    plat = _get_platform()
    return plat.find_binary("clamscan") is not None


def is_clamav_installed() -> bool:
    """Return True if at least the core clamscan binary can be found."""
    plat = _get_platform()
    return plat.find_binary("clamscan") is not None


# ── Config generation ────────────────────────────────────


def _write_clamd_conf():
    _ensure_dirs()
    db_dir = _effective_db_dir()
    conf = f"""\
# Auto-generated by Phoenix — do not edit manually
LocalSocket {_CLAMD_SOCKET}
PidFile {_CLAMD_PID}
DatabaseDirectory {db_dir}
LogFile {os.path.join(_LOG_DIR, "clamd.log")}
LogFileMaxSize 5M
LogTime yes
LogVerbose yes
LogClean yes
MaxThreads 8
TemporaryDirectory {tempfile.gettempdir()}
MaxDirectoryRecursion 20
FollowDirectorySymlinks yes
ExcludePath ^/proc
ExcludePath ^/sys
ExcludePath ^/dev
"""
    with open(_CLAMD_CONF, "w") as f:
        f.write(conf)


def _write_freshclam_conf():
    _ensure_dirs()
    plat = _get_platform()
    db_dir = _effective_db_dir(writable=True)
    conf = f"""\
# Auto-generated by Phoenix — do not edit manually
DatabaseDirectory {db_dir}
UpdateLogFile {os.path.join(_LOG_DIR, "freshclam.log")}
LogFileMaxSize 2M
LogTime yes
DatabaseMirror database.clamav.net
NotifyClamd {_CLAMD_CONF}
"""
    # Override the hardcoded CVD certs path baked into the CI-built binary.
    certs_dir = plat.find_certs_dir()
    if certs_dir:
        conf += f"CVDCertsDirectory {certs_dir}\n"
    else:
        logger.warning(
            "ClamAV: CVD certs directory not found — freshclam will fail "
            "signature verification. Run "
            "./scripts/build/download-clamav-artifacts.sh or copy "
            "clamav.crt into scripts/build/clamav-artifacts/certs/",
        )

    with open(_FRESHCLAM_CONF, "w") as f:
        f.write(conf)


def ensure_config():
    """Create/refresh config files and directories.

    Always regenerates configs because they are auto-generated from current
    runtime paths (e.g. CVDCertsDirectory depends on where binaries are found).
    """
    _ensure_dirs()
    _write_clamd_conf()
    _write_freshclam_conf()


# ── Signature database info ──────────────────────────────


def get_db_info() -> dict[str, str]:
    """Return signature count and last-checked date from local DB files.

    "Last updated" answers the user's question "when did MY computer last
    pull an update", so it reports the newest DB *file mtime* \u2014 i.e. the most
    recent successful freshclam write. freshclam rewrites daily.(cld|cvd) on
    every successful check, so the newest mtime always tracks the real
    download, and taking the *max* across files sidesteps the stale base-.cvd
    problem (an untouched main.cvd just has an older mtime than daily, so it
    never wins). This is deliberately NOT the CVD header build date, which is
    when ClamAV *published* the sigs (UTC, hours-to-days before download) and
    reads as confusingly off even when everything is working.
    """
    info: dict[str, str] = {"signatures": "\u2014", "last_updated": "\u2014"}

    db_dir = _effective_db_dir()
    cvd_files = glob.glob(os.path.join(db_dir, "*.cvd"))
    cvd_files += glob.glob(os.path.join(db_dir, "*.cld"))

    if not cvd_files:
        return info

    total_sigs = 0
    latest_mtime = 0.0  # newest file mtime = most recent successful update

    for cvd in cvd_files:
        try:
            with open(cvd, "rb") as f:
                header = f.read(512).decode("ascii", errors="replace")
            # CVD header: ClamAV-VDB:DD Mon YYYY HH-MM +ZZZZ:ver:sigs:...
            parts = header.split(":")
            if len(parts) >= 4:
                total_sigs += int(parts[3])
        except (OSError, ValueError):
            pass
        try:
            mtime = os.path.getmtime(cvd)
        except OSError:
            continue
        if mtime > latest_mtime:
            latest_mtime = mtime

    if total_sigs > 0:
        info["signatures"] = f"{total_sigs:,}"
    if latest_mtime > 0:
        info["last_updated"] = time.strftime(
            "%Y-%m-%d %H:%M", time.localtime(latest_mtime),
        )

    return info


def has_database() -> bool:
    """True if at least one signature database file exists."""
    db_dir = _effective_db_dir()
    return bool(
        glob.glob(os.path.join(db_dir, "*.cvd"))
        or glob.glob(os.path.join(db_dir, "*.cld"))
    )


# ── Freshclam (signature updates) ────────────────────────


def _try_fetch_cvd_cert() -> str | None:
    """Attempt to auto-download clamav.crt from GitHub into dev artifacts.

    Returns the certs directory path on success, None on failure.
    """
    import base64

    project_root = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
    target_dir = os.path.join(
        project_root, "scripts", "build", "clamav-artifacts", "certs",
    )
    target_cert = os.path.join(target_dir, "clamav.crt")
    if os.path.isfile(target_cert):
        return target_dir

    repo = "Resistine/ClamAV-Mac"
    remote_paths = (
        "certs/clamav.crt",
        "etc/certs/clamav.crt",
        "install/etc/certs/clamav.crt",
    )
    for remote_path in remote_paths:
        try:
            result = subprocess.run(
                [
                    "gh", "api", f"repos/{repo}/contents/{remote_path}",
                    "--jq", ".content",
                ],
                capture_output=True, text=True, timeout=GH_API_FETCH_TIMEOUT,
            )
            if result.returncode != 0 or not result.stdout.strip():
                continue
            cert_data = base64.b64decode(result.stdout.strip())
            if not cert_data:
                continue
            os.makedirs(target_dir, exist_ok=True)
            with open(target_cert, "wb") as f:
                f.write(cert_data)
            logger.info(
                f"ClamAV: auto-fetched CVD cert from {repo} ({remote_path})",
            )
            return target_dir
        except (subprocess.TimeoutExpired, FileNotFoundError, Exception):
            continue
    return None


def run_freshclam(
    on_line=None,
) -> tuple[bool, str]:
    """Run freshclam to update signature databases.

    Returns (success, summary_message).
    """
    plat = _get_platform()
    binary = plat.find_binary("freshclam")
    if not binary:
        return False, "freshclam binary not found."

    # Ensure certs exist before running freshclam — the CI-built binary has
    # a hardcoded certs path that won't exist on other machines, and
    # libfreshclam init crashes before reading the config or env override.
    certs_dir = plat.find_certs_dir()
    if not certs_dir:
        logger.info("ClamAV: CVD cert not found locally, attempting auto-fetch")
        fetched = _try_fetch_cvd_cert()
        if fetched:
            certs_dir = fetched
        else:
            return False, (
                "CVD certificate (clamav.crt) not found — freshclam cannot "
                "verify signatures without it. Run "
                "./scripts/build/download-clamav-artifacts.sh to fetch it, "
                "or copy clamav.crt from a ClamAV source tree into "
                "scripts/build/clamav-artifacts/certs/"
            )

    ensure_config()
    cmd = [binary, "--config-file", _FRESHCLAM_CONF, "--stdout"]
    logger.info(f"ClamAV: running freshclam — {' '.join(cmd)}")

    try:
        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
            env=plat.clamav_env(),
        )
        lines = []
        for line in proc.stdout:
            lines.append(line.rstrip())
            if on_line:
                on_line(line.rstrip())
        proc.wait()
        output = "\n".join(lines)

        if proc.returncode == 0:
            return True, "Signatures updated successfully."
        # Check for certs error before "up to date" — certs failure is
        # fatal even if some DBs reported up-to-date before the crash.
        if "invalid certs directory" in output.lower():
            return False, (
                "CVD certificate verification failed — clamav.crt is "
                "missing. Re-run ./scripts/build/download-clamav-artifacts.sh "
                "(it will fetch the cert automatically), or copy clamav.crt "
                "from a ClamAV source tree into "
                "scripts/build/clamav-artifacts/certs/"
            )
        if "up to date" in output.lower():
            return True, "Signatures already up to date."
        return False, f"freshclam exited with code {proc.returncode}"
    except Exception as exc:
        return False, str(exc)


# ── Clamd daemon ──────────────────────────────────────────


def _clamd_pid_alive() -> bool:
    if not os.path.exists(_CLAMD_PID):
        return False
    try:
        with open(_CLAMD_PID) as f:
            pid = int(f.read().strip())
        os.kill(pid, 0)
        return True
    except (OSError, ValueError):
        return False


def _ping_socket(sock_path: str) -> bool:
    """Send zPING to a clamd Unix socket and return True on PONG."""
    if not os.path.exists(sock_path):
        return False
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.settimeout(SOCKET_PING_TIMEOUT)
            s.connect(sock_path)
            s.sendall(b"zPING\0")
            return b"PONG" in s.recv(32)
    except (OSError, ConnectionRefusedError):
        return False


def _active_clamd_socket() -> str | None:
    """Return the socket path of a running clamd, or None.

    Checks the per-user socket first, then the system socket.
    """
    if _ping_socket(_CLAMD_SOCKET):
        return _CLAMD_SOCKET
    plat = _get_platform()
    system_sock = plat.system_clamd_socket_path()
    if system_sock and _ping_socket(system_sock):
        return system_sock
    return None


def is_clamd_running() -> bool:
    """Check if clamd is responsive via its socket."""
    return _active_clamd_socket() is not None


# ── Direct socket scanning ────────────────────────────────

_SKIP_DIRS = frozenset({".git", ".hg", ".svn", "node_modules", "__pycache__"})
# Windows system directories that should never be scanned — they contain
# millions of OS files, are permission-locked, and slow walks to a crawl.
_SKIP_DIRS_WINDOWS = frozenset({
    "$Recycle.Bin", "System Volume Information", "$WinREAgent",
    "Recovery", "PerfLogs", "Windows", "$SysReset",
}) if platform.system() == "Windows" else frozenset()
_PARALLEL_WORKERS = 6


def _instream_socket(sock_path: str, file_path: str) -> str:
    """Stream file bytes to clamd via INSTREAM; return a CONTSCAN-style response.

    Used as a fallback when clamd can't open the file directly (e.g. Ubuntu
    home dirs with 750 permissions blocking the clamav system user).
    Phoenix opens the file as the current user and pipes bytes over the
    socket, so clamd never needs filesystem access to the path.
    """
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.settimeout(SOCKET_SCAN_TIMEOUT)
        s.connect(sock_path)
        s.sendall(b"nINSTREAM\n")
        try:
            with open(file_path, "rb") as f:
                while True:
                    chunk = f.read(4096)
                    if not chunk:
                        break
                    s.sendall(struct.pack("!I", len(chunk)) + chunk)
        except OSError as exc:
            return f"{file_path}: {exc}. ERROR"
        s.sendall(b"\x00\x00\x00\x00")
        buf = b""
        while True:
            data = s.recv(4096)
            if not data:
                break
            buf += data
            if b"\n" in buf:
                break
    response = buf.decode(errors="replace").strip()
    # Normalize "stream: ..." → "{file_path}: ..." to match CONTSCAN format
    return response.replace("stream:", f"{file_path}:", 1)


def _contscan_socket(sock_path: str, file_path: str) -> str:
    """Send zCONTSCAN for one file to clamd; return the response line.

    Falls back to INSTREAM if clamd can't access the path directly
    (e.g. Ubuntu home dirs with 750 permissions).
    """
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.settimeout(SOCKET_SCAN_TIMEOUT)
        s.connect(sock_path)
        s.sendall(f"zCONTSCAN {file_path}\0".encode())
        buf = b""
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            buf += chunk
            if b"\0" in buf:
                break
        response = buf.decode(errors="replace").strip("\0").strip()

    if "Permission denied" in response or "File path check failure" in response:
        return _instream_socket(sock_path, file_path)
    return response


def _walk_files(
    target: str,
    whitelist: set[str],
    excluded_ext: frozenset[str] = frozenset(),
    max_size_bytes: int = 0,
    cancel: "threading.Event | None" = None,
):
    """Yield scannable file paths under *target*.

    Both *target* and *whitelist* entries are resolved via realpath so
    symlinks and non-canonical paths are matched consistently.
    Optionally filters by file extension and size.
    """
    resolved_wl = {os.path.realpath(p) for p in whitelist}
    resolved_target = os.path.realpath(target)

    # Block the entire walk when the target itself is whitelisted.
    if resolved_target in resolved_wl or any(
        resolved_target.startswith(w + os.sep) for w in resolved_wl
    ):
        return

    skip = _SKIP_DIRS | _SKIP_DIRS_WINDOWS
    for root, dirs, files in os.walk(target):
        if cancel and cancel.is_set():
            return
        dirs[:] = [
            d for d in dirs
            if d not in skip
            and os.path.realpath(os.path.join(root, d)) not in resolved_wl
        ]
        for fname in files:
            fpath = os.path.join(root, fname)
            if os.path.islink(fpath):
                continue
            if os.path.realpath(fpath) in resolved_wl:
                continue
            if excluded_ext:
                _, ext = os.path.splitext(fname)
                if ext.lower() in excluded_ext:
                    continue
            if max_size_bytes > 0:
                try:
                    if os.path.getsize(fpath) > max_size_bytes:
                        continue
                except OSError:
                    continue
            yield fpath


def _format_duration(elapsed: float) -> str:
    mins, secs = divmod(int(elapsed), 60)
    if mins:
        return f"{elapsed:.3f} sec ({mins} m {secs} s)"
    return f"{elapsed:.3f} sec ({secs} s)"


def _scan_file_socket(
    target: str, sock_path: str, result: dict,
    on_line: Callable | None,
    cancel: "threading.Event | None" = None,
) -> dict:
    """Scan a single file via direct clamd socket connection."""
    if cancel and cancel.is_set():
        result["error"] = "Scan cancelled."
        return result

    logger.info(f"ClamAV: socket scan — {target}")
    start = time.monotonic()
    try:
        response = _contscan_socket(sock_path, target)
    except OSError as exc:
        result["error"] = f"Socket error: {exc}"
        return result

    if on_line:
        on_line(response)

    result["scanned"] = 1
    if "FOUND" in response:
        result["infected"] = 1
        result["infections"] = [response]

    result["duration"] = _format_duration(time.monotonic() - start)
    return result


def _scan_dir_socket(
    target: str, sock_path: str, result: dict,
    on_line: Callable | None,
    cancel: "threading.Event | None",
    on_total: Callable | None = None,
) -> dict:
    """Scan a directory via parallel clamd socket connections."""
    whitelist = set(get_whitelist())
    excl = get_scan_exclusions()
    excluded_ext = frozenset(excl["extensions"])
    max_bytes = excl["max_size_mb"] * 1048576 if excl["max_size_mb"] else 0
    files = list(_walk_files(target, whitelist, excluded_ext, max_bytes, cancel))

    if cancel and cancel.is_set():
        result["error"] = "Scan cancelled."
        return result

    if not files:
        result["duration"] = "0.000 sec (0 s)"
        return result

    if on_total:
        on_total(len(files))

    logger.info(
        f"ClamAV: parallel scan — {len(files)} files, "
        f"{_PARALLEL_WORKERS} workers",
    )

    start = time.monotonic()
    scanned = 0
    infected = 0
    infections: list[str] = []

    skipped = 0
    pool = ThreadPoolExecutor(max_workers=_PARALLEL_WORKERS)
    try:
        futures = {
            pool.submit(_contscan_socket, sock_path, f): f for f in files
        }
        for future in as_completed(futures):
            if cancel and cancel.is_set():
                pool.shutdown(wait=False, cancel_futures=True)
                result["error"] = "Scan cancelled."
                return result

            try:
                response = future.result()
            except OSError as exc:
                skipped += 1
                logger.debug(f"ClamAV: skip {futures[future]}: {exc}")
                continue

            scanned += 1
            if on_line:
                on_line(response)
            if "FOUND" in response:
                infected += 1
                infections.append(response)
    finally:
        pool.shutdown(wait=False, cancel_futures=True)

    if skipped:
        logger.warning(f"ClamAV: {skipped} files skipped due to errors")

    result["scanned"] = scanned
    result["infected"] = infected
    result["infections"] = infections
    result["duration"] = _format_duration(time.monotonic() - start)
    return result


def start_clamd() -> tuple[bool, str]:
    """Start clamd daemon if not already running."""
    if is_clamd_running():
        return True, "clamd already running."

    plat = _get_platform()
    binary = plat.find_binary("clamd")
    if not binary:
        return False, "clamd binary not found."

    if not has_database():
        return False, "No signature database — run Update first."

    ensure_config()

    # Clean stale socket/pid
    for stale in (_CLAMD_SOCKET, _CLAMD_PID):
        if os.path.exists(stale):
            os.unlink(stale)

    cmd = [binary, "--config-file", _CLAMD_CONF]
    logger.info(f"ClamAV: starting clamd — {' '.join(cmd)}")

    try:
        subprocess.Popen(cmd, env=plat.clamav_env())
    except Exception as exc:
        return False, str(exc)

    # Wait for clamd to become responsive (up to 30s).
    # The socket file may appear quickly, but clamd needs additional
    # time to load the ~500 MB signature database before it responds
    # to PING. We check is_clamd_running() which sends a zPING to
    # the socket, so we know it's truly ready for scan requests.
    for _ in range(CLAMD_START_TIMEOUT_POLLS):
        time.sleep(0.5)
        if is_clamd_running():
            return True, "clamd started."
    return False, "clamd did not start in time."


def stop_clamd() -> tuple[bool, str]:
    """Stop clamd daemon."""
    if not _clamd_pid_alive():
        # Clean up stale files
        for f in (_CLAMD_SOCKET, _CLAMD_PID):
            if os.path.exists(f):
                os.unlink(f)
        return True, "clamd not running."

    try:
        with open(_CLAMD_PID) as f:
            pid = int(f.read().strip())
        os.kill(pid, 15)  # SIGTERM
        for _ in range(CLAMD_STOP_TIMEOUT_POLLS):
            time.sleep(0.5)
            if not _clamd_pid_alive():
                break
        return True, "clamd stopped."
    except Exception as exc:
        return False, str(exc)


# ── Scanning ──────────────────────────────────────────────


def scan_path(
    target: str,
    on_line: Callable | None = None,
    cancel: "threading.Event | None" = None,
    proc_ref: "list | None" = None,
    on_total: Callable | None = None,
) -> dict:
    """Scan a file or directory via direct clamd socket when available,
    otherwise falls back to standalone clamscan.

    Returns dict with keys: scanned, infected, infections, duration, error.
    Pass a threading.Event as *cancel* to allow early termination.
    Pass a one-element list as *proc_ref* to receive the subprocess handle
    (only populated when using clamscan fallback).
    """
    plat = _get_platform()
    result = {
        "target": target,
        "scanned": 0,
        "infected": 0,
        "infections": [],
        "duration": "",
        "error": "",
    }

    # If clamd is running, use direct socket scanning (parallel for dirs).
    # Otherwise start clamd, or fall back to standalone clamscan.
    active_socket = _active_clamd_socket()
    if not active_socket and has_database() and plat.find_binary("clamd"):
        logger.info("ClamAV: clamd not running — starting it for faster scan")
        ok, msg = start_clamd()
        if ok:
            active_socket = _active_clamd_socket()
        else:
            logger.warning(f"ClamAV: could not start clamd, falling back: {msg}")

    # Direct socket scanning — parallel for directories, fast for files.
    # Bypasses the clamdscan subprocess entirely.
    if active_socket:
        if os.path.isdir(target):
            return _scan_dir_socket(
                target, active_socket, result, on_line, cancel, on_total,
            )
        if on_total:
            on_total(1)
        return _scan_file_socket(target, active_socket, result, on_line, cancel)

    # Fallback: standalone clamscan (reloads entire signature DB each run)
    binary = plat.find_binary("clamscan")
    if not binary:
        result["error"] = "ClamAV not installed."
        return result

    if not has_database():
        result["error"] = "No signature database — run Update first."
        return result

    cmd = [binary, "--stdout", "--verbose", "-d", _effective_db_dir(), "--recursive"]
    for skip in (".git", ".hg", ".svn", "node_modules", "__pycache__"):
        cmd += ["--exclude-dir", skip]
    # clamscan --exclude-dir takes a regex matched against directory names,
    # --exclude takes a regex matched against file names (not full paths).
    for excluded in get_whitelist():
        escaped = re.escape(os.path.basename(excluded))
        if os.path.isdir(excluded):
            cmd += ["--exclude-dir", f"^{escaped}$"]
        else:
            cmd += ["--exclude", f"^{escaped}$"]

    # Apply scan exclusions (extension filter + max size)
    excl = get_scan_exclusions()
    if excl["extensions"]:
        ext_pattern = "|".join(re.escape(e) for e in excl["extensions"])
        cmd += ["--exclude", f"({ext_pattern})$"]
    if excl["max_size_mb"] > 0:
        cmd += ["--max-filesize", f"{excl['max_size_mb']}M"]

    cmd.append(target)

    # Pre-walk to count files for progress reporting
    if on_total:
        if os.path.isdir(target):
            wl = set(get_whitelist())
            ext_set = frozenset(excl["extensions"])
            max_bytes = excl["max_size_mb"] * 1048576 if excl["max_size_mb"] else 0
            total = sum(
                1 for _ in _walk_files(target, wl, ext_set, max_bytes, cancel)
            )
            on_total(total)
        else:
            on_total(1)

    logger.info(f"ClamAV: scanning — {' '.join(cmd)}")

    try:
        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
            env=plat.clamav_env(), bufsize=1,
        )
    except OSError as exc:
        result["error"] = f"Could not start ClamAV: {exc}"
        return result

    # Expose proc so callers can kill it directly (e.g. cancel button)
    if proc_ref is not None:
        proc_ref[0] = proc

    scanned_from_output = 0
    try:
        for line in proc.stdout:
            if cancel and cancel.is_set():
                proc.kill()
                proc.wait(timeout=SCAN_CANCEL_WAIT_TIMEOUT)
                result["error"] = "Scan cancelled."
                return result
            stripped = line.rstrip()
            if on_line:
                on_line(stripped)
            if "FOUND" in stripped:
                result["infections"].append(stripped)
                scanned_from_output += 1
            elif "OK" in stripped and ":" in stripped:
                # Lines like "/path/to/file: OK"
                scanned_from_output += 1
            elif stripped.startswith("Scanned files:"):
                try:
                    result["scanned"] = int(stripped.split(":")[-1].strip())
                except ValueError:
                    pass
            elif stripped.startswith("Infected files:"):
                try:
                    result["infected"] = int(stripped.split(":")[-1].strip())
                except ValueError:
                    pass
            elif stripped.startswith("Time:"):
                result["duration"] = stripped.split(":", 1)[-1].strip()

        proc.wait(timeout=SCAN_PROC_WAIT_TIMEOUT)

        rc = proc.returncode
        # clamscan: 0=clean, 1=found virus, 2=error
        # Negative = killed by signal (e.g. -9 = SIGKILL from quarantine)
        if rc is not None and rc < 0:
            sig = abs(rc)
            result["error"] = (
                f"ClamAV was killed by signal {sig}. "
                "The binary may be quarantined — run: "
                "xattr -cr scripts/build/clamav-artifacts/binaries/"
            )
        elif rc == 2 and not result["infections"]:
            result["error"] = "ClamAV encountered an error during scanning."

        # clamdscan doesn't output "Scanned files:" — derive from output lines
        if result["scanned"] == 0 and scanned_from_output > 0:
            result["scanned"] = scanned_from_output
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=SCAN_KILL_WAIT_TIMEOUT)
        result["error"] = "Scan timed out."
    except Exception as exc:
        proc.kill()
        proc.wait(timeout=SCAN_KILL_WAIT_TIMEOUT)
        result["error"] = str(exc)

    return result


# ── Quarantine ────────────────────────────────────────────


def quarantine_file(filepath: str) -> tuple[bool, str]:
    """Move an infected file to the quarantine directory."""
    if not os.path.exists(filepath):
        return False, "File not found."
    _ensure_dirs()
    basename = os.path.basename(filepath)
    dest = os.path.join(_QUARANTINE_DIR, f"{basename}.quarantined")
    counter = 1
    while os.path.exists(dest):
        dest = os.path.join(
            _QUARANTINE_DIR, f"{basename}.{counter}.quarantined",
        )
        counter += 1
    try:
        shutil.move(filepath, dest)
        os.chmod(dest, 0o000)
        logger.info(f"ClamAV: quarantined {filepath} → {dest}")
        return True, dest
    except Exception as exc:
        return False, str(exc)


def list_quarantined() -> list[str]:
    """Return list of quarantined file paths."""
    _ensure_dirs()
    return sorted(glob.glob(os.path.join(_QUARANTINE_DIR, "*.quarantined")))


def restore_quarantined(quarantine_path: str, dest: str) -> tuple[bool, str]:
    """Restore a quarantined file to the given destination."""
    if not os.path.exists(quarantine_path):
        return False, "Quarantined file not found."
    try:
        os.chmod(quarantine_path, 0o644)
        shutil.move(quarantine_path, dest)
        return True, f"Restored to {dest}"
    except Exception as exc:
        return False, str(exc)


def delete_quarantined(quarantine_path: str) -> tuple[bool, str]:
    """Permanently delete a quarantined file."""
    if not os.path.exists(quarantine_path):
        return False, "File not found."
    try:
        os.chmod(quarantine_path, 0o644)
        os.unlink(quarantine_path)
        return True, "Deleted."
    except Exception as exc:
        return False, str(exc)


# ── Whitelist ─────────────────────────────────────────────


def get_whitelist() -> list[str]:
    """Return list of whitelisted paths."""
    _ensure_dirs()
    if not os.path.exists(_WHITELIST_FILE):
        return []
    with open(_WHITELIST_FILE) as f:
        return [line.strip() for line in f if line.strip()]


def is_path_whitelisted(path: str) -> bool:
    """Check if *path* is whitelisted or inside a whitelisted directory."""
    entries = get_whitelist()
    if not entries:
        return False
    resolved = os.path.realpath(path)
    for entry in entries:
        resolved_entry = os.path.realpath(entry)
        if resolved == resolved_entry:
            return True
        if resolved.startswith(resolved_entry + os.sep):
            return True
    return False


def add_to_whitelist(path: str):
    """Add a path to the scan exclusion whitelist."""
    _ensure_dirs()
    current = get_whitelist()
    if path not in current:
        with open(_WHITELIST_FILE, "a") as f:
            f.write(path + "\n")
        logger.info(f"ClamAV: whitelisted {path}")


def remove_from_whitelist(path: str):
    """Remove a path from the whitelist."""
    current = get_whitelist()
    with open(_WHITELIST_FILE, "w") as f:
        for entry in current:
            if entry != path:
                f.write(entry + "\n")
    logger.info(f"ClamAV: removed from whitelist {path}")


# ── Scan Exclusions ──────────────────────────────────────


def get_scan_exclusions() -> dict:
    """Return scan exclusion settings (extensions list + max size)."""
    _ensure_dirs()
    defaults = {"extensions": [], "max_size_mb": 0}
    if not os.path.exists(_EXCLUSIONS_FILE):
        return defaults
    try:
        with open(_EXCLUSIONS_FILE) as f:
            data = json.load(f)
        raw_exts = data.get("extensions", [])
        normalized = [
            (e if e.startswith(".") else f".{e}").lower()
            for e in raw_exts if isinstance(e, str)
        ]
        return {
            "extensions": normalized,
            "max_size_mb": max(0, int(data.get("max_size_mb", 0))),
        }
    except (OSError, json.JSONDecodeError, TypeError, ValueError):
        return defaults


def set_scan_exclusions(exclusions: dict):
    """Save scan exclusion settings."""
    _ensure_dirs()
    try:
        with open(_EXCLUSIONS_FILE, "w") as f:
            json.dump(exclusions, f, indent=2)
    except OSError as exc:
        logger.error(f"ClamAV: failed to save exclusions: {exc}")


def _normalize_ext(ext: str) -> str:
    """Ensure extension has a leading dot and is lowercase."""
    if not ext.startswith("."):
        ext = "." + ext
    return ext.lower()


def add_excluded_extension(ext: str):
    """Add a file extension to the exclusion list."""
    ext = _normalize_ext(ext)
    excl = get_scan_exclusions()
    if ext not in excl["extensions"]:
        excl["extensions"].append(ext)
        set_scan_exclusions(excl)
        logger.info(f"ClamAV: excluded extension {ext}")


def add_excluded_extensions(exts: list[str]):
    """Add multiple file extensions at once (single read-modify-write)."""
    excl = get_scan_exclusions()
    added = []
    for ext in exts:
        ext = _normalize_ext(ext)
        if ext not in excl["extensions"]:
            excl["extensions"].append(ext)
            added.append(ext)
    if added:
        set_scan_exclusions(excl)
        logger.info(f"ClamAV: excluded extensions {added}")


def remove_excluded_extension(ext: str):
    """Remove a file extension from the exclusion list."""
    excl = get_scan_exclusions()
    if ext in excl["extensions"]:
        excl["extensions"].remove(ext)
        set_scan_exclusions(excl)
        logger.info(f"ClamAV: removed excluded extension {ext}")


def set_max_file_size(size_mb: int):
    """Set the maximum file size for scanning (0 = no limit)."""
    excl = get_scan_exclusions()
    excl["max_size_mb"] = max(0, size_mb)
    set_scan_exclusions(excl)
    logger.info(f"ClamAV: max file size set to {size_mb} MB")


# ── Realtime status ───────────────────────────────────────


def get_realtime_status() -> dict:
    """Return the real-time protection status for UI display.

    Two-dimensional state model:
    - setup_state: persisted installer lifecycle (from installer_service)
    - runtime_state: computed live from daemon health checks

    Also keeps backward-compatible keys for scanning logic.
    """
    import platform as _platform

    plat = _get_platform()
    installed = is_clamav_installed()
    db_present = has_database()
    clamd_ok = is_clamd_running()
    in_bundle = plat.is_app_bundle()

    clamonacc_ok = False
    system_clamd_ok = False
    approved = True
    fda = True

    if _platform.system() == "Darwin":
        clamonacc_ok = plat.is_clamonacc_running()
        if in_bundle:
            approved = plat.daemons_approved()
            fda = plat.has_full_disk_access()
            system_sock = plat.system_clamd_socket_path()
            if system_sock:
                system_clamd_ok = _ping_socket(system_sock)
    else:
        # On Linux/Windows there is one system-wide clamd, so the
        # "system" vs "user" distinction that exists on macOS does
        # not apply — the running-clamd check is the same one.
        system_clamd_ok = clamd_ok

    # Compute setup_state and runtime_state from installer service
    setup_state = "completed"  # Default for non-Darwin or pre-existing installs
    runtime_state = "offline"

    if _platform.system() == "Darwin":
        from plugins.antivirus.installer_service import (
            get_runtime_state,
            get_setup_state,
        )

        setup_state = get_setup_state()
        if setup_state == "completed":
            runtime_state = get_runtime_state()
        elif setup_state == "not_started":
            # Already-set-up users: if system clamd is running, mark completed
            if in_bundle and system_clamd_ok:
                from plugins.antivirus.installer_service import mark_completed

                mark_completed()
                setup_state = "completed"
                runtime_state = get_runtime_state()
    else:
        # Non-Darwin: derive legacy state
        if clamd_ok:
            runtime_state = "healthy"

    # Legacy "state" key — preserves the original priority order so existing
    # scanning logic and tests continue to work unchanged.
    # Priority: not_installed > no_database > approval > FDA > clamd > error
    if not installed:
        state = "not_installed"
    elif not db_present:
        state = "no_database"
    elif not approved:
        state = "approval_required"
    elif not fda:
        state = "fda_required"
    elif (in_bundle and system_clamd_ok) or (not in_bundle and clamd_ok):
        state = "protected"
    else:
        state = "error"

    return {
        "installed": installed,
        "db_present": db_present,
        "approved": approved,
        "fda_granted": fda,
        "clamd_running": clamd_ok,
        "clamonacc_running": clamonacc_ok,
        "system_clamd_running": system_clamd_ok,
        "in_bundle": in_bundle,
        "state": state,
        "setup_state": setup_state,
        "runtime_state": runtime_state,
    }
