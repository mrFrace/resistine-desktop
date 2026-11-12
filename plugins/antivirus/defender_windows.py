"""Windows Defender backend for the antivirus plugin.

Provides the same public surface as plugins.antivirus.clamav_common
(scan_path, run_freshclam, get_realtime_status, list_quarantined, etc.)
backed by Windows Defender via PowerShell cmdlets:
  Get-MpComputerStatus, Start-MpScan, Get-MpThreatDetection,
  Update-MpSignature, Set-MpPreference, Remove-MpThreat.

File-based bookkeeping (whitelist + scan-exclusion JSON) is shared with
the ClamAV backend by re-exporting from clamav_common — those helpers
are pure file ops with no engine-specific dependency.

Author: Phoenix Team
Copyright (c) Phoenix 2025
Licensed under the GNU General Public License v2 or later
"""
from __future__ import annotations

import json
import os
import subprocess
import threading
import time
from collections.abc import Callable

from utils.logger import logger
from utils.windows_admin import run_privileged

# ── Shared file-based bookkeeping ─────────────────────────
# Whitelist and scan-exclusion settings are user-level config, identical
# across engines. Re-exported so plugins.antivirus.clamav.* still resolves.
from plugins.antivirus.clamav_common import (  # noqa: F401
    _CLAMAV_DATA_DIR,
    _CLAMD_CONF,
    _CLAMD_PID,
    _CLAMD_SOCKET,
    _DB_DIR,
    _EXCLUSIONS_FILE,
    _FRESHCLAM_CONF,
    _LOG_DIR,
    _PARALLEL_WORKERS,
    _QUARANTINE_DIR,
    _RUN_DIR,
    _SKIP_DIRS,
    _WHITELIST_FILE,
    _ensure_dirs,
    _format_duration,
    _walk_files,
    add_excluded_extension,
    add_excluded_extensions,
    add_to_whitelist,
    ensure_config,
    get_scan_exclusions,
    get_whitelist,
    is_path_whitelisted,
    remove_excluded_extension,
    remove_from_whitelist,
    set_max_file_size,
    set_scan_exclusions,
)


_NO_WINDOW = 0x08000000  # CREATE_NO_WINDOW — keep PowerShell windows hidden

# ── Status cache ──────────────────────────────────────────
_status_cache: dict = {}
_status_cache_time: float = 0.0
_status_cache_lock = threading.Lock()
_STATUS_TTL: float = 8.0  # seconds; fits within the 10 s UI poll cycle
_last_good_status: dict = {}  # last successful Get-MpComputerStatus result


# ── PowerShell helpers ─────────────────────────────────────


def _ps(command: str, timeout: int = 30) -> tuple[int, str, str]:
    """Run a PowerShell command, return (rc, stdout, stderr)."""
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass",
             "-Command", command],
            capture_output=True, text=True, timeout=timeout,
            creationflags=_NO_WINDOW,
        )
        return result.returncode, result.stdout.strip(), result.stderr.strip()
    except subprocess.TimeoutExpired:
        return -1, "", "Timed out"
    except FileNotFoundError:
        return -1, "", "powershell not found"
    except Exception as exc:
        return -1, "", str(exc)


def _mp_status() -> dict:
    """Return a parsed Get-MpComputerStatus snapshot, or {} on failure.

    Results are cached for *_STATUS_TTL* seconds to avoid spawning
    redundant PowerShell processes when multiple callers query status
    in the same UI poll cycle.
    """
    global _status_cache, _status_cache_time

    now = time.monotonic()
    with _status_cache_lock:
        if _status_cache and (now - _status_cache_time) < _STATUS_TTL:
            return _status_cache

    rc, out, _ = _ps(
        "Get-MpComputerStatus | Select-Object "
        "AntivirusEnabled, RealTimeProtectionEnabled, "
        "AntivirusSignatureLastUpdated, AntivirusSignatureVersion, "
        "AMServiceEnabled "
        "| ConvertTo-Json -Compress",
        timeout=15,
    )
    if rc != 0 or not out:
        result = {}
    else:
        try:
            result = json.loads(out)
        except json.JSONDecodeError:
            result = {}

    with _status_cache_lock:
        _status_cache = result
        _status_cache_time = time.monotonic()

    return result


def _invalidate_status_cache() -> None:
    """Force the next _mp_status() call to re-query Defender."""
    global _status_cache, _status_cache_time
    with _status_cache_lock:
        _status_cache = {}
        _status_cache_time = 0.0


def _parse_mp_date(value) -> float | None:
    """Best-effort parse of Defender's date field into epoch seconds."""
    if not isinstance(value, str):
        return None
    if value.startswith("/Date(") and value.endswith(")/"):
        try:
            ms_part = value[6:-2]
            for sep in ("+", "-"):
                if sep in ms_part[1:]:
                    ms_part = ms_part.split(sep, 1)[0]
                    break
            return int(ms_part) / 1000.0
        except ValueError:
            return None
    try:
        from datetime import datetime
        return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
    except (ValueError, TypeError):
        return None


# ── Engine identity ──────────────────────────────────────


def engine_name() -> str:
    """Override clamav_common's "ClamAV" with Windows Defender."""
    return "Windows Defender"


# ── Status / availability ─────────────────────────────────


def is_available() -> bool:
    """True if Defender is installed and responsive on this machine."""
    return bool(_mp_status())


def is_clamav_installed() -> bool:
    """Check whether the antivirus engine is installed.

    Named ``is_clamav_installed`` for interface parity with the ClamAV
    backend.  On Windows this delegates to Defender's availability check.
    """
    return is_available()


def is_clamd_running() -> bool:
    """Check whether real-time protection is active.

    Named ``is_clamd_running`` for interface parity with the ClamAV
    backend (clamd daemon).  On Windows this checks Defender's
    RealTimeProtectionEnabled status.
    """
    return bool(_mp_status().get("RealTimeProtectionEnabled"))


def has_database() -> bool:
    """True if Defender reports a non-empty signature version."""
    return bool(_mp_status().get("AntivirusSignatureVersion"))


def get_db_info() -> dict[str, str]:
    """Return signature version + last-updated timestamp for the UI."""
    info = {"signatures": "—", "last_updated": "—"}
    s = _mp_status()
    ver = s.get("AntivirusSignatureVersion")
    if ver:
        info["signatures"] = str(ver)
    ts = _parse_mp_date(s.get("AntivirusSignatureLastUpdated"))
    if ts:
        info["last_updated"] = time.strftime(
            "%Y-%m-%d %H:%M", time.localtime(ts),
        )
    return info


def get_realtime_status() -> dict:
    """Match the schema of clamav_common.get_realtime_status."""
    global _last_good_status
    s = _mp_status()
    if not s and _last_good_status:
        s = _last_good_status
    elif s:
        _last_good_status = s
    installed = bool(s)
    db_present = bool(s.get("AntivirusSignatureVersion"))
    rt_enabled = bool(s.get("RealTimeProtectionEnabled"))

    if not installed:
        state = "not_installed"
    elif not db_present:
        state = "no_database"
    elif rt_enabled:
        state = "protected"
    else:
        state = "error"

    runtime_state = "healthy" if rt_enabled else "offline"

    return {
        "installed": installed,
        "db_present": db_present,
        "approved": True,
        "fda_granted": True,
        "clamd_running": rt_enabled,
        "clamonacc_running": rt_enabled,
        "system_clamd_running": rt_enabled,
        "in_bundle": False,
        "state": state,
        "setup_state": "completed",
        "runtime_state": runtime_state,
    }


# ── Real-time threat detection polling ─────────────────────


def get_recent_threats(since_seconds: int = 30) -> list[dict]:
    """Return threats Defender caught via real-time protection recently.

    Polls ``Get-MpThreatDetection`` for detections within the last
    *since_seconds*.  Each entry contains threat_id, name, and resources.
    """
    rc, out, _ = _ps(
        "Get-MpThreatDetection"
        f" | Where-Object {{ $_.InitialDetectionTime -gt"
        f" (Get-Date).AddSeconds(-{since_seconds}) }}"
        " | Select-Object ThreatID,"
        " @{N='ThreatName';E={(Get-MpThreat -ThreatID"
        " $_.ThreatID).ThreatName}}, Resources"
        " | ConvertTo-Json -Compress",
        timeout=20,
    )
    if rc != 0 or not out:
        return []
    try:
        data = json.loads(out)
    except json.JSONDecodeError:
        return []
    if isinstance(data, dict):
        data = [data]
    results = []
    for item in data:
        tid = item.get("ThreatID")
        if tid is None:
            continue
        resources = item.get("Resources") or []
        if isinstance(resources, str):
            resources = [resources]
        results.append({
            "threat_id": str(tid),
            "name": item.get("ThreatName") or "Unknown Threat",
            "resources": resources,
        })
    return results


# ── Daemon lifecycle ───────────────────────────────────────


def start_clamd() -> tuple[bool, str]:
    """Start the antivirus daemon (no-op on Windows).

    Named ``start_clamd`` for interface parity.  Defender's real-time
    protection service is managed by Windows and cannot be started
    independently.  Use activate_system_daemons() instead.
    """
    return True, "Defender is managed by Windows."


def stop_clamd() -> tuple[bool, str]:
    """Stop the antivirus daemon (no-op on Windows).

    Named ``stop_clamd`` for interface parity.  Defender's service is
    OS-managed.  Use deactivate_system_daemons() instead.
    """
    return True, "Defender is managed by Windows."


def activate_system_daemons() -> tuple[bool, str]:
    """Enable Defender real-time protection (requires admin).

    Uses UAC elevation if the current process is not running as
    administrator.  Maps to the ClamAV interface's daemon-start action.
    """
    ok, output = run_privileged(
        "Set-MpPreference -DisableRealtimeMonitoring $false",
        timeout=15,
    )
    _invalidate_status_cache()
    if ok:
        return True, "Real-time protection enabled."
    return False, output or "Failed to enable real-time protection."


def deactivate_system_daemons() -> tuple[bool, str]:
    """Disable Defender real-time protection (requires admin).

    Uses UAC elevation if the current process is not running as
    administrator.  Maps to the ClamAV interface's daemon-stop action.
    """
    ok, output = run_privileged(
        "Set-MpPreference -DisableRealtimeMonitoring $true",
        timeout=15,
    )
    _invalidate_status_cache()
    if ok:
        return True, "Real-time protection disabled."
    return False, output or "Failed to disable real-time protection."


def ensure_daemons_registered():
    """No-op — Defender ships with Windows."""


def refresh_system_configs():
    """No-op — no Phoenix-managed system configs on Windows."""


# ── Signature updates ─────────────────────────────────────


def run_freshclam(on_line: Callable | None = None) -> tuple[bool, str]:
    """Update antivirus signature definitions.

    Named ``run_freshclam`` for interface parity with the ClamAV
    backend (freshclam tool).  On Windows this invokes Defender's
    Update-MpSignature cmdlet.
    """
    if on_line:
        on_line("Updating Windows Defender signatures...")
    rc, out, err = _ps("Update-MpSignature", timeout=300)
    if rc == 0:
        return True, "Signatures updated successfully."
    return False, err or out or f"Update-MpSignature exited with code {rc}"


# ── Scanning ──────────────────────────────────────────────

# MpCmdRun exit codes: 0 = clean, 2 = threat found
_MPCMDRUN: str | None = None


def _find_mpcmdrun() -> str | None:
    """Locate MpCmdRun.exe (cached after first lookup)."""
    global _MPCMDRUN
    if _MPCMDRUN is not None:
        return _MPCMDRUN or None
    for base in (
        os.environ.get("ProgramFiles", r"C:\Program Files"),
        os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)"),
    ):
        path = os.path.join(base, "Windows Defender", "MpCmdRun.exe")
        if os.path.isfile(path):
            _MPCMDRUN = path
            return path
    _MPCMDRUN = ""
    return None


def _amsi_scan_file(
    filepath: str,
    cancel: "threading.Event | None" = None,
) -> str:
    """Scan one file via AMSI. Returns ClamAV-compatible result line."""
    if cancel and cancel.is_set():
        return f"{filepath}: OK"
    from plugins.antivirus import amsi_scanner
    _, line = amsi_scanner.scan_file(filepath)
    return line


def _scan_single_file(
    filepath: str,
    cancel: "threading.Event | None" = None,
) -> str:
    """Scan one file with MpCmdRun and return a ClamAV-style result line.

    Returns  "<filepath>: <ThreatName> FOUND"  or  "<filepath>: OK".
    """
    if cancel and cancel.is_set():
        return f"{filepath}: OK"
    exe = _find_mpcmdrun()
    if not exe:
        return f"{filepath}: OK"
    try:
        proc = subprocess.Popen(
            [exe, "-Scan", "-ScanType", "3", "-File", filepath],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            creationflags=_NO_WINDOW,
        )
    except OSError:
        return f"{filepath}: OK"
    # Poll so we can abort quickly on cancel
    while proc.poll() is None:
        if cancel and cancel.is_set():
            proc.kill()
            return f"{filepath}: OK"
        try:
            proc.wait(timeout=0.5)
        except subprocess.TimeoutExpired:
            pass
    if proc.returncode == 2:
        stdout = proc.stdout.read() if proc.stdout else ""
        for line in stdout.splitlines():
            stripped = line.strip()
            if stripped.startswith("Threat"):
                name = stripped.split(":", 1)[-1].strip() if ":" in stripped else "Unknown"
                return f"{filepath}: {name} FOUND"
    return f"{filepath}: OK"


def scan_path(
    target: str,
    on_line: Callable | None = None,
    cancel: "threading.Event | None" = None,
    proc_ref: "list | None" = None,
    on_total: Callable | None = None,
) -> dict:
    """Scan a file or directory with Windows Defender.

    Single files use per-file MpCmdRun. Directories use a single MpCmdRun
    process for the whole tree — one engine init, Defender handles parallelism.
    """
    result = {
        "target": target,
        "scanned": 0,
        "infected": 0,
        "infections": [],
        "duration": "",
        "error": "",
    }

    if not is_available():
        result["error"] = "Windows Defender is not available."
        return result

    # Single file scan
    if os.path.isfile(target):
        if on_total:
            on_total(1)
        if on_line:
            on_line(f"Scanning {os.path.basename(target)}...")
        start = time.monotonic()
        line = _scan_single_file(target, cancel)
        if on_line:
            on_line(line)
        result["scanned"] = 1
        if "FOUND" in line:
            result["infected"] = 1
            result["infections"] = [line]
        result["duration"] = _format_duration(time.monotonic() - start)
        return result

    # Directory scan — stream files to scan pool as they're discovered (no pre-index).
    # Uses AMSI if available (~1-10ms/file), falls back to MpCmdRun per-file.
    from concurrent.futures import ThreadPoolExecutor, as_completed
    from plugins.antivirus import amsi_scanner

    whitelist = set(get_whitelist())
    excl = get_scan_exclusions()
    excluded_ext = frozenset(excl["extensions"])
    max_bytes = excl["max_size_mb"] * 1048576 if excl["max_size_mb"] else 0

    short_name = os.path.basename(target) or target
    use_amsi = amsi_scanner.is_available()
    engine = "AMSI" if use_amsi else "MpCmdRun"
    scan_fn = _amsi_scan_file if use_amsi else _scan_single_file

    if on_line:
        on_line(f"Scanning {short_name} ({engine})...")

    # Count files on a side thread so the scan starts immediately but the
    # progress bar can switch from indeterminate to percentage once the
    # total lands (mirrors the ClamAV pre-count → on_total behaviour).
    if on_total:
        def _count():
            try:
                total = sum(1 for _ in _walk_files(
                    target, whitelist, excluded_ext, max_bytes, cancel))
                if not (cancel and cancel.is_set()):
                    on_total(total)
            except Exception:
                pass  # bar simply stays indeterminate

        threading.Thread(target=_count, daemon=True).start()

    start = time.monotonic()
    scanned = 0
    infected = 0
    infections: list[str] = []

    pool = ThreadPoolExecutor(max_workers=_PARALLEL_WORKERS)
    pending = set()
    try:
        for filepath in _walk_files(target, whitelist, excluded_ext, max_bytes, cancel):
            if cancel and cancel.is_set():
                break
            pending.add(pool.submit(scan_fn, filepath, cancel))

            # Harvest completed futures without blocking
            done = {f for f in pending if f.done()}
            for future in done:
                pending.discard(future)
                try:
                    line = future.result()
                except Exception:
                    continue
                scanned += 1
                if on_line:
                    on_line(line)
                if "FOUND" in line:
                    infected += 1
                    infections.append(line)

        # Drain remaining futures
        for future in as_completed(pending):
            if cancel and cancel.is_set():
                break
            try:
                line = future.result(timeout=5)
            except Exception:
                continue
            scanned += 1
            if on_line:
                on_line(line)
            if "FOUND" in line:
                infected += 1
                infections.append(line)
    finally:
        pool.shutdown(wait=False, cancel_futures=True)

    if cancel and cancel.is_set():
        result["error"] = "Scan cancelled."
        return result

    result["scanned"] = scanned
    result["infected"] = infected
    result["infections"] = infections
    result["duration"] = _format_duration(time.monotonic() - start)
    return result


# ── Quarantine ────────────────────────────────────────────




# list_quarantined, restore_quarantined, delete_quarantined, and
# quarantine_file are NOT overridden here — the clamav_common versions
# (imported at the top) use the local _QUARANTINE_DIR which is correct
# for Windows too, since we scan with -DisableRemediation and handle
# quarantine locally rather than through Defender's own quarantine.


# ── macOS-specific UI hooks (no-op on Windows) ────────────


def open_login_items_settings():
    logger.info("Defender: managed by Windows; no Login Items equivalent.")


def open_fda_settings():
    logger.info("Defender: full disk access is granted by Windows automatically.")


# ── Platform interface stubs ──────────────────────────────
# The functions below exist solely for interface parity with the ClamAV
# backend on macOS/Linux.  They return safe no-op values because
# Windows Defender does not use ClamAV binaries, sockets, configs,
# bundle detection, or FDA/Login Items approval.


def system_db_dir() -> str | None:
    return None


def system_db_dir_writable() -> str | None:
    return None


def system_clamd_socket_path() -> str:
    return ""


def system_clamd_conf_path() -> str:
    return ""


def find_binary(name: str) -> str | None:
    return None


def find_certs_dir() -> str | None:
    return None


def clamav_env() -> dict[str, str]:
    return {**os.environ}


def is_app_bundle() -> bool:
    return False


def daemons_approved() -> bool:
    return True


def has_full_disk_access() -> bool:
    return True


def is_clamonacc_running() -> bool:
    """Check whether on-access scanning is active.

    Named ``is_clamonacc_running`` for interface parity with the ClamAV
    backend (clamonacc daemon).  On Windows, Defender's real-time
    protection serves the same role.
    """
    return is_clamd_running()
