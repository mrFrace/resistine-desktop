"""
ClamAV Installer Service — Decoupled State Machine for macOS

Orchestrates DB seeding (user-level, network) and system setup (admin,
no network) as separate phases.  Mirrors the Wazuh installer service
pattern in plugins/wazuh/agent/installer_service.py.

Author: Resistine Team
Copyright (c) Resistine 2025
Licensed under the GNU General Public License v2 or later
"""

import glob
import os
import sys
import threading
import time

from utils import settings
from utils.logger import logger

# This module orchestrates the ClamAV setup state machine, but every concrete
# implementation it calls into (_launch_clamav_postinstall, _SYSTEM_*, FDA
# checks, fcntl-based locking) is macOS-only. Importing platform modules from
# inside helpers on Linux/Windows would raise, so each public entry point
# short-circuits with a safe default on non-Darwin platforms.
_IS_DARWIN = sys.platform == "darwin"

# ---------------------------------------------------------------------------
# Setup state constants (persisted lifecycle — one-time setup progress)
# ---------------------------------------------------------------------------
STATE_NOT_STARTED = "not_started"
STATE_SEEDING_DB = "seeding_db"
STATE_SEED_FAILED = "seed_failed"
STATE_DB_READY = "db_ready"
STATE_INSTALLING = "installing"
STATE_INSTALL_FAILED = "install_failed"
STATE_COMPLETED = "completed"

# ---------------------------------------------------------------------------
# Runtime state constants (computed live — never persisted)
# ---------------------------------------------------------------------------
RUNTIME_HEALTHY = "healthy"
RUNTIME_DEGRADED = "degraded"
RUNTIME_OFFLINE = "offline"
RUNTIME_APPROVAL_REQUIRED = "approval_required"
RUNTIME_FDA_REQUIRED = "fda_required"

_NAMESPACE = "antivirus"
_lock = threading.Lock()

# User-level DB seeding directory
_CLAMAV_DATA_DIR = os.path.join(
    os.path.expanduser("~/Library/Application Support/Phoenix"), "clamav",
)
_USER_DB_DIR = os.path.join(_CLAMAV_DATA_DIR, "db")
_LOCK_FILE = os.path.join(_CLAMAV_DATA_DIR, "freshclam.lock")

# Minimum valid CVD file size (rejects partial downloads)
_MIN_CVD_SIZE = 1_000_000  # 1 MB — main.cvd is ~160 MB


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def get_setup_state() -> str:
    """Return current persisted setup lifecycle state."""
    if not _IS_DARWIN:
        return STATE_NOT_STARTED
    return settings.get(_NAMESPACE, "setup_state", STATE_NOT_STARTED)


def get_runtime_state() -> str:
    """Compute live runtime health — never persisted.

    Only meaningful when setup_state == completed.
    """
    if not _IS_DARWIN:
        return RUNTIME_OFFLINE
    from plugins.antivirus.clamav_common import _ping_socket
    from plugins.antivirus.clamav_platform_darwin import (
        _SYSTEM_CLAMD_SOCKET,
        daemons_approved,
        has_full_disk_access,
        is_app_bundle,
        is_clamonacc_running,
    )

    if not is_app_bundle():
        # Dev mode: check user-level clamd
        from plugins.antivirus.clamav_common import is_clamd_running

        if is_clamd_running():
            return RUNTIME_HEALTHY
        return RUNTIME_OFFLINE

    if not daemons_approved():
        return RUNTIME_APPROVAL_REQUIRED

    if not _ping_socket(_SYSTEM_CLAMD_SOCKET):
        return RUNTIME_OFFLINE

    if not has_full_disk_access():
        return RUNTIME_FDA_REQUIRED

    if not is_clamonacc_running():
        return RUNTIME_DEGRADED

    return RUNTIME_HEALTHY


def get_failure_reason() -> str:
    """Return the last failure reason, or empty string."""
    if not _IS_DARWIN:
        return ""
    return settings.get(_NAMESPACE, "failure_reason", "")


def get_failure_detail() -> str:
    """Return structured failure detail for support debugging."""
    if not _IS_DARWIN:
        return ""
    return settings.get(_NAMESPACE, "failure_detail", "")


def ensure_db_seed_started():
    """Idempotent: run freshclam to seed user-level DB if needed.

    No admin required. Call from: login success, app startup. Thread-safe.
    Uses fcntl.flock() to prevent concurrent freshclam processes.
    """
    if not _IS_DARWIN:
        return
    with _lock:
        state = get_setup_state()

        # Already past seeding or currently seeding
        if state in (
            STATE_SEEDING_DB, STATE_DB_READY, STATE_INSTALLING,
            STATE_COMPLETED,
        ):
            return

        # Respect backoff on prior failure
        if state == STATE_SEED_FAILED and not _backoff_elapsed():
            return

        # Already have a valid DB
        if _validate_database():
            _set_state(STATE_DB_READY)
            settings.set(_NAMESPACE, "db_seeded_at", time.time())
            return

        _set_state(STATE_SEEDING_DB)

    # Seed outside the lock (long-running I/O)
    _do_db_seed()


def trigger_system_setup() -> bool:
    """User clicked "Set Up Protection" — launch postinstall script.

    Returns True if the script launched successfully.
    """
    if not _IS_DARWIN:
        return False
    from plugins.antivirus.clamav_platform_darwin import (
        _launch_clamav_postinstall,
    )

    with _lock:
        state = get_setup_state()
        if state != STATE_DB_READY:
            logger.warning(
                f"[AV-INSTALLER] trigger_system_setup in wrong state: {state}",
            )
            return False
        _set_state(STATE_INSTALLING)

    launched, status_file, osascript_pid = _launch_clamav_postinstall(_USER_DB_DIR)
    if not launched:
        _fail(STATE_INSTALL_FAILED, "user_canceled", "Admin prompt was cancelled")
        return False

    settings.set(_NAMESPACE, "install_status_file", status_file)
    settings.set(_NAMESPACE, "osascript_pid", osascript_pid)
    return True


def poll_setup_progress() -> dict:
    """Poll status file. Returns {finished, success, step, error}."""
    if not _IS_DARWIN:
        return {"finished": True, "success": False, "step": "", "error": "unsupported_platform"}
    from plugins.antivirus.clamav_platform_darwin import _poll_setup_status

    status_file = settings.get(_NAMESPACE, "install_status_file", "")
    if not status_file:
        if get_setup_state() == STATE_INSTALLING:
            _fail(STATE_INSTALL_FAILED, "no_status_file", "No status file found")
        return {"finished": True, "success": False, "step": "", "error": "no status file"}

    finished, success, details = _poll_setup_status(status_file)

    # Status file doesn't exist yet. This is normal while the user is
    # still on the admin password prompt (osascript is alive). Only fail
    # once osascript has exited — meaning the user cancelled or the
    # script crashed before writing anything.
    if not finished and not os.path.exists(status_file):
        osascript_pid = settings.get(_NAMESPACE, "osascript_pid", 0)
        osascript_alive = False
        if osascript_pid:
            try:
                os.kill(osascript_pid, 0)
                osascript_alive = True
            except ProcessLookupError:
                pass  # osascript exited
            except PermissionError:
                osascript_alive = True  # still running
        if not osascript_alive:
            _fail(
                STATE_INSTALL_FAILED, "user_canceled",
                "Install status file missing — script never ran",
            )
            return {"finished": True, "success": False, "step": "", "error": "cancelled"}

    if finished:
        if success:
            _set_state(STATE_COMPLETED)
            settings.set(_NAMESPACE, "retry_count", 0)
            logger.info("[AV-INSTALLER] System setup completed successfully")
        else:
            error = details.get("error", "script_failed")
            error_code = details.get("error_code", "unknown")
            _fail(
                STATE_INSTALL_FAILED, error_code,
                f"step={details.get('step', '?')} error={error}",
            )
        try:
            os.unlink(status_file)
        except OSError:
            pass

    return {
        "finished": finished,
        "success": success,
        "step": details.get("step", ""),
        "error": details.get("error", ""),
    }


def mark_completed():
    """Transition to completed state. Thread-safe public API."""
    if not _IS_DARWIN:
        return
    with _lock:
        _set_state(STATE_COMPLETED)
        settings.set(_NAMESPACE, "retry_count", 0)


def check_and_advance():
    """State machine tick. Resume pending work. Call on app start."""
    if not _IS_DARWIN:
        return
    with _lock:
        state = get_setup_state()

    # Already completed — but verify the system install still exists on
    # disk. An uninstall (or manual cleanup) can wipe the system-level
    # ClamAV files while leaving the user-level setup_state=completed,
    # which strands a *reinstall* showing "Start Protection" for daemons
    # that crash-loop with no config file. Self-heal by resetting to
    # NOT_STARTED so seeding + the admin postinstall re-run. Bundle mode
    # only — dev mode has no system install to validate.
    if state == STATE_COMPLETED:
        if _system_install_intact():
            return
        logger.warning(
            "[AV-INSTALLER] setup_state=completed but system ClamAV install "
            "is missing (likely wiped by a prior uninstall) — resetting to "
            "re-run setup",
        )
        with _lock:
            _set_state(STATE_NOT_STARTED)
            settings.set(_NAMESPACE, "retry_count", 0)
            settings.set(_NAMESPACE, "last_attempt_ts", 0.0)
        state = STATE_NOT_STARTED
        # Fall through — the NOT_STARTED handling below re-seeds the DB.

    # If system setup is already done (daemons running), mark completed
    from plugins.antivirus.clamav_common import _ping_socket
    from plugins.antivirus.clamav_platform_darwin import _SYSTEM_CLAMD_SOCKET

    if _ping_socket(_SYSTEM_CLAMD_SOCKET):
        mark_completed()
        return

    # System setup exists (dir + configs + valid DB) but clamd not yet
    # running. This covers upgrade users and dev mode where launchd
    # isn't managing daemons. Requires at least one CVD > 1 MB to
    # reject corrupted/partial files that clamd can't load.
    from plugins.antivirus.clamav_platform_darwin import _SYSTEM_DB_DIR

    if os.path.isdir(_SYSTEM_DB_DIR):
        has_valid_cvd = any(
            os.path.getsize(f) > _MIN_CVD_SIZE
            for f in glob.glob(os.path.join(_SYSTEM_DB_DIR, "*.cvd"))
            if os.path.isfile(f)
        )
        if has_valid_cvd:
            mark_completed()
            return

    # Recover from stuck SEEDING_DB: if state is SEEDING_DB but no
    # freshclam process holds the lock, a previous seed crashed without
    # transitioning. Reset to NOT_STARTED so ensure_db_seed_started
    # can retry.
    if state == STATE_SEEDING_DB:
        if _validate_database():
            with _lock:
                _set_state(STATE_DB_READY)
                settings.set(_NAMESPACE, "db_seeded_at", time.time())
            return
        # Try to acquire the flock non-blocking — if we get it, no
        # freshclam is running, so the previous seed died.
        import fcntl

        os.makedirs(_CLAMAV_DATA_DIR, exist_ok=True)
        try:
            with open(_LOCK_FILE, "w") as probe_fd:
                fcntl.flock(probe_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                fcntl.flock(probe_fd, fcntl.LOCK_UN)
            # Lock was available → no freshclam running → stuck state
            with _lock:
                logger.warning("[AV-INSTALLER] Stuck in SEEDING_DB, resetting")
                _set_state(STATE_NOT_STARTED)
                state = STATE_NOT_STARTED
        except (OSError, BlockingIOError):
            # Lock held → freshclam still running, leave state alone
            return

    # Resume seeding if it was interrupted or failed with backoff elapsed
    if state in (STATE_NOT_STARTED, STATE_SEED_FAILED):
        ensure_db_seed_started()
        return

    # If install was interrupted, poll once — poll_setup_progress
    # handles the missing-status-file case (user cancelled osascript).
    if state == STATE_INSTALLING:
        poll_setup_progress()

    # DB ready but not yet installed — wait for user action
    # Install failed — wait for manual retry


def retry():
    """Manual retry. Reset backoff, restart current phase."""
    if not _IS_DARWIN:
        return
    with _lock:
        settings.set(_NAMESPACE, "retry_count", 0)
        settings.set(_NAMESPACE, "last_attempt_ts", 0.0)
        state = get_setup_state()

        if state in (STATE_SEED_FAILED, STATE_NOT_STARTED):
            _set_state(STATE_NOT_STARTED)
        elif state == STATE_INSTALL_FAILED:
            if _validate_database():
                _set_state(STATE_DB_READY)
            else:
                _set_state(STATE_NOT_STARTED)

    # Kick off seeding outside the lock (long-running I/O)
    new_state = get_setup_state()
    if new_state == STATE_NOT_STARTED:
        ensure_db_seed_started()


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _set_state(state: str):
    """Persist state transition."""
    settings.set(_NAMESPACE, "setup_state", state)
    logger.info(f"[AV-INSTALLER] State -> {state}")


def _fail(state: str, reason: str, detail: str = ""):
    """Record failure and increment retry counter."""
    with _lock:
        settings.set(_NAMESPACE, "setup_state", state)
        settings.set(_NAMESPACE, "failure_reason", reason)
        settings.set(_NAMESPACE, "failure_detail", detail)
        count = settings.get(_NAMESPACE, "retry_count", 0)
        settings.set(_NAMESPACE, "retry_count", count + 1)
        settings.set(_NAMESPACE, "last_attempt_ts", time.time())
    logger.error(f"[AV-INSTALLER] Failed: state={state} reason={reason} detail={detail}")


def _backoff_elapsed() -> bool:
    """Return True if enough time has passed since last failure."""
    count = settings.get(_NAMESPACE, "retry_count", 0)
    if count >= 5:
        return False  # Max auto-retries exceeded, require manual
    last = settings.get(_NAMESPACE, "last_attempt_ts", 0.0)
    wait = min(60 * (2 ** count), 3600)
    return (time.time() - last) >= wait


def _validate_database() -> bool:
    """Check that a valid CVD database exists (user-level or system-level).

    Requires at least one .cvd file larger than _MIN_CVD_SIZE to reject
    partial downloads from killed freshclam processes.
    Checks both user and system dirs because freshclam writes to whichever
    _effective_db_dir(writable=True) returns.
    """
    from plugins.antivirus.clamav_common import _effective_db_dir

    dirs_to_check = [_USER_DB_DIR]
    try:
        effective = _effective_db_dir()
        if effective != _USER_DB_DIR:
            dirs_to_check.append(effective)
    except Exception:
        pass

    for db_dir in dirs_to_check:
        cvd_files = glob.glob(os.path.join(db_dir, "*.cvd"))
        for cvd in cvd_files:
            try:
                if os.path.getsize(cvd) > _MIN_CVD_SIZE:
                    return True
            except OSError:
                continue
    return False


def _system_install_intact() -> bool:
    """Return True if the system-level ClamAV install is present on disk.

    A bundle install places clamd.conf plus a seeded CVD under the system
    ClamAV dir via the admin postinstall. If those are gone (e.g. an
    uninstall wiped the directory) a persisted setup_state=completed is
    stale and setup must re-run. In dev mode (no app bundle) there is no
    system install to validate, so treat it as intact and let the live
    runtime checks handle health.
    """
    from plugins.antivirus.clamav_platform_darwin import (
        _SYSTEM_CLAMD_CONF,
        _SYSTEM_DB_DIR,
        is_app_bundle,
    )

    if not is_app_bundle():
        return True

    if not os.path.isfile(_SYSTEM_CLAMD_CONF):
        return False

    return any(
        os.path.getsize(f) > _MIN_CVD_SIZE
        for f in glob.glob(os.path.join(_SYSTEM_DB_DIR, "*.cvd"))
        if os.path.isfile(f)
    )


def _do_db_seed():
    """Execute freshclam with filesystem lock to prevent concurrent runs."""
    import fcntl

    os.makedirs(_CLAMAV_DATA_DIR, exist_ok=True)
    os.makedirs(_USER_DB_DIR, exist_ok=True)

    lock_fd = None
    try:
        lock_fd = open(_LOCK_FILE, "w")
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except (OSError, BlockingIOError):
            logger.info("[AV-INSTALLER] Another freshclam is running, skipping")
            lock_fd.close()
            return

        from plugins.antivirus.clamav_common import run_freshclam

        logger.info("[AV-INSTALLER] Starting DB seed via freshclam")
        ok, msg = run_freshclam()

        if ok and _validate_database():
            with _lock:
                settings.set(_NAMESPACE, "retry_count", 0)
                settings.set(_NAMESPACE, "db_seeded_at", time.time())
                _set_state(STATE_DB_READY)
        elif ok and not _validate_database():
            # freshclam reported success but DB files are missing/too small
            _fail(STATE_SEED_FAILED, "partial_download", msg)
        elif "cert" in msg.lower() or "cvd" in msg.lower():
            _fail(STATE_SEED_FAILED, "certs_missing", msg)
        elif "timeout" in msg.lower() or "timed out" in msg.lower():
            _fail(STATE_SEED_FAILED, "network_timeout", msg)
        elif "not found" in msg.lower() or "no such" in msg.lower():
            _fail(STATE_SEED_FAILED, "binary_missing", msg)
        elif "resolve" in msg.lower() or "connect" in msg.lower():
            _fail(STATE_SEED_FAILED, "dns_failed", msg)
        else:
            # code 11 can be certs OR network — classify as generic
            _fail(STATE_SEED_FAILED, "freshclam_failed", msg)

    finally:
        if lock_fd:
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_UN)
                lock_fd.close()
            except OSError:
                pass
