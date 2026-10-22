"""
Wazuh Installer Service — Decoupled State Machine for macOS

Orchestrates download (public internet), install (admin consent), and
enrollment (VPN) as separate phases with independent network requirements.

Author: Resistine Team
Copyright (c) Resistine 2025
Licensed under the GNU General Public License v2 or later
"""

import os
import threading
import time

from utils import settings
from utils.logger import logger

from plugins.wazuh.agent import phoenix_packages

# ---------------------------------------------------------------------------
# State constants
# ---------------------------------------------------------------------------
STATE_NOT_STARTED = "not_started"
STATE_DOWNLOADING = "downloading"
STATE_DOWNLOADED = "downloaded"
STATE_DOWNLOAD_FAILED = "download_failed"
STATE_INSTALLING = "installing"
STATE_INSTALL_FAILED = "install_failed"
STATE_INSTALLED = "installed"
STATE_ENROLLING = "enrolling"
STATE_ENROLL_FAILED = "enroll_failed"
STATE_READY = "ready"

_NAMESPACE = "wazuh"
_lock = threading.Lock()

# ---------------------------------------------------------------------------
# Cache path
# ---------------------------------------------------------------------------
_CACHE_DIR = os.path.join(
    os.path.expanduser("~/Library/Application Support/Phoenix"), "cache"
)
_CACHED_PKG = os.path.join(_CACHE_DIR, "phoenix-agent.pkg")


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def get_install_state() -> str:
    """Return current installer state for UI."""
    return settings.get(_NAMESPACE, "install_state", STATE_NOT_STARTED)


def get_failure_reason() -> str:
    """Return the last failure reason, or empty string."""
    return settings.get(_NAMESPACE, "failure_reason", "")


def ensure_download_started(force: bool = False):
    """Idempotent. Download if registered + not cached + not installed.

    Call from: login success, app startup. Thread-safe.

    ``force=True`` bypasses the auth-email gate — used when the user
    explicitly asks to install without being signed in (e.g. they imported
    a VPN config manually, or the Login plugin is uninstalled).
    """
    from plugins.wazuh.agent.wazuh_functions_darwin import is_agent_installed

    with _lock:
        state = get_install_state()

        # Already past download or currently downloading
        if state in (
            STATE_DOWNLOADING, STATE_DOWNLOADED, STATE_INSTALLING,
            STATE_INSTALLED, STATE_ENROLLING, STATE_READY,
        ):
            return

        # Agent already on disk
        if is_agent_installed():
            _set_state(STATE_INSTALLED)
            return

        # Not authenticated (check email rather than logged_in flag because
        # the download thread may start before logged_in is persisted).
        # Skipped on force — an explicit user request to install anyway.
        if not force and not settings.get("auth", "email", ""):
            return

        # Respect backoff on prior failure
        if state == STATE_DOWNLOAD_FAILED and not _backoff_elapsed():
            return

        # Already have a valid cached pkg (download() replaces it when the
        # server has a newer build)
        if os.path.isfile(_CACHED_PKG) and verify_package(_CACHED_PKG):
            _set_state(STATE_DOWNLOADED)
            settings.set(_NAMESPACE, "pkg_cached_path", _CACHED_PKG)
            return

        _set_state(STATE_DOWNLOADING)

    # Download outside the lock (long-running I/O)
    _do_download()


def trigger_install(app) -> bool:
    """Called after user consent. Creates LaunchDaemon, bootstraps it.

    Returns True if daemon launched successfully.
    """
    from plugins.wazuh.agent.wazuh_functions_darwin import (
        _launch_postinstall,
        get_agent_group,
        get_agent_name,
        write_env_file,
    )

    with _lock:
        state = get_install_state()
        if state != STATE_DOWNLOADED:
            logger.warning(f"[INSTALLER] trigger_install called in wrong state: {state}")
            return False
        _set_state(STATE_INSTALLING)

    pkg_path = settings.get(_NAMESPACE, "pkg_cached_path", _CACHED_PKG)
    # Re-checked right before the root install: the cache is user-writable.
    if not os.path.isfile(pkg_path) or not verify_package(pkg_path):
        _fail(STATE_INSTALL_FAILED, "pkg_corrupted")
        return False

    # Prepare agent identity. The Phoenix API enrolls server side, in the
    # user's group; without it the script runs agent-auth.
    from plugins.wazuh.agent import enrollment

    agent_name = get_agent_name()
    agent_group = get_agent_group()
    enrolled = enrollment.request(agent_name)
    if enrolled:
        agent_name = enrolled.agent_name
        agent_group = enrolled.group

    if not write_env_file(agent_name, agent_group):
        _fail(STATE_INSTALL_FAILED, "script_failed")
        return False

    # Always re-enroll so the manager receives the group on every install.
    launched, status_file = _launch_postinstall(
        pkg_path, agent_name, agent_group, restore_keys=False,
        key_file=enrolled.key_file if enrolled else None,
    )
    if not launched:
        enrollment.discard(enrolled)
        _fail(STATE_INSTALL_FAILED, "user_canceled")
        return False

    settings.set(_NAMESPACE, "install_status_file", status_file)
    return True


def poll_install_progress() -> dict:
    """Poll status file. Returns {finished, success, step, error, enrollment}."""
    from plugins.wazuh.agent.wazuh_functions_darwin import _poll_install_status

    status_file = settings.get(_NAMESPACE, "install_status_file", "")
    if not status_file:
        # No status file means install was never properly launched — fail the state
        # to break any polling loop.
        if get_install_state() == STATE_INSTALLING:
            _fail(STATE_INSTALL_FAILED, "no_status_file")
        return {"finished": True, "success": False, "step": "", "error": "no status file"}

    finished, success, details = _poll_install_status(status_file)

    if finished:
        if success:
            _install_succeeded(details)
            try:
                os.unlink(status_file)
            except OSError:
                pass
        else:
            error = details.get("error", "script_failed")
            _fail(STATE_INSTALL_FAILED, error)
            try:
                os.unlink(status_file)
            except OSError:
                pass

    return {
        "finished": finished,
        "success": success,
        "step": details.get("step", ""),
        "error": details.get("error", ""),
        "enrollment": details.get("enrollment", ""),
    }


def check_and_advance():
    """State machine tick. Resume pending work. Call on app start."""
    from plugins.wazuh.agent.wazuh_functions_darwin import get_agent_status, is_agent_installed

    state = get_install_state()

    # If agent is on disk, advance to installed/ready
    if is_agent_installed():
        if state in (STATE_NOT_STARTED, STATE_DOWNLOADING, STATE_DOWNLOADED,
                     STATE_INSTALLING, STATE_INSTALL_FAILED):
            if get_agent_status() == "Running":
                _set_state(STATE_READY)
            else:
                _set_state(STATE_INSTALLED)
        return

    # Resume download if it was interrupted or failed with backoff elapsed
    if state in (STATE_NOT_STARTED, STATE_DOWNLOAD_FAILED, STATE_DOWNLOADING):
        ensure_download_started()
        return

    # If installing was interrupted (app quit), check status file
    if state == STATE_INSTALLING:
        result = poll_install_progress()
        if not result["finished"]:
            # Script may still be running (LaunchDaemon). Leave state alone.
            pass


def retry():
    """Manual retry. Reset backoff, restart current phase."""
    with _lock:
        settings.set(_NAMESPACE, "retry_count", 0)
        settings.set(_NAMESPACE, "last_attempt_ts", 0.0)
        state = get_install_state()

    if state in (STATE_DOWNLOAD_FAILED, STATE_NOT_STARTED):
        _delete_cached_pkg()
        _set_state(STATE_NOT_STARTED)
        ensure_download_started()
    elif state == STATE_INSTALL_FAILED:
        reason = get_failure_reason()
        if reason in ("signature_invalid", "pkg_corrupted"):
            _delete_cached_pkg()
            _set_state(STATE_NOT_STARTED)
            ensure_download_started()
        else:
            _set_state(STATE_DOWNLOADED)


def verify_package(pkg_path: str) -> bool:
    """Verify the pkg against its minisign-signed Phoenix manifest. Non-negotiable.

    The Phoenix pkg carries no Apple Developer ID signature; the manifest saved
    next to it by download_package() is checked against the public key pinned
    in the app, and the pkg against the manifest's sha512 and size.
    """
    manifest = phoenix_packages.verify_cached(pkg_path, "macos-arm64")
    if not manifest:
        logger.warning(f"[INSTALLER] {pkg_path} failed Phoenix signature verification")
        return False
    logger.info(f"[INSTALLER] Package verified (Phoenix agent {manifest.dir})")
    return True


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _set_state(state: str):
    """Persist state transition."""
    settings.set(_NAMESPACE, "install_state", state)
    logger.info(f"[INSTALLER] State -> {state}")


def _fail(state: str, reason: str):
    """Record failure and increment retry counter."""
    with _lock:
        settings.set(_NAMESPACE, "install_state", state)
        settings.set(_NAMESPACE, "failure_reason", reason)
        count = settings.get(_NAMESPACE, "retry_count", 0)
        settings.set(_NAMESPACE, "retry_count", count + 1)
        settings.set(_NAMESPACE, "last_attempt_ts", time.time())
    logger.error(f"[INSTALLER] Failed: state={state} reason={reason}")


def _backoff_elapsed() -> bool:
    """Return True if enough time has passed since last failure."""
    count = settings.get(_NAMESPACE, "retry_count", 0)
    if count >= 5:
        return False  # Max auto-retries exceeded, require manual
    last = settings.get(_NAMESPACE, "last_attempt_ts", 0.0)
    wait = min(60 * (2 ** count), 3600)
    return (time.time() - last) >= wait


def _delete_cached_pkg():
    """Remove cached package file and its signed manifest."""
    phoenix_packages.remove_cached(_CACHED_PKG)
    settings.set(_NAMESPACE, "pkg_cached_path", "")
    settings.set(_NAMESPACE, "pkg_cached_version", "")


def _do_download():
    """Execute the download and verify signature."""
    from plugins.wazuh.agent.wazuh_functions_darwin import download_package

    pkg_path = download_package(output_path=_CACHED_PKG)
    if not pkg_path:
        # Network, sign-in and signature problems all land here; the log
        # has the reason.
        _fail(STATE_DOWNLOAD_FAILED, "dns_failed")
        return

    if not verify_package(pkg_path):
        _delete_cached_pkg()
        _fail(STATE_DOWNLOAD_FAILED, "signature_invalid")
        return

    manifest = phoenix_packages.verify_cached(pkg_path, "macos-arm64")
    with _lock:
        settings.set(_NAMESPACE, "pkg_cached_path", pkg_path)
        settings.set(_NAMESPACE, "pkg_cached_version", manifest.dir if manifest else "")
        settings.set(_NAMESPACE, "retry_count", 0)
        _set_state(STATE_DOWNLOADED)


def _install_succeeded(details: dict):
    """Handle successful install completion."""
    enrollment = details.get("enrollment", "")
    if enrollment in ("enrolled", "restored"):
        _set_state(STATE_READY)
    else:
        _set_state(STATE_INSTALLED)

    settings.set(_NAMESPACE, "retry_count", 0)
    settings.set(_NAMESPACE, "enrolled_email", settings.get("auth", "email", ""))
    _delete_cached_pkg()  # Clean up cache after successful install
    logger.info(f"[INSTALLER] Install succeeded, enrollment={enrollment}")
