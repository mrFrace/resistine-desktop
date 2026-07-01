"""
Linux Auto-Update Backend — Sparkle-like updater for portable installs.

Fetches the shared appcast.xml feed (same as macOS Sparkle), filters for
Linux entries (sparkle:os="linux"), presents a rich update dialog, downloads
a signed tarball, verifies its Ed25519 signature, extracts in-place over the
running source tree, and restarts the app.

Author: Resistine Team
Copyright (c) Resistine 2025
Licensed under the GNU General Public License v2 or later
"""
from __future__ import annotations

import base64
import os
import shutil
import sys
import tarfile
import tempfile
import threading

import requests

from utils import settings
from utils.logger import logger
from utils.updates.appcast import AppcastItem, get_latest_linux_update
from utils.updates.version import get_current_version, get_project_root

# Ed25519 public key (same key pair used by macOS Sparkle signatures)
_ED25519_PUBLIC_KEY_B64 = "2eiUHVoMgl+qqhEWO8iix5SUcRAKfkWYESh9F7jG6ls="

# Module state
_app = None
_available = False
_checking = False

# Directories to preserve during in-place extraction
_PRESERVE_DIRS = {".venv", ".git", ".claude", "__pycache__"}


# ---------------------------------------------------------------------------
# Public API (matches darwin.py contract, called by manager.py)
# ---------------------------------------------------------------------------


def init_updater(app) -> bool:
    """Initialize the Linux update backend.

    Stores a reference to the app's main window (needed for GUI-thread
    scheduling) and verifies that the version can be read from the spec file.
    """
    global _app, _available

    _app = app
    version = get_current_version()
    if version == "0.0.0":
        logger.warning(
            "[UPDATE-LINUX] Could not read version from spec file; "
            "updater disabled"
        )
        return False

    _available = True
    logger.info(f"[UPDATE-LINUX] Initialized, current version: {version}")
    return True


def check_for_updates():
    """Trigger an interactive update check (shows UI even if up-to-date).

    Returns "up_to_date" on success (Linux updater handles its own UI for
    available updates) or "error" on failure.
    """
    return "up_to_date" if _do_check_async(silent=False) else "error"


def check_for_updates_in_background() -> bool:
    """Trigger a silent background update check (dialog only if update found)."""
    return _do_check_async(silent=True)


def is_available() -> bool:
    """Return True if the update backend is operational."""
    return _available


# ---------------------------------------------------------------------------
# Internal — check logic
# ---------------------------------------------------------------------------


def _do_check_async(silent: bool) -> bool:
    """Spawn a background thread to check for updates."""
    global _checking
    if not _available:
        return False
    if _checking:
        logger.info("[UPDATE-LINUX] Check already in progress, skipping")
        return False

    _checking = True
    t = threading.Thread(target=_do_check, args=(silent,), daemon=True)
    t.start()
    return True


def _do_check(silent: bool):
    """Background thread: fetch appcast, compare versions, show dialog."""
    global _checking
    try:
        current = get_current_version()
        item = get_latest_linux_update(current)

        if item is None:
            if not silent:
                _app.after(0, _show_up_to_date)
            return

        # Check if user previously skipped this version
        skipped = settings.get("updates", "skipped_versions", [])
        if item.version in skipped and silent:
            logger.info(
                f"[UPDATE-LINUX] Version {item.version} was skipped by user"
            )
            return

        _app.after(0, _show_update_dialog, item)
    except Exception as e:
        logger.error(f"[UPDATE-LINUX] Check failed: {e}")
    finally:
        _checking = False


def _show_up_to_date():
    """Show a simple 'you are up to date' dialog (interactive checks only)."""
    from gui.dialogs import show_info

    version = get_current_version()
    show_info(
        _app,
        "Software Update",
        f"You're up to date!\n\nResistine {version} is the latest version.",
    )


def _show_update_dialog(item: AppcastItem):
    """Create and display the Sparkle-like update dialog."""
    from gui.update_dialog import UpdateDialog

    current = get_current_version()

    dialog = UpdateDialog(
        master=_app,
        current_version=current,
        new_version=item.version,
        release_notes_html=item.release_notes_html,
        on_install=lambda: _start_download(item, dialog),
        on_skip=_skip_version,
        on_remind_later=lambda: None,
        on_restart=_restart_app,
    )


# ---------------------------------------------------------------------------
# Internal — skip version persistence
# ---------------------------------------------------------------------------


def _skip_version(version: str):
    """Persist a skipped version so background checks won't nag."""
    skipped = settings.get("updates", "skipped_versions", [])
    if version not in skipped:
        skipped.append(version)
        settings.set("updates", "skipped_versions", skipped)
    logger.info(f"[UPDATE-LINUX] Skipped version {version}")


# ---------------------------------------------------------------------------
# Internal — download and verify
# ---------------------------------------------------------------------------


def _start_download(item: AppcastItem, dialog):
    """Start the download on a background thread."""
    t = threading.Thread(
        target=_download_worker, args=(item, dialog), daemon=True
    )
    t.start()


def _download_worker(item: AppcastItem, dialog):
    """Background thread: download, verify signature, apply update."""
    tmp_dir = os.path.join(tempfile.gettempdir(), "resistine-update")
    os.makedirs(tmp_dir, exist_ok=True)
    tmp_path = os.path.join(tmp_dir, "update.tar.gz")

    try:
        # --- Download with progress ---
        resp = requests.get(
            item.download_url, stream=True, timeout=(30, 120)
        )
        resp.raise_for_status()

        total = item.download_length or int(
            resp.headers.get("Content-Length", 0)
        )
        downloaded = 0

        with open(tmp_path, "wb") as f:
            for chunk in resp.iter_content(chunk_size=65536):
                if dialog.cancelled:
                    logger.info("[UPDATE-LINUX] Download cancelled by user")
                    _cleanup(tmp_path)
                    return

                f.write(chunk)
                downloaded += len(chunk)

                if total > 0:
                    frac = min(downloaded / total, 1.0)
                    mb_down = downloaded / (1024 * 1024)
                    mb_total = total / (1024 * 1024)
                    status = f"Downloading... {mb_down:.1f} / {mb_total:.1f} MB"
                    _app.after(
                        0, dialog.set_download_progress, frac, status
                    )

        _app.after(
            0, dialog.set_download_progress, 1.0, "Verifying signature..."
        )

        # --- Verify Ed25519 signature ---
        if item.signature:
            if not _verify_signature(tmp_path, item.signature):
                _app.after(
                    0,
                    dialog.show_error,
                    "Signature verification failed. The download may be "
                    "corrupted or tampered with.",
                    lambda: _start_download(item, dialog),
                )
                _cleanup(tmp_path)
                return
        else:
            logger.warning(
                "[UPDATE-LINUX] No signature in appcast entry, skipping "
                "verification"
            )

        # --- Apply update ---
        _app.after(
            0, dialog.set_download_progress, 1.0, "Extracting update..."
        )

        success, error = _apply_update(tmp_path)
        _cleanup(tmp_path)

        if success:
            _app.after(0, dialog.show_restart_prompt)
        else:
            _app.after(
                0,
                dialog.show_error,
                f"Failed to apply update: {error}",
                lambda: _start_download(item, dialog),
            )

    except requests.RequestException as e:
        logger.error(f"[UPDATE-LINUX] Download failed: {e}")
        _cleanup(tmp_path)
        _app.after(
            0,
            dialog.show_error,
            f"Download failed: {e}",
            lambda: _start_download(item, dialog),
        )
    except Exception as e:
        logger.error(f"[UPDATE-LINUX] Unexpected error: {e}")
        _cleanup(tmp_path)
        _app.after(0, dialog.show_error, f"Unexpected error: {e}")


def _verify_signature(file_path: str, signature_b64: str) -> bool:
    """Verify an Ed25519 signature against the downloaded file."""
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PublicKey,
        )

        pub_bytes = base64.b64decode(_ED25519_PUBLIC_KEY_B64)
        public_key = Ed25519PublicKey.from_public_bytes(pub_bytes)

        sig_bytes = base64.b64decode(signature_b64)

        with open(file_path, "rb") as f:
            data = f.read()

        public_key.verify(sig_bytes, data)
        logger.info("[UPDATE-LINUX] Signature verification passed")
        return True
    except Exception as e:
        logger.error(f"[UPDATE-LINUX] Signature verification failed: {e}")
        return False


# ---------------------------------------------------------------------------
# Internal — extract and apply
# ---------------------------------------------------------------------------


def _apply_update(archive_path: str) -> tuple[bool, str]:
    """Extract the tarball over the project root, preserving user data.

    Returns (True, "") on success or (False, error_message) on failure.
    """
    project_root = get_project_root()

    try:
        with tarfile.open(archive_path, "r:gz") as tar:
            # Detect if the archive has a single top-level directory
            # (common for GitHub release archives)
            members = tar.getmembers()
            if not members:
                return False, "Archive is empty"

            top_dirs = {m.name.split("/")[0] for m in members if "/" in m.name}
            strip_prefix = ""
            if len(top_dirs) == 1:
                prefix = top_dirs.pop()
                # Verify all members start with this prefix
                if all(
                    m.name == prefix or m.name.startswith(prefix + "/")
                    for m in members
                ):
                    strip_prefix = prefix + "/"

            for member in members:
                # Strip the top-level directory if present
                if strip_prefix:
                    if member.name == strip_prefix.rstrip("/"):
                        continue  # skip the top-level dir itself
                    if not member.name.startswith(strip_prefix):
                        continue
                    member.name = member.name[len(strip_prefix):]

                if not member.name:
                    continue

                # Security: reject path traversal
                dest = os.path.normpath(
                    os.path.join(project_root, member.name)
                )
                if not dest.startswith(os.path.normpath(project_root)):
                    logger.warning(
                        f"[UPDATE-LINUX] Skipping path traversal: "
                        f"{member.name}"
                    )
                    continue

                # Preserve user data directories
                first_component = member.name.split("/")[0]
                if first_component in _PRESERVE_DIRS:
                    continue

                # Extract
                tar.extract(member, project_root, filter="data")

        logger.info("[UPDATE-LINUX] Update extracted successfully")
        return True, ""
    except Exception as e:
        logger.error(f"[UPDATE-LINUX] Extraction failed: {e}")
        return False, str(e)


# ---------------------------------------------------------------------------
# Internal — restart
# ---------------------------------------------------------------------------


def _restart_app():
    """Restart the application by re-executing scripts/run/run.sh."""
    project_root = get_project_root()
    run_script = os.path.join(project_root, "scripts", "run", "run.sh")

    logger.info("[UPDATE-LINUX] Restarting application...")

    if os.path.isfile(run_script):
        try:
            bash = shutil.which("bash") or "/bin/bash"
            os.execv(bash, [bash, run_script])
        except OSError as e:
            logger.error(f"[UPDATE-LINUX] execv failed: {e}")

    # Fallback: re-execute python main.py
    main_py = os.path.join(project_root, "main.py")
    try:
        os.execv(sys.executable, [sys.executable, main_py])
    except OSError as e:
        logger.error(f"[UPDATE-LINUX] Fallback restart failed: {e}")


# ---------------------------------------------------------------------------
# Internal — cleanup
# ---------------------------------------------------------------------------


def _cleanup(path: str):
    """Remove a temporary file, ignoring errors."""
    try:
        if os.path.exists(path):
            os.unlink(path)
    except OSError:
        pass
