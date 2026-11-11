"""AMSI (Antimalware Scan Interface) wrapper for in-process Defender scanning.

Loads amsi.dll via ctypes and provides a fast per-file scan function that
talks directly to the Defender engine without spawning MpCmdRun.exe.
Each scan is ~1-10ms vs ~300-600ms for MpCmdRun process spawn.

The module initializes lazily on first use and is safe to import on
non-Windows platforms (all functions return safe defaults).

Author: Phoenix Team
Copyright (c) Phoenix 2025
Licensed under the GNU General Public License v2 or later
"""
from __future__ import annotations

import ctypes
import os
import sys
import threading
from ctypes import byref, c_uint, c_void_p, c_wchar_p

from utils.logger import logger

# AMSI result codes
AMSI_RESULT_CLEAN = 0
AMSI_RESULT_NOT_DETECTED = 1
AMSI_RESULT_DETECTED = 32768

# Module-level state
_amsi = None  # ctypes.WinDLL handle
_context = c_void_p(0)
_initialized = False
_init_lock = threading.Lock()
_session_local = threading.local()


def _ensure_initialized() -> bool:
    """Lazily initialize AMSI context (once, thread-safe)."""
    global _amsi, _context, _initialized
    if _initialized:
        return _context.value != 0

    with _init_lock:
        if _initialized:
            return _context.value != 0
        _initialized = True

        if sys.platform != "win32":
            return False

        try:
            _amsi = ctypes.windll.LoadLibrary("amsi.dll")
        except OSError:
            logger.warning("AMSI: amsi.dll not found")
            return False

        try:
            hr = _amsi.AmsiInitialize(
                c_wchar_p("Phoenix"), byref(_context),
            )
            if hr != 0:
                logger.warning(f"AMSI: AmsiInitialize failed (HRESULT 0x{hr:08X})")
                _context = c_void_p(0)
                return False
            logger.info("AMSI: initialized successfully")
            return True
        except Exception as e:
            logger.warning(f"AMSI: init error: {e}")
            _context = c_void_p(0)
            return False


def is_available() -> bool:
    """Return True if AMSI is usable on this system."""
    return _ensure_initialized()


def _get_session() -> c_void_p:
    """Get or create a per-thread AMSI session."""
    session = getattr(_session_local, "session", None)
    if session is not None:
        return session

    session = c_void_p(0)
    hr = _amsi.AmsiOpenSession(_context, byref(session))
    if hr != 0:
        logger.debug(f"AMSI: AmsiOpenSession failed (0x{hr:08X}), using null session")
        session = c_void_p(0)
    _session_local.session = session
    return session


def scan_file(filepath: str) -> tuple[bool, str]:
    """Scan a single file via AMSI.

    Returns (is_threat, result_line) where result_line is ClamAV-compatible:
      "filepath: OK" or "filepath: Malware FOUND"
    """
    if not _ensure_initialized():
        return False, f"{filepath}: OK"

    try:
        data = _read_file(filepath)
    except (OSError, PermissionError):
        return False, f"{filepath}: OK"

    if not data:
        return False, f"{filepath}: OK"

    session = _get_session()
    result = c_uint(0)
    filename_w = c_wchar_p(os.path.basename(filepath))

    try:
        hr = _amsi.AmsiScanBuffer(
            _context,
            data,
            len(data),
            filename_w,
            session,
            byref(result),
        )
    except Exception:
        return False, f"{filepath}: OK"

    if hr != 0:
        return False, f"{filepath}: OK"

    if result.value >= AMSI_RESULT_DETECTED:
        return True, f"{filepath}: Malware FOUND"

    return False, f"{filepath}: OK"


def _read_file(filepath: str, max_bytes: int = 64 * 1024 * 1024) -> bytes:
    """Read file contents for AMSI scanning (cap at 64MB)."""
    size = os.path.getsize(filepath)
    if size > max_bytes:
        # Read first + last chunks for large files
        with open(filepath, "rb") as f:
            head = f.read(32 * 1024 * 1024)
            f.seek(-min(size, 32 * 1024 * 1024), 2)
            tail = f.read()
            return head + tail
    with open(filepath, "rb") as f:
        return f.read()
