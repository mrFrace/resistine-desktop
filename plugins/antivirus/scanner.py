"""High-level scan runner for the Antivirus plugin.

Wraps clamav.scan_path in a background thread so the UI stays responsive.

Author: Phoenix Team
Copyright (c) Phoenix 2025
Licensed under the GNU General Public License v2 or later
"""
from __future__ import annotations

import threading
from collections.abc import Callable
from dataclasses import dataclass, field

from plugins.antivirus import clamav


@dataclass
class ScanResult:
    """Parsed output from a ClamAV scan."""

    target: str = ""
    scanned: int = 0
    infected: int = 0
    infections: list[str] = field(default_factory=list)
    duration: str = ""
    error: str = ""


class ScanHandle:
    """Handle returned by scan() that supports cancellation."""

    def __init__(self):
        self._cancelled = threading.Event()
        self._proc_ref: list = [None]

    @property
    def cancelled(self) -> bool:
        return self._cancelled.is_set()

    def cancel(self):
        self._cancelled.set()
        proc = self._proc_ref[0]
        if proc:
            try:
                proc.kill()
            except OSError:
                pass


def scan(
    target: str,
    on_progress: Callable | None = None,
    on_complete: Callable | None = None,
    on_total: Callable | None = None,
) -> ScanHandle:
    """Run a ClamAV scan on *target* in a background thread.

    Returns a ScanHandle whose cancel() method kills the subprocess.
    """
    handle = ScanHandle()

    if not clamav.is_available():
        result = ScanResult(
            target=target,
            error=f"{clamav.engine_name()} is not available.",
        )
        if on_complete:
            on_complete(result)
        return handle

    def _run():
        try:
            raw = clamav.scan_path(
                target, on_line=on_progress, cancel=handle._cancelled,
                proc_ref=handle._proc_ref, on_total=on_total,
            )
            if handle.cancelled:
                result = ScanResult(target=target, error="Scan cancelled.")
            else:
                result = ScanResult(
                    target=raw["target"],
                    scanned=raw["scanned"],
                    infected=raw["infected"],
                    infections=raw["infections"],
                    duration=raw["duration"],
                    error=raw["error"],
                )
        except Exception as exc:
            result = ScanResult(target=target, error=str(exc))
        if on_complete:
            on_complete(result)

    thread = threading.Thread(target=_run, daemon=True)
    thread.start()
    return handle
