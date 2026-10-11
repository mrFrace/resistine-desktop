"""Tests for plugins.antivirus.scanner — high-level scan runner.

Covers: ScanResult dataclass, ScanHandle cancellation, scan() function
with all code paths (not available, success, cancel, exception).
"""

import threading
from unittest.mock import patch

import pytest

from plugins.antivirus.scanner import ScanHandle, ScanResult, scan


# ---------------------------------------------------------------------------
# ScanResult dataclass
# ---------------------------------------------------------------------------

@pytest.mark.unit
class TestScanResult:
    def test_defaults(self):
        r = ScanResult()
        assert r.target == ""
        assert r.scanned == 0
        assert r.infected == 0
        assert r.infections == []
        assert r.duration == ""
        assert r.error == ""

    def test_custom_values(self):
        r = ScanResult(
            target="/tmp/test", scanned=10, infected=2,
            infections=["virus1", "virus2"], duration="5s", error="",
        )
        assert r.target == "/tmp/test"
        assert r.scanned == 10
        assert r.infected == 2
        assert len(r.infections) == 2

    def test_infections_list_independent(self):
        """Each ScanResult gets its own infections list (not shared)."""
        r1 = ScanResult()
        r2 = ScanResult()
        r1.infections.append("virus")
        assert r2.infections == []


# ---------------------------------------------------------------------------
# ScanHandle
# ---------------------------------------------------------------------------

@pytest.mark.unit
class TestScanHandle:
    def test_initial_not_cancelled(self):
        h = ScanHandle()
        assert h.cancelled is False

    def test_cancel_sets_flag(self):
        h = ScanHandle()
        h.cancel()
        assert h.cancelled is True

    def test_cancel_is_idempotent(self):
        h = ScanHandle()
        h.cancel()
        h.cancel()
        assert h.cancelled is True

    def test_internal_event_is_threading_event(self):
        h = ScanHandle()
        assert isinstance(h._cancelled, threading.Event)


# ---------------------------------------------------------------------------
# scan() function
# ---------------------------------------------------------------------------

@pytest.mark.unit
class TestScan:
    def test_not_available_calls_on_complete_sync(self):
        """When ClamAV is not available, on_complete is called synchronously."""
        results = []
        with patch("plugins.antivirus.scanner.clamav") as mock_clamav:
            mock_clamav.is_available.return_value = False
            mock_clamav.engine_name.return_value = "ClamAV"
            handle = scan("/tmp/test", on_complete=results.append)

        assert len(results) == 1
        # Message is engine-neutral (ClamAV on macOS/Linux, Defender on Windows).
        assert results[0].error == "ClamAV is not available."
        assert results[0].target == "/tmp/test"
        assert isinstance(handle, ScanHandle)

    def test_not_available_without_callback(self):
        """scan() still returns a handle even without on_complete."""
        with patch("plugins.antivirus.scanner.clamav") as mock_clamav:
            mock_clamav.is_available.return_value = False
            handle = scan("/tmp/test")
            assert isinstance(handle, ScanHandle)

    def test_success_runs_in_thread(self):
        """When ClamAV is available, scan runs in a background thread."""
        completed = threading.Event()
        results = []

        def _on_complete(result):
            results.append(result)
            completed.set()

        with patch("plugins.antivirus.scanner.clamav") as mock_clamav:
            mock_clamav.is_available.return_value = True
            mock_clamav.scan_path.return_value = {
                "target": "/tmp/test",
                "scanned": 5,
                "infected": 0,
                "infections": [],
                "duration": "2s",
                "error": "",
            }
            handle = scan("/tmp/test", on_complete=_on_complete)
            completed.wait(timeout=5)

        assert len(results) == 1
        assert results[0].scanned == 5
        assert results[0].infected == 0
        assert results[0].error == ""

    def test_on_progress_forwarded(self):
        """on_progress callback is passed through to clamav.scan_path."""
        completed = threading.Event()
        progress_lines = []

        def _on_progress(line):
            progress_lines.append(line)

        def _on_complete(result):
            completed.set()

        with patch("plugins.antivirus.scanner.clamav") as mock_clamav:
            mock_clamav.is_available.return_value = True
            mock_clamav.scan_path.return_value = {
                "target": "/tmp/test", "scanned": 0, "infected": 0,
                "infections": [], "duration": "", "error": "",
            }
            scan("/tmp/test", on_progress=_on_progress, on_complete=_on_complete)
            completed.wait(timeout=5)

        # Verify scan_path was called with on_line=on_progress
        call_kwargs = mock_clamav.scan_path.call_args
        assert call_kwargs.kwargs.get("on_line") is _on_progress or call_kwargs[1].get("on_line") is _on_progress

    def test_cancel_during_scan(self):
        """Cancelling the handle before scan_path finishes returns cancelled result."""
        completed = threading.Event()
        results = []

        def _slow_scan(*args, **kwargs):
            cancel = kwargs.get("cancel")
            # Simulate the cancel being set during the scan
            if cancel:
                cancel.wait(timeout=2)
            return {
                "target": "/tmp/test", "scanned": 0, "infected": 0,
                "infections": [], "duration": "", "error": "Scan cancelled.",
            }

        def _on_complete(result):
            results.append(result)
            completed.set()

        with patch("plugins.antivirus.scanner.clamav") as mock_clamav:
            mock_clamav.is_available.return_value = True
            mock_clamav.scan_path.side_effect = _slow_scan

            handle = scan("/tmp/test", on_complete=_on_complete)
            handle.cancel()
            completed.wait(timeout=5)

        assert len(results) == 1
        assert "cancelled" in results[0].error.lower()

    def test_exception_in_scan_path(self):
        """Exception during scan_path is caught and returned as error."""
        completed = threading.Event()
        results = []

        def _on_complete(result):
            results.append(result)
            completed.set()

        with patch("plugins.antivirus.scanner.clamav") as mock_clamav:
            mock_clamav.is_available.return_value = True
            mock_clamav.scan_path.side_effect = RuntimeError("disk exploded")

            scan("/tmp/test", on_complete=_on_complete)
            completed.wait(timeout=5)

        assert len(results) == 1
        assert "disk exploded" in results[0].error

    def test_scan_maps_raw_dict_to_dataclass(self):
        """Verify all fields from scan_path dict are mapped to ScanResult."""
        completed = threading.Event()
        results = []

        def _on_complete(result):
            results.append(result)
            completed.set()

        with patch("plugins.antivirus.scanner.clamav") as mock_clamav:
            mock_clamav.is_available.return_value = True
            mock_clamav.scan_path.return_value = {
                "target": "/home/user/docs",
                "scanned": 42,
                "infected": 3,
                "infections": ["f1: Trojan FOUND", "f2: Worm FOUND", "f3: Ransom FOUND"],
                "duration": "10.5 sec",
                "error": "",
            }
            scan("/home/user/docs", on_complete=_on_complete)
            completed.wait(timeout=5)

        r = results[0]
        assert r.target == "/home/user/docs"
        assert r.scanned == 42
        assert r.infected == 3
        assert len(r.infections) == 3
        assert r.duration == "10.5 sec"
        assert r.error == ""
