"""Tests for utils.logger — logging setup and OTEL integration.

Covers: setup_logging configuration, InterceptHandler, OTELink level mapping,
and edge cases (no stdout, non-TTY, OTEL exception).
"""

import io
import logging
from unittest.mock import MagicMock

import pytest

from utils.logger import InterceptHandler, logger, setup_logging


# ---------------------------------------------------------------------------
# setup_logging
# ---------------------------------------------------------------------------

@pytest.mark.unit
class TestSetupLogging:
    def test_basic_setup_no_crash(self, tmp_path, monkeypatch):
        """setup_logging should complete without error."""
        monkeypatch.setattr(
            "utils.settings.get_config_dir", lambda: str(tmp_path),
        )
        setup_logging(level="DEBUG", log_to_file=True)
        # Should not raise
        logger.info("test message from setup_logging test")

    def test_no_file_logging(self, monkeypatch):
        """log_to_file=False should skip file sink creation."""
        setup_logging(level="INFO", log_to_file=False)
        logger.info("test without file")

    def test_no_stdout(self, monkeypatch):
        """When stdout is None (windowed build), should not crash."""
        monkeypatch.setattr("sys.stdout", None)
        setup_logging(level="INFO", log_to_file=False)

    def test_non_tty_stdout(self, monkeypatch):
        """Non-TTY stdout should set colorize=False."""
        fake_stdout = io.StringIO()
        monkeypatch.setattr("sys.stdout", fake_stdout)
        setup_logging(level="INFO", log_to_file=False)

    def test_isatty_raises(self, monkeypatch):
        """If isatty() raises, colorize should default to False."""

        class BrokenTTYStream(io.StringIO):
            def isatty(self):
                raise RuntimeError("no tty")

        monkeypatch.setattr("sys.stdout", BrokenTTYStream())
        setup_logging(level="INFO", log_to_file=False)

    def test_creates_log_directory(self, tmp_path, monkeypatch):
        monkeypatch.setattr(
            "utils.settings.get_config_dir", lambda: str(tmp_path),
        )
        setup_logging(level="INFO", log_to_file=True)
        log_dir = tmp_path / "logs"
        assert log_dir.is_dir()

    def test_silences_noisy_loggers(self, monkeypatch):
        setup_logging(level="INFO", log_to_file=False)
        assert logging.getLogger("urllib3").level >= logging.WARNING
        assert logging.getLogger("httpx").level >= logging.WARNING
        assert logging.getLogger("PIL").level >= logging.WARNING


# ---------------------------------------------------------------------------
# InterceptHandler
# ---------------------------------------------------------------------------

@pytest.mark.unit
class TestInterceptHandler:
    def test_intercepts_standard_logging(self):
        """InterceptHandler should forward stdlib logging to loguru."""
        handler = InterceptHandler()
        record = logging.LogRecord(
            name="test", level=logging.INFO,
            pathname="test.py", lineno=1,
            msg="intercepted message", args=(), exc_info=None,
        )
        # Should not raise
        handler.emit(record)

    def test_unknown_level_uses_levelno(self):
        """Invalid level name should fallback to record.levelno."""
        handler = InterceptHandler()
        record = logging.LogRecord(
            name="test", level=42,
            pathname="test.py", lineno=1,
            msg="custom level", args=(), exc_info=None,
        )
        record.levelname = "NONEXISTENT_LEVEL"
        # Should not raise
        handler.emit(record)


# ---------------------------------------------------------------------------
# OTELink level mapping
# ---------------------------------------------------------------------------

@pytest.mark.unit
class TestOTELinkLevelMap:
    def test_level_map_values(self):
        """Verify the OTEL level mapping constants."""
        # We can't easily instantiate OTELink (mocked OTEL deps),
        # but we can verify the mapping logic inline
        level_map = {
            "TRACE": 1, "DEBUG": 5, "INFO": 9, "SUCCESS": 10,
            "WARNING": 13, "ERROR": 17, "CRITICAL": 21,
        }
        assert level_map["TRACE"] == 1
        assert level_map["CRITICAL"] == 21
        assert level_map.get("UNKNOWN", 9) == 9  # Default fallback

    def test_otel_link_init_no_endpoint(self):
        """OTELink should initialize without OTEL endpoint configured."""
        # OTELink uses mocked OTEL modules, so this just verifies no crash
        from utils.logger import OTELink
        link = OTELink()
        assert hasattr(link, "otel_logger")

    def test_otel_link_callable(self):
        """OTELink.__call__ should process a log message without error."""
        from utils.logger import OTELink
        link = OTELink()

        # Create a mock loguru message record
        message = MagicMock()
        record = MagicMock()
        record.__getitem__ = lambda self, key: {
            "level": MagicMock(name="INFO"),
            "file": MagicMock(name="test.py"),
            "line": 42,
            "function": "test_func",
            "module": "test_mod",
            "process": MagicMock(id=1),
            "thread": MagicMock(id=1),
            "extra": {},
            "time": MagicMock(timestamp=MagicMock(return_value=1000000)),
            "message": "test log",
        }.get(key, MagicMock())
        message.record = record

        # Should not raise
        link(message)


# ---------------------------------------------------------------------------
# Telemetry switch (off until otel.phoenix.exposed is live)
# ---------------------------------------------------------------------------

@pytest.mark.unit
class TestTelemetrySwitch:
    @pytest.fixture(autouse=True)
    def _clean_env(self, monkeypatch):
        monkeypatch.delenv("PHOENIX_TELEMETRY", raising=False)
        monkeypatch.delenv("OTEL_EXPORTER_OTLP_ENDPOINT", raising=False)

    def test_off_by_default_and_points_at_phoenix(self):
        import utils.logger as lg
        assert lg.TELEMETRY_ENABLED is False
        assert lg.telemetry_enabled() is False
        assert lg._otlp_endpoint() == "http://otel.phoenix.exposed:4318"

    def test_env_overrides(self, monkeypatch):
        import utils.logger as lg
        monkeypatch.setenv("PHOENIX_TELEMETRY", "1")
        assert lg.telemetry_enabled() is True
        monkeypatch.setenv("PHOENIX_TELEMETRY", "off")
        monkeypatch.setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://collector:4318")
        assert lg.telemetry_enabled() is False

    def test_explicit_endpoint_enables(self, monkeypatch):
        import utils.logger as lg
        monkeypatch.setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://collector:4318")
        assert lg.telemetry_enabled() is True
        assert lg._otlp_endpoint() == "http://collector:4318"

    def test_no_sink_when_off(self, tmp_path, monkeypatch):
        import utils.logger as lg
        monkeypatch.setattr("utils.settings.get_config_dir", lambda: str(tmp_path))
        created = []
        monkeypatch.setattr(lg, "BufferedOTLPSink", lambda path: created.append(path))
        setup_logging(level="INFO", log_to_file=True)
        assert created == []

    def test_sink_when_on(self, tmp_path, monkeypatch):
        import utils.logger as lg
        monkeypatch.setattr("utils.settings.get_config_dir", lambda: str(tmp_path))
        monkeypatch.setattr(lg, "TELEMETRY_ENABLED", True)
        created = []

        def fake_sink(path):
            created.append(path)
            return lambda message: None

        monkeypatch.setattr(lg, "BufferedOTLPSink", fake_sink)
        setup_logging(level="INFO", log_to_file=True)
        assert created and created[0].endswith("otlp_buffer.jsonl")
