import json
import logging
import os
import sys
import threading
import time

from loguru import logger
from opentelemetry import _logs
from opentelemetry.exporter.otlp.proto.http._log_exporter import OTLPLogExporter
from opentelemetry.sdk._logs import LoggerProvider, ReadableLogRecord
from opentelemetry.sdk._logs.export import BatchLogRecordProcessor
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.util.instrumentation import InstrumentationScope
from opentelemetry.trace import get_current_span


_DEFAULT_OTLP_ENDPOINT = "http://otel.phoenix.exposed:4318"

# Log shipping is off until the Phoenix collector (otel.phoenix.exposed) is
# live; the old otel.resisti.net no longer resolves and the exporter filled
# the log with retry errors every 30 s. Flip this to True to turn it back on.
# PHOENIX_TELEMETRY=1/0 overrides it either way, and setting
# OTEL_EXPORTER_OTLP_ENDPOINT (a collector to test against) also enables it.
TELEMETRY_ENABLED = False


def _otlp_endpoint():
    return os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT", _DEFAULT_OTLP_ENDPOINT)


def telemetry_enabled() -> bool:
    """Whether log records are shipped to the OTLP collector."""
    flag = os.environ.get("PHOENIX_TELEMETRY", "").strip().lower()
    if flag in ("1", "true", "yes", "on"):
        return True
    if flag in ("0", "false", "no", "off"):
        return False
    if os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT"):
        return True
    return TELEMETRY_ENABLED


# Loguru level name -> OTEL severity_number per OTEL log data model spec
_SEVERITY_NUMBER_BY_LEVEL = {
    "TRACE": 1, "DEBUG": 5, "INFO": 9, "SUCCESS": 10,
    "WARNING": 13, "ERROR": 17, "CRITICAL": 21,
}


class OTELink:
    """
    A sink for Loguru that sends logs to OpenTelemetry.
    """

    def __init__(self):
        # Initialize OTEL Logger Provider
        resource = Resource.create(
            {
                "service.name": "phoenix-desktop",
                "service.version": "1.0.0",
            }
        )

        self.logger_provider = LoggerProvider(resource=resource)
        _logs.set_logger_provider(self.logger_provider)

        # OTLP/HTTP receiver. Default routes to the Phoenix collector, which
        # forwards into the wazuh-indexer. Reachable only over the VPN; the
        # BatchLogRecordProcessor silently drops batches when unreachable.
        exporter = OTLPLogExporter(endpoint=f"{_otlp_endpoint()}/v1/logs")
        self.logger_provider.add_log_record_processor(
            BatchLogRecordProcessor(exporter)
        )

        self.otel_logger = self.logger_provider.get_logger("phoenix.logger")

    def __call__(self, message):
        record = message.record

        # Map Loguru level to OTEL Severity Number
        level_map = {
            "TRACE": 1,
            "DEBUG": 5,
            "INFO": 9,
            "SUCCESS": 10,
            "WARNING": 13,
            "ERROR": 17,
            "CRITICAL": 21,
        }

        severity_number = level_map.get(record["level"].name, 9)

        # Get trace context if available
        span = get_current_span()
        span_context = span.get_span_context()

        attributes = {
            "filename": record["file"].name,
            "line": record["line"],
            "function": record["function"],
            "module": record["module"],
            "process.id": record["process"].id,
            "thread.id": record["thread"].id,
        }

        # Add extra attributes from Loguru's 'extra' dict
        if record["extra"]:
            attributes.update(record["extra"])

        # Emit to OTEL
        log_record = _logs.LogRecord(
            timestamp=int(record["time"].timestamp() * 1e9),
            observed_timestamp=int(record["time"].timestamp() * 1e9),
            trace_id=span_context.trace_id if span_context.is_valid else None,
            span_id=span_context.span_id if span_context.is_valid else None,
            trace_flags=span_context.trace_flags if span_context.is_valid else None,
            severity_text=record["level"].name,
            severity_number=severity_number,
            body=record["message"],
            attributes=attributes,
        )

        self.otel_logger.emit(log_record)


class BufferedOTLPSink:
    """Loguru sink: disk-buffers records, ships them via OTLP when the
    collector becomes reachable. Ships whatever level Loguru passes it.

    Survives VPN outages and process restarts. Buffer file is capped; on
    overflow the oldest half is dropped. All sink-side failures are
    swallowed so logging never raises.
    """

    _FLUSH_INTERVAL_SEC = 30
    _FIRST_FLUSH_DELAY_SEC = 5
    _MAX_BUFFER_BYTES = 5 * 1024 * 1024  # 5 MB
    _EXPORT_TIMEOUT_SEC = 10

    def __init__(self, buffer_path):
        self._buffer_path = buffer_path
        os.makedirs(os.path.dirname(buffer_path), exist_ok=True)
        self._exporter = OTLPLogExporter(
            endpoint=f"{_otlp_endpoint()}/v1/logs",
            timeout=self._EXPORT_TIMEOUT_SEC,
        )
        self._resource = Resource.create({
            "service.name": "phoenix-desktop",
            "service.version": "1.0.0",
        })
        self._scope = InstrumentationScope("phoenix.logger")
        self._lock = threading.Lock()
        threading.Thread(
            target=self._flush_loop,
            name="otlp-buffer-flusher",
            daemon=True,
        ).start()

    def __call__(self, message):
        record = message.record
        entry = {
            "ts_ns": int(record["time"].timestamp() * 1e9),
            "level": record["level"].name,
            "body": record["message"],
            "attrs": {
                "filename": record["file"].name,
                "line": record["line"],
                "function": record["function"],
                "module": record["module"],
            },
        }
        if record["extra"]:
            entry["attrs"].update(
                {str(k): str(v) for k, v in record["extra"].items()}
            )
        if record["exception"]:
            import traceback as _tb
            entry["attrs"]["exception"] = "".join(
                _tb.format_exception(*record["exception"])
            )
        line = json.dumps(entry, default=str) + "\n"
        try:
            with self._lock:
                if (
                    os.path.exists(self._buffer_path)
                    and os.path.getsize(self._buffer_path) > self._MAX_BUFFER_BYTES
                ):
                    self._trim_locked()
                with open(self._buffer_path, "a", encoding="utf-8") as f:
                    f.write(line)
        except Exception:
            pass

    def _trim_locked(self):
        with open(self._buffer_path, "r", encoding="utf-8") as f:
            lines = f.readlines()
        keep = lines[len(lines) // 2:]
        with open(self._buffer_path, "w", encoding="utf-8") as f:
            f.writelines(keep)

    def _flush_loop(self):
        time.sleep(self._FIRST_FLUSH_DELAY_SEC)
        while True:
            try:
                self._flush_once()
            except Exception:
                pass
            time.sleep(self._FLUSH_INTERVAL_SEC)

    def _flush_once(self):
        # Snapshot the buffer under lock — note exact byte count we're shipping
        with self._lock:
            if (
                not os.path.exists(self._buffer_path)
                or os.path.getsize(self._buffer_path) == 0
            ):
                return
            with open(self._buffer_path, "rb") as f:
                raw = f.read()
            sent_bytes = len(raw)

        try:
            lines = raw.decode("utf-8", errors="replace").splitlines()
        except Exception:
            return

        records = []
        for line in lines:
            if not line.strip():
                continue
            try:
                entry = json.loads(line)
                records.append(self._build_readable(entry))
            except Exception:
                continue
        if not records:
            return

        try:
            result = self._exporter.export(records)
            # Compare by name — the public `LogExportResult` enum and the actual
            # returned `LogRecordExportResult` are distinct classes whose members
            # don't compare equal, so identity/equality checks always fail.
            if getattr(result, "name", "") != "SUCCESS":
                return
        except Exception:
            return  # VPN down, DNS fail, etc. — leave buffer for next attempt

        # Successful export — drop only the bytes we shipped, preserving anything
        # appended during the network call
        with self._lock:
            try:
                with open(self._buffer_path, "rb") as f:
                    current = f.read()
                if len(current) <= sent_bytes:
                    os.remove(self._buffer_path)
                else:
                    with open(self._buffer_path, "wb") as f:
                        f.write(current[sent_bytes:])
            except Exception:
                pass

    def _build_readable(self, entry):
        level = entry.get("level", "INFO")
        log_record = _logs.LogRecord(
            timestamp=entry.get("ts_ns"),
            observed_timestamp=entry.get("ts_ns"),
            severity_text=level,
            severity_number=_SEVERITY_NUMBER_BY_LEVEL.get(level, 9),
            body=entry.get("body", ""),
            attributes=entry.get("attrs", {}),
        )
        return ReadableLogRecord(
            log_record=log_record,
            resource=self._resource,
            instrumentation_scope=self._scope,
        )


class InterceptHandler(logging.Handler):
    """
    Default handler from Loguru docs to intercept standard logging messages
    and redirect them to Loguru.
    """

    def emit(self, record):
        # Get corresponding Loguru level if it exists
        try:
            level = logger.level(record.levelname).name
        except ValueError:
            level = record.levelno

        # Find caller from where originated the logged message
        frame, depth = logging.currentframe(), 2
        while frame.f_code.co_filename == logging.__file__:
            frame = frame.f_back
            depth += 1

        logger.opt(depth=depth, exception=record.exc_info).log(
            level, record.getMessage()
        )


def setup_logging(level="INFO", log_to_file=True):
    """
    Configures Loguru to intercept standard logging and adds OTEL sink.
    """
    # Remove default Loguru handler
    logger.remove()

    # On Windows the default console encoding is cp1252 which cannot encode
    # emoji characters used in log messages. Force UTF-8 with replacement
    # so log calls never raise UnicodeEncodeError.
    import platform as _plat
    if _plat.system() == "Windows":
        import io as _io
        for _attr in ("stdout", "stderr"):
            _stream = getattr(sys, _attr, None)
            if _stream is None:
                continue
            if getattr(_stream, "encoding", "utf-8").lower() == "utf-8":
                continue
            # Wrap the raw buffer — more reliable than reconfigure on Windows
            if hasattr(_stream, "buffer"):
                try:
                    _wrapped = _io.TextIOWrapper(
                        _stream.buffer, encoding="utf-8", errors="replace", line_buffering=True
                    )
                    setattr(sys, _attr, _wrapped)
                    continue
                except Exception:
                    pass
            # Fallback: reconfigure in-place
            if hasattr(_stream, "reconfigure"):
                try:
                    _stream.reconfigure(encoding="utf-8", errors="replace")
                except Exception:
                    pass

    # In PyInstaller windowed builds, stdout/stderr can be None.
    console_sink = sys.stdout if getattr(sys, "stdout", None) is not None else getattr(sys, "stderr", None)
    if console_sink is not None and hasattr(console_sink, "write"):
        try:
            colorize = bool(console_sink.isatty())
        except Exception:
            colorize = False

        logger.add(
            console_sink,
            level=level,
            format="<green>{time:YYYY-MM-DD HH:mm:ss}</green> | <level>{level: <8}</level> | <cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> - <level>{message}</level>",
            colorize=colorize,
        )

    # Add file sink
    if log_to_file:
        from utils.settings import get_config_dir

        log_dir = os.path.join(get_config_dir(), "logs")
        os.makedirs(log_dir, exist_ok=True)
        log_file = os.path.join(log_dir, "phoenix.log")
        logger.add(
            log_file,
            level=level,
            rotation="10 MB",
            retention="1 week",
            compression="zip",
            format="{time:YYYY-MM-DD HH:mm:ss} | {level: <8} | {name}:{function}:{line} - {message}",
        )

    # OTLP sink: disk-buffered, flushed to the collector when reachable.
    # Records that happen before the VPN is up are buffered to disk and shipped
    # once the tunnel comes up; survives process restarts too.
    # Off by default until the Phoenix collector exists (see TELEMETRY_ENABLED).
    if log_to_file and telemetry_enabled():
        try:
            from utils.settings import get_config_dir
            buffer_path = os.path.join(
                get_config_dir(), "logs", "otlp_buffer.jsonl",
            )
            logger.add(BufferedOTLPSink(buffer_path), level=level)
        except Exception as e:
            logger.warning(f"Failed to initialize buffered OTLP sink: {e}")

    # Intercept standard logging calls
    logging.basicConfig(handlers=[InterceptHandler()], level=0, force=True)

    # Silence some noisy loggers
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("PIL").setLevel(logging.WARNING)


# Export the logger for convenience
__all__ = ["logger", "setup_logging"]
