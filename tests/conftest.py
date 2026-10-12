"""
Shared pytest fixtures for the Resistine Desktop test suite.

All fixtures here are available to every test file without importing.
Key design goals:
- Never touch the real ~/.config/resistine or ~/Library/Application Support/Resistine
- Never touch the real system keyring
- Never make real network requests unless the test is explicitly marked @pytest.mark.network
- Never call real subprocess commands unless explicitly mocked
- Never open real log file handles or create real ProgramData directories
"""
import json
import logging
import os
import sys
import tempfile
from pathlib import Path
from unittest.mock import MagicMock

import pytest

# ---------------------------------------------------------------------------
# Ensure the project root is on sys.path so all project imports resolve.
# ---------------------------------------------------------------------------
PROJECT_ROOT = Path(__file__).parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


# ---------------------------------------------------------------------------
# Prevent module-load-time side effects from Windows code paths.
#
# Importing services.windows_vpn_service triggers:
#   logging.basicConfig(filename=r"C:\ProgramData\Resistine\vpn_service.log", ...)
#   os.makedirs(r"C:\ProgramData\Resistine\wireguard", exist_ok=True)
# On non-Windows or on real Windows outside the test env those would open
# real file handles / create real directories. Redirect them to a temp path
# BEFORE any test module imports the service.
# ---------------------------------------------------------------------------
_TEST_TMP_ROOT = Path(tempfile.gettempdir()) / "resistine_tests"
_TEST_TMP_ROOT.mkdir(exist_ok=True)
# NOTE: make sure it's an assignment here... not os.environ.setdefault. On
# Windows PROGRAMDATA is always pre-set, so setdefault was silently a no-op
# and tests were writing real files into C:\ProgramData\Resistine\. - Austin
_ORIGINAL_PROGRAMDATA = os.environ.get("PROGRAMDATA")
_ORIGINAL_APPDATA = os.environ.get("APPDATA")
os.environ["PROGRAMDATA"] = str(_TEST_TMP_ROOT / "ProgramData")
os.environ["APPDATA"] = str(_TEST_TMP_ROOT / "AppData")
(_TEST_TMP_ROOT / "ProgramData").mkdir(exist_ok=True)
(_TEST_TMP_ROOT / "AppData").mkdir(exist_ok=True)

# Seed a stub IPC token at the path the service_client / tray expect, so
# send_command() tests don't short-circuit with "IPC token unavailable"
# before their mocks run. Path mirrors plugins/vpn/wireguard/
# windows_vpn_service.IPC_TOKEN_FILE.
_TEST_TOKEN_DIR = _TEST_TMP_ROOT / "ProgramData" / "Resistine" / "wireguard"
_TEST_TOKEN_DIR.mkdir(parents=True, exist_ok=True)
(_TEST_TOKEN_DIR / ".ipc_token").write_text("test_stub_ipc_token_" + "0" * 40)

# NOTE: this logging.basicConfig wrapper is here because
# services.windows_vpn_service calls logging.basicConfig(filename=...) at
# module import time, and the path it hands over is a real
# C:\ProgramData\Resistine\vpn_service.log location. Without this sandbox
# every test import opens a real log file handle on your system and keeps
# appending to it across runs. Please don't try to simplify this (even if
# that module later stops configuring logging at import time) without
# checking that no other module is still doing the same, and if you add
# any new "filename=" bail-outs in the test tree please route them
# through here too, otherwise you'll have to deal with real log files
# growing in C:\ProgramData. - Austin
_original_basic_config = logging.basicConfig
def _sandboxed_basic_config(*args, **kwargs):
    """Redirect any filename= into the test tmp root so imports don't open real log paths."""
    if "filename" in kwargs and kwargs["filename"]:
        name = os.path.basename(str(kwargs["filename"]))
        kwargs["filename"] = str(_TEST_TMP_ROOT / name)
    return _original_basic_config(*args, **kwargs)
logging.basicConfig = _sandboxed_basic_config


# ---------------------------------------------------------------------------
# Stub out GUI-heavy dependencies before any project code is imported.
# Some modules import customtkinter at module load time; this prevents them
# from crashing on a headless CI server.
# ---------------------------------------------------------------------------
def _stub_gui_modules():
    """Insert lightweight stubs for GUI libraries not available in CI."""
    for mod_name in [
        # GUI toolkits
        "customtkinter",
        "tkinter",
        "tkinter.ttk",
        "tkinter.font",
        "PIL",
        "PIL.Image",
        "pystray",
        # OpenTelemetry — heavy dependency, not needed for tests
        "opentelemetry",
        "opentelemetry._logs",
        "opentelemetry.exporter",
        "opentelemetry.exporter.otlp",
        "opentelemetry.exporter.otlp.proto",
        "opentelemetry.exporter.otlp.proto.http",
        "opentelemetry.exporter.otlp.proto.http._log_exporter",
        "opentelemetry.sdk",
        "opentelemetry.sdk._logs",
        "opentelemetry.sdk._logs.export",
        "opentelemetry.sdk.resources",
        "opentelemetry.sdk.util",
        "opentelemetry.sdk.util.instrumentation",
        "opentelemetry.trace",
        # ServiceManagement (macOS only, not available in tests)
        "ServiceManagement",
    ]:
        if mod_name not in sys.modules:
            stub = MagicMock()
            sys.modules[mod_name] = stub

    # customtkinter.CTkImage must behave like a class
    ctk = sys.modules.get("customtkinter")
    if ctk:
        ctk.CTkImage = MagicMock(return_value=MagicMock())
        ctk.set_default_color_theme = MagicMock()
        ctk.set_appearance_mode = MagicMock()

    # opentelemetry stubs need realistic attributes
    otel_logs = sys.modules.get("opentelemetry._logs")
    if otel_logs:
        otel_logs.set_logger_provider = MagicMock()
        otel_logs.LogRecord = MagicMock()

    otel_trace = sys.modules.get("opentelemetry.trace")
    if otel_trace:
        mock_span = MagicMock()
        mock_span.get_span_context.return_value = MagicMock(is_valid=False)
        otel_trace.get_current_span = MagicMock(return_value=mock_span)


_stub_gui_modules()


# ---------------------------------------------------------------------------
# Win32 module stubs. On non-Windows these modules don't exist; on Windows
# we still stub them during tests so we never touch real services/registry.
#
# MagicMock records every call in call_args_list, which grows unboundedly
# across the suite. We keep the stubs in _WIN32_STUBS and reset all of them
# between tests via the autouse fixture below.
# ---------------------------------------------------------------------------
_WIN32_STUBS = {}
def _stub_win32_modules():
    for mod_name in [
        "win32serviceutil", "win32service", "win32event",
        "servicemanager", "win32con", "pywintypes", "pythoncom",
        "winreg",
    ]:
        if mod_name not in sys.modules:
            stub = MagicMock()
            sys.modules[mod_name] = stub
            _WIN32_STUBS[mod_name] = stub
        elif isinstance(sys.modules[mod_name], MagicMock):
            _WIN32_STUBS[mod_name] = sys.modules[mod_name]

    # ctypes exists on all platforms but .windll is Windows-only.
    # Provide a MagicMock .windll so ctypes.windll.shell32.IsUserAnAdmin() works.
    try:
        import ctypes
        if not hasattr(ctypes, "windll") or not isinstance(getattr(ctypes, "windll", None), MagicMock):
            ctypes.windll = MagicMock()
        _WIN32_STUBS["ctypes.windll"] = ctypes.windll
    except ImportError:
        pass

_stub_win32_modules()


@pytest.fixture(autouse=True)
def _reset_win32_mocks():
    # NOTE: the reset_mock call below is what keeps the suite's memory from
    # accumulating. These win32 stubs (servicemanager, win32event, winreg,
    # etc.) are shared across every test, and MagicMock quietly records every
    # call it ever receives into .call_args_list/.mock_calls. Over ~700 tests
    # that pile of references added up per run and was part of what pushed
    # older implementations toward 100% memory. If you add more module-level
    # stubs in the future, please register them in _WIN32_STUBS so they get
    # reset here too, otherwise you run the risk of memory problems. - Austin
    yield
    for stub in _WIN32_STUBS.values():
        try:
            stub.reset_mock(return_value=False, side_effect=False)
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Subprocess safety net.
#
# NOTE: this guard is here because I noticed that the suite actually ran
# `NET STOP WazuhSvc`, `Stop-Service`, and `sudo` on my real system during
# one of the earlier successful runs... some production helpers like
# start_agent/stop_agent/install_tunnel shell out to real system commands,
# and a test that forgets to mock subprocess will easily execute them on
# the host. Please don't remove this without a good reason (redone
# implementation etc.) and if a specific test needs a real subprocess, use
# the `allow_subprocess` that's already there instead of deleting the guard
# so nobody else runs into any issues related to this. - Austin
#
# This fixture replaces subprocess.run with a stub that returns a harmless
# result and records the attempt. Tests that need specific subprocess
# behavior must opt in by calling `allow_subprocess()` or patching
# subprocess.run themselves within a local patch context.
# ---------------------------------------------------------------------------
@pytest.fixture(autouse=True)
def _block_real_subprocess(request, monkeypatch):
    """Prevent any unmocked test from shelling out to the real machine.

    Opt out in a test by requesting the `allow_subprocess` fixture, or by
    patching subprocess.run inside the test (the inner patch wins).
    """
    if "allow_subprocess" in request.fixturenames:
        yield
        return

    import subprocess as _sp
    _real_run = _sp.run
    _real_check_output = _sp.check_output
    _real_popen = _sp.Popen

    def _blocked_run(*args, **kwargs):
        # Return a neutral "command not run" result so functions that call
        # subprocess.run at import time don't crash. Tests that want specific
        # behavior must set up their own patch.
        result = MagicMock()
        result.returncode = 1
        result.stdout = ""
        result.stderr = "blocked by _block_real_subprocess"
        result.args = args[0] if args else kwargs.get("args", [])
        return result

    def _blocked_check_output(*args, **kwargs):
        raise _sp.CalledProcessError(1, args[0] if args else "", "blocked by _block_real_subprocess")

    def _blocked_popen(*args, **kwargs):
        m = MagicMock()
        m.communicate.return_value = (b"", b"blocked")
        m.returncode = 1
        return m

    monkeypatch.setattr("subprocess.run", _blocked_run)
    monkeypatch.setattr("subprocess.check_output", _blocked_check_output)
    monkeypatch.setattr("subprocess.Popen", _blocked_popen)
    yield


@pytest.fixture
def allow_subprocess():
    """Opt-in marker to allow real subprocess calls in a test. Use only for
    explicit integration tests marked @pytest.mark.slow or @pytest.mark.network."""
    return True


# ---------------------------------------------------------------------------
# Settings safety net: no test writes the developer's real config.
#
# Like the subprocess guard: code under test that saves a setting (e.g. the
# antivirus plugin recording the last scan for the Dashboard) used to write
# ~/.config/phoenix of whoever ran the suite. Every test now starts with
# settings redirected to its own temp dir; `tmp_config_dir` /
# `isolated_settings` still give a test the path explicitly.
# ---------------------------------------------------------------------------
@pytest.fixture(autouse=True)
def _isolate_settings_dir(request, tmp_path_factory, monkeypatch):
    if request.node.get_closest_marker("real_config_dir"):
        yield  # tests of get_config_dir itself mock platform/env instead
        return
    config_dir = tmp_path_factory.mktemp("phoenix_config")
    monkeypatch.setattr("utils.settings.get_config_dir", lambda: str(config_dir))
    yield


# ---------------------------------------------------------------------------
# Isolated config directory — each test gets its own temp dir
# ---------------------------------------------------------------------------
@pytest.fixture()
def tmp_config_dir(tmp_path, monkeypatch):
    """Redirect all settings I/O to a private temp directory."""
    config_dir = tmp_path / "resistine_config"
    config_dir.mkdir()
    monkeypatch.setattr("utils.settings.get_config_dir", lambda: str(config_dir))
    return config_dir


# ---------------------------------------------------------------------------
# Mock keyring — never touch the real OS keyring during tests
# ---------------------------------------------------------------------------
@pytest.fixture()
def mock_keyring(monkeypatch):
    """In-memory keyring replacement.

    Provides get_password / set_password / delete_password backed by a dict.
    Monkeypatches the keyring module used by utils.settings and utils.encryption.
    """
    store: dict[tuple, str] = {}

    def _get(service, username):
        return store.get((service, username))

    def _set(service, username, password):
        store[(service, username)] = password

    def _delete(service, username):
        store.pop((service, username), None)

    mock_kr = MagicMock()
    mock_kr.get_password.side_effect = _get
    mock_kr.set_password.side_effect = _set
    mock_kr.delete_password.side_effect = _delete

    # Provide a mock backend class that looks "secure"
    mock_backend = MagicMock()
    mock_backend.__class__.__name__ = "SecureBackend"
    mock_backend.__class__.__module__ = "keyring.backends.macOS"
    mock_kr.get_keyring.return_value = mock_backend

    monkeypatch.setattr("utils.settings.keyring", mock_kr)
    monkeypatch.setattr("utils.encryption.keyring", mock_kr, raising=False)

    return mock_kr, store


# ---------------------------------------------------------------------------
# Convenience: settings with both tmp_config_dir + mock_keyring
# ---------------------------------------------------------------------------
@pytest.fixture()
def isolated_settings(tmp_config_dir, mock_keyring):
    """Return the settings module pre-configured for isolation."""
    import utils.settings as s
    return s


# ---------------------------------------------------------------------------
# Sample VPN config data
# ---------------------------------------------------------------------------
@pytest.fixture()
def sample_vpn_config_json():
    return {
        "Interface": {
            "PrivateKey": "",
            "Address": "10.0.0.2",
            "DNS": ["10.0.0.53"],
        },
        "Peer": {
            "PublicKey": "ABC123serverPubKey=",
            "AllowedIPs": ["10.0.0.0/24"],
            "Endpoint": "vpn.example.com:51820",
        },
    }


@pytest.fixture()
def sample_wireguard_conf():
    return (
        "[Interface]\n"
        "PrivateKey = myPrivateKey=\n"
        "Address = 10.0.0.2\n"
        "DNS = 10.0.0.53\n"
        "\n"
        "[Peer]\n"
        "PublicKey = serverPubKey=\n"
        "AllowedIPs = 10.0.0.0/24\n"
        "Endpoint = vpn.example.com:51820\n"
    )


# ---------------------------------------------------------------------------
# Wireguard folder (temp)
# ---------------------------------------------------------------------------
@pytest.fixture()
def wireguard_dir(tmp_path):
    wg = tmp_path / "wireguard"
    wg.mkdir()
    return wg


# ---------------------------------------------------------------------------
# Helpers for writing .conf files
# ---------------------------------------------------------------------------
@pytest.fixture()
def write_conf(wireguard_dir, sample_wireguard_conf):
    def _write(name, content=None):
        path = wireguard_dir / f"{name}.conf"
        path.write_text(content or sample_wireguard_conf)
        return path
    return _write


# ---------------------------------------------------------------------------
# Mock requests factory
# ---------------------------------------------------------------------------
@pytest.fixture()
def mock_requests_post(monkeypatch):
    """Return a factory to configure mock POST responses."""
    import requests as req_mod

    call_log = []

    class _MockPost:
        def configure(self, status_code=200, json_body=None, text=None, raise_exc=None):
            mock_resp = MagicMock()
            mock_resp.status_code = status_code
            mock_resp.ok = (200 <= status_code < 300)
            mock_resp.text = text or (json.dumps(json_body) if json_body else "")
            if json_body is not None:
                mock_resp.json.return_value = json_body
            else:
                mock_resp.json.side_effect = ValueError("no content")

            if raise_exc:
                monkeypatch.setattr(req_mod, "post", MagicMock(side_effect=raise_exc))
            else:
                def _post(*args, **kwargs):
                    call_log.append({"args": args, "kwargs": kwargs})
                    return mock_resp
                monkeypatch.setattr(req_mod, "post", _post)
            return mock_resp

    mp = _MockPost()
    mp.call_log = call_log
    return mp
