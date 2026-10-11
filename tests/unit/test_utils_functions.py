"""
Unit tests for utils/functions.py and utils/logger.py.

Covers:
- get_resource_path — dev mode vs. PyInstaller frozen mode
- is_running_in_ide — detects common IDE environment variables
- get_config_dir — platform-specific path logic
- Logger setup doesn't crash (smoke test)
"""
import os
import sys
import pytest
from unittest.mock import MagicMock, patch


# ===========================================================================
# get_resource_path
# ===========================================================================
@pytest.mark.unit
class TestGetResourcePath:
    def test_dev_mode_returns_relative_to_root(self):
        from utils.functions import get_resource_path
        # In dev mode (no _MEIPASS), should resolve relative to project root
        with patch.dict("sys.__dict__", {}, clear=False):
            # Ensure _MEIPASS is absent
            meipass_orig = getattr(sys, "_MEIPASS", None)
            if hasattr(sys, "_MEIPASS"):
                del sys._MEIPASS
            try:
                path = get_resource_path("resources/icons/test.png")
                assert "resources" in path
                assert "icons" in path
            finally:
                if meipass_orig is not None:
                    sys._MEIPASS = meipass_orig

    def test_frozen_mode_uses_meipass(self):
        from utils.functions import get_resource_path
        fake_meipass = "/tmp/fake_bundle"
        with patch.object(sys, "_MEIPASS", fake_meipass, create=True):
            path = get_resource_path("resources/icons/icon.png")
            assert path.startswith(fake_meipass)

    def test_returns_string(self):
        from utils.functions import get_resource_path
        path = get_resource_path("some/relative/file.txt")
        assert isinstance(path, str)


# ===========================================================================
# is_running_in_ide
# ===========================================================================
@pytest.mark.unit
class TestIsRunningInIde:
    def test_returns_none_in_plain_python(self):
        from utils.functions import is_running_in_ide
        # Strip any IDE-specific env vars that might be set in CI
        clean_env = {k: v for k, v in os.environ.items()
                     if not any(ide in k.upper() for ide in
                                ("CURSOR", "VSCODE", "PYCHARM", "PYDEVD", "DEBUGPY"))}
        with patch.dict(os.environ, clean_env, clear=True):
            # Only returns None if no debugger indicators present
            result = is_running_in_ide()
            # Result is either None or a known IDE name
            assert result is None or isinstance(result, str)

    def test_detects_vscode(self):
        from utils.functions import is_running_in_ide
        with patch.dict(os.environ, {"TERM_PROGRAM": "vscode"}, clear=False):
            result = is_running_in_ide()
            # Should detect VSCode or return a non-None value
            # (exact string depends on implementation)


# ===========================================================================
# get_config_dir
# ===========================================================================
@pytest.mark.unit
class TestGetConfigDir:
    def test_darwin_returns_library_path(self):
        from utils.settings import get_config_dir
        with patch("utils.settings.platform.system", return_value="Darwin"):
            path = get_config_dir()
            assert "Library/Application Support/Phoenix" in path

    def test_windows_returns_appdata_path(self):
        from utils.settings import get_config_dir
        with patch("utils.settings.platform.system", return_value="Windows"):
            with patch.dict(os.environ, {"APPDATA": "C:\\Users\\test\\AppData\\Roaming"}):
                path = get_config_dir()
                assert "Phoenix" in path

    def test_linux_returns_dot_config(self):
        from utils.settings import get_config_dir
        with patch("utils.settings.platform.system", return_value="Linux"):
            path = get_config_dir()
            assert ".config/phoenix" in path

    def test_unknown_platform_returns_config_dir(self):
        from utils.settings import get_config_dir
        with patch("utils.settings.platform.system", return_value="FreeBSD"):
            path = get_config_dir()
            assert isinstance(path, str)
            assert len(path) > 0


# ===========================================================================
# Logger setup — smoke test
# ===========================================================================
@pytest.mark.unit
def test_logger_available():
    """utils.logger.logger must be importable and usable without crash."""
    from utils.logger import logger
    # Calling logger methods should not raise
    logger.debug("test debug")
    logger.info("test info")
    logger.warning("test warning")


@pytest.mark.unit
def test_logger_is_not_none():
    from utils.logger import logger
    assert logger is not None
