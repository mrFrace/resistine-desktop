"""Extra tests for plugins.plugin_manager — state persistence and path helpers.

Supplements existing test_plugin_manager.py with coverage for:
- _load_state / _save_state
- get_plugins_path (frozen vs source)
- download_plugin download_order tracking
"""

import json
import os
from unittest.mock import MagicMock, patch

import pytest


@pytest.fixture()
def mgr(tmp_path, monkeypatch):
    monkeypatch.setattr("plugins.plugin_manager.get_config_dir", lambda: str(tmp_path))
    with patch("plugins.plugin_manager.PluginManager.load_plugins", return_value=[]):
        from plugins.plugin_manager import PluginManager
        return PluginManager(MagicMock())


# ---------------------------------------------------------------------------
# _load_state / _save_state
# ---------------------------------------------------------------------------

@pytest.mark.unit
class TestStatePersistence:
    def test_load_default_when_no_file(self, mgr, tmp_path):
        # Remove any state file that init may have created
        sf = tmp_path / "plugin_state.json"
        if sf.exists():
            sf.unlink()
        state = mgr._load_state()
        assert state == {"uninstalled": [], "download_order": {}}

    def test_load_existing_state(self, mgr, tmp_path):
        sf = tmp_path / "plugin_state.json"
        sf.write_text(json.dumps({"uninstalled": ["p1"], "download_order": {"p2": 101}}))
        state = mgr._load_state()
        assert "p1" in state["uninstalled"]
        assert state["download_order"]["p2"] == 101

    def test_load_corrupt_json_returns_default(self, mgr, tmp_path):
        sf = tmp_path / "plugin_state.json"
        sf.write_text("NOT VALID JSON{{{")
        state = mgr._load_state()
        assert state == {"uninstalled": [], "download_order": {}}

    def test_save_state_creates_file(self, mgr, tmp_path):
        mgr.state_file = str(tmp_path / "new_state.json")
        result = mgr._save_state({"uninstalled": ["x"], "download_order": {}})
        assert result is True
        saved = json.loads(open(mgr.state_file).read())
        assert saved["uninstalled"] == ["x"]

    def test_save_state_permission_error(self, mgr):
        mgr.state_file = "/nonexistent/path/state.json"
        result = mgr._save_state({"uninstalled": []})
        assert result is False


# ---------------------------------------------------------------------------
# get_plugins_path
# ---------------------------------------------------------------------------

@pytest.mark.unit
class TestGetPluginsPath:
    def test_source_mode(self, mgr, monkeypatch):
        monkeypatch.setattr("sys.frozen", False, raising=False)
        path = mgr.get_plugins_path()
        assert path.endswith("plugins")
        assert os.path.isabs(path)

    def test_frozen_mode(self, mgr, monkeypatch):
        monkeypatch.setattr("sys.frozen", True, raising=False)
        monkeypatch.setattr("sys._MEIPASS", "/tmp/meipass", raising=False)
        path = mgr.get_plugins_path()
        assert path == os.path.join("/tmp/meipass", "plugins")


# ---------------------------------------------------------------------------
# download_plugin — download_order tracking
# ---------------------------------------------------------------------------

@pytest.mark.unit
class TestDownloadOrder:
    def test_tracks_download_order(self, mgr, tmp_path):
        import io
        import zipfile

        mgr.state_file = str(tmp_path / "plugin_state.json")
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("main.py", "# code")
        zip_bytes = buf.getvalue()

        mock_resp = MagicMock()
        mock_resp.raise_for_status.return_value = None
        mock_resp.content = zip_bytes

        with patch("plugins.plugin_manager.requests.get", return_value=mock_resp), \
             patch.object(mgr, "load_plugins", return_value=[]):
            mgr.download_plugin("https://example.com/p.zip", plugin_id="new_plugin")

        state = json.loads(open(mgr.state_file).read())
        assert "new_plugin" in state.get("download_order", {})
        assert state["download_order"]["new_plugin"] >= 101

    def test_second_download_keeps_existing_order(self, mgr, tmp_path):
        import io
        import zipfile

        mgr.state_file = str(tmp_path / "plugin_state.json")
        # Pre-set download order
        state = {"uninstalled": [], "download_order": {"existing_plugin": 105}}
        with open(mgr.state_file, "w") as f:
            json.dump(state, f)

        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("main.py", "# code")
        zip_bytes = buf.getvalue()

        mock_resp = MagicMock()
        mock_resp.raise_for_status.return_value = None
        mock_resp.content = zip_bytes

        with patch("plugins.plugin_manager.requests.get", return_value=mock_resp), \
             patch.object(mgr, "load_plugins", return_value=[]):
            mgr.download_plugin("https://example.com/p.zip", plugin_id="existing_plugin")

        state = json.loads(open(mgr.state_file).read())
        # Should keep the original order, not assign a new one
        assert state["download_order"]["existing_plugin"] == 105
