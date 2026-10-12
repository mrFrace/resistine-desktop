"""Tests for plugins.dashboard.main — the PyQt6 Dashboard plugin.

Covers: plugin metadata, the three worker-thread data builders
(_endpoint_info / _ai_info / _system_info), the _Panel row/badge rendering,
refresh/_apply plumbing, the protection banner and timer teardown.
No real network or agent calls: the Wazuh backend, httpx and system_info
are monkeypatched.
"""

import threading
from unittest.mock import MagicMock

import pytest

from plugins.dashboard import main as dash
from plugins.dashboard.main import Plugin


@pytest.fixture()
def qapp():
    """A real (offscreen) QApplication for widget tests."""
    import os
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    from PyQt6.QtWidgets import QApplication
    return QApplication.instance() or QApplication([])


@pytest.fixture()
def dashboard_plugin():
    app = MagicMock()
    app.plugin_list = []
    app.plugins = []
    return Plugin(app)


@pytest.fixture()
def wz(monkeypatch):
    """plugins.wazuh.main with a fake, supported, installed+running agent."""
    from plugins.wazuh import main as wz
    monkeypatch.setattr(wz, "_platform_supported", True)
    monkeypatch.setattr(wz, "_PLATFORM", "Windows")  # skip Linux install row
    monkeypatch.setattr(wz, "WAZUH_MANAGER", "mgr.example")
    monkeypatch.setattr(wz, "is_agent_installed", lambda: True, raising=False)
    monkeypatch.setattr(wz, "get_agent_status", lambda: "Running", raising=False)
    monkeypatch.setattr(wz, "get_agent_connection", lambda: "connected", raising=False)
    monkeypatch.setattr(wz, "get_agent_name", lambda: "host-1", raising=False)
    monkeypatch.setattr(wz, "get_agent_group", lambda: "default", raising=False)
    return wz


# ===========================================================================
# Plugin metadata / init
# ===========================================================================
@pytest.mark.unit
class TestDashboardInit:
    def test_attributes(self, dashboard_plugin):
        assert dashboard_plugin.get_name() == "Dashboard"
        assert dashboard_plugin.order == 1
        assert dashboard_plugin.uninstall_enabled is False

    def test_id(self, dashboard_plugin):
        assert dashboard_plugin.id == "001"

    def test_starts_with_empty_data_cache(self, dashboard_plugin):
        assert dashboard_plugin._data == {"endpoint": None, "ai": None, "system": None}
        assert dashboard_plugin._timer is None
        assert dashboard_plugin._busy is False


# ===========================================================================
# _endpoint_info
# ===========================================================================
@pytest.mark.unit
class TestEndpointInfo:
    def test_unsupported_platform(self, wz, monkeypatch):
        monkeypatch.setattr(wz, "_platform_supported", False)
        assert dash._endpoint_info() == {"badge": ("info", "Unsupported"), "rows": {}}

    def test_not_installed(self, wz, monkeypatch):
        monkeypatch.setattr(wz, "is_agent_installed", lambda: False)
        info = dash._endpoint_info()
        assert info["badge"] == ("warning", "Not installed")
        assert info["rows"]["Manager"] == "mgr.example"

    def test_running_and_connected(self, wz):
        info = dash._endpoint_info()
        assert info["badge"] == ("ok", "Connected")
        assert info["rows"] == {
            "Service": "Running",
            "Connection": "Connected",
            "Agent name": "host-1",
            "Group": "default",
            "Manager": "mgr.example",
        }

    @pytest.mark.parametrize("conn,badge", [
        ("disconnected", ("error", "Not connected")),
        ("pending", ("warning", "Connecting")),
        ("unknown", ("ok", "Running")),
    ])
    def test_connection_states(self, wz, monkeypatch, conn, badge):
        monkeypatch.setattr(wz, "get_agent_connection", lambda: conn)
        info = dash._endpoint_info()
        assert info["badge"] == badge
        if conn == "unknown":
            assert info["rows"]["Connection"] == "—"

    def test_stopped_agent_does_not_query_connection(self, wz, monkeypatch):
        conn = MagicMock(return_value="connected")
        monkeypatch.setattr(wz, "get_agent_status", lambda: "Stopped")
        monkeypatch.setattr(wz, "get_agent_connection", conn)
        info = dash._endpoint_info()
        assert info["badge"] == ("error", "Stopped")
        assert info["rows"]["Connection"] == "—"
        conn.assert_not_called()

    def test_backend_exception_falls_back_to_default(self, wz, monkeypatch):
        def boom():
            raise RuntimeError("no agent")
        monkeypatch.setattr(wz, "get_agent_name", boom)
        assert dash._endpoint_info()["rows"]["Agent name"] == "—"


# ===========================================================================
# _ai_info
# ===========================================================================
class _Resp:
    def __init__(self, status, body=None):
        self.status_code = status
        self._body = body or {}

    def json(self):
        return self._body


@pytest.mark.unit
class TestAiInfo:
    @pytest.fixture()
    def env(self, isolated_settings, monkeypatch):
        import httpx

        from plugins.chat import main as chat
        from plugins.wazuh import main as wz
        monkeypatch.setattr(chat, "_tls_verify", lambda: True)
        monkeypatch.setattr(wz, "is_agent_running", lambda: True)
        get = MagicMock(return_value=_Resp(200, {"data": [{}, {}, {}]}))
        monkeypatch.setattr(httpx, "get", get)
        return isolated_settings, get, wz

    def test_online_when_models_listed_and_unlocked(self, env):
        settings, get, _ = env
        settings.set("chat", "openai_base_url", "https://ai.example:8002/v1/")
        settings.set_secret("chat", "openai_api_key", "sk-abc")
        info = dash._ai_info(MagicMock(model="m1"))
        assert info["badge"] == ("ok", "Online")
        assert info["rows"]["Server"] == "ai.example:8002"
        assert info["rows"]["Model"] == "m1"
        assert info["rows"]["Models"] == "3 available"
        assert info["rows"]["Access"].startswith("Unlocked")
        url = get.call_args.args[0]
        assert url == "https://ai.example:8002/v1/models"
        assert get.call_args.kwargs["headers"] == {"Authorization": "Bearer sk-abc"}

    def test_default_base_url_and_unused_key(self, env):
        from plugins.chat import main as chat
        _, get, _ = env
        dash._ai_info(None)
        assert get.call_args.args[0] == chat._DEFAULT_BASE_URL + "/models"
        assert get.call_args.kwargs["headers"] == {"Authorization": "Bearer unused"}

    def test_locked_when_agent_not_running(self, env, monkeypatch):
        _, _, wz = env
        monkeypatch.setattr(wz, "is_agent_running", lambda: False)
        info = dash._ai_info(None)
        assert info["badge"] == ("warning", "Locked")
        assert info["rows"]["Access"].startswith("Locked")
        assert info["rows"]["Model"] == "—"

    def test_http_error_status(self, env):
        _, get, _ = env
        get.return_value = _Resp(503)
        info = dash._ai_info(None)
        assert info["badge"] == ("warning", "HTTP 503")
        assert info["rows"]["Response"] == "HTTP 503"
        assert "Models" not in info["rows"]

    def test_unreachable(self, env):
        _, get, _ = env
        get.side_effect = ConnectionError("down")
        info = dash._ai_info(None)
        assert info["badge"] == ("error", "Unreachable")
        assert info["rows"]["Response"] == "ConnectionError"


# ===========================================================================
# _system_info
# ===========================================================================
@pytest.mark.unit
class TestSystemInfo:
    @pytest.fixture(autouse=True)
    def _collect(self, monkeypatch):
        from utils import system_info
        monkeypatch.setattr(system_info, "collect", lambda: {"Device": "box"})

    def _vpn(self, status):
        vpn = MagicMock()
        vpn.get_name.return_value = "VPN"
        vpn.get_status.return_value = status
        return vpn

    def test_vpn_connected(self):
        rows = dash._system_info(MagicMock(plugins=[self._vpn("OK")]))["rows"]
        assert rows["Device"] == "box"
        assert rows["VPN"] == "Connected"

    def test_vpn_off_or_missing(self):
        assert dash._system_info(MagicMock(plugins=[self._vpn("Warning")]))["rows"]["VPN"] == "Off"
        assert dash._system_info(MagicMock(plugins=[]))["rows"]["VPN"] == "Off"

    def test_vpn_status_error(self):
        vpn = self._vpn(None)
        vpn.get_status.side_effect = RuntimeError
        assert dash._system_info(MagicMock(plugins=[vpn]))["rows"]["VPN"] == "—"

    def test_includes_app_version(self, monkeypatch):
        from utils.updates import version
        monkeypatch.setattr(version, "get_current_version", lambda: "2026.07.01")
        info = dash._system_info(MagicMock(plugins=[]))
        assert info["badge"] is None
        assert info["rows"]["Phoenix"] == "2026.07.01"


# ===========================================================================
# _Panel
# ===========================================================================
def _grid_texts(panel):
    g = panel._grid
    return [[g.itemAtPosition(r, c).widget().text() for c in range(2)]
            for r in range(g.rowCount()) if g.itemAtPosition(r, 0)]


@pytest.mark.unit
class TestPanel:
    def test_loading_placeholder(self, qapp):
        p = dash._Panel("X", "/nonexistent.png")
        p.set_data(None)
        assert _grid_texts(p) == [["Loading…", ""]]
        assert p.badge is None

    def test_rows_and_badge(self, qapp):
        p = dash._Panel("X", "/nonexistent.png")
        p.set_data({"badge": ("ok", "Connected"), "rows": {"A": 1, "B": "two"}})
        assert p._grid.count() == 4
        assert p._grid.itemAtPosition(0, 0).widget().text() == "A"
        assert p._grid.itemAtPosition(0, 1).widget().text() == "1"
        assert p._grid.itemAtPosition(1, 1).widget().text() == "two"
        assert p.badge.text() == "Connected"
        assert p.badge.property("badge") == "ok"

    def test_update_replaces_badge(self, qapp):
        p = dash._Panel("X", "/nonexistent.png")
        p.set_data({"badge": ("ok", "Online"), "rows": {}})
        first = p.badge
        p.set_data({"badge": ("error", "Unreachable"), "rows": {"R": "x"}})
        assert p.badge is not first
        assert p.badge.text() == "Unreachable"
        assert p._head.indexOf(first) == -1
        assert p._head.indexOf(p.badge) != -1

    def test_open_button_invokes_callback(self, qapp):
        from PyQt6.QtWidgets import QPushButton
        cb = MagicMock()
        p = dash._Panel("X", "/nonexistent.png", on_open=cb)
        btn = next(b for b in p.findChildren(QPushButton) if b.text() == "Open")
        btn.click()
        cb.assert_called_once()


# ===========================================================================
# refresh / _apply / screen / destroy
# ===========================================================================
@pytest.mark.unit
class TestRefresh:
    def test_refresh_runs_probes_and_applies(self, dashboard_plugin, monkeypatch):
        monkeypatch.setattr(dash, "_endpoint_info", lambda: {"badge": None, "rows": {"e": 1}})
        monkeypatch.setattr(dash, "_system_info", lambda app: {"badge": None, "rows": {"s": 1}})
        monkeypatch.setattr(dash, "_ai_info", lambda chat: {"badge": None, "rows": {"a": chat}})
        chat = MagicMock()
        chat.get_name.return_value = "Chat"
        dashboard_plugin.app.plugins = [chat]
        done = threading.Event()

        def after(_ms, fn):
            fn()
            done.set()
        dashboard_plugin.app.after.side_effect = after

        dashboard_plugin.refresh()
        assert done.wait(5)
        assert dashboard_plugin._busy is False
        assert dashboard_plugin._data["endpoint"]["rows"] == {"e": 1}
        assert dashboard_plugin._data["system"]["rows"] == {"s": 1}
        assert dashboard_plugin._data["ai"]["rows"] == {"a": chat}

    def test_failing_probe_becomes_error_panel(self, dashboard_plugin, monkeypatch):
        def boom():
            raise RuntimeError("kaput")
        monkeypatch.setattr(dash, "_endpoint_info", boom)
        monkeypatch.setattr(dash, "_system_info", lambda app: {"badge": None, "rows": {}})
        monkeypatch.setattr(dash, "_ai_info", lambda chat: {"badge": None, "rows": {}})
        done = threading.Event()
        dashboard_plugin.app.after.side_effect = lambda _ms, fn: (fn(), done.set())

        dashboard_plugin.refresh()
        assert done.wait(5)
        assert dashboard_plugin._data["endpoint"] == {
            "badge": ("error", "Error"), "rows": {"Error": "kaput"}}

    def test_refresh_is_skipped_while_busy(self, dashboard_plugin, monkeypatch):
        thread = MagicMock()
        monkeypatch.setattr(dash.threading, "Thread", thread)
        dashboard_plugin._busy = True
        dashboard_plugin.refresh()
        thread.assert_not_called()

    def test_apply_updates_panels(self, dashboard_plugin):
        panel = MagicMock()
        dashboard_plugin._panels = {"system": panel}
        data = {"badge": None, "rows": {"x": "y"}}
        dashboard_plugin._busy = True
        dashboard_plugin._apply({"system": data})
        assert dashboard_plugin._busy is False
        panel.set_data.assert_called_once_with(data)

    def test_apply_tolerates_deleted_panel(self, dashboard_plugin):
        panel = MagicMock()
        panel.set_data.side_effect = RuntimeError("wrapped C/C++ object deleted")
        dashboard_plugin._panels = {"ai": panel}
        dashboard_plugin._apply({"ai": {"rows": {}}})  # must not raise
        assert dashboard_plugin._data["ai"] == {"rows": {}}


@pytest.mark.unit
class TestScreen:
    @pytest.fixture()
    def built(self, qapp, isolated_settings, dashboard_plugin, monkeypatch):
        monkeypatch.setattr(Plugin, "refresh", lambda self: None)

        def build(installed):
            monkeypatch.setattr(Plugin, "_agent_installed", staticmethod(lambda: installed))
            dashboard_plugin._data["system"] = {"badge": None, "rows": {"Device": "box"}}
            return dashboard_plugin.create_main_screen()
        yield build
        dashboard_plugin.destroy()

    def test_protected_glow_and_panels(self, built, dashboard_plugin):
        screen = built(True)  # keep a ref: the panels die with their page
        dashboard_plugin.app.set_protection_status.assert_called_with("ok")
        assert set(dashboard_plugin._panels) == {"endpoint", "ai", "system"}
        # Cached data is painted immediately on rebuild.
        assert _grid_texts(dashboard_plugin._panels["system"]) == [["Device", "box"]]
        assert _grid_texts(dashboard_plugin._panels["ai"]) == [["Loading…", ""]]
        del screen

    def test_not_protected_glow(self, built, dashboard_plugin):
        built(False)
        dashboard_plugin.app.set_protection_status.assert_called_with("error")

    def test_no_protection_banner(self, built):
        from PyQt6.QtWidgets import QLabel
        screen = built(True)
        assert not any("Protected" in lb.text()
                       for lb in screen.findChildren(QLabel))

    @pytest.mark.parametrize("kind, state", [
        ("ok", "ok"), ("error", "error"), ("warning", "error"), ("info", None)])
    def test_apply_maps_endpoint_badge_to_glow(self, dashboard_plugin, kind, state):
        dashboard_plugin._panels = {}
        dashboard_plugin._apply({"endpoint": {"badge": (kind, "x"), "rows": {}}})
        dashboard_plugin.app.set_protection_status.assert_called_with(state)

    def test_timer_started_and_destroy_stops_it(self, built, dashboard_plugin):
        built(True)
        timer = dashboard_plugin._timer
        assert timer is not None and timer.isActive()
        assert timer.interval() == dash._REFRESH_MS
        dashboard_plugin.destroy()
        assert not timer.isActive()

    def test_destroy_without_timer(self, dashboard_plugin):
        dashboard_plugin.destroy()  # never built: must not raise
        assert dashboard_plugin._timer is None
