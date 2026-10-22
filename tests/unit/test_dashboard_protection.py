"""Antivirus and VPN panels (plugins/dashboard/protection.py) and the VPN
plugin's request_toggle, which the Dashboard's switch calls."""

import time
from unittest.mock import MagicMock

import pytest

from plugins.dashboard import protection as pr

NOW = time.mktime((2026, 10, 13, 12, 0, 0, 0, 0, -1))
PROTECTED = {"state": "protected", "clamonacc_running": True}
FRESH_DB = {"signatures": "8,712,345", "last_updated": "2026-10-13 07:30"}


@pytest.mark.unit
class TestAntivirus:
    def test_protected(self):
        d = pr.antivirus_panel(PROTECTED, FRESH_DB, {"ts": NOW - 7200, "scanned": 1234, "infected": 0}, 0, NOW)
        assert d["badge"] == ("ok", "Protected")
        assert d["rows"] == {"Protection": "Active", "Real-time": "On",
                             "Signatures": "Updated 4 hours ago · 8,712,345",
                             "Last scan": "No threats · 1,234 files · 2 hours ago",
                             "Quarantine": "Empty"}

    def test_old_signatures_warn(self):
        d = pr.antivirus_panel(PROTECTED, {"signatures": "1", "last_updated": "2026-10-09 07:00"}, None, 0, NOW)
        assert d["badge"] == ("warning", "Signatures old") and d["rows"]["Last scan"] == "No scan yet"

    def test_threats_found(self):
        d = pr.antivirus_panel(PROTECTED, FRESH_DB, {"ts": NOW - 60, "scanned": 9, "infected": 2}, 2, NOW)
        assert d["badge"] == ("error", "Threats found")
        assert d["rows"]["Last scan"].startswith("2 threat(s) found") and d["rows"]["Quarantine"] == "2 files"

    def test_failed_scan_and_states(self):
        assert pr.antivirus_panel(PROTECTED, FRESH_DB, {"ts": NOW, "error": True}, None, NOW)["rows"]["Last scan"] \
            .startswith("Failed")
        assert pr.antivirus_panel({"state": "error"}, {}, None, None, NOW)["badge"] == ("error", "Stopped")
        assert pr.antivirus_panel({"state": "weird"}, {}, None, None, NOW)["badge"] == ("warning", "Checking")
        assert pr.antivirus_panel(None, None, None, None, NOW)["badge"] == ("info", "Not installed")
        d = pr.antivirus_panel({"state": "protected", "clamonacc_running": False}, {"last_updated": "—"}, None, 1, NOW)
        assert d["rows"]["Real-time"].startswith("Off") and d["rows"]["Signatures"] == "Never updated"


@pytest.mark.unit
class TestVpn:
    def test_states(self):
        assert pr.vpn_panel(True, "Running", "Phoenix (Default)", True) == {
            "badge": ("ok", "Connected"), "rows": {"Status": "Connected", "Configuration": "Phoenix (Default)"}}
        off = pr.vpn_panel(True, "Stopped", None, True)
        assert off["badge"] == ("warning", "Off") and off["rows"]["Status"] == "Not connected"
        assert off["rows"]["Configuration"].startswith("Phoenix")
        assert pr.vpn_panel(True, "Connecting", None, False)["badge"] == ("info", "Connecting")
        assert pr.vpn_panel(True, None, None, False)["rows"]["Configuration"].startswith("None")
        assert pr.vpn_panel(False, None, None, False)["badge"] == ("info", "Not installed")


@pytest.mark.unit
class TestRequestToggle:
    def plugin(self, monkeypatch):
        from plugins.vpn import main as vm
        p = vm.Plugin.__new__(vm.Plugin)
        p._toggle_busy = False
        p.vpn_toggle_switch = None  # Dashboard path: no VPN screen widget
        p.app = MagicMock()
        p.get_selected_conf_file_name = lambda: "phoenix"
        started = []
        monkeypatch.setattr(vm.threading, "Thread",
                            lambda target, args, daemon: MagicMock(start=lambda: started.append((target, args))))
        return p, started

    def test_dashboard_can_toggle_without_the_vpn_screen(self, monkeypatch):
        p, started = self.plugin(monkeypatch)
        p.request_toggle(1)
        assert p._toggle_busy and started == [(p._toggle_worker, (1, "phoenix"))]

    def test_busy_is_ignored(self, monkeypatch):
        p, started = self.plugin(monkeypatch)
        p._toggle_busy = True
        p.request_toggle(1)
        assert started == []

    def test_screen_switch_uses_the_same_path(self, monkeypatch):
        p, started = self.plugin(monkeypatch)
        p.vpn_toggle_switch = MagicMock(get=lambda: 0)
        p._on_toggle_clicked()
        assert started == [(p._toggle_worker, (0, "phoenix"))]
