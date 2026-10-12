"""Recent alerts panel (plugins/dashboard/alerts.py): SIEM alerts from
siemgent, summarised for the Dashboard. Bodies are untrusted text."""

from unittest.mock import MagicMock

import pytest

from plugins.dashboard import alerts as ra

NOW = 1_760_000_000.0


def alert(body, mins_ago=5, eid=None):
    return {"room_id": "!r", "event_id": eid or body[:8], "body": body, "ts": NOW - mins_ago * 60}


@pytest.mark.unit
class TestParse:
    @pytest.mark.parametrize("body,sev", [
        ("🔴 *TRUE POSITIVE* — ssh brute force on francispc", "high"),
        ("🚨 Ransomware behaviour", "critical"),
        ("Severity: medium\nSomething odd", "medium"),
        ("🟡 low noise 🔴 later marker", "low"),   # the first marker wins
        ("Plain text alert", "info"),
        ("", "info"),
    ])
    def test_severity(self, body, sev):
        assert ra.severity(body) == sev

    def test_title_strips_markup_and_markers(self):
        assert ra.title("\n\n🔴 **TRUE POSITIVE** — `sudo` abuse\nmore") == "TRUE POSITIVE — sudo abuse"
        assert ra.title("x" * 200).endswith("…") and len(ra.title("x" * 200)) == 91
        assert ra.title("\x1b[31m‮evil") == "[31mevil"
        assert ra.title("") == "SIEM alert"

    @pytest.mark.parametrize("secs,text", [(10, "Just now"), (300, "5 min ago"), (7200, "2 h ago"),
                                           (86400 * 3, "3 days ago")])
    def test_ago(self, secs, text):
        assert ra.ago(NOW - secs, NOW) == text


@pytest.mark.unit
class TestPanel:
    def test_empty(self):
        assert ra.panel_data([], 0, NOW)["badge"] == ("ok", "Quiet")

    def test_newest_first_with_unread_badge_by_worst_new(self):
        items = [alert("🟡 old low", 120, "a"), alert("🔴 ssh brute force", 3, "b"), alert("🟠 odd login", 10, "c")]
        d = ra.panel_data(items, 2, NOW)
        assert d["badge"] == ("error", "2 new")  # the two newest include a high
        assert list(d["rows"].values()) == ["🔴 ssh brute force", "🟠 odd login", "🟡 old low"]
        assert list(d["rows"])[0] == "3 min ago"

    def test_no_unread(self):
        assert ra.panel_data([alert("🔴 x")], 0, NOW)["badge"] == ("ok", "No new alerts")

    def test_caps_and_counts_older(self):
        items = [alert(f"⚪ n{i}", i, str(i)) for i in range(7)]
        d = ra.panel_data(items, 0, NOW)
        assert len(d["rows"]) == ra.SHOWN + 1 and d["rows"]["More"] == "3 older alerts"

    def test_same_minute_keeps_both(self):
        d = ra.panel_data([alert("⚪ a", 1, "a"), alert("⚪ b", 1, "b")], 0, NOW)
        assert len(d["rows"]) == 2

    def test_bad_input(self):
        assert ra.panel_data(["junk", None], 99, NOW)["badge"] == ("ok", "Quiet")


@pytest.fixture
def qapp():
    import os
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    from PyQt6.QtWidgets import QApplication
    return QApplication.instance() or QApplication([])


@pytest.mark.unit
def test_panel_updates_live_and_unsubscribes(qapp, isolated_settings, monkeypatch, tmp_path):
    from plugins.chat import siem_alerts
    from plugins.dashboard.main import Plugin

    monkeypatch.setattr(siem_alerts, "_store", siem_alerts.AlertStore(str(tmp_path / "a.json")))
    monkeypatch.setattr(siem_alerts, "_listeners", [])
    monkeypatch.setattr(Plugin, "refresh", lambda self: None)
    monkeypatch.setattr(Plugin, "_agent_installed", staticmethod(lambda: True))
    app = MagicMock()
    app.plugins = []
    app.after = lambda ms, fn: fn()
    plugin = Plugin(app)
    screen = plugin.create_main_screen()
    assert plugin._data["alerts"]["badge"] == ("ok", "Quiet")
    siem_alerts.publish("!r", "$e1", "🔴 ssh brute force on francispc")
    assert plugin._data["alerts"]["badge"] == ("error", "1 new")
    plugin.destroy()
    assert siem_alerts._listeners == [] and screen is not None
