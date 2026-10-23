"""The Alerts screen (plugins/alerts/main.py): SIEM alerts newest first, one
alert's page, Ask AI, and the desktop notification for a new serious alert.
The alert texts come from tests/unit/test_dashboard_alerts.py."""

from unittest.mock import MagicMock

import pytest

from tests.unit.test_dashboard_alerts import HUNT, RESULT_FP, TRIAGE


@pytest.fixture
def qapp():
    import os
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    from PyQt6.QtWidgets import QApplication
    return QApplication.instance() or QApplication([])


def _plugin(monkeypatch, tmp_path, chat=None):
    from plugins.alerts.main import Plugin
    from plugins.chat import siem_alerts

    monkeypatch.setattr(siem_alerts, "_store", siem_alerts.AlertStore(str(tmp_path / "a.json")))
    monkeypatch.setattr(siem_alerts, "_listeners", [])
    app = MagicMock()
    app.plugins = [chat] if chat else []
    app.after = lambda ms, fn, *args: fn(*args)
    return Plugin(app), siem_alerts, app


def _titles(rows):
    from gui.page_kit import MenuRow
    return [r.text() for r in rows.findChildren(MenuRow)]


@pytest.mark.unit
def test_list_is_newest_first_and_reads_alerts_when_seen(qapp, isolated_settings, monkeypatch, tmp_path):
    plugin, siem_alerts, _ = _plugin(monkeypatch, tmp_path)
    siem_alerts.publish("!r", "$t", TRIAGE, 1_000_000)
    siem_alerts.publish("!r", "$h", HUNT, 2_000_000)
    assert plugin.check_status() == "warning"  # unread: the nav icon glows
    screen = plugin.create_main_screen()
    rows, header = plugin._list
    assert rows.count() == 2 and siem_alerts.store().unread == 2  # not shown yet
    screen.show()
    plugin.on_screen_shown()
    assert siem_alerts.store().unread == 0 and plugin.check_status() is None
    assert header.subtitle.text() == "2 alerts, newest first"
    siem_alerts.publish("!r", "$r", RESULT_FP, 3_000_000)  # arrives while it is open
    titles = _titles(rows)
    assert len(titles) == 3 and siem_alerts.store().unread == 0
    assert titles[0].startswith("False positive") and titles[-1].startswith("25 alerts")
    plugin.destroy()
    assert siem_alerts._listeners == []


@pytest.mark.unit
def test_alert_page_and_back(qapp, isolated_settings, monkeypatch, tmp_path):
    from PyQt6.QtWidgets import QLabel

    from plugins.alerts.main import _AlertText
    plugin, siem_alerts, _ = _plugin(monkeypatch, tmp_path)
    siem_alerts.publish("!r", "$t", TRIAGE)
    screen = plugin.create_main_screen()
    plugin.open_alert("$t")
    page = plugin._detail
    texts = [w.text() for w in page.findChildren(QLabel)]
    assert "25 alerts on AnubisAI — File Modifications" in texts and "Config Changes" in texts
    view = page.findChild(_AlertText)
    assert "<b>" not in view.toPlainText() and "Verdict" in view.toPlainText()
    plugin.open_alert("$t")  # a second open replaces the page, never stacks
    assert screen.count() == 2
    plugin._close_detail(animate=False)
    assert plugin._detail is None and screen.count() == 1
    plugin.open_alert("$missing")  # gone from the store: nothing happens
    assert plugin._detail is None
    plugin.destroy()


@pytest.mark.unit
def test_alert_html_is_escaped(qapp):
    from plugins.alerts.main import _AlertText
    view = _AlertText('<img src="file:///etc/passwd"> <a href="https://evil">x</a> [y](https://evil)')
    assert "<img" in view.toPlainText()  # shown as text, not loaded
    assert not view.openLinks() and not view.openExternalLinks()


@pytest.mark.unit
def test_ask_ai(qapp, isolated_settings, monkeypatch, tmp_path):
    from PyQt6.QtCore import QTimer
    monkeypatch.setattr(QTimer, "singleShot", staticmethod(lambda ms, fn: fn()))
    chat = MagicMock()
    chat.get_name.return_value = "Chat"
    plugin, _, app = _plugin(monkeypatch, tmp_path, chat)
    plugin._ask_ai(HUNT)
    app.select_frame_by_name.assert_called_with("frame_Chat")
    chat.ask_about_alert.assert_called_once_with(HUNT, None)
    chat.client = None
    app.select_frame_by_name.reset_mock()
    plugin._ask_ai(HUNT)
    app.select_frame_by_name.assert_not_called()
    assert "Settings" in app.show_notification.call_args[0][0]
    plugin.destroy()


@pytest.mark.unit
def test_new_high_alert_notifies_once_and_opens_on_click(qapp, isolated_settings, monkeypatch, tmp_path):
    import time

    from plugins.alerts import main as alerts_main
    from utils import notifications
    sent = []
    monkeypatch.setattr(notifications, "send", lambda *a, **kw: sent.append((a, kw)))
    monkeypatch.setattr(alerts_main, "_NOTIFIED", set())
    plugin, siem_alerts, app = _plugin(monkeypatch, tmp_path)
    plugin.create_main_screen()
    monkeypatch.setattr(alerts_main, "_STARTED_AT", time.time() - 10)
    old_ms = int((time.time() - 3600) * 1000)
    siem_alerts.publish("!r", "$old", "🚨 history from before start", old_ms)
    siem_alerts.publish("!r", "$med", HUNT)
    assert sent == []  # backlog and medium alerts stay quiet
    siem_alerts.publish("!r", "$t", TRIAGE)
    assert len(sent) == 1
    (title, _body), kw = sent[0]
    assert title == "High alert on AnubisAI" and kw["urgency"] == "normal"
    plugin._notify(siem_alerts.store().all()[-1])  # same event again: no repeat
    assert len(sent) == 1
    kw["on_click"]()  # clicking opens the alert's page
    app.navigate.assert_called_with("Alerts")
    assert plugin._detail is not None
    isolated_settings.set("dashboard", "alert_notifications", False)
    siem_alerts.publish("!r", "$c", "🚨 ransomware")
    assert len(sent) == 1  # turned off in Settings
    plugin.destroy()


@pytest.mark.unit
def test_sidebar_button_returns_to_the_list(qapp, isolated_settings, monkeypatch, tmp_path):
    plugin, siem_alerts, _ = _plugin(monkeypatch, tmp_path)
    siem_alerts.publish("!r", "$t", TRIAGE)
    screen = plugin.create_main_screen()
    plugin.open_alert("$t")
    assert screen.count() == 2
    plugin.on_screen_shown()
    assert screen.currentIndex() == 0 and screen.count() == 1 and plugin._detail is None
    plugin.destroy()
