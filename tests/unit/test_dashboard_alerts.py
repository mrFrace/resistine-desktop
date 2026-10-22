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


TRIAGE = """*SIEM triage* — 25 alert(s)
[Affected asset(s)] AnubisAI agent 007 | window 2026-10-16T10:26:59.882Z → 2026-10-16T10:27:00Z | source: wazuh.fim

### Verdict

#### Top Findings

1. **File Modifications (High Severity)**
   - **Indicators**: `/usr/bin/env`, critical system files
   - **Severity**: High
2. **Finding: Config Changes**
   - **Severity:** Medium
3. **Tmpfiles (Low Severity)**
   - **Severity**: Low
"""

TRIAGE_PROSE = """*SIEM triage* — 25 alert(s)
[Affected asset(s)] AnubisAI agent 007 | at 2026-10-16T10:26:59.881Z | source: wazuh.fim

The /bin/sh alert might be of medium severity, while the rest might be of low severity.
"""

TRIAGE_NUMBERED = """*SIEM triage* — 25 alert(s)
[Affected asset(s)] AnubisAI agent 007 | at 2026-10-16T10:26:59.884Z | source: wazuh.fim

### Verdict

**Finding 1:**
- **Severity:** Low
- **Description:** Multiple files were modified on AnubisAI. They are config files.

**Finding 2:**
- **Indicators:** none
"""

HUNT = """🔍 *Solving possible issue*
📍 *Affected asset(s):*
• AnubisAI (id 007)
*When:* 2026-10-16 12:26:59 CEST
*Source:* wazuh.fim
*What:* Wazuh FIM - File modified - /boot/loader/entries/nixos-generation-30.conf · rule b7ab7d97-c94a
*Reason for hunt:* rule.level 7 · Critical system files were modified
"""

RESULT_FP = """🟢 *Hunt result — False positive* (55% FP)
📍 *Affected asset(s):*
• AnubisAI (id 007)
*What:* Wazuh FIM - File modified - /etc/group · rule abc
*Assessment:* Critical file, but routine.
"""

RESULT_INC = RESULT_FP.replace("🟢 *Hunt result — False positive* (55% FP)",
                               "🟡 *Hunt result — Inconclusive* (40% FP)")


@pytest.mark.unit
class TestSiemBotMessages:
    def test_triage_findings_and_worst(self):
        i = ra.parse(TRIAGE)
        assert i["kind"] == "triage" and i["count"] == 25 and i["severity"] == "high"
        assert i["findings"] == [{"severity": "high", "name": "File Modifications"},
                                 {"severity": "medium", "name": "Config Changes"},
                                 {"severity": "low", "name": "Tmpfiles"}]
        assert i["title"] == "25 alerts on AnubisAI — File Modifications"
        assert (i["host"], i["agent"], i["source"]) == ("AnubisAI", "007", "wazuh.fim")

    def test_triage_prose_is_not_a_severity(self):
        i = ra.parse(TRIAGE_PROSE)  # "might be of medium severity": no verdict field
        assert i["severity"] == "unknown" and i["findings"] == []
        assert i["title"] == "25 alerts on AnubisAI"

    def test_prose_does_not_override_the_verdict(self):
        i = ra.parse(TRIAGE_NUMBERED + "\nThe most urgent finding is of critical severity.\n")
        assert i["severity"] == "low"

    def test_numbered_findings_are_named_by_their_description(self):
        i = ra.parse(TRIAGE_NUMBERED)
        assert i["findings"] == [{"severity": "low", "name": "Multiple files were modified on AnubisAI"},
                                 {"severity": "unknown", "name": "Finding 2"}]
        assert i["title"] == "25 alerts on AnubisAI — Multiple files were modified on AnubisAI"

    def test_hunt_takes_the_rule_level_not_prose(self):
        i = ra.parse(HUNT)  # "Critical system files" is not a severity
        assert i["kind"] == "hunt" and i["severity"] == "medium"
        assert i["title"] == "Investigating: File modified - /boot/loader/entries/nixos-generation-30.conf"

    @pytest.mark.parametrize("level,sev", [("3", "info"), ("5", "low"), ("7", "medium"), ("12", "high"),
                                           ("15", "critical"), ("high", "high")])
    def test_hunt_levels(self, level, sev):
        assert ra.parse(HUNT.replace("rule.level 7", f"rule.level {level}"))["severity"] == sev

    def test_results(self):
        fp, inc = ra.parse(RESULT_FP), ra.parse(RESULT_INC)
        assert (fp["kind"], fp["verdict"], fp["fp"], fp["severity"]) == ("result", "False positive", 55, "info")
        assert fp["title"] == "False positive: File modified - /etc/group"
        assert (inc["verdict"], inc["severity"]) == ("Inconclusive", "unknown")  # 🟡 is the verdict's colour
        assert ra.parse(RESULT_FP.replace("🟢", "🔴").replace("False positive", "True positive"))["severity"] == "high"

    def test_detail_text_drops_the_header_lines(self):
        assert ra.detail_text(TRIAGE).startswith("### Verdict")
        assert ra.detail_text(HUNT).startswith("📍")

    def test_subtitle(self):
        s = ra.subtitle(ra.parse(RESULT_FP), None)
        assert s == "AnubisAI (agent 007) · 55% likely a false positive"

    def test_hostile_text_stays_text(self):
        i = ra.parse("*SIEM triage* — 2 alert(s)\n[Affected asset(s)] <b>x</b>\u202e agent 1 | source: y")
        assert i["kind"] == "triage" and "\u202e" not in i["title"]  # no bidi overrides
        assert len(ra.parse("🔍 *Solving possible issue*\n*What:* " + "a" * 500)["title"]) <= 91


@pytest.mark.unit
class TestPanel:
    def test_empty(self):
        assert ra.panel_data([], 0, NOW)["badge"] == ("ok", "Quiet")

    def test_newest_first_with_unread_badge_by_worst_new(self):
        items = [alert("🟡 old low", 120, "a"), alert("🔴 ssh brute force", 3, "b"), alert("🟠 odd login", 10, "c")]
        d = ra.panel_data(items, 2, NOW)
        assert d["badge"] == ("error", "2 new")  # the two newest include a high
        assert list(d["rows"].values()) == ["🔴 ssh brute force", "🟠 odd login", "🟡 old low",
                                            "3 incidents: 1 high · 1 medium · 1 low"]
        assert list(d["rows"])[0] == "3 min ago" and list(d["rows"])[-1] == "Last 7 days"

    def test_no_unread(self):
        assert ra.panel_data([alert("🔴 x")], 0, NOW)["badge"] == ("ok", "No new alerts")

    def test_caps_and_counts_older(self):
        items = [alert(f"⚪ n{i}", i, str(i)) for i in range(7)]
        d = ra.panel_data(items, 0, NOW)
        assert len(d["rows"]) == ra.SHOWN + 2 and d["rows"]["More"] == "3 older alerts"
        assert d["rows"]["Last 7 days"] == "7 incidents: 7 info"

    def test_same_minute_keeps_both(self):
        d = ra.panel_data([alert("⚪ a", 1, "a"), alert("⚪ b", 1, "b")], 0, NOW)
        assert len(d["rows"]) == 3  # both alerts + Last 7 days

    def test_rows_map_to_event_ids(self):
        d = ra.panel_data([alert(HUNT, 3, "$h"), alert(RESULT_FP, 1, "$r")], 1, NOW)
        assert d["ids"] == {"1 min ago": "$r", "3 min ago": "$h"}
        assert d["badge"] == ("info", "1 new")  # a false positive is not alarming
        assert d["rows"]["3 min ago"].startswith("🟠 Investigating: File modified")

    def test_bad_input(self):
        assert ra.panel_data(["junk", None], 99, NOW)["badge"] == ("ok", "Quiet")

    def test_unreadable_alerts_are_unknown_not_calm(self):
        from plugins.chat.siem_alerts import UNDECRYPTABLE
        i = ra.parse(UNDECRYPTABLE)
        assert (i["severity"], i["title"]) == ("unknown", "Alert not readable on this device")
        d = ra.panel_data([alert(UNDECRYPTABLE, 2, "$u"), alert("🟡 old low", 9, "l")], 1, NOW)
        assert d["badge"] == ("warning", "1 new")  # not knowing never reads calmer than low
        assert d["rows"]["2 min ago"].startswith("❔ ")
        assert d["rows"]["Last 7 days"] == "2 incidents: 1 unknown · 1 low"
        assert ra.notification(alert(UNDECRYPTABLE, 0, "$u"), NOW - 60) is None


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


DAY = 86400


@pytest.mark.unit
class TestActivity:
    def test_one_slot_per_day_ending_today(self):
        days = ra.activity([], NOW)
        assert len(days) == ra.DAYS and all(d["count"] == 0 and d["worst"] is None for d in days)
        from datetime import datetime, timedelta
        today = datetime.fromtimestamp(NOW).date()
        assert days[-1]["day"] == today and days[0]["day"] == today - timedelta(days=6)

    def test_counts_and_worst_per_day(self):
        items = [alert("🟡 a", 1, "a"), alert("🔴 b", 2, "b"), alert(HUNT, 3, "c"),
                 {"event_id": "d", "body": "🚨 old", "ts": NOW - 3 * DAY},
                 {"event_id": "e", "body": "🚨 too old", "ts": NOW - 30 * DAY},
                 {"event_id": "f", "body": "🚨 no ts"}, "junk"]
        days = ra.activity(items, NOW)
        from datetime import datetime
        by_day = {d["day"]: d for d in days}
        today = by_day[datetime.fromtimestamp(NOW - 60).date()]
        assert today["count"] >= 2 and today["worst"] == "high"
        old = by_day[datetime.fromtimestamp(NOW - 3 * DAY).date()]
        assert old["count"] == 1 and old["worst"] == "critical"
        assert sum(d["count"] for d in days) == 4  # 30 days old, no ts, junk: not counted

    def test_breakdown(self):
        items = [alert("🔴 a", 1, "a"), alert("🔴 b", 2, "b"), alert(HUNT, 3, "c"),
                 {"event_id": "e", "body": "🚨 too old", "ts": NOW - 30 * DAY}]
        assert ra.breakdown(items, NOW) == "3 incidents: 2 high · 1 medium"
        assert ra.breakdown([], NOW) == "None"

    def test_event_time(self):
        utc = ra.event_time("2026-10-16T10:26:59Z")
        assert ra.event_time("2026-10-16 12:26:59 CEST") == utc
        assert ra.event_time("2026-10-16T10:26:59.881Z → 2026-10-16T10:27:00Z") == pytest.approx(utc + 0.881)
        for bad in ("", "yesterday", "2026-10-16 12:26:59", "2026-10-16 12:26:59 XYZ"):
            assert ra.event_time(bad) is None

    def test_one_incident_is_counted_once(self):
        result = RESULT_FP.replace("*What:*", "*When:* 2026-10-16 12:26:59 CEST\n*What:*")
        hunt = HUNT  # 2026-10-16 12:26:59 CEST on AnubisAI (id 007)
        items = [alert(TRIAGE, 30, "t1"), alert(TRIAGE, 25, "t2"),  # re-triaged window
                 alert(hunt, 20, "h"), alert(result, 19, "r"),
                 alert(hunt.replace("12:26:59", "13:40:00"), 10, "later"),  # same machine, later
                 alert("🔴 no machine, no time", 5, "x")]
        inc = ra.incidents(items)
        assert [i["count"] for i in inc] == [4, 1, 1]
        assert inc[0]["severity"] == "high" and inc[0]["ts"] == items[0]["ts"]
        assert ra.breakdown(items, NOW) == "3 incidents: 2 high · 1 medium"

    def test_other_machines_are_other_incidents(self):
        other = TRIAGE.replace("AnubisAI agent 007", "francispc agent 004")
        assert len(ra.incidents([alert(TRIAGE, 3, "a"), alert(other, 2, "b")])) == 2

    def test_panel_has_strip(self):
        d = ra.panel_data([alert("🔴 a", 1, "a")], 1, NOW)
        assert len(d["strip"]) == ra.DAYS and d["strip"][-1]["worst"] == "high"
        assert "strip" not in ra.panel_data([], 0, NOW)


@pytest.mark.unit
class TestNotification:
    def test_high_and_critical_only(self):
        note = ra.notification(alert(TRIAGE, 0, "$t"), NOW - 600)
        assert note == {"title": "High alert on AnubisAI",
                        "body": "25 alerts on AnubisAI — File Modifications",
                        "urgency": "normal", "event_id": "$t"}
        assert ra.notification(alert("🚨 ransomware", 0, "$c"), NOW - 600)["urgency"] == "critical"
        assert ra.notification(alert(HUNT, 0), NOW - 600) is None       # medium
        assert ra.notification(alert(RESULT_FP, 0), NOW - 600) is None  # false positive

    def test_backlog_is_not_notified(self):
        started = NOW
        assert ra.notification(alert("🚨 x", 60, "$old"), started) is None   # an hour before start
        assert ra.notification(alert("🚨 x", 1, "$skew"), started) is not None  # within the slack
        assert ra.notification({"event_id": "$n", "body": "🚨 x"}, started) is None  # no ts
        assert ra.notification("junk", started) is None

    def test_untrusted_text_is_plain(self):
        body = "🚨 <a href='https://evil'>click</a> & \u202eevil\n" + "x" * 300
        note = ra.notification(alert(body, 0, "$x"), NOW - 600)
        assert "<" not in note["body"] and ">" not in note["body"] and "&" not in note["body"]
        assert "\u202e" not in note["body"] and len(note["body"]) <= 161
        host = "[Affected asset(s)] <b>evil</b> agent 007 | at now\n"
        note = ra.notification(alert("*SIEM triage* — 1 alert(s)\n" + host + "Severity: Critical", 0, "$y"),
                               NOW - 600)
        assert note["title"] == "Critical alert on bevil/b"


def _plugin(qapp, monkeypatch, tmp_path, chat=None):
    from plugins.chat import siem_alerts
    from plugins.dashboard.main import Plugin

    monkeypatch.setattr(siem_alerts, "_store", siem_alerts.AlertStore(str(tmp_path / "a.json")))
    monkeypatch.setattr(siem_alerts, "_listeners", [])
    monkeypatch.setattr(Plugin, "refresh", lambda self: None)
    monkeypatch.setattr(Plugin, "_agent_installed", staticmethod(lambda: True))
    app = MagicMock()
    app.plugins = [chat] if chat else []
    app.after = lambda ms, fn, *args: fn(*args)
    plugin = Plugin(app)
    plugin.create_main_screen()
    return plugin, siem_alerts, app


@pytest.mark.unit
def test_alert_list_and_detail_pages(qapp, isolated_settings, monkeypatch, tmp_path):
    plugin, siem_alerts, _ = _plugin(qapp, monkeypatch, tmp_path)
    siem_alerts.publish("!r", "$t", TRIAGE)
    siem_alerts.publish("!r", "$h", HUNT)
    assert siem_alerts.store().unread == 2
    plugin._open_alerts()
    rows, header = plugin._alerts_list
    assert rows.count() == 2 and siem_alerts.store().unread == 0  # seeing the list reads them
    assert plugin._data["alerts"]["badge"] == ("ok", "No new alerts")
    siem_alerts.publish("!r", "$r", RESULT_FP)  # arrives while the list is open
    assert rows.count() == 3 and siem_alerts.store().unread == 0
    plugin._open_alert("$t")
    assert len(plugin._alert_pages) == 2
    page = plugin._alert_pages[-1]
    texts = [w.text() for w in page.findChildren(type(header.title))]
    assert "25 alerts on AnubisAI — File Modifications" in texts and "Config Changes" in texts
    from plugins.dashboard.main import _AlertText
    view = page.findChild(_AlertText)
    assert "<b>" not in view.toPlainText() and "Verdict" in view.toPlainText()
    plugin._pop_page()
    plugin._pop_page()
    assert plugin._alert_pages == [] and plugin._alerts_list is None
    plugin._open_alert("$missing")  # gone from the store: nothing happens
    assert plugin._alert_pages == []
    plugin.destroy()


@pytest.mark.unit
def test_alert_html_is_escaped(qapp, isolated_settings, monkeypatch, tmp_path):
    from plugins.dashboard.main import _AlertText
    view = _AlertText('<img src="file:///etc/passwd"> <a href="https://evil">x</a> [y](https://evil)')
    assert "<img" in view.toPlainText()  # shown as text, not loaded
    assert not view.openLinks() and not view.openExternalLinks()


@pytest.mark.unit
def test_ask_ai(qapp, isolated_settings, monkeypatch, tmp_path):
    from PyQt6.QtCore import QTimer
    monkeypatch.setattr(QTimer, "singleShot", staticmethod(lambda ms, fn: fn()))
    chat = MagicMock()
    chat.get_name.return_value = "Chat"
    plugin, siem_alerts, app = _plugin(qapp, monkeypatch, tmp_path, chat)
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
    from plugins.dashboard import main as dash
    from utils import notifications
    sent = []
    monkeypatch.setattr(notifications, "send", lambda *a, **kw: sent.append((a, kw)))
    monkeypatch.setattr(dash, "_NOTIFIED", set())
    plugin, siem_alerts, app = _plugin(qapp, monkeypatch, tmp_path)
    monkeypatch.setattr(dash, "_STARTED_AT", time.time() - 10)
    old_ms = int((time.time() - 3600) * 1000)
    siem_alerts.publish("!r", "$old", "🚨 history from before start", old_ms)
    siem_alerts.publish("!r", "$med", HUNT)
    assert sent == []  # backlog and medium alerts stay quiet
    siem_alerts.publish("!r", "$t", TRIAGE)
    assert len(sent) == 1
    (title, body), kw = sent[0]
    assert title == "High alert on AnubisAI" and kw["urgency"] == "normal"
    plugin._notify_alert(siem_alerts.store().all()[-1])  # same event again: no repeat
    assert len(sent) == 1
    kw["on_click"]()  # clicking opens the alert's page
    app.navigate.assert_called_with("Dashboard")
    assert len(plugin._alert_pages) == 1
    isolated_settings.set("dashboard", "alert_notifications", False)
    siem_alerts.publish("!r", "$c", "🚨 ransomware")
    assert len(sent) == 1  # turned off in Settings
    plugin.destroy()


@pytest.mark.unit
def test_panels_paint_strip_and_sparkline(qapp, isolated_settings, monkeypatch, tmp_path):
    from plugins.dashboard.main import _DayStrip, _Sparkline
    plugin, siem_alerts, _ = _plugin(qapp, monkeypatch, tmp_path)
    siem_alerts.publish("!r", "$t", TRIAGE)
    panel = plugin._panels["alerts"]
    strip = panel.findChild(_DayStrip)
    assert strip is not None and "1 incident" in strip.toolTip()
    strip.resize(300, strip.height())
    strip.grab()  # paints without errors
    plugin._panels["posture"].set_data({"badge": ("ok", "Grade A"), "rows": {"Trend": "▲ 6 since last week"},
                                         "spark": [70, 72, 71, 76]})
    spark = plugin._panels["posture"].findChild(_Sparkline)
    assert spark is not None and "now 76" in spark.toolTip()
    spark.resize(300, spark.height())
    spark.grab()
    plugin.destroy()


def test_alert_question_keeps_the_server_marker_and_context():
    from plugins.chat.main import ALERT_QUESTION, alert_question

    q = alert_question(TRIAGE, ts=1_760_617_560)
    assert q.startswith(ALERT_QUESTION)
    assert q.lower().startswith("explain this phoenix siem alert")  # the server keys on this
    assert "don't look up other alerts" in q
    assert "AnubisAI" in q and "was sent" in q
    assert q.rstrip().endswith("--- end of alert ---")
    long = alert_question("x" * 9000, limit=100)
    assert "(alert shortened)" in long and "x" * 101 not in long
