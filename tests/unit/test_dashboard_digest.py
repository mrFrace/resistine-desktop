"""Daily alert digest, in the view only (plugins/dashboard/digest.py)."""

from datetime import datetime, timedelta

import pytest

from plugins.dashboard import alerts as ra
from plugins.dashboard import digest
from tests.unit.test_dashboard_alerts import HUNT, NOW, RESULT_FP, TRIAGE, alert

pytestmark = pytest.mark.unit

TODAY = datetime.fromtimestamp(NOW).date()
MIN_PER_DAY = 24 * 60


def _on(body, host, agent):
    return body.replace("AnubisAI agent 007", f"{host} agent {agent}").replace(
        "AnubisAI (id 007)", f"{host} (id {agent})")


def test_quiet_alerts_fold_per_day_and_serious_ones_stay_out():
    items = [alert(TRIAGE, 5, "high-today"),              # high: own row
             alert(HUNT, 10, "h1"), alert(RESULT_FP, 20, "r1"),
             alert(_on(HUNT, "francispc", "004"), 30, "h2"),
             alert(HUNT, MIN_PER_DAY + 5, "h-yesterday"),
             alert("🚨 ransomware", MIN_PER_DAY + 10, "crit-yesterday"),
             alert("🟡 old", 9 * MIN_PER_DAY, "old")]
    rows = digest.fold(items, NOW)
    assert [r["kind"] for r in rows] == ["alert", "day", "day", "alert", "day"]
    assert rows[0]["alert"]["event_id"] == "high-today"
    today = rows[1]
    assert today["day"] == TODAY and [a["event_id"] for a in today["alerts"]] == ["h1", "r1", "h2"]
    assert today["counts"]["medium"] == 2 and today["counts"]["info"] == 1
    assert today["hosts"] == ["AnubisAI", "francispc"]
    assert digest.title(today, NOW) == "Today · 3 alerts"
    assert digest.hint(today) == "2 medium · 1 info · AnubisAI, francispc"
    assert digest.title(rows[2], NOW) == "Yesterday · 1 alert"
    assert rows[3]["alert"]["event_id"] == "crit-yesterday"
    assert digest.title(rows[4], NOW) == (TODAY - timedelta(days=9)).strftime("%a %d %b") + " · 1 alert"
    assert digest.panel_value(today) == "3 alerts: 2 medium · 1 info"


def test_hosts_are_capped_and_bad_input_dropped():
    items = [alert(_on(HUNT, f"box{i}", f"00{i}"), i, f"h{i}") for i in range(5)]
    [day] = digest.fold(items + ["junk", {"ts": "x"}], NOW)
    assert digest.hint(day).endswith("box0, box1, box2 and 2 more")
    assert digest.fold([], NOW) == [] and digest.fold(None, NOW) == []


def test_setting_round_trip(isolated_settings):
    assert digest.enabled() is False
    digest.set_enabled(True)
    assert digest.enabled() is True


def test_panel_rows_fold_with_the_digest_and_keep_the_badge():
    items = [alert(TRIAGE, 5, "high"), alert(HUNT, 10, "h1"), alert(RESULT_FP, 20, "r1"),
             alert(HUNT, MIN_PER_DAY + 5, "y1")]
    plain = ra.panel_data(items, 2, NOW)
    folded = ra.panel_data(items, 2, NOW, digest=True)
    assert folded["badge"] == plain["badge"] == ("error", "2 new")
    assert list(folded["rows"]) == ["5 min ago", "Today", "Yesterday", "Last 7 days"]
    assert folded["rows"]["Today"] == "2 alerts: 1 medium · 1 info"
    assert folded["ids"] == {"5 min ago": "high", "Today": None, "Yesterday": None}
    assert folded["strip"] == plain["strip"]
    assert "More" not in folded["rows"]  # every alert is represented
    many = [alert(HUNT, MIN_PER_DAY * d + 1, f"d{d}") for d in range(6)]
    assert ra.panel_data(many, 0, NOW, digest=True)["rows"]["More"] == "2 older alerts"
