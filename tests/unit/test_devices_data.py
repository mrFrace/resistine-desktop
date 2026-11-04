"""Tests for plugins.devices.data — the Devices page's data shaping (no Qt).

Also pins that every catalog key the plugin asks for exists in en.json, since
get_text raises on a missing key and the page would fail to build.
"""

import json
import os
import re
import time
from datetime import datetime

import pytest

from plugins.devices import data

_REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _card(host="HOST-A", grade="F", score=35, **over):
    c = {
        "schema": "phoenix.posture.v1",
        "agent_id": "029",
        "hostname": host,
        "os": "Microsoft Windows 11 Home",
        "agent_status": "active",
        "computed_at": datetime.now().isoformat(),
        "score": score,
        "grade": grade,
        "health": "at_risk",
        "vulnerabilities": {
            "total": 206,
            "critical": 9,
            "high": 128,
            "medium": 53,
            "low": 12,
            "available": True,
            "reason": None,
        },
        "compliance": {"score_pct": 26, "failed_checks": 350, "checks": 474},
        "alerts": {"window_hours": 24, "critical": 1, "high": 2, "available": True},
        "recommendations": ["Patch 9 critical vulnerabilities"],
        "mitigations": [],
    }
    c.update(over)
    return c


@pytest.mark.unit
class TestFleetRows:
    def test_this_machine_first_then_worst_grade(self):
        rows = data.fleet_rows(
            [_card("b", "A", 95), _card("c", "D", 50), _card("mine", "B", 80)],
            local_names={"MINE"},
        )
        assert [r["hostname"] for r in rows] == ["mine", "c", "b"]
        assert rows[0]["this_machine"] and not rows[1]["this_machine"]

    def test_counts_coerced_and_text_cut(self):
        card = _card(
            host="x" * 500,
            score="35",
            vulnerabilities={"critical": "9", "high": None, "medium": -3, "low": "bad"},
        )
        row = data.fleet_rows([card], set())[0]
        assert row["vulns"] == {"critical": 9, "high": 0, "medium": 0, "low": 0}
        assert row["score"] == 35
        assert len(row["hostname"]) <= 65

    def test_non_dict_cards_skipped(self):
        assert (
            data.fleet_rows([None, "x", 3, _card()], set())
            and len(data.fleet_rows([None], set())) == 0
        )

    def test_control_characters_dropped(self):
        esc, bidi = chr(0x1B), chr(0x202E)
        row = data.fleet_rows([_card(host=f"evil{esc}[31mname{bidi}")], set())[0]
        assert esc not in row["hostname"] and bidi not in row["hostname"]

    def test_this_machine_by_agent_id_and_name_prefix(self):
        cards = [
            _card("DrakeHP-97EF26154AD1-813392", agent_id="029"),
            _card("other", agent_id="030"),
        ]
        by_id = data.fleet_rows(cards, set(), local_agent_ids=["029"])
        assert by_id[0]["hostname"].startswith("DrakeHP") and by_id[0]["this_machine"]
        by_prefix = data.fleet_rows(cards, {"drakehp"})
        assert by_prefix[0]["this_machine"] and not by_prefix[1]["this_machine"]
        assert not data.is_this_machine(
            "drakehpx", "", {"drakehp"}
        )  # prefix needs the dash


@pytest.mark.unit
class TestTotals:
    def setup_method(self):
        self.rows = data.fleet_rows(
            [
                _card("a"),
                _card(
                    "b",
                    "A",
                    90,
                    vulnerabilities={"critical": 0, "high": 1, "medium": 0, "low": 0},
                    compliance={"score_pct": 90, "failed_checks": 10, "checks": 100},
                    alerts={"critical": 0, "high": 0, "window_hours": 24},
                ),
            ],
            set(),
        )

    def test_scope(self):
        assert len(data.scope_rows(self.rows, data.ALL_DEVICES)) == 2
        assert [r["hostname"] for r in data.scope_rows(self.rows, "B")] == ["b"]
        assert data.scope_rows(self.rows, "nope") == []

    def test_vuln_totals(self):
        vt = data.vuln_totals(self.rows)
        assert (
            vt["critical"] == 9
            and vt["high"] == 129
            and vt["total"] == 9 + 129 + 53 + 12
        )
        assert vt["scanned"] is True

    def test_vuln_totals_flag_unscanned(self):
        rows = data.fleet_rows(
            [_card(vulnerabilities={"available": False, "reason": "not_covered"})],
            set(),
        )
        assert data.vuln_totals(rows)["scanned"] is False
        assert rows[0]["vulns_reason"] == "not_covered"

    def test_compliance_from_checks(self):
        ct = data.compliance_totals(self.rows)
        assert ct["checks"] == 574 and ct["failed"] == 360
        assert ct["pct"] == round(100 * (574 - 360) / 574)

    def test_compliance_without_checks_averages_pct(self):
        rows = data.fleet_rows(
            [
                _card(compliance={"score_pct": 40}),
                _card("b", compliance={"score_pct": 60}),
            ],
            set(),
        )
        assert data.compliance_totals(rows)["pct"] == 50
        assert data.compliance_totals([])["pct"] is None

    def test_alert_and_agent_totals(self):
        assert data.alert_totals(self.rows) == {
            "critical": 1,
            "high": 2,
            "window_h": 24,
            "available": True,
        }
        assert data.agent_totals(self.rows) == {"active": 2, "total": 2}
        assert data.worst_grade(self.rows) == "F"


@pytest.mark.unit
class TestHeaderSummary:
    def test_states_without_rows(self):
        assert data.header_summary("signed_out", [], None)["pill"] == (
            "info",
            "Sign in",
        )
        assert (
            data.header_summary("not_enrolled", [], None)["pill"][1] == "Not enrolled"
        )
        assert data.header_summary(None, [], None)["pill"][1] == "Loading"
        s = data.header_summary("error", [], None, error="boom")
        assert s["pill"][0] == "warning" and "boom" in s["note"]

    def test_with_rows_and_stale_error(self):
        rows = data.fleet_rows([_card("a", "C", 70)], set())
        s = data.header_summary("error", rows, time.time() - 30, error="HTTP 503")
        assert s["pill"] == ("warning", "Worst grade C")
        assert "1 device with" in s["subtitle"] and "just now" in s["subtitle"]
        assert s["note"].startswith("Showing the last known posture")


def _parse(body):
    sev, _, host = body.partition("|")
    return {
        "severity": sev or "info",
        "host": host,
        "title": body[:20],
        "kind": "other",
    }


@pytest.mark.unit
class TestAlerts:
    def test_scoped_alerts_keep_unplaced(self):
        alerts = [
            {"event_id": "1", "ts": 10, "body": "high|HOST-A"},
            {"event_id": "2", "ts": 20, "body": "low|OTHER"},
            {"event_id": "3", "ts": 30, "body": "critical|"},
        ]
        mine = data.scoped_alerts(alerts, _parse, ["host-a"])
        assert [a["event_id"] for a in mine] == [
            "3",
            "1",
        ]  # newest first; unplaced kept
        assert len(data.scoped_alerts(alerts, _parse, None)) == 3

    def test_severity_counts_and_days(self):
        now = time.time()
        alerts = [
            {"event_id": str(i), "ts": now - i * 86400, "body": sev + "|h"}
            for i, sev in enumerate(["critical", "high", "high", "info", "weird"])
        ]
        parsed = data.scoped_alerts(alerts, _parse, None)
        counts = data.severity_counts(parsed)
        assert counts["critical"] == 1 and counts["high"] == 2 and counts["other"] == 2
        days = data.alerts_by_day(parsed, days=7, now=now)
        assert len(days) == 7 and days[-1]["label"] == "Today"
        assert days[-1]["counts"]["critical"] == 1
        assert sum(sum(d["counts"].values()) for d in days) == 5

    def test_recent_rows_cut_title(self):
        rows = data.recent_alert_rows(
            data.scoped_alerts(
                [{"event_id": "1", "ts": 1, "body": "high|h"}],
                lambda b: {"title": "x" * 300, "severity": "high"},
                None,
            )
        )
        assert len(rows[0]["title"]) <= 91


@pytest.mark.unit
class TestCatalogKeys:
    def test_every_key_the_plugin_uses_exists(self):
        with open(
            os.path.join(_REPO, "plugins", "devices", "main.py"), encoding="utf-8"
        ) as f:
            src = f.read()
        used = set(re.findall(r'_t\("([a-z_]+)"', src))
        with open(
            os.path.join(_REPO, "plugins", "devices", "tabs.py"), encoding="utf-8"
        ) as f:
            used |= set(re.findall(r'self\.t\("([a-z_]+)"', f.read()))
        # Keys built from the inventory view names at runtime.
        for view in ("devices", "processes", "ports", "network", "packages"):
            used |= {f"inv_view_{view}", f"inv_lead_{view}"}
            if view != "devices":
                used.add(f"inv_word_{view}")
        used |= {f"tab_{k}" for k in ("overview", "vulns", "events", "inventory")}
        assert used, "no keys found"
        with open(
            os.path.join(_REPO, "utils", "i18n", "en.json"), encoding="utf-8"
        ) as f:
            catalog = json.load(f)
        missing = sorted(k for k in used if f"devices.{k}" not in catalog)
        assert not missing, f"missing en.json keys: {missing}"
