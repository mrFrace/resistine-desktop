"""The week in one sentence (plugins/dashboard/weekly.py)."""

import pytest

from plugins.dashboard import weekly
from tests.unit.test_dashboard_alerts import HUNT, NOW, RESULT_FP, RESULT_INC, TRIAGE, alert

pytestmark = pytest.mark.unit

_AT = "*When:* 2026-10-16 12:26:59 CEST\n*What:*"  # same incident as HUNT
RESULT_FP = RESULT_FP.replace("*What:*", _AT)
RESULT_INC = RESULT_INC.replace("*What:*", _AT)
RESULT_TP = RESULT_FP.replace("🟢 *Hunt result — False positive* (55% FP)",
                              "🔴 *Hunt result — True positive* (5% FP)")
OK_TILES = {"endpoint": {"badge": ("ok", "Running")}, "antivirus": {"badge": ("ok", "Protected")},
            "posture": {"badge": ("ok", "Grade A")}}


def _on_other_box(body, host="francispc", agent="004"):
    return body.replace("AnubisAI agent 007", f"{host} agent {agent}").replace(
        "AnubisAI (id 007)", f"{host} (id {agent})")


def test_quiet_week():
    assert weekly.sentence([], 0, 0, OK_TILES, NOW) == "No alerts this week. Nothing needs you."


def test_all_false_positives_is_calm():
    items = [alert(TRIAGE, 30, "t"), alert(HUNT, 20, "h"), alert(RESULT_FP, 19, "r")]
    assert weekly.sentence(items, 0, 0, OK_TILES, NOW) == \
        "1 alert this week, all false positives. Nothing needs you."


def test_unread_and_confirmed_need_you():
    items = [alert(TRIAGE, 30, "t"), alert(HUNT, 20, "h"), alert(RESULT_TP, 19, "r"),
             alert(_on_other_box(TRIAGE), 10, "t2")]
    assert weekly.sentence(items, 2, 0, OK_TILES, NOW) == "2 alerts this week, not all read yet."
    assert weekly.sentence(items, 0, 0, OK_TILES, NOW) == "2 alerts this week, 1 confirmed."


def test_open_hunt_is_seen_not_closed():
    items = [alert(TRIAGE, 30, "t"), alert(HUNT, 20, "h"), alert(RESULT_INC, 19, "r")]
    assert weekly.sentence(items, 0, 0, OK_TILES, NOW) == "1 alert this week, all seen. Nothing needs you."
    # no result at all: the same
    assert weekly.alerts_clause([alert(TRIAGE, 30, "t")], 0, NOW) == ("1 alert this week, all seen.", False)


def test_old_alerts_are_not_this_week():
    items = [alert("🔴 old", mins_ago=60 * 24 * 9, eid="old")]
    assert weekly.sentence(items, 0, 0, OK_TILES, NOW).startswith("No alerts this week.")


def test_fixes_to_do():
    assert weekly.sentence([], 0, 1, OK_TILES, NOW) == "No alerts this week. 1 fix to do on this machine."
    assert weekly.sentence([], 0, 3, OK_TILES, NOW) == "No alerts this week. 3 fixes to do on this machine."


def test_unknown_tile_withholds_the_verdict():
    tiles = dict(OK_TILES, endpoint={"badge": ("unknown", "Not checked")})
    assert weekly.sentence([], 0, 0, tiles, NOW) == "No alerts this week. Endpoint not checked."
    tiles = dict(OK_TILES, posture={"badge": ("warning", "Stale")})
    assert weekly.sentence([], 0, 0, tiles, NOW) == "No alerts this week. Posture not checked."


def test_error_tile_needs_attention():
    tiles = dict(OK_TILES, endpoint={"badge": ("error", "Stopped")},
                 antivirus={"badge": ("error", "Not installed")})
    assert weekly.sentence([], 0, 0, tiles, NOW) == \
        "No alerts this week. Endpoint needs attention. Antivirus needs attention."


def test_missing_or_loading_tiles_are_not_unknown():
    assert weekly.sentence([], 0, 0, {"endpoint": None}, NOW) == "No alerts this week. Nothing needs you."
    assert weekly.sentence([], 0, 0, {}, NOW).endswith("Nothing needs you.")


def test_bad_input_does_not_raise():
    assert weekly.sentence(None, None, 0, None, NOW) == "No alerts this week. Nothing needs you."
    assert weekly.sentence(["junk", {"ts": "x"}], 0, 0, OK_TILES, NOW).startswith("No alerts")


class TestWeeklyPost:
    def test_due_a_week_after_the_last_post(self):
        assert weekly.post_due(None, NOW) is False          # clock not set yet
        assert weekly.post_due("x", NOW) is False
        assert weekly.post_due(NOW - 6 * 86400, NOW) is False
        assert weekly.post_due(NOW - 7 * 86400, NOW) is True

    def test_first_post_clock_set_once(self, isolated_settings):
        from utils import settings
        weekly.first_post_clock(NOW)
        weekly.first_post_clock(NOW + 100)
        assert settings.get("dashboard", "weekly_posted_at") == NOW
        weekly.mark_posted(NOW + 5)
        assert settings.get("dashboard", "weekly_posted_at") == NOW + 5

    def test_post_text_names_this_machine_only(self):
        text = weekly.post_text("No alerts this week. Nothing needs you.", "francispc")
        assert text == "Phoenix · francispc\nNo alerts this week. Nothing needs you."
        assert weekly.post_text("x", "evil\x1bhost" + "a" * 100).startswith("Phoenix · evilhost")
        assert len(weekly.post_text("x", "a" * 100).splitlines()[0]) <= len("Phoenix · ") + 63
