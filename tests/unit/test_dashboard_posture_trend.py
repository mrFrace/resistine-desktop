"""Security score trend (plugins/dashboard/posture.py): one point per day."""

from datetime import date, timedelta

import pytest

from plugins.dashboard import posture

TODAY = date(2026, 10, 16)


def day(n):
    return (TODAY - timedelta(days=n)).isoformat()


@pytest.mark.unit
class TestHistory:
    def test_one_point_per_day_latest_wins(self):
        h = posture.add_point([], 70, TODAY)
        h = posture.add_point(h, 74, TODAY)
        assert h == [[TODAY.isoformat(), 74]]

    def test_keeps_thirty_days_sorted(self):
        h = [[day(n), 50 + n] for n in range(40, 0, -1)]
        h = posture.add_point(h, 90, TODAY)
        assert len(h) == posture.HISTORY_DAYS and h[-1] == [TODAY.isoformat(), 90]
        assert h[0][0] == day(posture.HISTORY_DAYS - 1)

    def test_bad_points_are_dropped(self):
        h = posture.add_point([["nope", 1], [day(1)], None, [day(2), "x"], [day(3), 60]], 61, TODAY)
        assert h == [[day(3), 60], [TODAY.isoformat(), 61]]
        assert posture.add_point("junk", 61, TODAY) == [[TODAY.isoformat(), 61]]

    def test_record_score_persists(self, isolated_settings):
        at = f"{day(2)}T06:04:37"
        assert posture.record_score({"score": 80, "computed_at": at}) == [[day(2), 80]]
        assert posture.history() == [[day(2), 80]]
        for bad in ({"score": "80", "computed_at": at}, {"score": 140, "computed_at": at},
                    {"score": True, "computed_at": at}, {"score": 81}, {"score": 81, "computed_at": "?"},
                    {}, None):
            assert posture.record_score(bad) == [[day(2), 80]]

    def test_a_stale_card_adds_no_new_day(self, isolated_settings):
        card = {"score": 88, "computed_at": f"{day(3)}T06:04:37"}
        for _ in range(3):  # the app refreshes on three days; the server never recomputed
            posture.record_score(card)
        assert posture.history() == [[day(3), 88]]


@pytest.mark.unit
class TestTrend:
    def test_needs_two_days(self):
        assert posture.trend([]) is None
        assert posture.trend([[day(0), 70]], TODAY) is None

    def test_since_last_week(self):
        h = [[day(10), 60], [day(8), 64], [day(3), 66], [day(0), 70]]
        t = posture.trend(h, TODAY)
        assert t == {"points": [60, 64, 66, 70], "delta": 6, "text": "▲ 6 since last week"}

    def test_short_history_and_drop(self):
        t = posture.trend([[day(2), 75], [day(0), 72]], TODAY)
        assert t["delta"] == -3 and t["text"] == "▼ 3 in 2 days"
        assert posture.trend([[day(1), 72], [day(0), 72]], TODAY)["text"] == "No change in 1 day"

    def test_panel_shows_trend(self):
        st = {"status": "ok", "cards": [{"hostname": "box", "grade": "B", "score": 72,
                                         "computed_at": "2026-10-16T06:00:00"}]}
        t = posture.trend([[day(8), 66], [day(0), 72]], TODAY)
        from datetime import datetime
        d = posture.panel_data(st, {"box"}, now=datetime(2026, 10, 16, 9), score_trend=t)
        assert d["rows"]["Trend"] == "▲ 6 since last week" and d["spark"] == [66, 72]
        d = posture.panel_data(st, {"other"}, now=datetime(2026, 10, 16, 9), score_trend=t)
        assert "spark" not in d and "Trend" not in d["rows"]  # not this machine's card
