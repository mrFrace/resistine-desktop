"""Dashboard tile placement (plugins/dashboard/tile_layout.py): width spans
on a unit grid, automatic heights, tiles kept where the user dropped them."""

import pytest

from plugins.dashboard import tile_layout as tl

ORDER = ["posture", "alerts", "antivirus", "vpn", "endpoint", "ai", "system"]
HEIGHTS = {"posture": 300, "alerts": 260, "antivirus": 160, "vpn": 140,
           "endpoint": 160, "ai": 140, "system": 160}


def h(key, span):
    return HEIGHTS[key]


def overlaps(placed):
    cells = {}
    for key, (col, span, top, height) in placed.items():
        for c in range(col, col + span):
            for other, (t, b) in cells.get(c, []):
                if top < b and t < top + height:
                    return (key, other)
            cells.setdefault(c, []).append((key, (top, top + height)))
    return None


@pytest.mark.unit
class TestUnits:
    @pytest.mark.parametrize("width,units", [(300, 2), (700, 2), (840, 4), (1250, 6), (1600, 6), (1700, 8), (4000, 8)])
    def test_units_by_width(self, width, units):
        assert tl.units_for(width) == units

    def test_hysteresis_keeps_the_count_near_a_boundary(self):
        boundary = 6 * (tl.UNIT + tl.GAP) - tl.GAP  # first width with 6 units
        assert tl.units_for(boundary) == 6
        assert tl.units_for(boundary - 10, prev=6) == 6   # just under: stays
        assert tl.units_for(boundary - 10) == 4
        assert tl.units_for(boundary - 60, prev=6) == 4   # clearly under: changes
        assert tl.units_for(boundary + 10, prev=4) == 4

    def test_wide_tiles_only_when_there_is_room_beside_them(self):
        assert tl.span_of("posture", {}, 4) == 2 and tl.span_of("posture", {}, 6) == 4
        assert tl.span_of("posture", {"posture": {"span": 3}}, 4) == 3  # the user's choice stays


@pytest.mark.unit
class TestPlace:
    def test_defaults_wide_posture_and_alerts_no_overlap(self):
        placed, total = tl.place(ORDER, {}, 6, h)
        assert placed["posture"][:3] == (0, 4, 0)
        assert placed["alerts"][1] == 4 and placed["vpn"][1] == 2
        assert overlaps(placed) is None
        assert total == max(top + height for _, _, top, height in placed.values())

    def test_auto_tiles_take_the_highest_spot(self):
        placed, _ = tl.place(ORDER, {}, 6, h)
        assert placed["alerts"][:3] == (0, 4, 316)   # under posture: right side is only 2 wide
        assert placed["antivirus"][:3] == (4, 2, 0)  # fills the free top-right

    def test_dropped_column_is_kept(self):
        placed, _ = tl.place(ORDER, {"vpn": {"col": 4}}, 6, h)
        assert placed["vpn"][0] == 4
        assert overlaps(placed) is None

    def test_spans_and_columns_fit_a_narrow_grid(self):
        layout = {"posture": {"span": 6, "col": 2}, "vpn": {"col": 5}}
        placed, _ = tl.place(ORDER, layout, 2, h)
        assert all(col == 0 and span == 2 for col, span, _, _ in placed.values())  # one per row
        assert overlaps(placed) is None

    def test_height_is_measured_at_the_span(self):
        seen = []
        tl.place(["posture"], {"posture": {"span": 3}}, 6, lambda k, s: seen.append(s) or 100)
        assert seen == [3]


@pytest.mark.unit
class TestDropAndResize:
    def test_drop_keeps_tiles_above_in_place(self):
        placed, _ = tl.place(ORDER, {}, 6, h)
        y = placed["vpn"][2] + 1  # dropped at vpn's height
        order, layout = tl.drop(ORDER, {}, "system", 2, y, placed)
        assert layout == {"system": {"col": 2}}
        before = order[:order.index("system")]
        above = {k for k, (_, _, top, hh) in placed.items() if k != "system" and top + hh / 2 < y}
        assert above <= set(before)  # after every tile whose middle is above the drop point
        new, _ = tl.place(order, layout, 6, h)
        assert all(new[k] == placed[k] for k in before)  # none of those moved
        assert new["system"][0] == 2 and overlaps(new) is None

    def test_drop_unknown_key_changes_nothing(self):
        assert tl.drop(ORDER, {}, "nope", 1, 0, {}) == (ORDER, {})

    def test_resize_pins_the_column(self):
        layout = tl.resize({}, "vpn", 3, 2)
        assert layout == {"vpn": {"span": 3, "col": 2}}
        assert tl.resize({}, "vpn", 1, 0)["vpn"]["span"] == tl.MIN_SPAN

    @pytest.mark.parametrize("span,label", [(2, "1 ×"), (3, "1.5 ×"), (4, "2 ×")])
    def test_width_label(self, span, label):
        assert tl.width_label(span) == label


@pytest.mark.unit
def test_clean_layout_drops_junk():
    saved = {"vpn": {"span": 3, "col": 1}, "ai": {"span": 1, "col": -2}, "bogus": {"span": 3},
             "system": "x", "endpoint": {"span": True, "col": 99}}
    assert tl.clean_layout(saved, ORDER) == {"vpn": {"span": 3, "col": 1},
                                             "endpoint": {"col": tl.MAX_UNITS - tl.MIN_SPAN}}
    assert tl.clean_layout("junk", ORDER) == {}
