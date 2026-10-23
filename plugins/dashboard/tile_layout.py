"""Dashboard tile placement: width spans on a unit grid, heights automatic.

The grid has 2, 4, 6 or 8 units (one per ~195 px or more, half a card): an
even count, so whole cards fill a row. A tile spans at least two units; the
user widens or narrows it by its right edge, by half a card. Tiles are placed
in the user's order, each at the top of its place: a tile the user dropped
somewhere keeps that column, the others take the column where they sit
highest. Nothing here knows Qt; _PanelGrid in main.py measures and moves the
widgets.
"""

from __future__ import annotations

from typing import Callable, Optional

GAP = 16
UNIT = 195          # the narrowest a unit gets: two cards in 840 px, three in 1250
MIN_UNITS, MAX_UNITS = 2, 8
MIN_SPAN = 2        # a tile is at least two units (~420 px) wide
HYSTERESIS = 24     # px past a boundary before the unit count changes
WIDE = {"posture": 4, "alerts": 4}  # default spans from 6 units; the rest are MIN_SPAN
WIDE_FROM = 6


def _raw_units(width: float) -> int:
    n = max(MIN_UNITS, min(MAX_UNITS, (int(width) + GAP) // (UNIT + GAP)))
    return n - n % 2


def units_for(width: float, prev: Optional[int] = None) -> int:
    """Units for a grid this wide. Near a boundary the previous count stays,
    so the layout doesn't flip back and forth while the window is resized."""
    n = _raw_units(width)
    if prev is not None and prev != n and _raw_units(width - HYSTERESIS) <= prev <= _raw_units(width + HYSTERESIS):
        return prev
    return n


def unit_width(width: float, units: int) -> float:
    return max(1.0, (width - GAP * (units - 1)) / units)


def clean_layout(saved, keys) -> dict:
    """The saved {key: {"span", "col"}}, keeping only valid entries."""
    out = {}
    if not isinstance(saved, dict):
        return out
    for key in keys:
        spec = saved.get(key)
        if not isinstance(spec, dict):
            continue
        clean = {}
        span, col = spec.get("span"), spec.get("col")
        if isinstance(span, int) and not isinstance(span, bool) and span >= MIN_SPAN:
            clean["span"] = min(span, MAX_UNITS)
        if isinstance(col, int) and not isinstance(col, bool) and col >= 0:
            clean["col"] = min(col, MAX_UNITS - MIN_SPAN)
        if clean:
            out[key] = clean
    return out


def span_of(key: str, layout: dict, units: int) -> int:
    default = WIDE.get(key, MIN_SPAN) if units >= WIDE_FROM else MIN_SPAN
    span = (layout.get(key) or {}).get("span") or default
    return max(min(MIN_SPAN, units), min(span, units))


def place(order: list, layout: dict, units: int,
          height: Callable[[str, int], int]) -> tuple[dict, int]:
    """({key: (col, span, top, height)}, total height) for the tiles in order.

    A tile with a saved column goes there (moved left only when it would
    stick out); one without takes the column where it sits highest
    (ties: leftmost). ``height(key, span)`` measures a tile at that span."""
    tops = [0] * units
    out = {}
    for key in order:
        span = span_of(key, layout, units)
        want = (layout.get(key) or {}).get("col")
        if want is not None:
            col = max(0, min(int(want), units - span))
        else:
            col = min(range(units - span + 1), key=lambda c: (max(tops[c:c + span]), c))
        top = max(tops[col:col + span])
        h = int(height(key, span))
        out[key] = (col, span, top, h)
        for c in range(col, col + span):
            tops[c] = top + h + GAP
    return out, max(0, max(tops) - GAP) if out else 0


def drop(order: list, layout: dict, key: str, col: int, y: int, placed: dict) -> tuple[list, dict]:
    """(order, layout) with ``key`` dropped at column ``col``, height ``y``.

    The tile keeps that column. In the order it goes after every tile whose
    middle is above the drop point, so those stay where they are and only
    the tiles after it are placed again."""
    if key not in order:
        return list(order), dict(layout)
    others = [k for k in order if k != key]
    idx = 0
    for i, k in enumerate(others):
        if k in placed and placed[k][2] + placed[k][3] / 2 < y:
            idx = i + 1
    new_layout = {k: dict(v) for k, v in layout.items()}
    new_layout.setdefault(key, {})["col"] = max(0, int(col))
    return others[:idx] + [key] + others[idx:], new_layout


def resize(layout: dict, key: str, span: int, col: int) -> dict:
    """Layout with ``key`` set to ``span`` units, kept at ``col`` (a tile
    being resized must not jump to another column under the mouse)."""
    new_layout = {k: dict(v) for k, v in layout.items()}
    spec = new_layout.setdefault(key, {})
    spec["span"] = max(MIN_SPAN, min(int(span), MAX_UNITS))
    spec["col"] = max(0, int(col))
    return new_layout


def width_label(span: int) -> str:
    """'1 ×', '1.5 ×', '2 ×': the tile's width in cards, for the resize chip."""
    cards = span / MIN_SPAN
    return f"{cards:g} ×"
