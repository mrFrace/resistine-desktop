"""The week in one sentence, at the top of the Dashboard.

The tiles compete for attention; this line says first what they add up
to, in words: "3 alerts this week, all false positives. Nothing needs
you." It is built from what the Dashboard already has (the alert store,
this machine's open mitigations, the tiles' badges), so it costs nothing
and never says more than the tiles can back up:

* "Nothing needs you." is said only when nothing is unread, no incident
  was confirmed, nothing is left to fix here, no tile is in error and no
  tile is unknown. An unknown tile is named instead ("Endpoint not
  checked.") and the verdict is withheld: not knowing is not calm.

No Qt in here.
"""

from __future__ import annotations

import time
from datetime import datetime, timedelta
from typing import Optional

from plugins.dashboard import alerts as recent_alerts
from utils.i18n import get_text

DAYS = 7
# Tiles the sentence watches, in the order they are named.
TILES = ("endpoint", "antivirus", "posture")


def _t(key: str, **fmt) -> str:
    return get_text(f"dashboard.week_{key}", **fmt)


def _this_week(alerts: list, now: float) -> list:
    cutoff = datetime.fromtimestamp(now).date() - timedelta(days=DAYS - 1)
    return [i for i in recent_alerts.incidents(alerts)
            if datetime.fromtimestamp(i["ts"]).date() >= cutoff]


def alerts_clause(alerts: list, unread: int, now: Optional[float] = None) -> tuple[str, bool]:
    """("3 alerts this week, all false positives.", needs_you)."""
    incs = _this_week(alerts, now or time.time())
    if not incs:
        return _t("no_alerts"), False
    n = len(incs)
    head = _t("alerts_one") if n == 1 else _t("alerts_many", n=n)
    confirmed = sum(1 for i in incs if i["verdict"] == "tp")
    if unread and int(unread) > 0:
        return head + _t("tail_unread"), True
    if confirmed:
        return head + _t("tail_confirmed", n=confirmed), True
    if all(i["verdict"] == "fp" for i in incs):
        return head + _t("tail_false_positives"), False
    return head + _t("tail_seen"), False


def tiles_clause(tiles: dict) -> tuple[list, bool, bool]:
    """([clauses], needs_you, unknown) from the tiles' badges
    ({key: {"badge": (kind, label), ...}})."""
    out, needs, unknown = [], False, False
    for key in TILES:
        badge = (tiles.get(key) or {}).get("badge") or (None, "")
        kind, label = badge[0], str(badge[1] or "")
        name = _t(f"tile_{key}")
        if kind == "error":
            out.append(_t("tile_attention", tile=name))
            needs = True
        elif kind == "unknown" or (key == "posture" and label == "Stale"):
            out.append(_t("tile_unknown", tile=name))
            unknown = True
    return out, needs, unknown


def sentence(alerts: list, unread: int, todo_open: int, tiles: dict,
             now: Optional[float] = None) -> str:
    """The whole line. *todo_open*: this machine's mitigations still to
    fix (open or restart needed)."""
    first, needs = alerts_clause(alerts, unread, now)
    parts = [first]
    if todo_open:
        parts.append(_t("todo_one") if todo_open == 1 else _t("todo_many", n=todo_open))
        needs = True
    clauses, tile_needs, unknown = tiles_clause(tiles or {})
    parts.extend(clauses)
    if not (needs or tile_needs or unknown):
        parts.append(_t("nothing"))
    return " ".join(parts)
