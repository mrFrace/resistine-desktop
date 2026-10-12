"""Security posture of the user's machines, for the Dashboard.

LLMAgent-api recomputes a posture per Wazuh agent every day at 06:00 and when
an agent reconnects. The app reads the signed-in user's cards from
``GET /v1/me/posture`` on api.phoenix.exposed: the server takes the user from
the MAS token and returns only that user's agents (phoenix.posture.v1 cards:
grade, score, counts, recommendations). This module fetches them (throttled,
with ETag), keeps the last good answer so the panel paints at once and
survives being offline, and turns them into the panel's rows.

No Qt in here; fetch() runs on the Dashboard's worker thread.
"""

from __future__ import annotations

import socket
import threading
import time
from datetime import datetime
from typing import Iterable, Optional

from utils import settings
from utils.logger import logger

SCHEMA = "phoenix.posture.v1"
_NS = "dashboard"
_KEY = "posture"
MIN_INTERVAL_S = 300       # the data changes daily; ETag makes repeats cheap
STALE_AFTER_S = 26 * 3600  # one missed daily run
_lock = threading.Lock()

# Outcome of the last fetch: ok | not_modified | signed_out | not_enrolled | error
_last = {"status": None, "error": None, "tried_at": 0.0}


def _cache() -> dict:
    c = settings.get(_NS, _KEY)
    return c if isinstance(c, dict) else {}


def _valid_cards(body) -> list:
    agents = body.get("agents") if isinstance(body, dict) else None
    if not isinstance(agents, list):
        return []
    return [c for c in agents if isinstance(c, dict) and c.get("schema") == SCHEMA]


def fetch(force: bool = False) -> dict:
    """Refresh from the server unless fetched recently. Returns state()."""
    if not settings.get("auth", "logged_in", False):
        _last.update(status="signed_out", error=None)
        return state()
    with _lock:
        if not force and time.time() - _last["tried_at"] < MIN_INTERVAL_S:
            return state()
        _last["tried_at"] = time.time()
        from plugins.vpn.provisioning import ProvisioningError, _authorized_request

        cache = _cache()
        headers = {"If-None-Match": cache["etag"]} if cache.get("etag") else {}
        try:
            r = _authorized_request("GET", "/v1/me/posture", headers=headers)
        except ProvisioningError as e:
            _last.update(status="error", error=str(e))
            return state()
        if r.status_code == 304:
            _last.update(status="not_modified", error=None)
        elif r.status_code == 200:
            try:
                cards = _valid_cards(r.json())
            except ValueError:
                _last.update(status="error", error="The Phoenix service sent an invalid answer.")
                return state()
            settings.set(_NS, _KEY, {"etag": r.headers.get("ETag"), "cards": cards,
                                     "fetched_at": time.time()})
            _last.update(status="ok", error=None)
        elif r.status_code == 403:
            settings.set(_NS, _KEY, {})
            _last.update(status="not_enrolled", error=None)
        else:
            logger.warning(f"[POSTURE] /v1/me/posture answered HTTP {r.status_code}")
            _last.update(status="error", error=f"The Phoenix service answered HTTP {r.status_code}.")
    return state()


def state() -> dict:
    c = _cache()
    return {"status": _last["status"], "error": _last["error"],
            "cards": c.get("cards") or [], "fetched_at": c.get("fetched_at")}


def local_names(include_agent: bool = True) -> set:
    """Names this machine may have as a Wazuh agent (lower case).

    include_agent=False skips asking the agent (keep the UI thread fast)."""
    names = set()
    if include_agent:
        try:
            from plugins.wazuh import main as wz
            name = wz._safe(wz.get_agent_name, None)
            if name and name != "—":
                names.add(str(name).lower())
        except Exception:  # noqa: BLE001
            pass
    host = socket.gethostname().lower()
    names.update({host, host.split(".")[0]})
    return {n for n in names if n}


# --------------------------------------------------------------------------
# Panel rows
# --------------------------------------------------------------------------

def _computed(card: dict) -> Optional[datetime]:
    try:
        return datetime.fromisoformat(str(card.get("computed_at")))
    except ValueError:
        return None


def _age_text(when: Optional[datetime], now: datetime) -> str:
    if when is None:
        return "—"
    secs = (now.replace(tzinfo=None) - when.replace(tzinfo=None)).total_seconds()
    if secs < 3600:
        return "Less than an hour ago"
    if secs < 86400:
        h = int(secs // 3600)
        return f"{h} hour{'s' if h != 1 else ''} ago"
    d = int(secs // 86400)
    return f"{d} day{'s' if d != 1 else ''} ago"


def _grade_kind(grade: str) -> str:
    return {"A": "ok", "B": "ok", "C": "warning"}.get(grade, "error")


def _n(value) -> str:
    return f"{int(value or 0):,}"


def split_cards(cards: list, names: Iterable[str]) -> tuple:
    """(this machine's card or None, the other cards)."""
    names = {n.lower() for n in names}
    mine = next((c for c in cards if str(c.get("hostname", "")).lower() in names), None)
    return mine, [c for c in cards if c is not mine]


def panel_data(st: dict, names: Iterable[str], now: Optional[datetime] = None,
               todo: Optional[str] = None) -> Optional[dict]:
    """The Security posture panel's badge and rows (None: still loading).

    ``todo``: this machine's mitigation summary (mitigations.summary); when
    absent the server's plain recommendations are shown."""
    now = now or datetime.now()
    status, cards = st.get("status"), st.get("cards") or []
    if status == "signed_out":
        return {"badge": ("info", "Sign in"),
                "rows": {"Posture": "Sign in to see the security posture of your machines."}}
    if status == "not_enrolled":
        return {"badge": ("info", "Not enrolled"),
                "rows": {"Posture": "Your account is not enrolled for security posture yet."}}
    if not cards:
        if status == "error":
            return {"badge": ("warning", "Unavailable"), "rows": {"Posture": st.get("error") or "Unavailable"}}
        if status is None:
            return None  # first fetch still running: the panel says Loading…
        return {"badge": ("info", "No data"),
                "rows": {"Posture": "No posture has been computed for your machines yet."}}

    mine, others = split_cards(cards, names)
    rows: dict = {}
    if mine is None:
        badge = ("info", "No data for this machine")
        rows["This machine"] = "No posture for this machine (it may not be enrolled yet)."
    else:
        grade = str(mine.get("grade") or "?")
        when = _computed(mine)
        stale = when is None or (now.replace(tzinfo=None) - when.replace(tzinfo=None)).total_seconds() > STALE_AFTER_S
        badge = ("warning", "Stale") if stale else (_grade_kind(grade), f"Grade {grade}")
        v, comp, al = mine.get("vulnerabilities") or {}, mine.get("compliance") or {}, mine.get("alerts") or {}
        rows["Machine"] = str(mine.get("hostname") or "—")
        health = str(mine.get("health") or "").replace("_", " ")
        rows["Score"] = f"{grade} · {mine.get('score', '—')}/100" + (f", {health}" if health else "")
        rows["Vulnerabilities"] = f"{_n(v.get('critical'))} critical · {_n(v.get('high'))} high"
        pct = comp.get("score_pct")
        rows["Compliance"] = (f"{pct}%" if pct is not None else "—") + (
            f" ({_n(comp.get('failed_checks'))} failed checks)" if comp.get("failed_checks") else "")
        if al.get("available", True):
            rows[f"Alerts ({al.get('window_hours') or 24} h)"] = (
                f"{_n(al.get('critical'))} critical · {_n(al.get('high'))} high")
        rows["Updated"] = _age_text(when, now)
        recs = [str(r) for r in (mine.get("recommendations") or []) if r][:3]
        if todo:
            rows["To do"] = todo
        elif recs:
            rows["To do"] = "\n".join(recs)
    if others:
        rows["Other machines"] = "\n".join(
            f"{c.get('hostname') or c.get('agent_id')}: {c.get('grade') or '?'} · {c.get('score', '—')}"
            for c in others)
    if status == "error" and st.get("error"):
        rows["Note"] = f"Showing the last known posture. {st['error']}"
    return {"badge": badge, "rows": rows}
