"""Devices page: the data behind it, with no Qt.

The page replaces the old Wazuh Overview, which read vulnerability, inventory
and SCA tables from the old company's dashboard API by source IP. The Phoenix
API exposes none of that; what it does give a signed-in user is one posture
card per agent (``GET /v1/me/posture``, schema phoenix.posture.v1: grade,
score, vulnerability counts by severity, compliance checks, alert counts over
the last day, recommendations and structured mitigations). Together with the
SIEM alerts siem-bot sends over Matrix (plugins/chat/siem_alerts.py) and this
machine's own agent state, that is what the page shows.

Everything here is pure: cards and alerts in, rows and counts out. The server
and the alert bodies are untrusted input, so values are coerced defensively
and text is cut to size before it reaches a label.
"""

from __future__ import annotations

import time
from collections.abc import Iterable
from datetime import datetime

from utils.i18n import get_text

SEVERITIES = ("critical", "high", "medium", "low")
ALL_DEVICES = "all"
DAYS = 7
MAX_TEXT = 120


def _t(key: str, **fmt) -> str:
    return get_text(f"devices.{key}", **fmt)


def _int(v) -> int:
    try:
        return max(0, int(v))
    except (TypeError, ValueError):
        return 0


def _text(v, limit: int = MAX_TEXT) -> str:
    s = "".join(ch for ch in str(v or "") if ch.isprintable()).strip()
    return s[:limit] + ("…" if len(s) > limit else "")


def grade_kind(grade) -> str:
    """Badge kind for a grade: A/B ok, C warning, anything else error."""
    return {"A": "ok", "B": "ok", "C": "warning"}.get(str(grade or "").upper(), "error")


def health_kind(health, grade=None) -> str:
    """Badge kind for the server's health state.

    The pill text IS the health string, so its colour must follow the same
    value — colouring by grade painted a green pill that said
    "Needs attention" (grade B + needs_attention health).
    """
    h = str(health or "").strip().lower()
    if h in ("ok", "healthy", "protected", "good"):
        return "ok"
    if "attention" in h or h in ("degraded", "warning", "stale"):
        return "warning"
    if h in ("at risk", "critical", "compromised", "error"):
        return "error"
    return grade_kind(grade)


def grade_rank(grade) -> int:
    return {"A": 0, "B": 1, "C": 2, "D": 3, "F": 4}.get(str(grade or "").upper(), 5)


def computed_at(card: dict) -> datetime | None:
    try:
        return datetime.fromisoformat(str(card.get("computed_at"))).replace(tzinfo=None)
    except (TypeError, ValueError):
        return None


def age_text(when: datetime | None, now: datetime | None = None) -> str:
    if when is None:
        return "—"
    secs = max(
        0.0, ((now or datetime.now()).replace(tzinfo=None) - when).total_seconds()
    )
    if secs < 3600:
        return _t("age_lt_hour")
    if secs < 86400:
        h = int(secs // 3600)
        return _t("age_hour" if h == 1 else "age_hours", n=h)
    d = int(secs // 86400)
    return _t("age_day" if d == 1 else "age_days", n=d)


def is_this_machine(
    host: str,
    agent_id: str,
    local_names: Iterable[str],
    local_agent_ids: Iterable[str] = (),
) -> bool:
    """Whether a card is about the machine the app runs on.

    The agent id this device enrolled with is exact. Names are looser: the
    agent name is the hostname plus a machine-id suffix and, after a
    re-enrollment, a time suffix ("DrakeHP-97EF26154AD1-813392"), so a card
    whose hostname starts with a local name followed by "-" counts too.
    """
    ids = {str(i) for i in local_agent_ids if i}
    if agent_id and agent_id in ids:
        return True
    h = host.lower()
    for n in local_names:
        n = str(n or "").lower()
        if n and (h == n or h.startswith(n + "-")):
            return True
    return False


# --------------------------------------------------------------------------
# Fleet: one row per posture card
# --------------------------------------------------------------------------


def is_placeholder(value) -> bool:
    """A server-side "don't know" for a name or an OS: empty, or the literal
    placeholders the posture service emits when the agent has not reported
    (its card then says hostname "Unknown", os "Unknown")."""
    return str(value or "").strip().lower() in ("", "unknown", "n/a", "none", "—", "-")


def canonical_agent_id(agent_id) -> str:
    """"004" and "4" are one agent; the manager pads, other sources may not."""
    s = str(agent_id or "").strip()
    return str(int(s)) if s.isdigit() else s


def inventory_names(devices: Iterable[dict] | None) -> dict:
    """agent_id (canonical) -> {name, os} from the /me/inventory devices
    (plugins.devices.api.fetch_inventory_full), to name a posture card the
    posture service could not."""
    out: dict = {}
    for d in devices or []:
        if not isinstance(d, dict) or not d.get("agent_id"):
            continue
        os_info = d.get("os") if isinstance(d.get("os"), dict) else {}
        out[canonical_agent_id(d["agent_id"])] = {
            "name": d.get("agent_name") or "",
            "os": os_info.get("name") or "",
        }
    return out


def fleet_rows(
    cards: Iterable[dict],
    local_names: Iterable[str],
    local_agent_ids: Iterable[str] = (),
    now: datetime | None = None,
    names_by_agent: dict | None = None,
) -> list:
    """Cards as rows, this machine first, then by grade (worst first) and name.

    ``names_by_agent`` (see inventory_names) fills a hostname or OS the posture
    card lacks: the posture service reports an agent it has no scan for as
    hostname "Unknown", which would otherwise be the device's name in the
    scope picker and the header."""
    names = [str(n) for n in local_names if n]
    rows = []
    for c in cards or []:
        if not isinstance(c, dict):
            continue
        agent_id = _text(c.get("agent_id"), 16)
        known = (names_by_agent or {}).get(canonical_agent_id(agent_id)) or {}
        host_raw = c.get("hostname")
        if is_placeholder(host_raw) and known.get("name"):
            host_raw = known["name"]
        os_raw = c.get("os")
        if is_placeholder(os_raw) and known.get("os"):
            os_raw = known["os"]
        host = _text(host_raw or c.get("agent_id") or "—", 64)
        v = (
            c.get("vulnerabilities")
            if isinstance(c.get("vulnerabilities"), dict)
            else {}
        )
        comp = c.get("compliance") if isinstance(c.get("compliance"), dict) else {}
        al = c.get("alerts") if isinstance(c.get("alerts"), dict) else {}
        when = computed_at(c)
        rows.append(
            {
                "hostname": host,
                "agent_id": agent_id,
                "os": _text(os_raw, 64),
                "grade": _text(c.get("grade") or "?", 2).upper(),
                "score": _int(c.get("score")) if c.get("score") is not None else None,
                "health": _text(c.get("health"), 32).replace("_", " "),
                "agent_status": _text(c.get("agent_status"), 16).lower(),
                "vulns": {s: _int(v.get(s)) for s in SEVERITIES},
                "vulns_available": v.get("available", True) is not False,
                "vulns_reason": _text(v.get("reason"), 32),
                "compliance_pct": (
                    _int(comp["score_pct"])
                    if comp.get("score_pct") is not None
                    else None
                ),
                "failed_checks": _int(comp.get("failed_checks")),
                "checks": _int(comp.get("checks")),
                "alerts_critical": _int(al.get("critical")),
                "alerts_high": _int(al.get("high")),
                "alerts_window_h": _int(al.get("window_hours")) or 24,
                "alerts_available": al.get("available", True) is not False,
                "computed_at": when,
                "updated": age_text(when, now),
                "recommendations": [
                    _text(r) for r in (c.get("recommendations") or []) if r
                ][:5],
                "this_machine": is_this_machine(host, agent_id, names, local_agent_ids),
                "card": c,
            }
        )
    rows.sort(
        key=lambda r: (
            not r["this_machine"],
            -grade_rank(r["grade"]),
            r["hostname"].lower(),
        )
    )
    return rows


def scope_rows(rows: list, scope: str) -> list:
    """The rows the page is scoped to: all of them, or one hostname."""
    if not scope or scope == ALL_DEVICES:
        return list(rows)
    return [r for r in rows if r["hostname"].lower() == scope.lower()]


def this_machine_row(rows: list) -> dict | None:
    return next((r for r in rows if r["this_machine"]), None)


def vuln_totals(rows: list) -> dict:
    """Per-severity sums plus whether every scoped device was scanned."""
    out = {s: 0 for s in SEVERITIES}
    for r in rows:
        for s in SEVERITIES:
            out[s] += r["vulns"][s]
    out["total"] = sum(out[s] for s in SEVERITIES)
    out["scanned"] = all(r["vulns_available"] for r in rows) if rows else False
    out["devices"] = len(rows)
    return out


def compliance_totals(rows: list) -> dict:
    """Checks passed over checks run, across the scoped devices."""
    checks = sum(r["checks"] for r in rows)
    failed = sum(r["failed_checks"] for r in rows)
    with_pct = [r["compliance_pct"] for r in rows if r["compliance_pct"] is not None]
    if checks:
        pct = round(100 * (checks - failed) / checks)
    elif with_pct:
        pct = round(sum(with_pct) / len(with_pct))
    else:
        pct = None
    return {"pct": pct, "failed": failed, "checks": checks}


def alert_totals(rows: list) -> dict:
    return {
        "critical": sum(r["alerts_critical"] for r in rows),
        "high": sum(r["alerts_high"] for r in rows),
        "window_h": max((r["alerts_window_h"] for r in rows), default=24),
        "available": all(r["alerts_available"] for r in rows) if rows else False,
    }


def agent_totals(rows: list) -> dict:
    active = sum(1 for r in rows if r["agent_status"] in ("active", "connected"))
    return {"active": active, "total": len(rows)}


def worst_grade(rows: list) -> str | None:
    return max((r["grade"] for r in rows), key=grade_rank, default=None)


def header_summary(
    status: str | None,
    rows: list,
    fetched_at: float | None,
    error: str | None = None,
    now: float | None = None,
) -> dict:
    """The page header's pill and subtitle for a posture state.

    status is posture.fetch()'s outcome: ok | not_modified | signed_out |
    not_enrolled | error | None (first fetch still running).
    """
    if status == "signed_out":
        return {"pill": ("info", _t("hdr_sign_in")), "subtitle": _t("hdr_sign_in_sub"), "note": ""}
    if status == "not_enrolled":
        return {"pill": ("info", _t("hdr_not_enrolled")), "subtitle": _t("hdr_not_enrolled_sub"),
                "note": ""}
    if not rows:
        if status is None:
            return {"pill": ("info", _t("hdr_loading")), "subtitle": _t("hdr_loading_sub"), "note": ""}
        if status == "error":
            return {"pill": ("warning", _t("hdr_unavailable")), "subtitle": _t("hdr_unavailable_sub"),
                    "note": _text(error, 160)}
        return {"pill": ("info", _t("hdr_no_data")), "subtitle": _t("hdr_no_data_sub"), "note": ""}
    n = len(rows)
    grade = worst_grade(rows)
    pill = (
        (grade_kind(grade), _t("hdr_worst_grade", grade=grade)) if grade
        else ("info", _t("hdr_no_grade"))
    )
    ago = ""
    if fetched_at:
        secs = max(0, (now or time.time()) - float(fetched_at))
        ago = " · " + (
            _t("hdr_checked_now") if secs < 120
            else _t("hdr_checked_min", n=int(secs // 60)) if secs < 7200
            else _t("hdr_checked_h", n=int(secs // 3600))
        )
    subtitle = (_t("hdr_devices_one", ago=ago) if n == 1
                else _t("hdr_devices_many", n=n, ago=ago))
    note = ""
    if status == "error":
        note = _t("hdr_last_known") + " " + _text(error, 160)
    return {"pill": pill, "subtitle": subtitle, "note": note}


# --------------------------------------------------------------------------
# Alerts: the SIEM alerts siem-bot sent, scoped to the devices shown
# --------------------------------------------------------------------------


def scoped_alerts(alerts: Iterable[dict], parse, hosts: Iterable[str] | None) -> list:
    """Parsed alerts, newest first. ``hosts`` None: every alert; otherwise only
    those about one of the hostnames (an alert naming no machine is kept, so
    a scoped view never hides a triage it cannot place)."""
    wanted = None if hosts is None else {str(h).lower() for h in hosts}
    out = []
    for a in alerts or []:
        if not isinstance(a, dict):
            continue
        info = parse(a.get("body", ""))
        host = str(info.get("host") or "").lower()
        if wanted is not None and host and host not in wanted:
            continue
        out.append(
            {
                "event_id": a.get("event_id"),
                "ts": a.get("ts") or 0,
                "info": info,
                "body": a.get("body", ""),
            }
        )
    out.sort(key=lambda x: x["ts"], reverse=True)
    return out


def severity_counts(parsed: list) -> dict:
    out = {s: 0 for s in SEVERITIES}
    out["other"] = 0
    for a in parsed:
        sev = a["info"].get("severity")
        if sev in out:
            out[sev] += 1
        else:
            out["other"] += 1
    return out


def alerts_by_day(parsed: list, days: int = DAYS, now: float | None = None) -> list:
    """One bucket per day, oldest first: {"label", "counts": {severity: n}}.

    Bucketed on the alert's local calendar day; "info" and unknown severities
    count under "other" so the chart's height is every alert, not just the
    graded ones."""
    now = now or time.time()
    today = datetime.fromtimestamp(now).date()
    buckets = []
    index = {}
    for i in range(days - 1, -1, -1):
        day = datetime.fromtimestamp(now - i * 86400).date()
        label = "Today" if day == today else day.strftime("%a")
        buckets.append(
            {
                "label": label,
                "date": day.isoformat(),
                "counts": {**{s: 0 for s in SEVERITIES}, "other": 0},
            }
        )
        index[day.isoformat()] = buckets[-1]
    for a in parsed:
        ts = a.get("ts") or 0
        if not ts:
            continue
        key = datetime.fromtimestamp(ts).date().isoformat()
        b = index.get(key)
        if b is None:
            continue
        sev = a["info"].get("severity")
        b["counts"][sev if sev in SEVERITIES else "other"] += 1
    return buckets


def recent_alert_rows(parsed: list, limit: int = 8) -> list:
    """The newest alerts for the list: title, severity, kind, host, ts."""
    rows = []
    for a in parsed[:limit]:
        info = a["info"]
        rows.append(
            {
                "event_id": a["event_id"],
                "ts": a["ts"],
                "title": _text(info.get("title") or "SIEM alert", 90),
                "severity": info.get("severity") or "info",
                "kind": info.get("kind") or "other",
                "host": _text(info.get("host"), 64),
            }
        )
    return rows
