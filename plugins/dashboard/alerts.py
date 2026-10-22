"""Recent SIEM alerts, for the Dashboard.

siemgent's @siem-bot posts alerts about the user's machines into encrypted
Matrix DMs; the chat transport stores them (plugins/chat/siem_alerts.py).
This module turns that store into the Recent alerts panel (unread count,
the newest few with severity, a one-line title and how long ago) and into
the alert detail page.

siem-bot sends three kinds of message (see parse()):

* triage: "*SIEM triage* — 25 alert(s)", then an "[Affected asset(s)]"
  line, then the model's verdict with one "Severity: High" per finding;
* hunt: "🔍 *Solving possible issue*" with *What:* and "rule.level 7";
* result: "🟢/🟡/🔴 *Hunt result — False positive* (55% FP)" with *What:*.

The prose is model output, so a word like "critical system files" says
nothing about severity: only the structured fields count. Bodies are
untrusted and parsed defensively. No Qt in here.

"unknown" is a severity of its own, for an alert that could not be read
on this device and a hunt that could not decide: it ranks above low, so
not knowing never looks calmer than a minor alert.
"""

from __future__ import annotations

import re
import time
from datetime import datetime, timedelta, timezone
from typing import Optional

from plugins.chat.siem_alerts import UNDECRYPTABLE

SHOWN = 4
_SEV_EMOJI = {"🚨": "critical", "🔴": "high", "🟠": "medium", "🟡": "low", "⚪": "info"}
_SEV_WORD = re.compile(r"\b(critical|high|medium|low)\b", re.IGNORECASE)
_SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "unknown": 1.5, "low": 1, "info": 0}
_MARKUP = re.compile(r"[*_`#>]+")


def _first_marker(body: str) -> str:
    head = (body or "")[:240]
    hits = [(head.find(e), sev) for e, sev in _SEV_EMOJI.items() if e in head]
    if hits:
        return min(hits)[1]  # the first marker in the text
    m = _SEV_WORD.search(head)
    return m.group(1).lower() if m else "info"


_TRIAGE = re.compile(r"^\W*SIEM triage\W*(\d+)\s+alert", re.IGNORECASE)
_HUNT = re.compile(r"^\W*Solving possible issue", re.IGNORECASE)
_RESULT = re.compile(r"^\W*Hunt result\s*[—–-]\s*([^*(\n]+?)\s*\*?\s*(?:\((\d+)% FP\))?\s*$",
                     re.IGNORECASE)
_ASSET_TRIAGE = re.compile(r"^\[Affected asset\(s\)\]\s*(.+?)\s+agent\s+(\S+)\s*(?:\|(.*))?$",
                           re.IGNORECASE)
_ASSET_BULLET = re.compile(r"^\s*•\s*(.+?)\s*\(id\s*([^)]+)\)", re.IGNORECASE)
_FIELD = re.compile(r"^\*(What|When|Source|Assessment):\*\s*(.+)$", re.IGNORECASE)
_RULE_LEVEL = re.compile(r"rule\.level\s+(\d+|critical|high|medium|low|informational)", re.IGNORECASE)
_SEVS = "critical|high|medium|low"
# Only the verdict's fields: a "- **Severity:** High" line, or a finding
# header's "(High Severity)". Prose like "might be of medium severity" is
# the model thinking aloud and changes from one run to the next.
_SEV_LINE = re.compile(rf"^[\s\-•*]*severity[\s*]*:[\s*]*({_SEVS})\b", re.IGNORECASE)
# "1. **Name**", "1. **Finding: Name**", "**Finding:** Name", "**Finding 2:**"
_FINDING = re.compile(r"^\s*(?:\d+\.\s+\*\*(?:Finding:\s*)?(.+?)\*\*"
                      r"|\*\*(Finding(?:\s+\d+)?):\*\*\s*(.*))", re.IGNORECASE)
_GENERIC_FINDING = re.compile(r"^Finding(?:\s+\d+)?$", re.IGNORECASE)
_DESCRIPTION = re.compile(r"^[\s\-•*]*description[\s*]*:[\s*]*(.+)$", re.IGNORECASE)
_SEV_SUFFIX = re.compile(rf"\s*\(({_SEVS})\s+severity\)\s*$", re.IGNORECASE)


def _level_severity(level: str) -> str:
    """Wazuh rule level (0-15, or a v5 label) as a severity."""
    if not level.isdigit():
        return {"informational": "info"}.get(level.lower(), level.lower())
    n = int(level)
    return "critical" if n >= 15 else "high" if n >= 12 else "medium" if n >= 7 else \
        "low" if n >= 4 else "info"


def _printable(text: str) -> str:
    return "".join(ch for ch in text if ch.isprintable())  # also drops bidi overrides


def _clean(line: str) -> str:
    return _printable(_MARKUP.sub("", line)).strip()


def _what(text: str) -> str:
    """"Wazuh FIM - File modified - /etc/x · rule <uuid>" -> "File modified - /etc/x"."""
    text = re.sub(r"\s*·\s*rule\s+\S+\s*$", "", text)
    return re.sub(r"^Wazuh\s+\w+\s+-\s+", "", text).strip()


def _worst(sevs) -> str:
    return max(sevs, key=lambda s: _SEV_RANK.get(s, 0), default="info")


def parse(body: str) -> dict:
    """Kind, severity, title and the structured fields of one alert.

    Keys: kind (triage | hunt | result | other), severity, title, host,
    agent, when, source, what, count (triage), verdict and fp (result),
    findings (triage: list of {"severity", "name"}, in message order).
    """
    body = body or ""
    lines = body.splitlines()
    first = next((ln for ln in lines if ln.strip()), "")
    out = {"kind": "other", "severity": "info", "title": "", "host": "", "agent": "",
           "when": "", "source": "", "what": "", "count": None, "verdict": "",
           "fp": None, "findings": []}
    for ln in lines[:12]:
        m = _ASSET_TRIAGE.match(_printable(ln).strip())
        if m:
            out["host"], out["agent"] = _clean(m.group(1)), _clean(m.group(2))
            for part in (m.group(3) or "").split("|"):
                part = part.strip()
                if part.startswith("source:"):
                    out["source"] = part[7:].strip()
                elif part.startswith(("at ", "window ")):
                    out["when"] = part.split(" ", 1)[1].strip()
            continue
        m = _ASSET_BULLET.match(ln)
        if m and not out["host"]:
            out["host"], out["agent"] = _clean(m.group(1)), _clean(m.group(2))
            continue
        m = _FIELD.match(ln.strip())
        if m:
            key = m.group(1).lower()
            val = _clean(m.group(2))
            if key in ("what", "when", "source") and not out[key]:
                out[key] = _what(val) if key == "what" else val

    on = f" on {out['host']}" if out["host"] else ""
    m_triage, m_result = _TRIAGE.match(_clean(first)), _RESULT.match(_clean(first))
    if m_triage:
        out["kind"], out["count"] = "triage", int(m_triage.group(1))
        loose = []  # severity lines before any finding header
        for ln in lines:
            m = _FINDING.match(ln)
            if m:
                name = _clean(m.group(1) or m.group(3) or m.group(2))
                suffix = _SEV_SUFFIX.search(name)
                out["findings"].append({"severity": suffix.group(1).lower() if suffix else None,
                                        "name": _SEV_SUFFIX.sub("", name)})
                continue
            m = _DESCRIPTION.match(ln)
            if m and out["findings"] and _GENERIC_FINDING.match(out["findings"][-1]["name"]):
                # "**Finding 1:**" names nothing; its description does.
                desc = _clean(m.group(1)).split(". ")[0].rstrip(".")
                out["findings"][-1]["name"] = desc[:80] + ("…" if len(desc) > 80 else "")
                continue
            m = _SEV_LINE.match(_printable(ln))
            if m:
                if out["findings"] and out["findings"][-1]["severity"] is None:
                    out["findings"][-1]["severity"] = m.group(1).lower()
                elif not out["findings"]:
                    loose.append(m.group(1).lower())
        # The worst stated severity; none stated at all: unknown.
        stated = [f["severity"] for f in out["findings"] if f["severity"]] + loose
        out["severity"] = _worst(stated) if stated else "unknown"
        for f in out["findings"]:
            f["severity"] = f["severity"] or "unknown"
        top = next((f["name"] for f in out["findings"] if f["severity"] == out["severity"]), "")
        n = out["count"]
        out["title"] = f"{n} alert{'s' if n != 1 else ''}{on}" + (f" — {top}" if top else "")
    elif _HUNT.match(_clean(first)):
        out["kind"] = "hunt"
        m = _RULE_LEVEL.search(body)
        out["severity"] = _level_severity(m.group(1)) if m else "info"
        out["title"] = f"Investigating: {out['what']}" if out["what"] else f"Investigating{on}"
    elif m_result:
        out["kind"] = "result"
        out["verdict"] = m_result.group(1).strip().capitalize()
        out["fp"] = int(m_result.group(2)) if m_result.group(2) else None
        v = out["verdict"].lower()
        # The result's 🟢/🟡/🔴 is the verdict's colour, not a severity:
        # an inconclusive (or unadjudicated) hunt is unknown, not low.
        out["severity"] = "info" if "false" in v else "high" if "true" in v else "unknown"
        out["title"] = f"{out['verdict']}: {out['what']}" if out["what"] else f"Hunt result: {out['verdict']}"
    elif body.strip() == UNDECRYPTABLE:
        out["severity"], out["title"] = "unknown", "Alert not readable on this device"
    else:
        out["severity"] = _first_marker(body)
        out["title"] = title(body)
    if len(out["title"]) > 90:
        out["title"] = out["title"][:90] + "…"
    return out


def severity(body: str) -> str:
    return parse(body)["severity"]


def title(body: str, limit: int = 90) -> str:  # for messages parse() doesn't know
    """First meaningful line, without markdown or leading markers."""
    for line in (body or "").splitlines():
        line = _MARKUP.sub("", line)
        line = "".join(ch for ch in line if ch.isprintable())
        line = line.strip().lstrip("".join(_SEV_EMOJI) + "🚨⚠️ -:·").strip()
        if line:
            return line[:limit] + ("…" if len(line) > limit else "")
    return "SIEM alert"


def ago(ts: Optional[float], now: Optional[float] = None) -> str:
    if not ts:
        return "—"
    secs = max(0, (now or time.time()) - ts)
    if secs < 60:
        return "Just now"
    if secs < 3600:
        return f"{int(secs // 60)} min ago"
    if secs < 86400:
        return f"{int(secs // 3600)} h ago"
    days = int(secs // 86400)
    return f"{days} day{'s' if days != 1 else ''} ago"


_DOT = {"critical": "🚨", "high": "🔴", "medium": "🟠", "unknown": "❔", "low": "🟡", "info": "⚪"}


def detail_text(body: str) -> str:
    """The body for the detail page: without the first line, which the page
    shows as its title (and the triage asset line, shown as its subtitle)."""
    lines = (body or "").splitlines()
    while lines and not lines[0].strip():
        lines.pop(0)
    lines = lines[1:]
    if lines and _ASSET_TRIAGE.match(lines[0].strip()):
        lines = lines[1:]
    return "\n".join(lines).strip()


def subtitle(info: dict, ts: Optional[float]) -> str:
    """"AnubisAI (agent 007) · 16 Oct 12:26 · wazuh.fim"."""
    parts = []
    if info.get("host"):
        parts.append(info["host"] + (f" (agent {info['agent']})" if info.get("agent") else ""))
    if ts:
        parts.append(time.strftime("%d %b %H:%M", time.localtime(ts)))
    if info.get("source"):
        parts.append(info["source"])
    if info.get("fp") is not None:
        parts.append(f"{info['fp']}% likely a false positive")
    return " · ".join(parts)


def newest_first(alerts: list) -> list:
    alerts = [a for a in alerts or [] if isinstance(a, dict)]
    return sorted(alerts, key=lambda a: a.get("ts") or 0, reverse=True)


# --------------------------------------------------------------------------
# Activity over the last days, and desktop notifications
# --------------------------------------------------------------------------

DAYS = 7
SEV_ORDER = ("critical", "high", "medium", "unknown", "low", "info")


INCIDENT_GAP_S = 300  # events on one machine this close together are one incident
# Zone names siemgent prints in *When:* ("2026-10-16 12:26:59 CEST").
_TZ_HOURS = {"UTC": 0, "GMT": 0, "WET": 0, "WEST": 1, "BST": 1, "CET": 1, "CEST": 2,
             "EET": 2, "EEST": 3, "MSK": 3, "EST": -5, "EDT": -4, "CST": -6, "CDT": -5,
             "MST": -7, "MDT": -6, "PST": -8, "PDT": -7}
_WHEN_ZONE = re.compile(r"^(\d{4}-\d\d-\d\d[ T]\d\d:\d\d(?::\d\d)?)\s+([A-Z]{2,5})$")


def event_time(when: str) -> Optional[float]:
    """When the alerted event happened (epoch seconds), from a parsed
    "when": an ISO time or window start, or "<local time> <zone>"."""
    when = (when or "").split("→")[0].strip()
    try:
        t = datetime.fromisoformat(when.replace("Z", "+00:00"))
        return t.timestamp() if t.tzinfo else None
    except ValueError:
        pass
    m = _WHEN_ZONE.match(when)
    if m and m.group(2) in _TZ_HOURS:
        try:
            t = datetime.fromisoformat(m.group(1)).replace(tzinfo=timezone.utc)
        except ValueError:
            return None
        return t.timestamp() - _TZ_HOURS[m.group(2)] * 3600
    return None


def incidents(alerts: list) -> list:
    """The alerts grouped by what they are about, oldest first.

    siem-bot sends several messages per incident: a triage (sometimes
    re-sent for the same window), then per finding an "Investigating" and
    a hunt result. Messages about one machine whose events are at most
    INCIDENT_GAP_S apart are one incident; a message with no machine or
    event time is one on its own. Each: {"ts": first message, "severity":
    the worst of its messages, "count": messages}."""
    by_host: dict = {}
    out = []
    for a in alerts or []:
        if not isinstance(a, dict) or not isinstance(a.get("ts"), (int, float)):
            continue
        info = parse(a.get("body", ""))
        host = (info["agent"] or info["host"]).lower()
        et = event_time(info["when"])
        if not host or et is None:
            out.append({"ts": a["ts"], "severity": info["severity"], "count": 1})
            continue
        by_host.setdefault(host, []).append((et, a["ts"], info["severity"]))
    for events in by_host.values():
        events.sort()
        last = None
        for et, ts, sev in events:
            if last is None or et - last > INCIDENT_GAP_S:
                cur = {"ts": ts, "severity": sev, "count": 0}
                out.append(cur)
            cur["ts"] = min(cur["ts"], ts)
            cur["severity"] = _worst((cur["severity"], sev))
            cur["count"] += 1
            last = et
    return sorted(out, key=lambda i: i["ts"])


def activity(alerts: list, now: Optional[float] = None, days: int = DAYS) -> list:
    """Incidents per local day (by first message), oldest first, ending
    today: {"day": date, "count": n, "worst": severity or None}."""
    today = datetime.fromtimestamp(now or time.time()).date()
    first = today - timedelta(days=days - 1)
    out = [{"day": first + timedelta(days=i), "count": 0, "worst": None} for i in range(days)]
    for inc in incidents(alerts):
        day = datetime.fromtimestamp(inc["ts"]).date()
        if not first <= day <= today:
            continue
        slot = out[(day - first).days]
        slot["count"] += 1
        if slot["worst"] is None or _SEV_RANK[inc["severity"]] > _SEV_RANK[slot["worst"]]:
            slot["worst"] = inc["severity"]
    return out


def breakdown(alerts: list, now: Optional[float] = None, days: int = DAYS) -> str:
    """"7 incidents: 2 high · 5 medium" for the last *days* days, or "None"."""
    counts = dict.fromkeys(SEV_ORDER, 0)
    cutoff = datetime.fromtimestamp(now or time.time()).date() - timedelta(days=days - 1)
    for inc in incidents(alerts):
        if datetime.fromtimestamp(inc["ts"]).date() >= cutoff:
            counts[inc["severity"]] += 1
    total = sum(counts.values())
    if not total:
        return "None"
    parts = " · ".join(f"{n} {sev}" for sev, n in counts.items() if n)
    return f"{total} incident{'s' if total != 1 else ''}: {parts}"


NOTIFY_SEVERITIES = ("critical", "high")
NOTIFY_SLACK_S = 120  # clock skew between the bot's server and this machine


def _plain(text: str, limit: int) -> str:
    """Notification text: no markup a notification server could interpret
    (freedesktop bodies may be HTML-ish), single line, capped."""
    text = _printable(re.sub(r"[<>]", "", text or "")).replace("&", "and").strip()
    return text[:limit] + ("…" if len(text) > limit else "")


def notification(alert: dict, started_at: float) -> Optional[dict]:
    """The desktop notification for a newly received *alert*, or None.

    Only high and critical alerts sent after the app started: the first sync
    after start re-delivers the rooms' recent history, which must not pop up
    as a burst of old alerts."""
    if not isinstance(alert, dict):
        return None
    ts = alert.get("ts")
    if not isinstance(ts, (int, float)) or ts < started_at - NOTIFY_SLACK_S:
        return None
    info = parse(alert.get("body", ""))
    sev = info["severity"]
    if sev not in NOTIFY_SEVERITIES:
        return None
    where = f" on {info['host']}" if info["host"] else ""
    return {"title": _plain(f"{sev.capitalize()} alert{where}", 80),
            "body": _plain(info["title"], 160) or "Open Phoenix to see the alert.",
            "urgency": "critical" if sev == "critical" else "normal",
            "event_id": alert.get("event_id")}


def panel_data(alerts: list, unread: int, now: Optional[float] = None) -> dict:
    """Badge and rows for the Recent alerts panel. "ids" maps each alert
    row's key to its event_id, so a click opens that alert."""
    alerts = newest_first(alerts)
    if not alerts:
        return {"badge": ("ok", "Quiet"),
                "rows": {"Alerts": "No alerts yet. Alerts about machines you own appear here."}}
    newest = alerts
    unread = max(0, min(int(unread or 0), len(alerts)))
    worst_new = max((_SEV_RANK[severity(a.get("body", ""))] for a in newest[:unread]), default=-1)
    if unread:
        kind = ("error" if worst_new >= _SEV_RANK["high"] else
                "warning" if worst_new >= _SEV_RANK["unknown"] else "info")
        badge = (kind, f"{unread} new")
    else:
        badge = ("ok", "No new alerts")
    rows: dict = {}
    ids: dict = {}
    for a in newest[:SHOWN]:
        info = parse(a.get("body", ""))
        key = ago(a.get("ts"), now)
        while key in rows:  # same minute: keep both rows
            key += " "
        rows[key] = f"{_DOT[info['severity']]} {info['title']}"
        ids[key] = a.get("event_id")
    if len(alerts) > SHOWN:
        rows["More"] = f"{len(alerts) - SHOWN} older alert{'s' if len(alerts) - SHOWN != 1 else ''}"
    rows[f"Last {DAYS} days"] = breakdown(alerts, now)
    return {"badge": badge, "rows": rows, "ids": ids, "strip": activity(alerts, now)}
