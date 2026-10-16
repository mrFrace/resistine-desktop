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
"""

from __future__ import annotations

import re
import time
from typing import Optional

SHOWN = 4
_SEV_EMOJI = {"🚨": "critical", "🔴": "high", "🟠": "medium", "🟡": "low", "⚪": "info"}
_SEV_WORD = re.compile(r"\b(critical|high|medium|low)\b", re.IGNORECASE)
_SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
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
# "**Severity:** High", "Severity: Medium", "(High Severity)", "of medium severity"
_SEV_FIELD = re.compile(rf"severity\W{{0,6}}({_SEVS})\b|\b({_SEVS})\s+severity\b", re.IGNORECASE)
_FINDING = re.compile(r"^\s*\d+\.\s+\*\*(?:Finding:\s*)?(.+?)\*\*", re.IGNORECASE)
_SEV_SUFFIX = re.compile(rf"\s*\((?:{_SEVS})\s+severity\)\s*$", re.IGNORECASE)


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
        for ln in lines:
            m = _FINDING.match(ln)
            if m:
                out["findings"].append({"severity": "info", "name": _SEV_SUFFIX.sub("", _clean(m.group(1)))})
            for m in _SEV_FIELD.finditer(ln):
                sev = (m.group(1) or m.group(2)).lower()
                if out["findings"] and out["findings"][-1]["severity"] == "info":
                    out["findings"][-1]["severity"] = sev
                elif not out["findings"]:
                    out.setdefault("_loose", []).append(sev)
        loose = out.pop("_loose", [])
        out["severity"] = _worst([f["severity"] for f in out["findings"]] + loose)
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
        out["severity"] = ("info" if "false" in v else "high" if "true" in v
                           else _first_marker(first) if _first_marker(first) != "info" else "low")
        out["title"] = f"{out['verdict']}: {out['what']}" if out["what"] else f"Hunt result: {out['verdict']}"
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


_DOT = {"critical": "🚨", "high": "🔴", "medium": "🟠", "low": "🟡", "info": "⚪"}


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
        kind = "error" if worst_new >= _SEV_RANK["high"] else "warning" if worst_new >= 2 else "info"
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
    return {"badge": badge, "rows": rows, "ids": ids}
