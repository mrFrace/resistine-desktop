"""Recent SIEM alerts, for the Dashboard.

siemgent's @siem-bot posts alerts about the user's machines into encrypted
Matrix DMs; the chat transport stores them (plugins/chat/siem_alerts.py).
This module turns that store into the Recent alerts panel: unread count,
the newest few with severity, a one-line title and how long ago.

Alert bodies are siemgent's triage text (often led by a severity marker
such as 🔴 or a "severity: high" word). They are parsed defensively and
only ever shown as plain text. No Qt in here.
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


def severity(body: str) -> str:
    head = (body or "")[:240]
    hits = [(head.find(e), sev) for e, sev in _SEV_EMOJI.items() if e in head]
    if hits:
        return min(hits)[1]  # the first marker in the text
    m = _SEV_WORD.search(head)
    return m.group(1).lower() if m else "info"


def title(body: str, limit: int = 90) -> str:
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


def panel_data(alerts: list, unread: int, now: Optional[float] = None) -> dict:
    """Badge and rows for the Recent alerts panel."""
    alerts = [a for a in alerts or [] if isinstance(a, dict)]
    if not alerts:
        return {"badge": ("ok", "Quiet"),
                "rows": {"Alerts": "No alerts yet. Alerts about machines you own appear here."}}
    newest = sorted(alerts, key=lambda a: a.get("ts") or 0, reverse=True)
    unread = max(0, min(int(unread or 0), len(alerts)))
    worst_new = max((_SEV_RANK[severity(a.get("body", ""))] for a in newest[:unread]), default=-1)
    if unread:
        kind = "error" if worst_new >= _SEV_RANK["high"] else "warning" if worst_new >= 2 else "info"
        badge = (kind, f"{unread} new")
    else:
        badge = ("ok", "No new alerts")
    rows: dict = {}
    for a in newest[:SHOWN]:
        sev = severity(a.get("body", ""))
        key = ago(a.get("ts"), now)
        while key in rows:  # same minute: keep both rows
            key += " "
        rows[key] = f"{_DOT[sev]} {title(a.get('body', ''))}"
    if len(alerts) > SHOWN:
        rows["More"] = f"{len(alerts) - SHOWN} older alert{'s' if len(alerts) - SHOWN != 1 else ''}"
    return {"badge": badge, "rows": rows}
