"""Daily digest of SIEM alerts, in the view only.

With the digest on, the Alerts screen and the Dashboard's Recent alerts
panel fold each day's quieter alerts into one row ("Today · 7 alerts",
"2 medium · 4 low · 1 info · AnubisAI, francispc") instead of listing them
one by one. Two things never change with the setting:

* a high or critical alert is shown on its own, in its place, whatever
  the setting (and its desktop notification is sent as before);
* nothing happens on the server: alerts are not acknowledged, read or
  dropped by folding them. The store is untouched; only the rows differ.

A digest line carries counts and host names, never alert text. Host
names come from the alerts (server text) and are shown as plain text.
No Qt in here.
"""

from __future__ import annotations

import time
from datetime import date, datetime, timedelta
from typing import Optional

from plugins.dashboard import alerts as recent_alerts
from utils import settings
from utils.i18n import get_text

BYPASS = ("critical", "high")  # always their own row
_NS, _KEY = "dashboard", "alert_digest"


def enabled() -> bool:
    return bool(settings.get(_NS, _KEY, False))


def set_enabled(on: bool) -> None:
    settings.set(_NS, _KEY, bool(on))


def _t(key: str, **fmt) -> str:
    return get_text(f"alerts.digest_{key}", **fmt)


def fold(alerts: list, now: Optional[float] = None, bypass=BYPASS) -> list:
    """The alerts as rows, newest first: {"kind": "alert", "alert", "ts",
    "info"} for one shown on its own, {"kind": "day", "day", "ts" (its
    newest alert), "alerts" (newest first), "counts" {severity: n},
    "hosts"} for a day's folded alerts."""
    days: dict = {}
    out = []
    for a in recent_alerts.newest_first(alerts):
        ts = a.get("ts")
        if not isinstance(ts, (int, float)):
            continue
        info = recent_alerts.parse(a.get("body", ""))
        if info["severity"] in bypass:
            out.append({"kind": "alert", "alert": a, "ts": ts, "info": info})
            continue
        day = datetime.fromtimestamp(ts).date()
        entry = days.get(day)
        if entry is None:
            entry = days[day] = {"kind": "day", "day": day, "ts": ts, "alerts": [],
                                 "counts": dict.fromkeys(recent_alerts.SEV_ORDER, 0), "hosts": []}
            out.append(entry)
        entry["alerts"].append(a)
        entry["counts"][info["severity"]] += 1
        if info["host"] and info["host"] not in entry["hosts"]:
            entry["hosts"].append(info["host"])
    return sorted(out, key=lambda e: e["ts"], reverse=True)


def day_label(day: date, now: Optional[float] = None) -> str:
    today = datetime.fromtimestamp(now or time.time()).date()
    if day == today:
        return _t("today")
    if day == today - timedelta(days=1):
        return _t("yesterday")
    return day.strftime("%a %d %b")


def title(entry: dict, now: Optional[float] = None) -> str:
    """"Today · 7 alerts"."""
    n = len(entry["alerts"])
    return f"{day_label(entry['day'], now)} · " + (
        _t("alerts_one") if n == 1 else _t("alerts_many", n=n))


def hint(entry: dict, max_hosts: int = 3) -> str:
    """"2 medium · 4 low · 1 info · AnubisAI, francispc"."""
    parts = [f"{n} {sev}" for sev, n in entry["counts"].items() if n]
    hosts = entry["hosts"]
    if hosts:
        shown = ", ".join(hosts[:max_hosts])
        if len(hosts) > max_hosts:
            shown += _t("more_hosts", n=len(hosts) - max_hosts)
        parts.append(shown)
    return " · ".join(parts)


def panel_value(entry: dict) -> str:
    """The Dashboard row's value: "7 alerts: 2 medium · 4 low"."""
    n = len(entry["alerts"])
    counts = " · ".join(f"{k} {sev}" for sev, k in entry["counts"].items() if k)
    return (_t("alerts_one") if n == 1 else _t("alerts_many", n=n)) + f": {counts}"
