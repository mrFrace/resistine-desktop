"""Antivirus and VPN panels for the Dashboard: badge and rows from the
plugins' cached state. No Qt in here; the Dashboard gathers the inputs on
its worker thread."""

from __future__ import annotations

import time
from datetime import datetime
from typing import Optional

SIG_STALE_S = 2 * 86400  # freshclam runs daily; two missed days is stale

_AV_STATE = {
    "protected": ("ok", "Protected", "Active"),
    "not_installed": ("info", "Not installed", "ClamAV is not installed"),
    "no_database": ("warning", "No signatures", "Signatures not downloaded yet"),
    "approval_required": ("warning", "Needs approval", "Allow the ClamAV services in System Settings"),
    "fda_required": ("warning", "Needs access", "Grant Full Disk Access in System Settings"),
    "error": ("error", "Stopped", "The scanner is not running"),
}


def _ago(secs: float) -> str:
    if secs < 3600:
        return "less than an hour ago"
    if secs < 86400:
        h = int(secs // 3600)
        return f"{h} hour{'s' if h != 1 else ''} ago"
    d = int(secs // 86400)
    return f"{d} day{'s' if d != 1 else ''} ago"


def _sig_age(last_updated: str, now: float) -> Optional[float]:
    try:
        return now - datetime.strptime(last_updated, "%Y-%m-%d %H:%M").timestamp()
    except (TypeError, ValueError):
        return None


def antivirus_panel(status: Optional[dict], db: Optional[dict], last_scan: Optional[dict],
                    quarantined: Optional[int], now: Optional[float] = None) -> dict:
    now = now or time.time()
    if status is None:
        return {"badge": ("info", "Not installed"),
                "rows": {"Antivirus": "The Antivirus plugin is not installed."}}
    kind, text, protection = _AV_STATE.get(str(status.get("state") or ""), ("warning", "Checking", "Checking…"))
    rows = {"Protection": protection}
    if status.get("state") == "protected":
        rows["Real-time"] = "On" if status.get("clamonacc_running") else "Off (scheduled and manual scans)"
    db = db or {}
    age = _sig_age(db.get("last_updated", ""), now)
    if age is not None:
        rows["Signatures"] = f"Updated {_ago(age)}" + (
            f" · {db['signatures']}" if db.get("signatures") not in (None, "—") else "")
        if age > SIG_STALE_S and kind == "ok":
            kind, text = "warning", "Signatures old"
    elif status.get("state") not in ("not_installed",):
        rows["Signatures"] = "Never updated"
    if isinstance(last_scan, dict) and last_scan.get("ts"):
        when = _ago(max(0.0, now - float(last_scan["ts"])))
        if last_scan.get("error"):
            rows["Last scan"] = f"Failed {when}"
        elif last_scan.get("infected"):
            rows["Last scan"] = f"{last_scan['infected']} threat(s) found {when}"
            if kind == "ok":
                kind, text = "error", "Threats found"
        else:
            rows["Last scan"] = f"No threats · {int(last_scan.get('scanned') or 0):,} files · {when}"
    else:
        rows["Last scan"] = "No scan yet"
    if quarantined is not None:
        rows["Quarantine"] = "Empty" if not quarantined else f"{quarantined} file{'s' if quarantined != 1 else ''}"
    return {"badge": (kind, text), "rows": rows}


_VPN_STATE = {
    "Running": ("ok", "Connected"),
    "Connecting": ("info", "Connecting"),
    "Starting": ("info", "Connecting"),
}


def vpn_panel(installed: bool, state: Optional[str], config: Optional[str],
              signed_in: bool) -> dict:
    if not installed:
        return {"badge": ("info", "Not installed"), "rows": {"VPN": "The VPN plugin is not installed."}}
    kind, text = _VPN_STATE.get(state or "", ("warning", "Off"))
    rows = {"Status": text if text != "Off" else "Not connected"}
    if config:
        rows["Configuration"] = config
    elif signed_in:
        rows["Configuration"] = "Phoenix (set up on first connect)"
    else:
        rows["Configuration"] = "None: sign in or import a config"
    return {"badge": (kind, text), "rows": rows}
