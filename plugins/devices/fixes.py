"""Vulnerabilities as fixes: the posture's package items grouped by upgrade.

The posture cards (phoenix.posture.v1) carry, per machine, at most ten
mitigation items (mitigations.items_of), each with at most five CVE ids and
only its critical and high counts. There is no full CVE list yet, so the
Devices page leads with what to do instead: one row per package fix
("openssl → 3.0.13 · 2 critical · on 3 devices"), opening to the machines
and the CVEs the items name. The counts are the worst machine's, never a
sum: the same CVE on three machines is still one CVE.

A first-seen ledger stands in for the server's missing first_detected_at:
each (agent, package, installed version) is stamped with the day the server
computed the card that first named it, so cached or repeated fetches add
nothing. Items that were already there when the ledger started are dated
"before" that day, never shown as new. An item dropping out of a card does
not mean it was fixed (it may have fallen out of the top ten), so the ledger
records detections only, never resolutions.

No Qt in here.
"""

from __future__ import annotations

from datetime import date, datetime, timedelta
from typing import Iterable, Optional

from plugins.dashboard import mitigations
from utils import settings
from utils.i18n import get_text

_NS = "devices"
_LEDGER_KEY = "fix_seen"
LEDGER_DAYS = 30
_SEV_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def _t(key: str, **fmt) -> str:
    return get_text(f"devices.{key}", **fmt)


def _host(card: dict) -> str:
    return str(card.get("hostname") or card.get("agent_id") or "?")


def _agent(card: dict) -> str:
    return str(card.get("agent_id") or card.get("hostname") or "?")[:64]


def _version_key(v: str) -> list:
    """Sort "3.0.2" before "3.0.11" (digits as numbers, the rest as text)."""
    out, num, txt = [], "", ""
    for ch in v:
        if ch.isdigit():
            if txt:
                out.append((1, txt))
                txt = ""
            num += ch
        else:
            if num:
                out.append((0, int(num)))
                num = ""
            txt += ch
    if num:
        out.append((0, int(num)))
    if txt:
        out.append((1, txt))
    return out


# --------------------------------------------------------------------------
# Grouping
# --------------------------------------------------------------------------

def group(cards: list, names: Iterable[str]) -> list:
    """One dict per package fix, most urgent first:

    {"package", "package_type", "fixed_version" (None: unknown or none),
     "no_fix" (the scanner says no fix is released), "severity" (worst),
     "critical", "high" (worst machine's), "cves" (sorted union),
     "installed" (versions, oldest first),
     "devices": [{"agent_id", "hostname", "this_machine", "version", "item"}]}

    ``names`` are this machine's names (posture.local_names()); its entry
    comes first in "devices"."""
    names = {n.lower() for n in names}
    groups: dict = {}
    for card in cards if isinstance(cards, list) else []:
        if not isinstance(card, dict):
            continue
        mine = str(card.get("hostname", "")).lower() in names
        for item in mitigations.items_of(card):
            if item["kind"] != "package_update":
                continue
            c, ev = item["check"], item["evidence"]
            key = (c["package"], ev["fixed_version"])
            g = groups.get(key)
            if g is None:
                g = groups[key] = {
                    "package": c["package"], "package_type": c["package_type"],
                    "fixed_version": ev["fixed_version"], "no_fix": False,
                    "severity": item["severity"], "critical": 0, "high": 0,
                    "cves": set(), "installed": set(), "devices": [],
                }
            if _SEV_RANK[item["severity"]] > _SEV_RANK[g["severity"]]:
                g["severity"] = item["severity"]
            g["critical"] = max(g["critical"], ev["critical"])
            g["high"] = max(g["high"], ev["high"])
            g["cves"].update(ev["cves"])
            g["installed"].add(c["version"])
            g["package_type"] = g["package_type"] or c["package_type"]
            if not ev["fixed_version"] and ev["fix_available"] is False:
                g["no_fix"] = True
            g["devices"].append({"agent_id": _agent(card), "hostname": _host(card),
                                 "this_machine": mine, "version": c["version"], "item": item})
    out = []
    for g in groups.values():
        g["cves"] = sorted(g["cves"])
        g["installed"] = sorted(g["installed"], key=_version_key)
        g["devices"].sort(key=lambda d: (not d["this_machine"], d["hostname"].lower()))
        out.append(g)
    out.sort(key=lambda g: (-_SEV_RANK[g["severity"]], -len(g["devices"]),
                            -(g["critical"] + g["high"]), g["package"]))
    return out


def other_items(cards: list) -> list:
    """[(card, item)] for the items that are not package fixes (failed CIS
    checks, an agent not reporting), worst first."""
    out = []
    for card in cards if isinstance(cards, list) else []:
        if isinstance(card, dict):
            out += [(card, i) for i in mitigations.items_of(card) if i["kind"] != "package_update"]
    out.sort(key=lambda ci: (-_SEV_RANK[ci[1]["severity"]], _host(ci[0]).lower()))
    return out


def title(g: dict) -> str:
    if g["fixed_version"]:
        return f"{g['package']} → {g['fixed_version']}"
    if g["no_fix"]:
        return _t("fix_no_fix", package=g["package"])
    return g["package"]


def _where(g: dict) -> str:
    devs = g["devices"]
    if len(devs) == 1:
        return _t("fix_on_this") if devs[0]["this_machine"] else _t("fix_on_host", host=devs[0]["hostname"])
    if any(d["this_machine"] for d in devs):
        return _t("fix_on_n_here", n=len(devs))
    return _t("fix_on_n", n=len(devs))


def hint(g: dict) -> str:
    """'installed 3.0.2, 3.0.11 · 2 critical · 1 high · on 3 machines'."""
    versions = ", ".join(g["installed"][:3]) + ("…" if len(g["installed"]) > 3 else "")
    bits = [_t("fix_installed", versions=versions)]
    if g["critical"]:
        bits.append(_t("fix_n_critical", n=g["critical"]))
    if g["high"]:
        bits.append(_t("fix_n_high", n=g["high"]))
    bits.append(_where(g))
    return " · ".join(bits)


def summary(groups: list) -> str:
    """'4 fixes · 2 on this machine' for a header."""
    if not groups:
        return _t("fix_none")
    here = sum(1 for g in groups if any(d["this_machine"] for d in g["devices"]))
    text = _t("fix_count_one") if len(groups) == 1 else _t("fix_count", n=len(groups))
    return text + (" · " + _t("fix_count_here", n=here) if here else "")


# --------------------------------------------------------------------------
# First-seen ledger
# --------------------------------------------------------------------------

def _computed(card: dict) -> Optional[date]:
    try:
        return datetime.fromisoformat(str(card.get("computed_at"))).date()
    except ValueError:
        return None


def _key(agent_id: str, package: str, version: str) -> str:
    return f"{agent_id}|{package}|{version}"


def _clean(ledger) -> dict:
    ledger = ledger if isinstance(ledger, dict) else {}
    try:
        since = date.fromisoformat(str(ledger.get("since"))).isoformat()
    except ValueError:
        since = None
    items = {}
    raw = ledger.get("items") if isinstance(ledger.get("items"), dict) else {}
    for k, v in raw.items():
        try:
            first = date.fromisoformat(str(v["first"])).isoformat()
            last = date.fromisoformat(str(v["last"])).isoformat()
        except (TypeError, KeyError, ValueError):
            continue
        sev = v.get("severity") if v.get("severity") in _SEV_RANK else "low"
        items[str(k)] = {"first": first, "last": last, "severity": sev}
    return {"since": since, "items": items}


def update_ledger(ledger, cards: list, today: date) -> dict:
    """The ledger with every package item of ``cards`` stamped with its
    card's computed day; entries not seen for LEDGER_DAYS are dropped."""
    out = _clean(ledger)
    items = out["items"]
    for card in cards if isinstance(cards, list) else []:
        day = _computed(card) if isinstance(card, dict) else None
        if day is None:
            continue
        d = day.isoformat()
        if out["since"] is None or d < out["since"]:
            out["since"] = d
        for item in mitigations.items_of(card):
            if item["kind"] != "package_update":
                continue
            k = _key(_agent(card), item["check"]["package"], item["check"]["version"])
            e = items.get(k)
            if e is None:
                items[k] = {"first": d, "last": d, "severity": item["severity"]}
            else:
                e["first"], e["last"] = min(e["first"], d), max(e["last"], d)
                if _SEV_RANK[item["severity"]] > _SEV_RANK[e["severity"]]:
                    e["severity"] = item["severity"]
    cutoff = (today - timedelta(days=LEDGER_DAYS)).isoformat()
    out["items"] = {k: v for k, v in items.items() if v["last"] >= cutoff}
    return out


def record(cards: list, today: Optional[date] = None) -> dict:
    """Update the stored ledger from the current cards; returns it."""
    old = _clean(settings.get(_NS, _LEDGER_KEY))
    new = update_ledger(old, cards, today or date.today())
    if new != old:
        settings.set(_NS, _LEDGER_KEY, new)
    return new


def ledger() -> dict:
    return _clean(settings.get(_NS, _LEDGER_KEY))


def first_seen(ledger: dict, device: dict) -> str:
    """'first seen 4 Nov', 'seen before 1 Nov' (already there when the
    ledger started) or '' for one entry of a group's "devices"."""
    led = _clean(ledger)
    e = led["items"].get(_key(device["agent_id"], device["item"]["check"]["package"], device["version"]))
    if e is None:
        return ""
    first = date.fromisoformat(e["first"])
    day = f"{first.day} {first:%b}"
    if e["first"] == led["since"]:
        return _t("fix_seen_before", day=day)
    return _t("fix_first_seen", day=day)


def detections(ledger: dict, today: date, days: int = LEDGER_DAYS) -> list:
    """New items per day, oldest first, ending today, in the shape of
    alerts.activity(): {"day": date, "count": n, "worst": severity or None}.
    Items already there when the ledger started are not counted."""
    led = _clean(ledger)
    first_day = today - timedelta(days=days - 1)
    out = [{"day": first_day + timedelta(days=i), "count": 0, "worst": None} for i in range(days)]
    for e in led["items"].values():
        if e["first"] == led["since"]:
            continue
        day = date.fromisoformat(e["first"])
        if not first_day <= day <= today:
            continue
        slot = out[(day - first_day).days]
        slot["count"] += 1
        if slot["worst"] is None or _SEV_RANK[e["severity"]] > _SEV_RANK[slot["worst"]]:
            slot["worst"] = e["severity"]
    return out
