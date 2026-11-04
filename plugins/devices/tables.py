"""Devices page: the Vulnerabilities, Events and Inventory tabs' data, no Qt.

Carried over from the old Wazuh Overview's module-level helpers: bucketing
for the charts, the search/severity filters, the inventory row shaping and
column specs, and the display formatters. Plus what the new system adds:
CVEs drawn from the posture card's mitigations (so the Vulnerabilities tab
has rows before the API's vulnerability endpoint exists), the SIEM alert
feed as events, and the posture cards as the device roster.
"""

from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

SEVERITIES = ("critical", "high", "medium", "low")
SEVERITY_SHORT = {"critical": "CRIT", "high": "HIGH", "medium": "MED", "low": "LOW"}
SEV_TO_STATUS = {
    "critical": "CRITICAL",
    "high": "HIGH",
    "medium": "WARNING",
    "low": "OK",
}
THREAT_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "ok": 0}
RANK_TO_SEV = {v: k for k, v in THREAT_RANK.items()}
PAGE_SIZE = 50
INVENTORY_PAGE_SIZE = 20
INV_ITEM_PAGE = 25
GROUP_ALL = "All groups"
GROUP_NONE = "(no group)"


def _text(v, limit: int = 160) -> str:
    s = "".join(
        ch for ch in str(v if v is not None else "") if ch.isprintable()
    ).strip()
    return s[:limit] + ("…" if len(s) > limit else "")


# --------------------------------------------------------------------------
# Formatting
# --------------------------------------------------------------------------


def parse_iso(ts) -> datetime | None:
    if not ts:
        return None
    try:
        dt = datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def format_relative(iso_ts, now: datetime | None = None) -> str:
    """Compact 'X ago' from an ISO-8601 timestamp."""
    dt = parse_iso(iso_ts)
    if dt is None:
        return "—" if not iso_ts else _text(iso_ts, 40)
    sec = int(((now or datetime.now(timezone.utc)) - dt).total_seconds())
    if sec < 0:
        return "in the future"
    if sec < 60:
        return "just now"
    if sec < 3600:
        return f"{sec // 60}m ago"
    if sec < 86400:
        return f"{sec // 3600}h ago"
    days = sec // 86400
    if days == 1:
        return "1 day ago"
    if days < 30:
        return f"{days} days ago"
    months = days // 30
    return f"{months} mo ago" if months < 12 else f"{months // 12}y ago"


def format_timestamp(iso_ts) -> str:
    """'MMM DD HH:MM:SS' in local time."""
    dt = parse_iso(iso_ts)
    if dt is None:
        return "—" if not iso_ts else _text(iso_ts, 40)
    return dt.astimezone().strftime("%b %d %H:%M:%S")


def as_int(value) -> int:
    """Sort key for mixed-typed fields; unparsable values sort last."""
    try:
        return int(value)
    except (TypeError, ValueError):
        return 1 << 62


def num(value) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def join_host_port(host, port) -> str:
    if not host and port in (None, ""):
        return ""
    shown = host or "*"
    if ":" in shown:
        shown = f"[{shown}]"
    return f"{shown}:{'' if port is None else port}"


def cell_text(value) -> str:
    if value is None:
        return "—"
    text = _text(value, 200)
    return text or "—"


def format_bytes(value) -> str:
    try:
        n = float(value)
    except (TypeError, ValueError):
        return "—"
    if n < 0:
        return "—"
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024.0
    return "—"


def format_traffic(rx, tx) -> str:
    rx_t, tx_t = format_bytes(rx), format_bytes(tx)
    return "" if rx_t == "—" and tx_t == "—" else f"{rx_t} / {tx_t}"


def format_ram(value) -> str:
    """``hardware.ram_total_mb`` is reported in kilobytes despite its name."""
    try:
        kb = float(value)
    except (TypeError, ValueError):
        return "—"
    return "—" if kb <= 0 else f"{kb / (1024.0 * 1024.0):.1f} GB"


def distinct_count(items, key) -> int:
    return len(
        {str(it.get(key)).strip() for it in items if str(it.get(key) or "").strip()}
    )


def top_value(items, key) -> str:
    counts: dict = {}
    for it in items:
        value = str(it.get(key) or "").strip()
        if value:
            counts[value] = counts.get(value, 0) + 1
    if not counts:
        return "—"
    value, n = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))[0]
    return f"{value} ×{n}" if n > 1 else value


# --------------------------------------------------------------------------
# Scope, severity, filters
# --------------------------------------------------------------------------


def scope_records(records: list, field: str, scope) -> list:
    """Records for the selected device; all of them for no scope."""
    if not scope:
        return list(records)
    return [r for r in records if str(r.get(field) or "").lower() == str(scope).lower()]


def bucket_by_severity(items) -> dict:
    counts = {s: 0 for s in SEVERITIES}
    for it in items:
        sev = (it.get("severity") or "").lower() if isinstance(it, dict) else ""
        if sev in counts:
            counts[sev] += 1
    return counts


def vuln_key(v: dict) -> str:
    return (
        f"{v.get('agent_id') or ''}::{v.get('id') or ''}::{v.get('package_name') or ''}"
    )


def filter_vulns(vulns: list, query: str = "", severity: str | None = None) -> list:
    """Search over id / package / version / severity / status / description /
    device, optional severity, CVSS descending (unknown scores last)."""
    q = (query or "").lower().strip()
    out = []
    for v in vulns:
        if severity and (v.get("severity") or "").lower() != severity:
            continue
        if (
            q
            and q
            not in " ".join(
                str(v.get(k) or "")
                for k in (
                    "id",
                    "package_name",
                    "package_version",
                    "severity",
                    "status",
                    "description",
                    "agent_name",
                )
            ).lower()
        ):
            continue
        out.append(v)
    out.sort(
        key=lambda x: (
            x.get("cvss_score") is None,
            -(x.get("cvss_score") or 0.0),
            -THREAT_RANK.get(x.get("severity") or "low", 0),
            x.get("id") or "",
        )
    )
    return out


def filter_events(
    events: list,
    query: str = "",
    severity: str | None = None,
    hour_bucket: datetime | None = None,
) -> list:
    q = (query or "").lower().strip()
    out = []
    for ev in events:
        if hour_bucket is not None:
            dt = parse_iso(ev.get("timestamp"))
            if (
                dt is None
                or dt.astimezone(timezone.utc).replace(
                    minute=0, second=0, microsecond=0
                )
                != hour_bucket
            ):
                continue
        if severity and (ev.get("severity") or "").lower() != severity:
            continue
        if (
            q
            and q
            not in " ".join(
                str(f)
                for f in (
                    ev.get("rule_id", ""),
                    ev.get("description", ""),
                    ev.get("ip", ""),
                    ev.get("agent", ""),
                    ev.get("severity") or "",
                    " ".join(ev.get("mitre") or []),
                )
            ).lower()
        ):
            continue
        out.append(ev)
    return out


def page_slice(items: list, page: int, size: int) -> tuple:
    """(items on the page, clamped page, total pages)."""
    total_pages = max(1, (len(items) + size - 1) // size)
    page = max(1, min(int(page or 1), total_pages))
    start = (page - 1) * size
    return items[start : start + size], page, total_pages


# --------------------------------------------------------------------------
# Chart buckets
# --------------------------------------------------------------------------


def bucket_vulns_daily(vulns: list, days: int = 30, today=None) -> tuple:
    """(dates oldest first, {date: {severity: n}}) by ``first_detected_at``,
    in the viewer's local day."""
    today = today or datetime.now().astimezone().date()
    dates = [today - timedelta(days=i) for i in range(days - 1, -1, -1)]
    counts = {d: {s: 0 for s in SEVERITIES} for d in dates}
    first = dates[0]
    for v in vulns:
        dt = parse_iso(v.get("first_detected_at"))
        if dt is None:
            continue
        d = dt.astimezone().date()
        if d < first or d > today:
            continue
        sev = (v.get("severity") or "").lower()
        if sev in SEVERITIES:
            counts[d][sev] += 1
    return dates, counts


def bucket_events_hourly(events: list, now: datetime | None = None) -> tuple:
    """24 hourly UTC buckets ending at the next hour boundary."""
    now = now or datetime.now(timezone.utc)
    right = now.astimezone(timezone.utc).replace(
        minute=0, second=0, microsecond=0
    ) + timedelta(hours=1)
    left = right - timedelta(hours=24)
    buckets = [left + timedelta(hours=i) for i in range(24)]
    counts = {b: {s: 0 for s in SEVERITIES} for b in buckets}
    for ev in events:
        dt = parse_iso(ev.get("timestamp"))
        if dt is None:
            continue
        dt = dt.astimezone(timezone.utc)
        sev = (ev.get("severity") or "").lower()
        if sev not in SEVERITIES or dt < left or dt >= right:
            continue
        counts[buckets[int((dt - left).total_seconds() // 3600)]][sev] += 1
    return buckets, counts


# --------------------------------------------------------------------------
# What the new system provides without the endpoints
# --------------------------------------------------------------------------


def posture_cves(cards: list) -> list:
    """CVEs named by the posture cards' mitigations, in the CVE row shape.

    The posture scan names the top CVEs per vulnerable package (with the
    installed and fixed versions), not every CVE on the device; ``source``
    is "posture" so the tab can say the list is partial."""
    out = []
    for c in cards or []:
        if not isinstance(c, dict):
            continue
        host = _text(c.get("hostname"), 64)
        aid = _text(c.get("agent_id"), 16)
        for item in c.get("mitigations") or []:
            if not isinstance(item, dict) or item.get("kind") != "package_update":
                continue
            ev = item.get("evidence") if isinstance(item.get("evidence"), dict) else {}
            sev = _text(item.get("severity"), 16).lower()
            fixed = _text(ev.get("fixed_version"), 64)
            desc = (
                f"Named by the posture scan under \"{_text(item.get('title'), 80)}\"."
            )
            if fixed:
                desc += f" Fixed in {fixed}."
            elif ev.get("fix_available") is False:
                desc += " No fixed version has been released yet."
            for cve in (ev.get("cves") or [])[:50]:
                cid = _text(cve, 64)
                if not cid:
                    continue
                out.append(
                    {
                        "id": cid,
                        "severity": sev if sev in SEVERITIES else "low",
                        "cvss_score": None,
                        "epss": None,
                        "package_name": _text(ev.get("package"), 120),
                        "package_version": _text(ev.get("version"), 64),
                        "description": desc,
                        "status": "",
                        "published_date": "",
                        "modified_date": "",
                        "first_detected_at": _text(c.get("computed_at"), 40),
                        "agent_id": aid,
                        "agent_name": host,
                        "source": "posture",
                    }
                )
    return out


def alerts_as_events(parsed: list) -> list:
    """The SIEM alert feed (plugins.devices.data.scoped_alerts output) in the
    event row shape, so the Events tab has a stream before the API's
    detection-events endpoint exists."""
    out = []
    for a in parsed or []:
        info = a.get("info") or {}
        ts = a.get("ts") or 0
        sev = (info.get("severity") or "").lower()
        out.append(
            {
                "id": f"siem::{a.get('event_id')}",
                "rule_id": {
                    "triage": "triage",
                    "hunt": "hunt",
                    "result": "verdict",
                }.get(info.get("kind"), "siem"),
                "level": "",
                "severity": sev if sev in SEVERITIES else "low",
                "description": _text(info.get("title") or "SIEM alert", 300),
                "timestamp": (
                    datetime.fromtimestamp(ts, timezone.utc).isoformat() if ts else ""
                ),
                "agent": _text(info.get("host"), 64),
                "host": _text(info.get("host"), 64),
                "ip": "",
                "mitre": [],
                "hash": _text(a.get("event_id"), 128),
                "raw_log": "".join(
                    ch
                    for ch in str(a.get("body") or "")
                    if ch.isprintable() or ch == "\n"
                )[:4000],
                "source": "siem",
            }
        )
    return out


def devices_from_posture(rows: list) -> list:
    """Posture rows (plugins.devices.data.fleet_rows) as inventory agents
    with no syscollector data: the Devices view can list them before the
    inventory endpoint exists."""
    agents = []
    for r in rows or []:
        agents.append(
            shape_inventory_agent(
                {
                    "agent_id": r.get("agent_id"),
                    "agent_name": r.get("hostname"),
                    "status": r.get("agent_status"),
                    "os": {"name": r.get("os"), "version": ""},
                    "hardware": {},
                },
                None,
            )
        )
        agents[-1]["basic_info"]["lastKeepAlive"] = (
            r["computed_at"].isoformat() if r.get("computed_at") else None
        )
    return agents


# --------------------------------------------------------------------------
# Inventory shaping (ported)
# --------------------------------------------------------------------------


def interfaces_with_addresses(interfaces, addresses) -> list:
    by_iface: dict = {}
    for addr in addresses or []:
        if not isinstance(addr, dict):
            continue
        name, value = addr.get("interface"), addr.get("address")
        if name and value:
            by_iface.setdefault(name, []).append((addr.get("proto") or "", value))
    out = []
    for iface in interfaces or []:
        if not isinstance(iface, dict):
            continue
        found = by_iface.get(iface.get("name"), [])
        found.sort(key=lambda pv: (pv[0] != "ipv4", pv[1]))
        merged = dict(iface)
        merged["ip_addresses"] = [v for _, v in found]
        out.append(merged)
    return out


def shape_inventory_agent(summary: dict, detail: dict | None, caller_groups=()) -> dict:
    """A /me/inventory device (+ optional /me/inventory/{id} detail) in the
    {basic_info, syscollector, hardware} shape the Inventory tab reads."""
    os_info = summary.get("os") if isinstance(summary.get("os"), dict) else {}
    hw = summary.get("hardware") if isinstance(summary.get("hardware"), dict) else {}
    basic_info = {
        "id": summary.get("agent_id"),
        "name": summary.get("agent_name"),
        "ip": summary.get("agent_ip") or "—",
        "status": summary.get("status"),
        "os": os_info,
        "lastKeepAlive": os_info.get("last_scan") or hw.get("last_scan"),
        "group": list(caller_groups),
    }
    syscollector: dict = {}
    if isinstance(detail, dict):
        network = (
            detail.get("network") if isinstance(detail.get("network"), dict) else {}
        )
        syscollector = {
            "processes": {
                "affected_items": [
                    p for p in (detail.get("processes") or []) if isinstance(p, dict)
                ]
            },
            "network": {
                "ports": {
                    "affected_items": [
                        p for p in (detail.get("ports") or []) if isinstance(p, dict)
                    ]
                },
                "interfaces": {
                    "affected_items": interfaces_with_addresses(
                        network.get("interfaces"), network.get("addresses")
                    )
                },
            },
            "packages": {
                "affected_items": [
                    p for p in (detail.get("packages") or []) if isinstance(p, dict)
                ]
            },
        }
    return {"basic_info": basic_info, "syscollector": syscollector, "hardware": hw}


INVENTORY_VIEWS = ("Devices", "Processes", "Ports", "Network", "Packages")
INVENTORY_FIELDS = {
    "Devices": None,
    "Processes": ("syscollector", "processes"),
    "Ports": ("syscollector", "network", "ports"),
    "Network": ("syscollector", "network", "interfaces"),
    "Packages": ("syscollector", "packages"),
}
INVENTORY_LEAD_HEADER = {
    "Devices": "THREAT",
    "Processes": "PROCESSES",
    "Ports": "OPEN PORTS",
    "Network": "INTERFACES",
    "Packages": "PACKAGES",
}

INVENTORY_ITEM_COLUMNS = {
    "Processes": (
        ("NAME", 180, lambda it: it.get("name")),
        ("PID", 70, lambda it: it.get("pid")),
        ("PPID", 70, lambda it: it.get("ppid")),
        ("USER", 130, lambda it: it.get("user")),
        ("COMMAND", 0, lambda it: it.get("command")),
    ),
    "Ports": (
        (
            "LOCAL",
            190,
            lambda it: join_host_port(it.get("local_ip"), it.get("local_port")),
        ),
        ("PROTOCOL", 80, lambda it: it.get("protocol")),
        ("STATE", 100, lambda it: it.get("state")),
        ("PROCESS", 0, lambda it: it.get("process")),
        ("PID", 70, lambda it: it.get("pid")),
    ),
    "Network": (
        ("NAME", 160, lambda it: it.get("name")),
        ("STATE", 70, lambda it: it.get("state")),
        ("IP ADDRESS", 150, lambda it: ", ".join(it.get("ip_addresses") or [])),
        ("MAC", 150, lambda it: it.get("mac")),
        (
            "RX / TX",
            0,
            lambda it: format_traffic(it.get("rx_bytes"), it.get("tx_bytes")),
        ),
    ),
    "Packages": (
        ("NAME", 0, lambda it: it.get("name")),
        ("VERSION", 140, lambda it: it.get("version")),
        ("VENDOR", 180, lambda it: it.get("vendor")),
        ("FORMAT", 70, lambda it: it.get("format")),
        ("ARCH", 90, lambda it: it.get("architecture")),
    ),
}

INVENTORY_ITEM_SORTS = {
    "Processes": lambda it: str(it.get("name") or "").lower(),
    "Ports": lambda it: as_int(it.get("local_port")),
    "Network": lambda it: (
        str(it.get("state") or "").lower() != "up",
        str(it.get("name") or "").lower(),
    ),
    "Packages": lambda it: str(it.get("name") or "").lower(),
}


def last_seen_text(row) -> str:
    if row.get("status") in ("active", "connected"):
        return "Active now"
    return format_relative(row.get("last_keep"))


def cpu_ram_text(row) -> str:
    parts = []
    if row.get("cpu"):
        cores = row.get("cpu_cores")
        parts.append(f"{row['cpu']}{f' ({cores}c)' if cores else ''}")
    ram = format_ram(row.get("ram_total"))
    if ram != "—":
        parts.append(ram)
    return " · ".join(parts) or "—"


def proc_users(row) -> str:
    n = distinct_count(row.get("items") or [], "user")
    return str(n) if n else "—"


def ports_proto_split(row) -> str:
    items = row.get("items") or []
    tcp = sum(1 for it in items if str(it.get("protocol") or "").startswith("tcp"))
    udp = sum(1 for it in items if str(it.get("protocol") or "").startswith("udp"))
    return f"{tcp} / {udp}"


def ports_listening(row) -> str:
    items = row.get("items") or []
    if not any(str(it.get("state") or "").strip() for it in items):
        return "—"
    return str(
        sum(1 for it in items if str(it.get("state") or "").lower() == "listening")
    )


def ports_top(row) -> str:
    ports = sorted({as_int(it.get("local_port")) for it in (row.get("items") or [])})
    shown = [str(p) for p in ports if 0 < p < (1 << 62)][:4]
    return ", ".join(shown) or "—"


def iface_up_down(row) -> str:
    items = row.get("items") or []
    up = sum(1 for it in items if str(it.get("state") or "").lower() == "up")
    return f"{up} / {len(items) - up}"


def iface_addresses(row) -> str:
    n = sum(len(it.get("ip_addresses") or []) for it in (row.get("items") or []))
    return str(n) if n else "—"


def iface_traffic_total(row) -> str:
    items = row.get("items") or []
    if not items:
        return "—"
    return (
        format_traffic(
            sum(num(it.get("rx_bytes")) for it in items),
            sum(num(it.get("tx_bytes")) for it in items),
        )
        or "—"
    )


def pkg_formats(row) -> str:
    counts: dict = {}
    for it in row.get("items") or []:
        value = str(it.get("format") or "").strip()
        if value:
            counts[value] = counts.get(value, 0) + 1
    if not counts:
        return "—"
    ranked = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))[:3]
    return " · ".join(f"{fmt} {n}" for fmt, n in ranked)


INVENTORY_SUMMARY_COLUMNS = {
    "Devices": (
        ("OS", 170, lambda r: cell_text(r.get("os"))),
        ("CPU / RAM", 190, cpu_ram_text),
        ("LAST SEEN", 130, last_seen_text),
    ),
    "Processes": (
        ("UNIQUE", 80, lambda r: str(distinct_count(r.get("items") or [], "name"))),
        ("USERS", 70, proc_users),
        ("TOP PROCESS", 200, lambda r: top_value(r.get("items") or [], "name")),
    ),
    "Ports": (
        ("TCP / UDP", 90, ports_proto_split),
        ("LISTENING", 80, ports_listening),
        ("TOP PORTS", 180, ports_top),
    ),
    "Network": (
        ("UP / DOWN", 90, iface_up_down),
        ("ADDRESSES", 90, iface_addresses),
        ("TOTAL RX / TX", 170, iface_traffic_total),
    ),
    "Packages": (
        ("FORMATS", 150, pkg_formats),
        ("VENDORS", 80, lambda r: str(distinct_count(r.get("items") or [], "vendor"))),
        ("TOP VENDOR", 190, lambda r: top_value(r.get("items") or [], "vendor")),
    ),
}


def agent_groups(bi: dict) -> list:
    raw = bi.get("group")
    if isinstance(raw, list):
        return [g for g in raw if g]
    return [raw] if raw else []


def base_agent_row(agent: dict) -> dict:
    bi = agent.get("basic_info") or {}
    os_info = bi.get("os") if isinstance(bi.get("os"), dict) else {}
    hw = agent.get("hardware") or {}
    return {
        "name": _text(bi.get("name") or "(unknown)", 64),
        "status": str(bi.get("status") or "").lower(),
        "last_keep": bi.get("lastKeepAlive"),
        "agent_id": _text(bi.get("id") or "—", 16),
        "ip": _text(bi.get("ip") or "—", 64),
        "groups": agent_groups(bi),
        "os": " ".join(
            _text(p, 64) for p in (os_info.get("name"), os_info.get("version")) if p
        ),
        "cpu": _text(hw.get("cpu_name") or "", 64),
        "cpu_cores": hw.get("cpu_cores"),
        "ram_total": hw.get("ram_total_mb"),
        "ram_pct": hw.get("ram_usage_pct"),
    }


def events_threat_by_agent(events: list) -> dict:
    out: dict = {}
    for ev in events:
        name = str(ev.get("agent") or "").strip()
        sev = (ev.get("severity") or "").lower()
        if (
            name
            and sev in THREAT_RANK
            and THREAT_RANK[sev] > THREAT_RANK.get(out.get(name, "ok"), 0)
        ):
            out[name] = sev
    return out


def vulns_threat_for_name(vulns: list, name: str) -> str | None:
    best = None
    for v in vulns:
        if v.get("agent_name") != name:
            continue
        sev = (v.get("severity") or "").lower()
        if sev in THREAT_RANK and (
            best is None or THREAT_RANK[sev] > THREAT_RANK[best]
        ):
            best = sev
    return best


def device_threat_level(name: str, events_by_agent: dict, vulns: list) -> str:
    best = 0
    for sev in (events_by_agent.get(name), vulns_threat_for_name(vulns, name)):
        if sev and THREAT_RANK.get(sev, 0) > best:
            best = THREAT_RANK[sev]
    return RANK_TO_SEV.get(best, "ok")


def inventory_rows(agents: list, events: list, vulns: list) -> list:
    """Devices view rows, worst threat first."""
    by_agent = events_threat_by_agent(events)
    rows = []
    for a in agents:
        row = base_agent_row(a)
        row["threat"] = device_threat_level(row["name"], by_agent, vulns)
        rows.append(row)
    rows.sort(key=lambda r: (-THREAT_RANK.get(r["threat"], 0), r["name"].lower()))
    return rows


def inventory_counts_rows(agents: list, view: str) -> list:
    """Rows for a non-Devices view, each carrying its device's items."""
    path = INVENTORY_FIELDS.get(view)
    sort_key = INVENTORY_ITEM_SORTS.get(view)
    rows = []
    for a in agents:
        node = a
        for key in path or ():
            node = node.get(key) if isinstance(node, dict) else None
            if node is None:
                break
        items = node.get("affected_items") if isinstance(node, dict) else None
        items = [it for it in (items or []) if isinstance(it, dict)]
        if sort_key is not None:
            items.sort(key=sort_key)
        row = base_agent_row(a)
        row["items"] = items
        row["count"] = len(items)
        rows.append(row)
    rows.sort(key=lambda r: (-r["count"], r["name"].lower()))
    return rows


def inventory_group_values(agents: list) -> list:
    seen, has_empty = set(), False
    for a in agents:
        groups = agent_groups(a.get("basic_info") or {})
        if groups:
            seen.update(groups)
        else:
            has_empty = True
    out = [GROUP_ALL] + sorted(seen)
    if has_empty:
        out.append(GROUP_NONE)
    return out


def row_in_group(row: dict, group_filter: str) -> bool:
    if group_filter == GROUP_ALL:
        return True
    groups = row.get("groups") or []
    if group_filter == GROUP_NONE:
        return not groups
    return group_filter in groups


def now_ts() -> float:
    return time.time()
