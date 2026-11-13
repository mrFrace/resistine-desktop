"""Phoenix API client for the Devices page: ``GET /v1/me/*``.

The old Wazuh Overview consumed these shapes from the old company's
dashboard service (``/api/v1/me/*``, identified by source IP). The contract
is carried over unchanged, now on ``api.phoenix.exposed`` with the MAS
bearer token (plugins/vpn/provisioning._authorized_request), so the server
side can be implemented against dev-docs/plans/devices-api.md and the page
lights up without a client release.

Every ``fetch_*`` returns ``(data, error)``. ``error`` is None on success;
NOT_AVAILABLE when the API answers 404 (the endpoint is not deployed yet),
which the page shows as "not provided by the Phoenix API yet" rather than
as a failure. Response shapes are normalised here (flat vs wrapped
variants, the Wazuh ``data.affected_items`` envelope) so the UI reads one
shape. Everything that comes back is untrusted: strings are cut, counts
coerced, lists capped.
"""

from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor, as_completed

from utils.logger import logger

PREFIX = "/v1/me"
NOT_AVAILABLE = "not_available"
MAX_PARALLEL_FETCHES = 8
_MAX_ITEMS = 5000
_MAX_TEXT = 4000


def _s(v, limit: int = 200) -> str:
    s = "".join(
        ch for ch in str(v if v is not None else "") if ch.isprintable() or ch == "\n"
    )
    return s[:limit]


def _get(path: str, params: dict | None = None):
    """Shared GET on the Phoenix API. Returns (parsed_json, error)."""
    from plugins.vpn.provisioning import ProvisioningError, _authorized_request

    try:
        r = _authorized_request("GET", PREFIX + path, params=params)
    except ProvisioningError as e:
        return None, _s(e, 200)
    except (
        Exception
    ) as e:  # noqa: BLE001 - a transport failure is an error string, not a crash
        return None, f"network: {_s(e, 160)}"
    if r.status_code == 404:
        return None, NOT_AVAILABLE
    if r.status_code != 200:
        return None, f"http {r.status_code}"
    try:
        return r.json(), None
    except ValueError:
        return None, "bad json"


def _affected_items(payload):
    """The ``data.affected_items`` list of a Wazuh-style envelope, if present."""
    if not isinstance(payload, dict):
        return None
    data = payload.get("data")
    if isinstance(data, dict) and isinstance(data.get("affected_items"), list):
        return data["affected_items"]
    return None


def _list(payload, *keys):
    """The first list found under ``keys``, else the envelope's items, else []."""
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict):
        for k in keys:
            if isinstance(payload.get(k), list):
                return payload[k]
        items = _affected_items(payload)
        if items is not None:
            return items
    return []


# --------------------------------------------------------------------------
# Normalisers (pure)
# --------------------------------------------------------------------------


def level_to_severity(level) -> str:
    """A Wazuh rule.level (0-15) or a 5.x label as one of the four buckets."""
    if isinstance(level, str) and not level.isdigit():
        word = level.lower()
        return {"informational": "low", "info": "low"}.get(
            word, word if word in ("critical", "high", "medium", "low") else "low"
        )
    try:
        n = int(level)
    except (TypeError, ValueError):
        return "low"
    return (
        "critical" if n >= 14 else "high" if n >= 12 else "medium" if n >= 7 else "low"
    )


def normalize_cve(
    raw: dict, detected_at=None, agent_id: str = "", agent_name: str = ""
) -> dict:
    """A /me/vulnerabilities CVE record in the page's shape.

    The live API uses indexer-shaped fields (cve / cvss3_score / package /
    version / published / updated); the page reads id / cvss_score /
    package_name / package_version / first_detected_at / published_date /
    modified_date / severity. Each fallback also accepts the page's own
    names so a server that adopts them keeps working."""
    if not isinstance(raw, dict):
        return {}
    score = raw.get("cvss3_score")
    if score is None:
        score = raw.get("cvss2_score")
    if score is None:
        score = raw.get("cvss_score")
    try:
        score = float(score) if score is not None else None
    except (TypeError, ValueError):
        score = None
    try:
        epss = float(raw["epss"]) if raw.get("epss") is not None else None
    except (TypeError, ValueError):
        epss = None
    return {
        "id": _s(raw.get("cve") or raw.get("id") or "", 64),
        "severity": _s(raw.get("severity") or "", 16).lower() or "low",
        "cvss_score": score,
        "epss": epss,
        "package_name": _s(raw.get("package") or raw.get("package_name") or "", 120),
        "package_version": _s(
            raw.get("version") or raw.get("package_version") or "", 64
        ),
        "description": _s(raw.get("description") or "", _MAX_TEXT),
        "status": _s(raw.get("status") or "", 32),
        "published_date": _s(
            raw.get("published") or raw.get("published_date") or "", 40
        ),
        "modified_date": _s(raw.get("updated") or raw.get("modified_date") or "", 40),
        "first_detected_at": _s(raw.get("first_detected_at") or detected_at or "", 40),
        "agent_id": _s(agent_id, 16),
        "agent_name": _s(agent_name, 64),
        "source": "api",
    }


def normalize_event(hit: dict) -> dict:
    """A vulnerability-detection event (OpenSearch hit, flattened payload or
    the live flat shape) in the page's event shape."""
    if not isinstance(hit, dict):
        return {}
    src = hit.get("_source") if isinstance(hit.get("_source"), dict) else hit
    rule = src.get("rule") if isinstance(src.get("rule"), dict) else {}
    agent = src.get("agent") if isinstance(src.get("agent"), dict) else {}
    mitre = (
        (rule.get("mitre") or {}).get("id")
        if isinstance(rule.get("mitre"), dict)
        else []
    )
    if not isinstance(mitre, list):
        mitre = [mitre]
    raw_log = src.get("full_log") or src.get("previous_output") or ""
    if not raw_log:
        data = src.get("data")
        if data:
            try:
                raw_log = json.dumps(data, indent=2)
            except (TypeError, ValueError):
                raw_log = str(data)
        elif src.get("cve"):
            raw_log = json.dumps(
                {k: src.get(k) for k in ("cve", "package", "version", "title")},
                indent=2,
            )
    rule_level = src.get("rule_level", rule.get("level"))
    severity = _s(src.get("severity") or "", 16).lower() or level_to_severity(
        rule_level
    )
    cve = src.get("cve")
    return {
        "id": _s(hit.get("_id") or src.get("id") or cve or "", 128),
        "rule_id": _s(src.get("rule_id") or rule.get("id", ""), 32),
        "level": (
            rule_level if isinstance(rule_level, (int, float)) else _s(rule_level, 16)
        ),
        "severity": (
            severity if severity in ("critical", "high", "medium", "low") else "low"
        ),
        "description": _s(
            src.get("title") or rule.get("description", "") or cve or "", 300
        ),
        "timestamp": _s(src.get("timestamp") or "", 40),
        "agent": _s(agent.get("name", "") or src.get("agent_name", ""), 64),
        "host": _s(agent.get("name", "") or src.get("agent_name", ""), 64),
        "ip": _s(agent.get("ip", ""), 64),
        "mitre": [_s(m, 32) for m in mitre][:8],
        "hash": _s(src.get("id", "") or cve or "", 128),
        "raw_log": _s(raw_log, _MAX_TEXT),
        "source": "api",
    }


# --------------------------------------------------------------------------
# Endpoints
# --------------------------------------------------------------------------


def fetch_agent(agent_id: str | None = None):
    """GET /v1/me/agent: this device's agent record (or ``agent_id``'s)."""
    payload, err = _get("/agent", {"agent_id": agent_id} if agent_id else None)
    if err:
        return None, err
    if not isinstance(payload, dict):
        return None, "bad shape"
    for key in ("agent", "basic_info"):
        if isinstance(payload.get(key), dict):
            return payload[key], None
    return payload, None


def fetch_vulnerabilities_summary(severity: str | None = None, top: int = 5):
    """GET /v1/me/vulnerabilities: group totals (``by_severity``) and a short
    per-device preview. Cheap; the Overview cards can use it."""
    params = {"top": top}
    if severity:
        params["severity"] = severity
    payload, err = _get("/vulnerabilities", params)
    if err:
        return None, err
    if not isinstance(payload, dict):
        return None, "bad shape"
    return payload, None


def _device_vulnerabilities_page(agent_id: str, severity=None, limit=500, offset=0):
    params = {"limit": limit, "offset": offset}
    if severity:
        params["severity"] = severity
    payload, err = _get(f"/vulnerabilities/{agent_id}", params)
    if err:
        return None, None, err
    if not isinstance(payload, dict):
        return None, None, "bad shape"
    items = _list(payload, "vulnerabilities", "cves")
    return list(items), payload.get("detected_at"), None


def fetch_device_vulnerabilities(
    agent_id: str,
    agent_name: str = "",
    severity=None,
    page_size: int = 500,
    max_cves: int = _MAX_ITEMS,
):
    """GET /v1/me/vulnerabilities/{agent_id}, every page, normalised."""
    merged, detected_at, offset = [], None, 0
    while True:
        page, page_detected, err = _device_vulnerabilities_page(
            agent_id, severity, page_size, offset
        )
        if err:
            return None, err
        if detected_at is None and page_detected:
            detected_at = page_detected
        if not page:
            break
        merged.extend(page)
        if len(page) < page_size or len(merged) >= max_cves:
            break
        offset += page_size
    out = [
        normalize_cve(c, detected_at, agent_id, agent_name) for c in merged[:max_cves]
    ]
    return [c for c in out if c.get("id")], None


def fetch_all_vulnerabilities(devices: list):
    """Per-device CVE lists for ``devices`` ([{agent_id, agent_name}]) fetched
    in parallel and merged. Partial success returns what loaded; every
    device failing returns the first error (NOT_AVAILABLE when that is why)."""
    by_id = {str(d.get("agent_id")): d for d in devices or [] if d.get("agent_id")}
    if not by_id:
        return [], None
    merged, errors = [], []
    with ThreadPoolExecutor(max_workers=min(len(by_id), MAX_PARALLEL_FETCHES)) as ex:
        futures = {
            ex.submit(
                fetch_device_vulnerabilities, aid, str(d.get("agent_name") or "")
            ): aid
            for aid, d in by_id.items()
        }
        for fut in as_completed(futures):
            cves, err = fut.result()
            if err:
                errors.append(err)
                logger.warning(
                    f"[DEVICES] vulnerabilities for agent {futures[fut]}: {err}"
                )
                continue
            merged.extend(cves or [])
    if errors and len(errors) == len(by_id):
        return None, (
            NOT_AVAILABLE if all(e == NOT_AVAILABLE for e in errors) else errors[0]
        )
    return merged, None


def fetch_device_vulnerability_events_page(agent_id: str, limit=50, offset=0, hours=24):
    params = {"limit": limit, "offset": offset, "hours": hours}
    payload, err = _get(f"/vulnerabilities/{agent_id}/events", params)
    if err:
        return None, err
    if not isinstance(payload, dict):
        return None, "bad shape"
    items = _list(payload, "events")
    if (
        not items
        and isinstance(payload.get("hits"), dict)
        and isinstance(payload["hits"].get("hits"), list)
    ):
        items = payload["hits"]["hits"]
    return list(items), None


def fetch_device_vulnerability_events(
    agent_id: str, agent_name: str = "", page_size=50, max_events=2000, hours=24
):
    """All detection events for one device in the window, newest first."""
    out, offset = [], 0
    while True:
        page, err = fetch_device_vulnerability_events_page(
            agent_id, page_size, offset, hours
        )
        if err:
            return None, err
        if not page:
            break
        out.extend(page)
        if len(page) < page_size or len(out) >= max_events:
            break
        offset += page_size
    events = []
    for h in out[:max_events]:
        ev = normalize_event(h)
        if not ev:
            continue
        ev["agent"] = ev["agent"] or _s(agent_name, 64)
        ev["host"] = ev["host"] or ev["agent"]
        events.append(ev)
    events.sort(key=lambda e: e.get("timestamp") or "", reverse=True)
    return events, None


def fetch_sca():
    """GET /v1/me/sca: SCA policy results (``invalid`` folded from ``not_applicable``)."""
    payload, err = _get("/sca")
    if err:
        return None, err
    items = [
        it
        for it in _list(payload, "policies", "affected_items")
        if isinstance(it, dict)
    ]
    for it in items:
        if "invalid" not in it and "not_applicable" in it:
            it["invalid"] = it["not_applicable"]
    return items[:200], None


def normalize_inventory_device(raw: dict) -> dict:
    """One /me/inventory device in the documented ``agent_*`` shape.

    The backend (phoenix-provisioning, AR-B7) answers with the Wazuh manager's
    own ``/agents`` projection ``{id, name, status, ip}``; the data contract
    (dev-docs/plans/devices-data-contract.md) names the same fields
    ``agent_id`` / ``agent_name`` / ``agent_ip``. Accept both so the rest of
    the plugin reads one shape; the documented keys win when both are present.
    """
    d = dict(raw)
    for want, alt in (("agent_id", "id"), ("agent_name", "name"), ("agent_ip", "ip")):
        if not d.get(want) and d.get(alt) not in (None, ""):
            d[want] = d[alt]
    if not d.get("agent_name") and d.get("hostname"):
        d["agent_name"] = d["hostname"]
    if d.get("agent_id") is not None:
        d["agent_id"] = str(d["agent_id"])
    return d


def fetch_inventory_full(page_size: int = 200):
    """GET /v1/me/inventory, every page: the account's device summaries."""
    devices, offset = [], 0
    while True:
        payload, err = _get("/inventory", {"limit": page_size, "offset": offset})
        if err:
            return None, err
        if not isinstance(payload, dict):
            return None, "bad shape"
        page = [
            normalize_inventory_device(d)
            for d in _list(payload, "devices", "items")
            if isinstance(d, dict)
        ]
        devices.extend(page)
        if payload.get("has_more") is False or not page:
            break
        if payload.get("has_more") is None:
            total = payload.get("total_devices", payload.get("total"))
            try:
                if total is None or len(devices) >= int(total):
                    break
            except (TypeError, ValueError):
                break
        if len(devices) >= _MAX_ITEMS:
            break
        offset += page_size
    return devices, None


def fetch_device_inventory(agent_id: str):
    """GET /v1/me/inventory/{agent_id}: os / hardware / packages / ports /
    processes / network for one device."""
    payload, err = _get(f"/inventory/{agent_id}")
    if err:
        return None, err
    if not isinstance(payload, dict):
        return None, "bad shape"
    return payload, None


def fetch_hotfixes():
    """GET /v1/me/hotfixes: Windows KB updates (empty elsewhere)."""
    payload, err = _get("/hotfixes")
    if err:
        return None, err
    return [h for h in _list(payload, "hotfixes") if isinstance(h, dict)][
        :_MAX_ITEMS
    ], None
