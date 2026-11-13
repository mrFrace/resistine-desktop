"""Phoenix API client for Active Response visibility: ``GET /v1/me/active-response*``.

Read-only. The desktop never talks to Wazuh or the indexer: it asks
``api.phoenix.exposed`` (the MAS Bearer token, plugins/vpn/provisioning.
_authorized_request), which forwards to the indexer reader with a
readonly-signed principal. Scoping to the user's own agents happens upstream;
the client only displays what comes back.

Three endpoints, mirroring plugins/devices/sessions_api.py: each ``fetch_*``
returns ``(data, error)``. ``error`` is None on success, ``NOT_AVAILABLE`` when
the API answers 404 (the route is not deployed yet, so the tab degrades to its
empty state), or a short reason otherwise. Everything the server sends is
untrusted: strings are stripped and cut, booleans coerced, lists capped.

Backend contract (docs/active-response-P0.md, §llmagent-api response shapes):
  * ``GET /v1/me/active-response`` -> ``{"active_responses": [channel, ...]}``
  * ``GET /v1/me/active-response/monitors`` -> ``{"monitors": [monitor, ...]}``
  * ``GET /v1/me/active-response/executions`` -> ``{"executions": [exec, ...]}``
    (optional ``?agent_id=`` filter; the backend has already scoped the rows to
    the user's agents).
"""

from __future__ import annotations

from plugins.devices.api import NOT_AVAILABLE, _list, _s

PREFIX = "/v1/me"
_AR = "/active-response"
_MAX_ITEMS = 2000


def _get(path: str, params: dict | None = None):
    """Shared GET on ``PREFIX + path`` with the MAS token. Returns
    ``(parsed_json, error)``; 404 maps to ``NOT_AVAILABLE`` like
    plugins/devices/api.py so an undeployed route degrades gracefully."""
    from plugins.vpn.provisioning import ProvisioningError, _authorized_request

    try:
        r = _authorized_request("GET", PREFIX + path, params=params)
    except ProvisioningError as e:
        return None, _s(e, 200)
    except Exception as e:  # noqa: BLE001 - a transport failure is an error string
        return None, f"network: {_s(e, 160)}"
    if r.status_code == 404:
        return None, NOT_AVAILABLE
    if r.status_code != 200:
        return None, f"http {r.status_code}"
    try:
        return r.json(), None
    except ValueError:
        return None, "bad json"


def _bool(v) -> bool:
    return v is True


def _str_list(v, limit: int = 40, cap: int = 20) -> list:
    """A list of short strings from ``v`` (a list, or a single scalar)."""
    items = v if isinstance(v, list) else [v] if v not in (None, "") else []
    return [_s(x, limit) for x in items[:cap] if x not in (None, "")]


# --------------------------------------------------------------------------
# Parsers (pure): one untrusted record -> the shape the tab reads
# --------------------------------------------------------------------------


def parse_channel(raw) -> dict | None:
    """An AR channel (policy): the command that would run, where, and whether
    it affects the signed-in user's fleet."""
    if not isinstance(raw, dict):
        return None
    cid = _s(raw.get("config_id"), 64)
    name = _s(raw.get("name"), 120)
    if not cid and not name:
        return None
    timeout = raw.get("stateful_timeout")
    return {
        "config_id": cid,
        "name": name or cid,
        "executable": _s(raw.get("executable"), 120),
        "location": _s(raw.get("location"), 32),
        "agent_id": _s(raw.get("agent_id"), 16),
        "type": _s(raw.get("type"), 32),
        "stateful_timeout": (
            _s(timeout, 16) if timeout not in (None, "") else ""
        ),
        "is_enabled": raw.get("is_enabled", True) is not False,
        "affects_me": _bool(raw.get("affects_me")),
    }


def parse_monitor(raw) -> dict | None:
    """A monitor (detection rule) that fires an AR channel. ``destination_id``
    points at the channel's ``config_id``."""
    if not isinstance(raw, dict):
        return None
    mid = _s(raw.get("monitor_id"), 64)
    name = _s(raw.get("name"), 120)
    if not mid and not name:
        return None
    return {
        "monitor_id": mid,
        "name": name or mid,
        "enabled": raw.get("enabled", True) is not False,
        "indices": _str_list(raw.get("indices"), 80),
        "queries": _str_list(raw.get("queries") or raw.get("query"), 200),
        "trigger_condition": _s(raw.get("trigger_condition"), 200),
        "destination_id": _s(raw.get("destination_id"), 64),
    }


def _target_text(raw) -> str:
    """The AR target as one short string: ``target`` may be ``{ip|user}``,
    a bare string, or absent."""
    target = raw.get("target")
    if isinstance(target, dict):
        ip = _s(target.get("ip"), 64)
        user = _s(target.get("user"), 64)
        if ip:
            return ip
        if user:
            return user
        return ""
    if target not in (None, ""):
        return _s(target, 64)
    # Some shapes carry the target flattened onto the record.
    return _s(raw.get("ip") or raw.get("user") or "", 64)


def parse_execution(raw) -> dict | None:
    """One AR execution row (a command that ran on an agent)."""
    if not isinstance(raw, dict):
        return None
    return {
        "agent_id": _s(raw.get("agent_id"), 16),
        "agent_name": _s(raw.get("agent_name"), 64),
        "executable": _s(raw.get("executable"), 120),
        "command": _s(raw.get("command"), 16).lower(),
        "target": _target_text(raw),
        "timestamp": _s(raw.get("@timestamp") or raw.get("timestamp"), 40),
        "status": _s(raw.get("status"), 32),
        "finding_id": _s(raw.get("finding_id"), 128),
        "monitor_id": _s(raw.get("monitor_id"), 64),
        "config_id": _s(raw.get("config_id"), 64),
    }


def _parse_all(payload, key, parser) -> list:
    out = []
    for raw in _list(payload, key)[:_MAX_ITEMS]:
        row = parser(raw)
        if row:
            out.append(row)
    return out


# --------------------------------------------------------------------------
# Endpoints
# --------------------------------------------------------------------------


def fetch_channels():
    """GET /v1/me/active-response: the AR channels (policies). Global, not
    per-user; each carries ``affects_me``. Returns ``(channels, error)``."""
    payload, err = _get(_AR)
    if err:
        return None, err
    return _parse_all(payload, "active_responses", parse_channel), None


def fetch_monitors():
    """GET /v1/me/active-response/monitors: the monitors that fire channels.
    Global. Returns ``(monitors, error)``."""
    payload, err = _get(f"{_AR}/monitors")
    if err:
        return None, err
    return _parse_all(payload, "monitors", parse_monitor), None


def fetch_executions(agent_id: str | None = None):
    """GET /v1/me/active-response/executions: AR executions, already scoped to
    the user's agents by the backend. ``agent_id`` narrows it to one device.
    Returns ``(executions, error)``."""
    params = {"agent_id": agent_id} if agent_id else None
    payload, err = _get(f"{_AR}/executions", params)
    if err:
        return None, err
    return _parse_all(payload, "executions", parse_execution), None


# --------------------------------------------------------------------------
# Pure helpers the tab uses (kept here so they are testable without Qt)
# --------------------------------------------------------------------------

# How a channel's ``location`` decides whether it would run on a given agent.
RUNS_YES = "yes"          # definitely runs on this agent
RUNS_ON_TRIGGER = "local"  # runs on whichever agent raised the finding
RUNS_NO = "no"            # never runs on this agent (e.g. the manager)


def channel_runs_on(channel: dict, agent_id: str | None) -> str:
    """Would ``channel`` execute on the device with ``agent_id``?

    Wazuh AR ``location`` values: ``all`` (every agent), ``local`` (the agent
    that raised the alert), ``server`` (the manager, never an agent) and a
    specific-agent form that pins ``agent_id``. Returns one of ``RUNS_*``.
    """
    loc = (channel.get("location") or "").lower()
    if loc == "server":
        return RUNS_NO
    if loc in ("all", "any"):
        return RUNS_YES
    if loc == "local":
        return RUNS_ON_TRIGGER
    # A pinned agent: matches only when the ids line up.
    pinned = channel.get("agent_id") or ""
    if pinned:
        return RUNS_YES if agent_id and pinned == agent_id else RUNS_NO
    # Unknown/blank location: fall back to the backend's own verdict.
    return RUNS_YES if channel.get("affects_me") else RUNS_NO


def triggered_by(channels: list, monitors: list) -> dict:
    """Map each channel ``config_id`` -> list of monitor names that fire it
    (``monitor.destination_id`` == ``channel.config_id``)."""
    out: dict[str, list] = {}
    for m in monitors or []:
        dest = m.get("destination_id")
        if dest:
            out.setdefault(dest, []).append(m.get("name") or m.get("monitor_id"))
    return out
