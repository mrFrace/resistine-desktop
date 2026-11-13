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

from urllib.parse import quote

from plugins.devices.api import NOT_AVAILABLE, _list, _s

PREFIX = "/v1/me"
_AR = "/active-response"
_MAX_ITEMS = 2000

# The two shipped Tier-1 executables the Desktop may build a policy over
# (docs/active-response-P2.md §desktop AR-D3). A brand-new script is Tier-2,
# which is PR/gitops only and never offered here.
EXECUTABLES = ("block-ip", "disable-account")


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


def _request(method: str, path: str, *, params: dict | None = None,
             json: dict | None = None):
    """A write (POST/PUT/DELETE) on ``PREFIX + path`` with the MAS token.

    Mirrors ``_get``'s ``(data, error)`` contract and the P0 error mapping,
    but surfaces the server's own ``detail``/``error`` message (via
    ``provisioning._error_detail``) so a gate refusal — "use gitops", a
    thymus self-test fail, a per-user 403 — reaches the operator verbatim.
    A 2xx with no body returns ``{}``; 404 (route not deployed, or the
    config is gone) maps to ``NOT_AVAILABLE``. The desktop only ever holds
    the MAS token: the write principal is signed server-side (D-3)."""
    from plugins.vpn.provisioning import (
        ProvisioningError,
        _authorized_request,
        _error_detail,
    )

    try:
        r = _authorized_request(method, PREFIX + path, params=params, json=json)
    except ProvisioningError as e:
        return None, _s(e, 200)
    except Exception as e:  # noqa: BLE001 - a transport failure is an error string
        return None, f"network: {_s(e, 160)}"
    if r.status_code == 404:
        return None, NOT_AVAILABLE
    if r.status_code == 204:
        return {}, None
    if not 200 <= r.status_code < 300:
        return None, _s(_error_detail(r), 200)
    try:
        return r.json(), None
    except ValueError:
        return {}, None  # a 2xx with an empty/invalid body is still success


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
        "rule_title": _s(raw.get("rule_title") or raw.get("rule_description"), 200),
        "monitor_id": _s(raw.get("monitor_id"), 64),
        "config_id": _s(raw.get("config_id"), 64),
    }


def parse_agent(raw) -> dict | None:
    """One of the caller's own agents from ``GET /v1/me/inventory`` — the
    universe the blast-radius preview is drawn from."""
    if not isinstance(raw, dict):
        if raw in (None, ""):
            return None
        return {"agent_id": _s(raw, 16), "agent_name": ""}
    aid = _s(raw.get("agent_id") or raw.get("id"), 16)
    name = _s(raw.get("agent_name") or raw.get("name") or raw.get("hostname"), 64)
    if not aid and not name:
        return None
    return {"agent_id": aid, "agent_name": name}


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


def monitors_by_channel(channels: list, monitors: list) -> dict:
    """Map each channel ``config_id`` -> the monitor dicts that fire it (not
    just their names, so ``policy_enabled`` can read ``enabled``)."""
    out: dict[str, list] = {}
    for m in monitors or []:
        dest = m.get("destination_id")
        if dest:
            out.setdefault(dest, []).append(m)
    return out


def policy_enabled(channel: dict, monitors_for_channel: list | None) -> bool:
    """Is this policy actually live? (AR-D8a — the consent ledger must say
    "No" for a disabled policy.)

    A policy only runs when its **channel** ``is_enabled`` is true and, when
    it has firing monitors, **at least one** of them is enabled. A channel
    with no monitors can still be fired ad-hoc, so its liveness rides on the
    channel flag alone.
    """
    if not channel.get("is_enabled", True):
        return False
    mons = monitors_for_channel or []
    if mons and not any(m.get("enabled", True) for m in mons):
        return False
    return True


def channel_name_by_id(channels: list) -> dict:
    """Map ``config_id`` -> the channel's display name (for the executions
    view, AR-D8c, so a thin AR record can name the policy that ran)."""
    out: dict[str, str] = {}
    for c in channels or []:
        cid = c.get("config_id")
        if cid:
            out[cid] = c.get("name") or cid
    return out


# --------------------------------------------------------------------------
# Payload builders (pure) — one place that knows the write wire shapes
# --------------------------------------------------------------------------


def build_policy(*, name: str, executable: str, trigger: str,
                 stateful_timeout, agent_id: str,
                 config_id: str | None = None) -> dict:
    """The create/edit body for a Tier-1 policy, pinned to the caller's own
    agent. **Always** ``location=defined-agent`` (D-2: the Desktop never
    writes ``location=all``); ``type=stateful`` with a positive timeout."""
    payload = {
        "name": (name or "").strip(),
        "executable": executable,
        "trigger": (trigger or "").strip(),
        "type": "stateful",
        "stateful_timeout": int(stateful_timeout),
        "location": "defined-agent",
        "agent_id": (agent_id or "").strip(),
    }
    if config_id:
        payload["config_id"] = config_id
    return payload


def build_fire(agent_id: str, executable: str, target: str) -> dict:
    """The fire/stop body: which agent, which executable, and the target.

    **Always** pins ``location=defined-agent`` (D-2). The preview and the
    actual fire are built from this same function, so the blast radius the
    operator self-tests is the blast radius that is written — never an
    unpinned fire the manager could default to a wider scope."""
    return {
        "agent_id": (agent_id or "").strip(),
        "executable": executable,
        "location": "defined-agent",
        # The server keys the target by executable (block-ip -> source.ip,
        # disable-account -> user.name); send the raw value it typed, a plain string.
        "target": (target or "").strip(),
    }


def validate_policy(*, name: str, executable: str, trigger: str,
                    stateful_timeout, agent_id: str) -> str | None:
    """A short reason the policy can't be saved, or None. The server enforces
    the real gate (AR-S2); this only keeps an obviously-bad form off the wire
    and mirrors the gate's ``stateful_timeout > 0`` rule."""
    if not (name or "").strip():
        return "missing name"
    if executable not in EXECUTABLES:
        return "executable must be block-ip or disable-account"
    if not (trigger or "").strip():
        return "missing trigger"
    if not (agent_id or "").strip():
        return "missing agent"
    try:
        if int(stateful_timeout) <= 0:
            return "stateful timeout must be greater than 0"
    except (TypeError, ValueError):
        return "stateful timeout must be a whole number of seconds"
    return None


def validate_fire(agent_id: str, executable: str, target: str) -> str | None:
    """A short reason an ad-hoc fire/stop can't go, or None."""
    if not (agent_id or "").strip():
        return "missing agent"
    if executable not in EXECUTABLES:
        return "executable must be block-ip or disable-account"
    if not (target or "").strip():
        return "missing target"
    return None


def _as_list(v) -> list:
    return v if isinstance(v, list) else []


def parse_preview(raw) -> dict:
    """The ``/preview`` result normalised: blast radius + the mandatory thymus
    self-test. ``self_test.ran`` is False when the server sent none (the UI
    then blocks save until it has one). Everything untrusted is cut/coerced."""
    if not isinstance(raw, dict):
        raw = {}

    def agent_entry(x) -> dict:
        if isinstance(x, dict):
            return {
                "agent_id": _s(x.get("agent_id") or x.get("id"), 16),
                "agent_name": _s(x.get("agent_name") or x.get("name"), 64),
                "reason": _s(x.get("reason") or x.get("excluded_reason") or "", 160),
            }
        return {"agent_id": _s(x, 16), "agent_name": "", "reason": ""}

    included = [agent_entry(x) for x in _as_list(raw.get("included"))][:_MAX_ITEMS]
    excluded = [agent_entry(x) for x in _as_list(raw.get("excluded"))][:_MAX_ITEMS]
    refusals = [
        _s(x, 200) for x in _as_list(raw.get("refusals")) if x not in (None, "")
    ][:_MAX_ITEMS]
    st_raw = raw.get("self_test") if isinstance(raw.get("self_test"), dict) else None
    st = st_raw or {}
    # A self_test only counts as "ran" when it carries the actual verdict
    # field: an empty ``{}`` is not a passed test, it is a missing one, and
    # must not open the save gate (preview_blocks_save).
    ran = st_raw is not None and "would_fire_on_self" in st_raw
    self_test = {
        "ran": ran,
        "would_fire_on_self": st.get("would_fire_on_self") is True,
        "offending": [
            _s(x, 160) for x in _as_list(st.get("offending")) if x not in (None, "")
        ][:50],
    }
    count = raw.get("count")
    try:
        count = int(count)
    except (TypeError, ValueError):
        count = len(included)
    return {
        "count": count,
        "included": included,
        "excluded": excluded,
        "refusals": refusals,
        "self_test": self_test,
    }


def preview_blocks_save(preview: dict | None) -> str | None:
    """A short reason the preview blocks the save (so the UI can disable the
    hold-to-confirm), or None when it's clear to proceed. Mirrors the gate:
    no self-test ⇒ not shown yet; a self-hit or a refusal ⇒ blocked."""
    if not isinstance(preview, dict):
        return "run the preview first"
    st = preview.get("self_test") or {}
    if not st.get("ran"):
        return "self-test has not run"
    if st.get("would_fire_on_self"):
        return "self-test: would fire on your own infrastructure"
    if preview.get("refusals"):
        return "the gate refused this policy"
    return None


# --------------------------------------------------------------------------
# Write endpoints (AR-D1b) — CRUD, fire/stop, preview, inventory
# --------------------------------------------------------------------------


def fetch_inventory():
    """GET /v1/me/inventory: the caller's own agents (for blast-radius).
    Returns ``(agents, error)``."""
    payload, err = _get("/inventory")
    if err:
        return None, err
    agents = []
    for raw in _list(payload, "agents", "devices", "items")[:_MAX_ITEMS]:
        row = parse_agent(raw)
        if row:
            agents.append(row)
    return agents, None


def preview(payload: dict):
    """POST /v1/me/active-response/preview: blast radius + thymus self-test,
    no write. Returns ``(parsed_preview, error)``."""
    data, err = _request("POST", f"{_AR}/preview", json=payload)
    if err:
        return None, err
    return parse_preview(data), None


def create_policy(payload: dict):
    """POST /v1/me/active-response: create a Tier-1 channel+monitor. Refuses a
    ``location=all`` body on the client too (D-2; the server also refuses)."""
    if (payload or {}).get("location") == "all":
        return None, "fleet-wide (all agents) is managed via gitops, not the desktop"
    return _request("POST", _AR, json=payload)


def update_policy(config_id: str, payload: dict):
    """PUT /v1/me/active-response/{config_id}: edit a policy."""
    cid = _s(config_id, 64)
    if not cid:
        return None, "missing config id"
    if (payload or {}).get("location") == "all":
        return None, "fleet-wide (all agents) is managed via gitops, not the desktop"
    return _request("PUT", f"{_AR}/{quote(cid, safe='')}", json=payload)


def delete_policy(config_id: str):
    """DELETE /v1/me/active-response/{config_id}: remove a policy."""
    cid = _s(config_id, 64)
    if not cid:
        return None, "missing config id"
    return _request("DELETE", f"{_AR}/{quote(cid, safe='')}")


def fire(agent_id: str, executable: str, target: str):
    """POST /v1/me/active-response/fire: run an AR once on one of the caller's
    agents ("block this IP now"). Returns ``(result, error)``."""
    return _request("POST", f"{_AR}/fire",
                    json=build_fire(agent_id, executable, target))


def stop(agent_id: str, executable: str, target: str):
    """POST /v1/me/active-response/stop: revert an ad-hoc fire early."""
    return _request("POST", f"{_AR}/stop",
                    json=build_fire(agent_id, executable, target))
