"""Phoenix API client for the account's signed-in devices: ``/v1/devices``.

``GET /v1/devices`` lists every device of the user: its MAS session (or
None when it is no longer signed in), its VPN peer and its Wazuh agent.
``DELETE /v1/devices/{id}`` signs another device out and drops its VPN
peer and agent on the server (dev-docs/plans/device-sessions.md, "Server
contract"). Same conventions as plugins/devices/api.py: ``(data, error)``,
NOT_AVAILABLE when the route is not deployed, and everything from the
server is untrusted text.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional
from urllib.parse import quote

from plugins.devices.api import NOT_AVAILABLE, _s

PATH = "/v1/devices"
_MAX_DEVICES = 200
PHX_RE = re.compile(r"^PHX_[A-Z2-7]{16}$")
_DEVICE_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")  # MAS session device ids too


@dataclass
class Session:
    client_name: str = ""
    user_agent: str = ""
    created_at: str = ""
    last_active_at: str = ""
    last_active_ip: str = ""


@dataclass
class Vpn:
    hostname: str = ""
    address: str = ""


@dataclass
class Agent:
    agent_id: str = ""
    agent_name: str = ""
    linked: bool = False


@dataclass
class DeviceRow:
    device_id: str
    current: bool = False
    kind: str = "matrix"                 # "phoenix" | "matrix"
    session: Optional[Session] = None    # None: no longer signed in
    vpn: Optional[Vpn] = None
    agent: Optional[Agent] = None

    @property
    def phoenix(self) -> bool:
        return self.kind == "phoenix"

    @property
    def signed_in(self) -> bool:
        return self.session is not None


def _block(cls, raw, **limits):
    if not isinstance(raw, dict):
        return None
    out = {}
    for name in cls.__dataclass_fields__:
        v = raw.get(name)
        if isinstance(cls.__dataclass_fields__[name].default, bool):
            out[name] = v is True
        else:
            out[name] = _s(v, limits.get(name, 120))
    return cls(**out)


def parse_devices(payload) -> list[DeviceRow]:
    """``{"devices": [...]}`` -> rows; malformed entries are dropped."""
    items = payload.get("devices") if isinstance(payload, dict) else None
    rows = []
    for raw in (items if isinstance(items, list) else [])[:_MAX_DEVICES]:
        if not isinstance(raw, dict):
            continue
        dev = raw.get("device_id")
        if not isinstance(dev, str) or not _DEVICE_RE.match(dev):
            continue
        kind = raw.get("kind")
        rows.append(DeviceRow(
            device_id=dev,
            current=raw.get("current") is True,
            kind="phoenix" if kind == "phoenix" and PHX_RE.match(dev) else "matrix",
            session=_block(Session, raw.get("session"), user_agent=300),
            vpn=_block(Vpn, raw.get("vpn")),
            agent=_block(Agent, raw.get("agent")),
        ))
    return rows


def list_devices():
    """(rows, error): error is None, NOT_AVAILABLE, or a short reason."""
    from plugins.vpn.provisioning import ProvisioningError, _authorized_request, _error_detail

    try:
        r = _authorized_request("GET", PATH)
    except ProvisioningError as e:
        return None, _s(e, 200)
    except Exception as e:  # noqa: BLE001 - a transport failure is an error string
        return None, f"network: {_s(e, 160)}"
    if r.status_code == 404:
        return None, NOT_AVAILABLE
    if r.status_code != 200:
        return None, _s(_error_detail(r), 200)
    try:
        return parse_devices(r.json()), None
    except ValueError:
        return None, "bad json"


def remove_device(device_id: str):
    """(removed, error). error: None, "gone" (already removed: refresh),
    or the server's reason (409 this device, 503 a service down)."""
    from plugins.vpn.provisioning import ProvisioningError, _authorized_request, _error_detail

    if not isinstance(device_id, str) or not _DEVICE_RE.match(device_id):
        return False, "invalid device id"
    try:
        r = _authorized_request("DELETE", f"{PATH}/{quote(device_id, safe='')}")
    except ProvisioningError as e:
        return False, _s(e, 200)
    except Exception as e:  # noqa: BLE001
        return False, f"network: {_s(e, 160)}"
    if r.status_code == 204:
        return True, None
    if r.status_code == 404:
        return False, "gone"
    return False, _s(_error_detail(r), 200)
