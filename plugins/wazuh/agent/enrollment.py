"""Server-side agent enrollment through the Phoenix API (api.phoenix.exposed).

    POST /v1/agent/enroll {"name": <agent name>}
      -> {"agent_id", "agent_name", "group", "manager", "key"}

The API registers this device's agent with the Wazuh manager and puts it in
the signed-in user's group (u_<localpart>, created there on first use); user
and device come from the MAS token. "key" is the agent's client.keys line,
base64-encoded. A device keeps its agent while it exists on the manager, so
the name the server answers with can be an earlier one.

The key goes to the root install step in a 0600 file inside a private 0700
directory, never on a command line (other users can read argv). The root step
checks the line's shape again (key_write_sh / the PowerShell equivalent)
before writing client.keys, so a swapped file can't make it copy anything else.

When the API can't enroll (not signed in, endpoint not configured: 503) the
installers fall back to agent-auth against the manager's enrollment port.

Agents live in one Wazuh group per Phoenix user, u_<Matrix localpart>. The
group the server answers with is remembered for the signed-in account
(enrolled_group()); without one, agent_group() derives it from the Matrix ID
with the server's rule (wazuh_group in phoenix-provisioning), so an agent-auth
fallback lands in the same group. The email-derived groups of the old OTP
sign-in (alice-example.com) are no longer used.

The enrollment is also remembered against the Matrix device and account it
was made for (enrolled_for_this_sign_in()). Signing out deletes the device's
agent on the server and clears this record, and the next sign-in is a new
Matrix device, so the setup wizard enrolls again instead of trusting an agent
that is still installed and running locally. The server's device -> agent
mapping is what LLMAgent-api's Matrix bridge uses for "this machine".

Contract: matrix repo, packages/phoenix-provisioning (enroll_agent).
"""

from __future__ import annotations

import base64
import os
import re
import tempfile
from dataclasses import dataclass
from typing import Optional

from utils import settings
from utils.logger import logger

ENROLL_PATH = "/v1/agent/enroll"
_NS = "wazuh"
GROUP_PREFIX = "u_"
_NAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
# "<id> <name> <ip|any> <64 hex>" -- the same pattern is used by the root step.
KEY_LINE_PATTERN = r"[0-9]{3,8} [A-Za-z0-9._-]{1,64} (any|[0-9A-Fa-f.:/]{2,64}) [0-9a-f]{64}"
_KEY_LINE_RE = re.compile(f"^{KEY_LINE_PATTERN}$")


@dataclass(frozen=True)
class Enrollment:
    agent_id: str
    agent_name: str
    group: str
    key_line: str      # the client.keys line, without newline
    key_file: str      # private 0600 file holding key_line, for the root step


def request(agent_name: str) -> Optional[Enrollment]:
    """Enroll this device's agent; None when the API can't (the caller then
    falls back to agent-auth). Never raises."""
    if not _NAME_RE.match(agent_name or ""):
        logger.error(f"[ENROLL] unusable agent name {agent_name!r}")
        return None
    try:
        from plugins.vpn import provisioning
        r = provisioning._authorized_request("POST", ENROLL_PATH, json={"name": agent_name})
    except Exception as e:  # noqa: BLE001 - ProvisioningError, import problems
        logger.warning(f"[ENROLL] API enrollment unavailable: {e}")
        return None
    if r.status_code != 200:
        logger.warning(f"[ENROLL] API enrollment answered HTTP {r.status_code}: "
                       f"{provisioning._error_detail(r)}")
        return None
    try:
        body = r.json()
        line = base64.b64decode(body["key"], validate=True).decode("ascii").strip()
        agent_id, name, group = str(body["agent_id"]), str(body["agent_name"]), str(body["group"])
    except Exception as e:  # noqa: BLE001
        logger.error(f"[ENROLL] malformed enrollment answer: {e}")
        return None
    parts = line.split(" ")
    if not _KEY_LINE_RE.match(line) or parts[0] != agent_id or parts[1] != name:
        logger.error("[ENROLL] the enrollment answer's key does not match its agent")
        return None
    # The group goes into ossec.conf and install scripts.
    if not _NAME_RE.match(group):
        logger.error(f"[ENROLL] unusable group {group!r} in the enrollment answer")
        return None
    logger.info(f"[ENROLL] agent {agent_id} {name} in group {group}")
    _remember_group(group)
    mark_enrolled(agent_id)
    return Enrollment(agent_id, name, group, line, _write_private(line))


def _account() -> str:
    return settings.get("auth", "user_id", "") or settings.get("auth", "email", "") or ""


def _remember_group(group: str) -> None:
    settings.set(_NS, "enrolled_group", group)
    settings.set(_NS, "enrolled_group_account", _account())


def _device() -> str:
    """The Matrix device signed in now (set from /whoami at sign-in)."""
    return settings.get("auth", "device_id", "") or ""


def mark_enrolled(agent_id: str = "") -> None:
    """Remember that this device's agent was enrolled for the current sign-in.

    request() calls it with the server's agent ID; the setup wizard calls it
    without one after an agent-auth fallback, so a server it couldn't reach
    doesn't send the wizard round in circles."""
    settings.set(_NS, "enrolled_agent_id", agent_id or "")
    settings.set(_NS, "enrolled_device", _device())
    settings.set(_NS, "enrolled_device_account", _account())


def enrolled_for_this_sign_in() -> bool:
    """Whether this device's agent was enrolled for the Matrix device and
    account signed in now. True when there is no Matrix sign-in to compare
    with (nothing on the server is keyed by a device then)."""
    device, account = _device(), _account()
    if not device or not account:
        return True
    return (settings.get(_NS, "enrolled_device", "") == device
            and settings.get(_NS, "enrolled_device_account", "") == account)


def enrolled_group() -> Optional[str]:
    """The group the server last enrolled this device's agent in, if that was
    for the account signed in now; else None."""
    group = settings.get(_NS, "enrolled_group", "")
    account = _account()
    if (group and _NAME_RE.match(group) and account
            and settings.get(_NS, "enrolled_group_account", "") == account):
        return group
    return None


def user_group() -> Optional[str]:
    """u_<localpart> for the signed-in Matrix user, as the server names it."""
    user_id = settings.get("auth", "user_id", "") or ""
    if not user_id.startswith("@"):
        return None
    localpart = user_id[1:].split(":", 1)[0].lower()
    return GROUP_PREFIX + (re.sub(r"[^a-z0-9._-]", "_", localpart)[:60] or "_")


def agent_group() -> str:
    """The Wazuh group this device's agent belongs in."""
    return enrolled_group() or user_group() or "default"


def _write_private(line: str) -> str:
    d = tempfile.mkdtemp(prefix="phoenix-enroll-")  # 0700, unique (O_EXCL)
    path = os.path.join(d, "client.keys")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(line + "\n")
    return path


def discard(enrollment: Optional[Enrollment]) -> None:
    """Remove the private key file (call once the root step has run)."""
    if not enrollment:
        return
    try:
        os.unlink(enrollment.key_file)
        os.rmdir(os.path.dirname(enrollment.key_file))
    except OSError:
        pass


def _q(value: str) -> str:
    return "'" + value.replace("'", "'\\''") + "'"


def key_write_sh(key_file: str, client_keys: str, owner: str = "root:wazuh") -> str:
    """POSIX sh (run as root) installing the key line from ``key_file`` as
    ``client_keys`` after re-checking its shape; otherwise prints KEY_INVALID
    and leaves no client.keys (the rest of the script still runs)."""
    return (
        f"k=$(head -c 512 {_q(key_file)} 2>/dev/null | head -n 1); "
        f"rm -f {_q(client_keys)}; "
        f"if printf '%s\\n' \"$k\" | grep -Eqx {_q(KEY_LINE_PATTERN)}; then "
        f"(umask 027; printf '%s\\n' \"$k\" > {_q(client_keys)}); "
        f"chown {owner} {_q(client_keys)} 2>/dev/null; chmod 640 {_q(client_keys)}; "
        f"else echo KEY_INVALID; fi"
    )
