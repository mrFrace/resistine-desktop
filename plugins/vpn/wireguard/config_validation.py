"""
WireGuard config validation helpers.

Values received from the VPN API are interpolated into a WireGuard ``.conf``
file. Without validation a malicious or compromised API response could inject
extra lines (for example ``PostUp = <shell command>``, which wg-quick runs as
root) or extra ``[Peer]`` sections. Every server-provided value is therefore
checked here before it is written to disk.

Config *names* also become file paths (``<wireguard_folder>/<name>.conf``) and,
on Linux, interface names passed to wg-quick, so they are restricted to a safe
character set to prevent path traversal.

This module is platform-neutral and has no side effects.

Copyright (c) Resistine 2025
Licensed under the GNU General Public License v2 or later
"""

from __future__ import annotations

import ipaddress
import re

# Config names: alphanumeric, underscore, dash; must not start with a dash
# (it would be parsed as an option by wg/wg-quick). No separators, no dots,
# so "..", "/abs/path" and "a/../b" are all rejected.
_CONFIG_NAME_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_-]*$")

# WireGuard keys are base64; we only enforce the (standard or URL-safe)
# alphabet, not the exact length, so the check stays a pure injection guard.
_KEY_RE = re.compile(r"^[A-Za-z0-9+/_-]+={0,2}$")

# RFC 1123-ish hostname (also used for DNS search domains).
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*\.?$"
)

# Simple tokens such as MTU / ListenPort / PersistentKeepalive / Table / FwMark
# ("1420", "25", "off", "auto", "0x1234").
_TOKEN_RE = re.compile(r"^[A-Za-z0-9]+$")

# Script hooks that wg-quick executes as root. Never accepted from the server.
SCRIPT_HOOK_KEYS = frozenset({"preup", "postup", "predown", "postdown"})


def validate_config_name(name):
    """Return ``name`` if it is a safe config name, else raise ValueError."""
    if not isinstance(name, str) or not _CONFIG_NAME_RE.fullmatch(name):
        raise ValueError(
            f"Invalid config name: {name!r} - only letters, digits, '_' and '-' "
            "are allowed"
        )
    return name


def is_valid_config_name(name):
    """Return True if ``name`` is a safe config name."""
    try:
        validate_config_name(name)
    except ValueError:
        return False
    return True


def validate_wg_field(value, field_name):
    """Reject values that could break out of a single ``Key = value`` line.

    Raises ValueError for non-strings and for any control character
    (newline, carriage return, NUL, tab, DEL, ...).
    """
    if not isinstance(value, str):
        raise ValueError(f"{field_name}: expected string, got {type(value).__name__}")
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in value):
        raise ValueError(
            f"{field_name}: contains control/newline characters (possible injection)"
        )
    return value


def validate_key(value, field_name):
    """Validate a base64 WireGuard key (PublicKey / PrivateKey / PresharedKey)."""
    validate_wg_field(value, field_name)
    if not _KEY_RE.fullmatch(value):
        raise ValueError(f"{field_name}: not a base64 key")
    return value


def _validate_host(host):
    if host.startswith("[") and host.endswith("]"):
        ipaddress.IPv6Address(host[1:-1])
        return
    try:
        ipaddress.ip_address(host)
        return
    except ValueError:
        pass
    if not _HOSTNAME_RE.fullmatch(host):
        raise ValueError(f"invalid host: {host!r}")


def validate_endpoint(endpoint):
    """Validate a WireGuard endpoint ``host:port`` (host may be ``[ipv6]``)."""
    validate_wg_field(endpoint, "Endpoint")
    if ":" not in endpoint:
        raise ValueError(f"Endpoint: invalid format (expected host:port): {endpoint!r}")
    host, port_str = endpoint.rsplit(":", 1)
    if not port_str.isdigit() or not 1 <= int(port_str) <= 65535:
        raise ValueError(f"Endpoint: invalid port: {port_str!r}")
    try:
        _validate_host(host)
    except ValueError:
        raise ValueError(f"Endpoint: invalid host: {host!r}") from None
    return endpoint


def _split_list(value, field_name):
    """Turn a list or a comma-separated string into stripped items."""
    if isinstance(value, (list, tuple)):
        items = list(value)
    else:
        validate_wg_field(value, field_name)
        items = value.split(",")
    result = []
    for item in items:
        validate_wg_field(item, field_name)
        item = item.strip()
        if item:
            result.append(item)
    return result


def validate_ip_or_cidr(value, field_name):
    """Validate one IP address or CIDR (``10.0.0.2`` or ``10.0.0.0/24``)."""
    validate_wg_field(value, field_name)
    try:
        ipaddress.ip_interface(value.strip())
    except ValueError:
        raise ValueError(f"{field_name}: invalid IP/CIDR: {value!r}") from None
    return value


def validate_ip_list(value, field_name):
    """Validate Address / AllowedIPs: a list or a comma-separated string of
    IPs/CIDRs (e.g. ``"10.0.0.0/17, 10.0.65.0/24"``). Must be non-empty."""
    items = _split_list(value, field_name)
    if not items:
        raise ValueError(f"{field_name}: empty")
    for item in items:
        validate_ip_or_cidr(item, field_name)
    return value


def validate_dns_list(value, field_name="DNS"):
    """Validate DNS: list or comma-separated string of IPs or search domains.

    An empty value is allowed (DNS is optional).
    """
    for item in _split_list(value, field_name):
        try:
            ipaddress.ip_address(item)
        except ValueError:
            if not _HOSTNAME_RE.fullmatch(item):
                raise ValueError(f"{field_name}: invalid entry: {item!r}") from None
    return value


def validate_token(value, field_name):
    """Validate a simple scalar such as MTU / ListenPort / PersistentKeepalive."""
    if isinstance(value, bool):
        raise ValueError(f"{field_name}: unexpected boolean")
    if isinstance(value, int):
        value = str(value)
    validate_wg_field(value, field_name)
    if not _TOKEN_RE.fullmatch(value.strip()):
        raise ValueError(f"{field_name}: invalid value: {value!r}")
    return value


# Allowed keys per section (lower-case) and their validators. Keys not listed
# here are not part of the WireGuard config format.
_INTERFACE_VALIDATORS = {
    "privatekey": validate_key,
    "address": validate_ip_list,
    "dns": validate_dns_list,
    "mtu": validate_token,
    "listenport": validate_token,
    "table": validate_token,
    "fwmark": validate_token,
}
_PEER_VALIDATORS = {
    "publickey": validate_key,
    "presharedkey": validate_key,
    "allowedips": validate_ip_list,
    "endpoint": lambda v, _name: validate_endpoint(v),
    "persistentkeepalive": validate_token,
}
SECTION_VALIDATORS = {"Interface": _INTERFACE_VALIDATORS, "Peer": _PEER_VALIDATORS}


def validate_section_entry(section, key, value):
    """Validate a ``key = value`` pair for a section of a server-provided config.

    Returns True if the pair should be written, False if the key is unknown
    (caller should skip it). Raises ValueError for script hooks, malformed
    keys or invalid values.
    """
    validate_wg_field(key, f"[{section}] key")
    lowered = key.strip().lower()
    if lowered in SCRIPT_HOOK_KEYS:
        raise ValueError(f"[{section}] {key}: script hooks are not accepted from the server")
    validator = SECTION_VALIDATORS[section].get(lowered)
    if validator is None:
        return False
    validator(value, key)
    return True


def validate_server_config(server_public_key, endpoint, client_address,
                           allowed_ips, dns_servers):
    """Validate the fields the macOS/Linux writers interpolate into the .conf.

    Raises ValueError on the first invalid value.
    """
    validate_key(server_public_key, "PublicKey")
    validate_endpoint(endpoint)
    validate_ip_list(client_address, "Address")
    validate_ip_list(allowed_ips, "AllowedIPs")
    validate_dns_list(dns_servers, "DNS")


def optional_peer_lines(peer_config):
    """Validated ``PresharedKey`` / ``PersistentKeepalive`` lines for [Peer].

    The macOS/Linux writers build the .conf from fixed fields; these two are
    optional (the Phoenix VPN server uses a per-device preshared key). Returns
    the lines to append (possibly empty). Raises ValueError on a bad value.
    """
    lines = []
    psk = peer_config.get("PresharedKey")
    if psk:
        validate_key(psk, "PresharedKey")
        lines.append(f"PresharedKey = {psk}")
    keepalive = peer_config.get("PersistentKeepalive")
    if keepalive not in (None, ""):
        keepalive = str(keepalive)
        validate_token(keepalive, "PersistentKeepalive")
        if not keepalive.isdigit() or not 0 <= int(keepalive) <= 65535:
            raise ValueError("PersistentKeepalive must be 0-65535 seconds")
        lines.append(f"PersistentKeepalive = {keepalive}")
    return lines

