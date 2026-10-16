"""VPN provisioning through the Phoenix API (api.phoenix.exposed).

After a Phoenix (MAS) sign-in the app has an access token but no WireGuard
config. This module gets one:

  1. generate a WireGuard keypair locally (the private key never leaves the
     machine; it is stored with the platform's secret storage)
  2. POST /v1/vpn/peer with the public key and the MAS Bearer token
  3. the API reads user + device from the token, assigns this device a stable
     address, adds the peer on the VPN server and returns the config in the
     same {"Interface": {...}, "Peer": {...}} shape the old /verify-otp
     returned, so the existing validated writers save it unchanged

Signing out calls DELETE /v1/device, which removes this device's peer.

Contract: dev-docs/plans/vpn-provisioning-api.md.
"""

from __future__ import annotations

import os
import platform
import socket
from typing import Callable, Optional, Tuple

from utils.logger import logger

API_URL = "https://api.phoenix.exposed"
_TIMEOUT = 20
# The server-issued config uses the config manager's built-in name, so the
# VPN screen shows it as "Phoenix (Default)".
CONFIG_NAME = "resistine"


class ProvisioningError(Exception):
    """VPN provisioning failed. ``str(e)`` is safe to show to the user."""


def api_url() -> str:
    """Base URL of the provisioning API (PHOENIX_API_URL overrides it)."""
    return (os.environ.get("PHOENIX_API_URL") or API_URL).rstrip("/")


def _vpn_backend():
    system = platform.system()
    if system == "Linux":
        from plugins.vpn.wireguard import vpn_functions_linux as backend
    elif system == "Darwin":
        from plugins.vpn.wireguard import vpn_functions_darwin as backend
    elif system == "Windows":
        from plugins.vpn.wireguard import vpn_functions_windows as backend
    else:
        raise ProvisioningError(f"VPN is not supported on {system}.")
    return backend


def _authorized_request(method: str, path: str, **kwargs):
    """Call the API with the MAS token; refresh once on 401."""
    from plugins.login import oidc

    try:
        token = oidc.refresh()
    except oidc.OIDCError as e:
        raise ProvisioningError(f"Couldn't reach the sign-in server: {e}") from e
    if not token:
        raise ProvisioningError("You're not signed in to Phoenix. Sign in again.")

    http = oidc._session()
    url = f"{api_url()}{path}"
    extra_headers = kwargs.pop("headers", None) or {}
    for attempt in (1, 2):
        try:
            r = http.request(method, url, timeout=_TIMEOUT, verify=True,
                             headers={**extra_headers, "Authorization": f"Bearer {token}"}, **kwargs)
        except Exception as e:  # noqa: BLE001
            raise ProvisioningError(
                f"Couldn't reach the Phoenix service ({api_url()}). "
                "Check your internet connection and try again.") from e
        if r.status_code == 401 and attempt == 1:
            token = oidc.refresh(force=True)
            if not token:
                raise ProvisioningError("Your Phoenix session ended. Sign in again.")
            continue
        return r
    return r


def _error_detail(r) -> str:
    try:
        body = r.json()
        detail = body.get("detail") or body.get("error") or ""
        if isinstance(detail, str) and detail:
            return detail[:200]
    except Exception:  # noqa: BLE001
        pass
    return f"HTTP {r.status_code}"


def _check_config(cfg) -> dict:
    """Reject a response that isn't a WireGuard config before writing it.

    Field-level validation (no newlines, valid keys/IPs/endpoint) happens in
    the platform writer; this only checks the shape.
    """
    if not isinstance(cfg, dict):
        raise ProvisioningError("The Phoenix service sent an invalid VPN config.")
    iface, peer = cfg.get("Interface"), cfg.get("Peer")
    if not isinstance(iface, dict) or not isinstance(peer, dict):
        raise ProvisioningError("The Phoenix service sent an invalid VPN config.")
    for section, keys in ((iface, ("Address",)), (peer, ("PublicKey", "Endpoint", "AllowedIPs"))):
        missing = [k for k in keys if not section.get(k)]
        if missing:
            raise ProvisioningError(
                f"The Phoenix VPN config is missing {', '.join(missing)}.")
    return cfg


def request_peer(public_key: str, hostname: Optional[str] = None) -> dict:
    """Ask the API for this device's peer; return the WireGuard config dict."""
    r = _authorized_request("POST", "/v1/vpn/peer", json={
        "public_key": public_key,
        "hostname": hostname or socket.gethostname(),
    })
    if r.status_code == 403:
        raise ProvisioningError(
            "Your Phoenix account doesn't include VPN access. "
            f"({_error_detail(r)})")
    if not r.ok:
        raise ProvisioningError(f"Couldn't get a VPN config: {_error_detail(r)}")
    try:
        return _check_config(r.json())
    except ValueError as e:
        raise ProvisioningError("The Phoenix service sent an invalid VPN config.") from e


def ensure_vpn_config(on_status: Optional[Callable[[str], None]] = None,
                      force: bool = False) -> Tuple[str, str]:
    """Make sure this device has a Phoenix VPN config; return (name, path).

    Reuses the existing config unless ``force``. Otherwise generates a fresh
    keypair, has the API register it and saves the returned config as the
    active one. Raises ProvisioningError with a user-facing message.
    """
    from plugins.vpn.main import _config_manager

    if not force:
        path = _config_manager.get_active_config_path()
        if (_config_manager.get_active_config_name() == CONFIG_NAME
                and path and os.path.exists(path)):
            return CONFIG_NAME, path

    backend = _vpn_backend()
    unavailable = getattr(backend, "vpn_unavailable_reason", None)
    reason = unavailable() if unavailable else None
    if isinstance(reason, str) and reason:  # before registering a key the device couldn't use
        raise ProvisioningError(reason)
    if on_status:
        on_status("Creating your VPN keys…")
    public_key = backend.setup_vpn_keys()
    if not public_key:
        raise ProvisioningError("Couldn't create VPN keys on this device.")

    if on_status:
        on_status("Getting your VPN configuration…")
    cfg = request_peer(public_key)

    path = backend.save_vpn_configuration(cfg, CONFIG_NAME)
    if not path:
        raise ProvisioningError(
            "The VPN config from the Phoenix service was rejected as invalid.")
    _config_manager.register_config(CONFIG_NAME, source="phoenix")
    _config_manager.set_active_config(CONFIG_NAME)
    logger.info(f"[VPN-PROV] VPN config for this device saved ({cfg['Interface'].get('Address')})")
    return CONFIG_NAME, path


def release_device() -> bool:
    """Tell the API this device signed out (removes its VPN peer). Best effort."""
    try:
        r = _authorized_request("DELETE", "/v1/device")
    except ProvisioningError as e:
        logger.warning(f"[VPN-PROV] could not release device: {e}")
        return False
    if r.ok or r.status_code == 404:
        logger.info("[VPN-PROV] device released")
        return True
    logger.warning(f"[VPN-PROV] release failed: {_error_detail(r)}")
    return False
