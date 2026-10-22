# -*- coding: utf-8 -*-
# @file plugins/login/oidc.py
# @namespace plugins.login.oidc
# Description: Sign-in with the Phoenix Matrix account (Matrix Authentication
# Service, OIDC). Discovery, client registration, auth code + PKCE over a
# loopback redirect (RFC 8252), device code fallback, refresh and revoke.
# Licensed under the GNU General Public License v2 or later
"""Phoenix account sign-in against MAS (auth.phoenix.exposed).

The desktop is a public OAuth client. Its client_id comes from dynamic
client registration (MSC2966) and is cached per issuer in the ``oidc``
settings namespace, which survives logout; a pre-registered static client
can be forced with ``oidc.static_client_id``.

The session (tokens, user id, email) lives in the ``auth`` namespace, tokens
encrypted with ``set_secret``. Logout clears that namespace.
"""

from __future__ import annotations

import base64
import hashlib
import html
import http.server
import platform
import secrets
import threading
import time
import urllib.parse
import webbrowser
from dataclasses import dataclass
from typing import Callable, Optional

import requests

from utils import http_trace, settings
from utils.logger import logger

HOMESERVER_URL = "https://matrix.phoenix.exposed"
CLIENT_NAME = "Phoenix Desktop"
CLIENT_URI = "https://phoenix.exposed/"
DEVICE_CODE_GRANT = "urn:ietf:params:oauth:grant-type:device_code"

_AUTH_NS = "auth"      # per-session, wiped on logout
_OIDC_NS = "oidc"      # per-install (client registration, device id)
_TIMEOUT = 15
_LOGIN_TIMEOUT = 300   # seconds the browser flow may take


class OIDCError(Exception):
    """Sign-in failed. ``str(e)`` is safe to show to the user."""


class Cancelled(OIDCError):
    pass


def _user_agent() -> str:
    try:
        from utils.updates.version import get_build, get_current_version
        ver = get_current_version()
        build = get_build()
        if build:
            ver += f"+{build}"
    except Exception:
        ver = "dev"
    return f"Phoenix-Desktop/{ver} ({platform.system()})"


def _session() -> requests.Session:
    # Cloudflare's Browser Integrity Check rejects the default python UA.
    s = requests.Session()
    s.headers["User-Agent"] = _user_agent()
    s.headers["Accept"] = "application/json"
    return s


def homeserver_url() -> str:
    return (settings.get(_OIDC_NS, "homeserver_url") or HOMESERVER_URL).rstrip("/")


# --------------------------------------------------------------------------
# Discovery + registration
# --------------------------------------------------------------------------

def discover(http: Optional[requests.Session] = None) -> dict:
    """Return the auth server metadata the homeserver delegates to."""
    http = http or _session()
    hs = homeserver_url()
    try:
        r = http.get(f"{hs}/_matrix/client/v1/auth_metadata", timeout=_TIMEOUT)
        if r.ok:
            return r.json()
        # Older homeservers: MSC2965 unstable endpoint -> issuer discovery.
        r = http.get(
            f"{hs}/_matrix/client/unstable/org.matrix.msc2965/auth_issuer",
            timeout=_TIMEOUT)
        r.raise_for_status()
        issuer = r.json()["issuer"].rstrip("/")
        r = http.get(f"{issuer}/.well-known/openid-configuration", timeout=_TIMEOUT)
        r.raise_for_status()
        return r.json()
    except (requests.RequestException, ValueError, KeyError) as e:
        raise OIDCError(f"Could not reach the Phoenix sign-in server ({hs}): {e}") from e


def _client_key(meta: dict) -> str:
    return "client_id:" + meta["issuer"]


def get_client_id(meta: dict, http: Optional[requests.Session] = None) -> str:
    """Return the client_id for this install, registering one if needed."""
    static = settings.get(_OIDC_NS, "static_client_id")
    if static:
        return static
    cached = settings.get(_OIDC_NS, _client_key(meta))
    if cached:
        return cached
    endpoint = meta.get("registration_endpoint")
    if not endpoint:
        raise OIDCError("The sign-in server does not allow client registration "
                        "and no static client is configured.")
    http = http or _session()
    body = {
        "client_name": CLIENT_NAME,
        "client_uri": CLIENT_URI,
        "application_type": "native",
        # Loopback redirect: MAS ignores the port for loopback URIs (RFC 8252
        # section 7.3), so the ephemeral port chosen per login still matches.
        "redirect_uris": ["http://127.0.0.1/callback"],
        "grant_types": ["authorization_code", "refresh_token", DEVICE_CODE_GRANT],
        "response_types": ["code"],
        "token_endpoint_auth_method": "none",
    }
    try:
        r = http.post(endpoint, json=body, timeout=_TIMEOUT)
    except requests.RequestException as e:
        raise OIDCError(f"Client registration failed: {e}") from e
    if not r.ok:
        raise OIDCError(f"Client registration was refused ({r.status_code}): "
                        f"{_error_text(r)}")
    client_id = r.json()["client_id"]
    settings.set(_OIDC_NS, _client_key(meta), client_id)
    logger.info(f"[OIDC] registered client {client_id} at {meta['issuer']}")
    return client_id


# --------------------------------------------------------------------------
# Device identity (one Matrix device per install)
# --------------------------------------------------------------------------

def get_device_id() -> str:
    """Matrix device ID for this install: ``PHX_`` + 16 random base32 chars.

    Random, generated once and kept in the config dir next to matrix-store.
    It used to be a hash of the hardware ID, which made a reinstall or a
    wiped config sign in as the SAME device with NEW encryption keys. Other
    clients then fail on that device: messages to it could not be decrypted
    (seen live 2026-10-12 with PHX_NBZK6DHPKKUEAQLA). A fresh install now
    gets a fresh device; the old one is a stale session to remove in
    Element → Sessions.
    """
    cached = settings.get(_OIDC_NS, "device_id")
    if cached:
        return cached
    device_id = "PHX_" + base64.b32encode(secrets.token_bytes(10)).decode().rstrip("=")[:16]
    settings.set(_OIDC_NS, "device_id", device_id)
    return device_id


def _scope(device_id: str) -> str:
    return " ".join([
        "openid",
        "email",
        "urn:matrix:client:api:*",
        f"urn:matrix:client:device:{device_id}",
    ])


# --------------------------------------------------------------------------
# Tokens
# --------------------------------------------------------------------------

@dataclass
class Tokens:
    access_token: str
    refresh_token: Optional[str]
    expires_at: Optional[float]
    scope: str = ""

    @classmethod
    def from_response(cls, data: dict) -> "Tokens":
        expires_in = data.get("expires_in")
        return cls(
            access_token=data["access_token"],
            refresh_token=data.get("refresh_token"),
            expires_at=time.time() + float(expires_in) if expires_in else None,
            scope=data.get("scope", ""),
        )


def _error_text(r: requests.Response) -> str:
    try:
        data = r.json()
        return data.get("error_description") or data.get("error") or r.text[:200]
    except ValueError:
        return r.text[:200]


def _token_request(meta: dict, form: dict,
                   http: Optional[requests.Session] = None) -> requests.Response:
    http = http or _session()
    try:
        return http.post(meta["token_endpoint"], data=form, timeout=_TIMEOUT)
    except requests.RequestException as e:
        raise OIDCError(f"Token request failed: {e}") from e


# --------------------------------------------------------------------------
# Auth code + PKCE over a loopback redirect
# --------------------------------------------------------------------------

_DONE_PAGE = """<!doctype html><html><head><meta charset="utf-8">
<title>Phoenix</title><style>body{{font-family:system-ui,sans-serif;
background:#0A1A33;color:#fff;display:flex;align-items:center;
justify-content:center;height:100vh;margin:0}}div{{text-align:center}}
h1{{color:#5AC8FA}}</style></head><body><div><h1>{title}</h1>
<p>{text}</p></div></body></html>"""


class _CallbackServer(http.server.HTTPServer):
    result: Optional[dict] = None
    done: threading.Event


class _CallbackHandler(http.server.BaseHTTPRequestHandler):
    server: _CallbackServer

    def do_GET(self):  # noqa: N802 - http.server API
        url = urllib.parse.urlsplit(self.path)
        if url.path != "/callback":
            self.send_error(404)
            return
        params = dict(urllib.parse.parse_qsl(url.query))
        http_trace.event("browser -> app: loopback redirect GET /callback", params)
        if self.server.result is None:
            self.server.result = params
        ok = "code" in params
        page = _DONE_PAGE.format(
            title="Signed in" if ok else "Sign-in failed",
            text=("You can close this tab and return to Phoenix." if ok else
                  html.escape(params.get("error_description")
                              or params.get("error", "Unknown error"))))
        body = page.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
        self.server.done.set()

    def log_message(self, format, *args):  # noqa: A002 - keep codes out of the log
        pass


def login_browser(cancel: Optional[threading.Event] = None,
                  open_url: Callable[[str], object] = webbrowser.open) -> Tokens:
    """Open the system browser on the MAS login page and wait for the result."""
    cancel = cancel or threading.Event()
    http = _session()
    meta = discover(http)
    client_id = get_client_id(meta, http)
    device_id = get_device_id()

    server = _CallbackServer(("127.0.0.1", 0), _CallbackHandler)
    server.done = threading.Event()
    redirect_uri = f"http://127.0.0.1:{server.server_address[1]}/callback"
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        verifier = secrets.token_urlsafe(64)
        challenge = base64.urlsafe_b64encode(
            hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
        state = secrets.token_urlsafe(24)
        url = meta["authorization_endpoint"] + "?" + urllib.parse.urlencode({
            "response_type": "code",
            "response_mode": "query",
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "scope": _scope(device_id),
            "state": state,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        })
        logger.info(f"[OIDC] opening browser for sign-in (device {device_id})")
        http_trace.event("app -> system browser: open authorization URL",
                         {"url": url.split("?")[0],
                          **dict(urllib.parse.parse_qsl(url.split("?", 1)[1]))})
        open_url(url)

        deadline = time.monotonic() + _LOGIN_TIMEOUT
        while not server.done.wait(0.25):
            if cancel.is_set():
                raise Cancelled("Sign-in cancelled.")
            if time.monotonic() > deadline:
                raise OIDCError("Sign-in timed out. Please try again.")
        params = server.result or {}
    finally:
        server.shutdown()
        server.server_close()

    if params.get("state") != state:
        raise OIDCError("Sign-in response did not match the request (state).")
    if "error" in params:
        raise OIDCError(params.get("error_description") or params["error"])
    r = _token_request(meta, {
        "grant_type": "authorization_code",
        "code": params.get("code", ""),
        "redirect_uri": redirect_uri,
        "client_id": client_id,
        "code_verifier": verifier,
    }, http)
    if not r.ok:
        raise OIDCError(f"Sign-in failed: {_error_text(r)}")
    return Tokens.from_response(r.json())


# --------------------------------------------------------------------------
# Device code grant (RFC 8628)
# --------------------------------------------------------------------------

@dataclass
class DeviceCode:
    user_code: str
    verification_uri: str
    verification_uri_complete: Optional[str]
    expires_in: int


def login_device_code(on_code: Callable[[DeviceCode], None],
                      cancel: Optional[threading.Event] = None) -> Tokens:
    """Show a code (``on_code``) the user enters on any device, then poll."""
    cancel = cancel or threading.Event()
    http = _session()
    meta = discover(http)
    endpoint = meta.get("device_authorization_endpoint")
    if not endpoint:
        raise OIDCError("The sign-in server does not support sign-in with a code.")
    client_id = get_client_id(meta, http)
    try:
        r = http.post(endpoint, data={
            "client_id": client_id, "scope": _scope(get_device_id())},
            timeout=_TIMEOUT)
    except requests.RequestException as e:
        raise OIDCError(f"Could not start sign-in: {e}") from e
    if not r.ok:
        raise OIDCError(f"Could not start sign-in: {_error_text(r)}")
    data = r.json()
    on_code(DeviceCode(
        user_code=data["user_code"],
        verification_uri=data["verification_uri"],
        verification_uri_complete=data.get("verification_uri_complete"),
        expires_in=int(data.get("expires_in", 600)),
    ))

    interval = float(data.get("interval", 5))
    deadline = time.monotonic() + int(data.get("expires_in", 600))
    while time.monotonic() < deadline:
        if cancel.wait(interval):
            raise Cancelled("Sign-in cancelled.")
        r = _token_request(meta, {
            "grant_type": DEVICE_CODE_GRANT,
            "device_code": data["device_code"],
            "client_id": client_id,
        }, http)
        if r.ok:
            return Tokens.from_response(r.json())
        try:
            err = r.json().get("error")
        except ValueError:
            err = None
        if err == "authorization_pending":
            continue
        if err == "slow_down":
            interval += 5
            continue
        raise OIDCError(f"Sign-in failed: {_error_text(r)}")
    raise OIDCError("The sign-in code expired. Please try again.")


# --------------------------------------------------------------------------
# Session (stored in the auth namespace)
# --------------------------------------------------------------------------

def _whoami(access_token: str, http: requests.Session) -> dict:
    r = http.get(f"{homeserver_url()}/_matrix/client/v3/account/whoami",
                 headers={"Authorization": f"Bearer {access_token}"},
                 timeout=_TIMEOUT)
    if not r.ok:
        raise OIDCError(f"Could not read the account ({r.status_code}): "
                        f"{_error_text(r)}")
    return r.json()


def _userinfo(meta: dict, access_token: str, http: requests.Session) -> dict:
    endpoint = meta.get("userinfo_endpoint")
    if not endpoint:
        return {}
    try:
        r = http.get(endpoint, headers={"Authorization": f"Bearer {access_token}"},
                     timeout=_TIMEOUT)
        return r.json() if r.ok else {}
    except (requests.RequestException, ValueError):
        return {}


def _store_tokens(tokens: Tokens) -> None:
    settings.set_secret(_AUTH_NS, "access_token", tokens.access_token)
    if tokens.refresh_token:
        settings.set_secret(_AUTH_NS, "refresh_token", tokens.refresh_token)
    settings.set(_AUTH_NS, "expires_at", tokens.expires_at)


def complete_login(tokens: Tokens) -> dict:
    """Resolve the account behind ``tokens`` and persist the session.

    Returns ``{"user_id", "device_id", "email"}``. ``auth.email`` keeps
    feeding the Wazuh group name (``user-example.com``) until enrollment
    moves to api.phoenix.exposed; it is only set when MAS knows an email.
    """
    http = _session()
    meta = discover(http)
    who = _whoami(tokens.access_token, http)
    info = _userinfo(meta, tokens.access_token, http)
    email = info.get("email") or None
    _store_tokens(tokens)
    settings.set(_AUTH_NS, "method", "mas")
    settings.set(_AUTH_NS, "issuer", meta["issuer"])
    settings.set(_AUTH_NS, "user_id", who.get("user_id"))
    settings.set(_AUTH_NS, "device_id", who.get("device_id") or get_device_id())
    if email:
        settings.set(_AUTH_NS, "email", email)
    http_trace.event("session stored in settings namespace 'auth'",
                     {k: settings.get(_AUTH_NS, k) for k in
                      ("method", "issuer", "user_id", "device_id", "email",
                       "access_token", "refresh_token", "expires_at")})
    logger.info(f"[OIDC] signed in as {who.get('user_id')} "
                f"(device {who.get('device_id')}, email {'set' if email else 'none'})")
    return {"user_id": who.get("user_id"), "device_id": who.get("device_id"),
            "email": email}


def refresh(force: bool = False) -> Optional[str]:
    """Return a valid access token, refreshing it when it is (nearly) expired.

    Returns None when there is no session or the server rejected the refresh
    token (session ended elsewhere). Raises OIDCError on network problems,
    so callers can tell "offline" from "signed out".
    """
    access = settings.get_secret(_AUTH_NS, "access_token")
    if not access:
        return None
    expires_at = settings.get(_AUTH_NS, "expires_at")
    if not force and (not expires_at or expires_at - time.time() > 60):
        return access
    refresh_token = settings.get_secret(_AUTH_NS, "refresh_token")
    if not refresh_token:
        return None
    http = _session()
    meta = discover(http)
    r = _token_request(meta, {
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
        "client_id": get_client_id(meta, http),
    }, http)
    if r.ok:
        tokens = Tokens.from_response(r.json())
        if not tokens.refresh_token:
            tokens.refresh_token = refresh_token
        _store_tokens(tokens)
        return tokens.access_token
    if r.status_code in (400, 401):
        logger.info(f"[OIDC] refresh rejected: {_error_text(r)}")
        return None
    raise OIDCError(f"Token refresh failed ({r.status_code}): {_error_text(r)}")


def has_session() -> bool:
    return settings.get(_AUTH_NS, "method") == "mas" and bool(
        settings.get(_AUTH_NS, "access_token"))


def validate_session() -> bool:
    """Startup check. False only when the server says the session is gone;
    offline (network error) keeps the user signed in."""
    if not has_session():
        return True  # nothing to validate (legacy or skipped login)
    try:
        return refresh() is not None
    except OIDCError as e:
        logger.warning(f"[OIDC] could not validate session, assuming offline: {e}")
        return True


def revoke() -> None:
    """End the session at MAS (best effort, used on logout)."""
    if not has_session():
        return
    try:
        http = _session()
        meta = discover(http)
        endpoint = meta.get("revocation_endpoint")
        if not endpoint:
            return
        client_id = get_client_id(meta, http)
        # Revoking the refresh token ends the whole MAS session.
        for kind in ("refresh_token", "access_token"):
            token = settings.get_secret(_AUTH_NS, kind)
            if token:
                http.post(endpoint, data={"token": token, "client_id": client_id,
                                          "token_type_hint": kind},
                          timeout=_TIMEOUT)
                break
        logger.info("[OIDC] session revoked")
    except Exception as e:  # noqa: BLE001
        logger.warning(f"[OIDC] revoke failed: {e}")


def account_url() -> str:
    try:
        return discover().get("account_management_uri") or "https://auth.phoenix.exposed/account/"
    except OIDCError:
        return "https://auth.phoenix.exposed/account/"
