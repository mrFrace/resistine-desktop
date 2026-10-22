# -*- coding: utf-8 -*-
# @file utils/http_trace.py
# @namespace utils.http_trace
# Description: Opt-in trace of every HTTP exchange and privileged step, with
# secrets masked, for following sign-in and first-run setup end to end.
# Licensed under the GNU General Public License v2 or later
"""Wire trace for debugging the sign-in and setup flow.

Off unless the app starts with ``--trace`` (or ``PHOENIX_TRACE=1``). It then
wraps ``requests.Session.send``, which every call in the app goes through
(``requests.post`` too), and writes each request and response to
``<config dir>/logs/trace-<time>.log``. Non-HTTP steps (the browser redirect,
root scripts) are added with ``event()``.

The trace never goes through the logger: the logger can ship records to
telemetry, and this file holds payloads. Tokens, codes and keys are masked to
a short prefix and their length; JWTs are decoded (header and claims) with
the signature dropped. Public keys, user IDs and addresses stay readable.
"""

from __future__ import annotations

import base64
import json
import os
import re
import threading
import time
import urllib.parse
from typing import Any, Optional

_lock = threading.Lock()
_path: Optional[str] = None
_seq = 0
_t0 = time.monotonic()

_MAX_BODY = 64 * 1024

# Field names whose values are secrets (case-insensitive, exact match).
_SECRET_KEYS = {
    "access_token", "refresh_token", "id_token", "token", "code",
    "code_verifier", "device_code", "client_secret", "password", "otp",
    "privatekey", "private_key", "key", "presharedkey", "secret", "state",
    "user_code",
}
_JWT_RE = re.compile(r"^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$")
# Bearer tokens, MAS tokens and query-string secrets inside free text.
_TEXT_PATTERNS = [
    (re.compile(r"\b(ma[trc]_[A-Za-z0-9_]{6})[A-Za-z0-9_]+"), r"\1…"),
    (re.compile(r"(?i)\b(code|state|access_token|refresh_token|code_verifier"
                r"|device_code)=([^&\s\"']{4})[^&\s\"']*"), r"\1=\2…"),
]
_SHOW_HEADERS = {
    "content-type", "content-length", "location", "www-authenticate",
    "cache-control", "user-agent", "accept", "authorization", "cookie",
    "set-cookie", "x-request-id", "cf-ray", "server",
}


def enabled() -> bool:
    return _path is not None


def enable(log_dir: str) -> str:
    """Start tracing to a new file in ``log_dir``; return its path."""
    global _path
    if _path:
        return _path
    os.makedirs(log_dir, exist_ok=True)
    _path = os.path.join(log_dir, time.strftime("trace-%Y%m%d-%H%M%S.log"))
    fd = os.open(_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    os.close(fd)
    _patch_requests()
    _write("TRACE START", f"pid {os.getpid()}  file {_path}")
    return _path


# --------------------------------------------------------------------------
# Masking
# --------------------------------------------------------------------------

def mask(value: Any) -> str:
    s = str(value)
    if len(s) <= 6:
        return f"<{len(s)} chars>"
    return f"{s[:6]}…<{len(s)} chars>"


def _b64json(part: str) -> Any:
    try:
        return json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))
    except (ValueError, TypeError):
        return None


def _jwt(value: str) -> Any:
    header, claims, _sig = value.split(".")
    h, c = _b64json(header), _b64json(claims)
    if not isinstance(h, dict) or not isinstance(c, dict):
        return None
    for k in ("iat", "exp", "nbf", "auth_time"):
        if isinstance(c.get(k), (int, float)):
            c[k] = f"{c[k]} ({time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(c[k]))})"
    return {"JWT header": h, "JWT claims": c, "signature": "<dropped>"}


def _wazuh_key(value: str) -> Any:
    """client.keys line (base64 in the enroll answer): keep id/name/ip."""
    try:
        line = base64.b64decode(value, validate=True).decode("ascii").strip()
        parts = line.split(" ")
        if len(parts) == 4:
            return (f"base64 of client.keys line: '{parts[0]} {parts[1]} {parts[2]} "
                    f"{mask(parts[3])}'")
    except (ValueError, UnicodeDecodeError):
        pass
    return mask(value)


def scrub(obj: Any, key: str = "") -> Any:
    """Copy of ``obj`` with secret values masked."""
    if isinstance(obj, dict):
        return {k: scrub(v, str(k)) for k, v in obj.items()}
    if isinstance(obj, list):
        return [scrub(v, key) for v in obj]
    if isinstance(obj, str):
        low = key.lower()
        if _JWT_RE.match(obj) and len(obj) > 40:
            decoded = _jwt(obj)
            if decoded is not None:
                return decoded
        if low == "key":
            return _wazuh_key(obj)
        if low in _SECRET_KEYS:
            return mask(obj)
        return scrub_text(obj)
    return obj


def scrub_text(text: str) -> str:
    for pattern, repl in _TEXT_PATTERNS:
        text = pattern.sub(repl, text)
    return text


def _scrub_url(url: str) -> str:
    parts = urllib.parse.urlsplit(url)
    if not parts.query:
        return url
    q = urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
    return urllib.parse.urlunsplit(parts._replace(query="")) + "?\n" + "\n".join(
        f"      {k} = {scrub(v, k)}" for k, v in q)


def _headers(h) -> str:
    lines = []
    for k, v in h.items():
        if k.lower() not in _SHOW_HEADERS:
            continue
        if k.lower() == "authorization":
            scheme, _, cred = str(v).partition(" ")
            v = f"{scheme} {mask(cred)}"
        elif k.lower() in ("cookie", "set-cookie"):
            v = mask(v)
        lines.append(f"    {k}: {v}")
    return "\n".join(lines)


def _body(raw: Any, content_type: str) -> str:
    if raw is None or raw == b"" or raw == "":
        return "    (empty)"
    if isinstance(raw, bytes):
        if len(raw) > _MAX_BODY:
            return f"    <{len(raw)} bytes, not shown>"
        try:
            raw = raw.decode("utf-8")
        except UnicodeDecodeError:
            return f"    <{len(raw)} bytes binary>"
    if not isinstance(raw, str):
        return f"    <{type(raw).__name__} body>"
    ct = (content_type or "").lower()
    try:
        data = json.loads(raw)
        return _indent(json.dumps(scrub(data), indent=2, ensure_ascii=False))
    except ValueError:
        pass
    if "x-www-form-urlencoded" in ct or ("=" in raw and "\n" not in raw and " " not in raw):
        form = urllib.parse.parse_qsl(raw, keep_blank_values=True)
        if form:
            return _indent(json.dumps({k: scrub(v, k) for k, v in form},
                                      indent=2, ensure_ascii=False)) + "\n    (form-encoded)"
    return _indent(scrub_text(raw[:4000]) + ("…" if len(raw) > 4000 else ""))


def _indent(text: str, pad: str = "    ") -> str:
    return "\n".join(pad + line for line in text.splitlines())


# --------------------------------------------------------------------------
# Output
# --------------------------------------------------------------------------

def _write(title: str, text: str = "") -> int:
    global _seq
    if not _path:
        return 0
    with _lock:
        _seq += 1
        n = _seq
        stamp = time.strftime("%H:%M:%S") + f" +{time.monotonic() - _t0:7.2f}s"
        block = f"\n#{n:03d} {stamp} [{threading.current_thread().name}] {title}\n"
        if text:
            block += text.rstrip() + "\n"
        with open(_path, "a", encoding="utf-8") as f:
            f.write(block)
    return n


def event(title: str, detail: Any = None) -> None:
    """Record a non-HTTP step; dicts/lists are scrubbed and pretty-printed."""
    if not _path:
        return
    if detail is None:
        text = ""
    elif isinstance(detail, (dict, list)):
        text = _indent(json.dumps(scrub(detail), indent=2, ensure_ascii=False, default=str))
    else:
        text = _indent(scrub_text(str(detail)))
    _write("EVENT " + title, text)


# --------------------------------------------------------------------------
# requests hook
# --------------------------------------------------------------------------

def _patch_requests() -> None:
    import requests

    original = requests.Session.send

    def send(self, request, **kwargs):
        ct = request.headers.get("Content-Type", "")
        n = _write(f">>> {request.method} {_scrub_url(request.url)}",
                   _headers(request.headers) + "\n  body:\n" + _body(request.body, ct))
        start = time.monotonic()
        try:
            response = original(self, request, **kwargs)
        except Exception as e:
            _write(f"<<< #{n:03d} FAILED {type(e).__name__}: {scrub_text(str(e))}")
            raise
        ms = (time.monotonic() - start) * 1000
        rct = response.headers.get("Content-Type", "")
        if kwargs.get("stream"):
            body = (f"    <streamed: {response.headers.get('Content-Length', '?')} "
                    f"bytes {rct}>")
        else:
            body = _body(response.content, rct)
        _write(f"<<< #{n:03d} HTTP {response.status_code} {response.reason} "
               f"({ms:.0f} ms) {request.method} {response.url.split('?')[0]}",
               _headers(response.headers) + "\n  body:\n" + body)
        return response

    requests.Session.send = send
