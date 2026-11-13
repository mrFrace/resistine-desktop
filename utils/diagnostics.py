"""Diagnostics: what the app knows about itself, as redacted text.

Settings → Diagnostics shows versions, the plugins' states and the recent
jobs (utils/jobs.py), and "Copy diagnostics" puts a report on the
clipboard: those facts plus the tail of the log. The clipboard is the
risk, not the page, so everything in the report goes through redact():
the masks of utils/http_trace.py (tokens, codes) plus the key shapes the
log could carry (WireGuard keys, a Matrix recovery key, the agent key,
"PrivateKey = …" lines, bearer headers, encrypted settings values).
Nothing is read from the secret store; redaction is the second line.

No Qt in here.
"""

from __future__ import annotations

import os
import platform
import re
import sys
import time
from typing import Optional

from utils import http_trace, jobs, settings

LOG_TAIL_LINES = 80
_MAX_LINE = 400

# Order matters: named values first (keeps the label), then bare key shapes.
_PATTERNS = [
    # "PrivateKey = abc…", "password: x", "Authorization: Bearer …", "api_key=…":
    # the rest of the line goes (a JSON line may hold several values).
    (re.compile(r"(?i)\b(private[ _-]?key|preshared[ _-]?key|recovery[ _-]?key|agent[ _-]?key"
                r"|api[ _-]?key|client[ _-]?secret|secret|password|passwd|passphrase|otp"
                r"|access[ _-]?token|refresh[ _-]?token|id[ _-]?token|token|authorization)"
                r"\b[\"']?\s*[:=].*$"), r"\1 = [redacted]"),
    (re.compile(r"(?i)\bbearer\s+\S+"), "Bearer [redacted]"),
    (re.compile(r"\bENC:\S+"), "ENC:[redacted]"),
    # A Matrix recovery key: 12 groups of 4 base58 characters.
    (re.compile(r"\b(?:[A-Za-z0-9]{4} ){11}[A-Za-z0-9]{4}\b"), "[recovery key]"),
    # A WireGuard key (32 bytes, base64).
    (re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=(?![A-Za-z0-9+/=])"), "[key]"),
    # Anything else that looks like a long opaque blob (JWTs, agent keys).
    (re.compile(r"(?<![A-Za-z0-9+/=_.-])[A-Za-z0-9+/=_.-]{60,}(?![A-Za-z0-9+/=_.-])"), "[blob]"),
]


def redact(text: str) -> str:
    out = []
    for line in str(text or "").splitlines():
        line = "".join(ch for ch in line if ch.isprintable() or ch == "\t")
        for pattern, repl in _PATTERNS:
            line = pattern.sub(repl, line)
        line = http_trace.scrub_text(line)
        out.append(line if len(line) <= _MAX_LINE else line[:_MAX_LINE - 1] + "…")
    return "\n".join(out)


def app_version() -> str:
    try:
        from utils.updates.version import get_display_version
        return str(get_display_version() or "unknown")
    except Exception:  # noqa: BLE001
        return "unknown"


def facts() -> list:
    """(label, value) rows: what the app is and where it runs."""
    rows = [("Phoenix Desktop", app_version()),
            ("System", f"{platform.system()} {platform.release()} ({platform.machine()})"),
            ("Python", platform.python_version() + (" (frozen)" if getattr(sys, "frozen", False) else "")),
            ("Config", settings.get_config_dir())]
    user = settings.get("auth", "user_id")
    rows.append(("Account", user or ("signed in" if settings.get("auth", "logged_in") else "not signed in")))
    transport = settings.get("chat", "transport") or "default"
    rows.append(("Chat transport", str(transport)))
    return rows


def services(statuses: Optional[dict]) -> list:
    """(plugin, state, reason) rows from the shell's cached statuses
    ({name: Status}); "—" when a plugin has not been read yet."""
    out = []
    for name, st in (statuses or {}).items():
        kind = getattr(st, "kind", None)
        if kind == "off":
            continue
        out.append((str(name), str(kind or "—"), str(getattr(st, "reason", "") or "")))
    return out


def events(limit: int = 12, now: Optional[float] = None) -> list:
    """(code, text) for the recent jobs, newest first."""
    return [(j["code"], jobs.describe(j, now)) for j in jobs.recent(limit)]


def log_path() -> str:
    return os.path.join(settings.get_config_dir(), "logs", "phoenix.log")


def log_tail(lines: int = LOG_TAIL_LINES) -> list:
    try:
        with open(log_path(), "rb") as fh:
            fh.seek(0, os.SEEK_END)
            size = fh.tell()
            fh.seek(max(0, size - 256 * 1024))
            data = fh.read().decode("utf-8", "replace")
    except OSError:
        return []
    return data.splitlines()[-lines:]


def report(statuses: Optional[dict] = None, now: Optional[float] = None) -> str:
    """The whole thing as text, redacted."""
    now = now or time.time()
    lines = ["Phoenix Desktop diagnostics", time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(now)), ""]
    lines += [f"{k}: {v}" for k, v in facts()]
    svc = services(statuses)
    if svc:
        lines += ["", "Services"] + [f"  {n}: {k}" + (f" — {r}" if r else "") for n, k, r in svc]
    ev = events(now=now)
    if ev:
        lines += ["", "Recent jobs"] + [f"  {c}  {t}" for c, t in ev]
    tail = log_tail()
    if tail:
        lines += ["", f"Log (last {len(tail)} lines of {os.path.basename(log_path())})"] + [f"  {ln}" for ln in tail]
    return redact("\n".join(lines))
