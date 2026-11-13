"""Jobs: the app's long actions, each with a short code.

A scan, an agent install, a VPN connect, an update check: each gets a code
like ``PX-4K7Q`` when it starts and a one-line summary when it ends. The
codes are what the user can point at later: Settings → Diagnostics lists
the recent jobs, and a code typed into the chat attaches that job's local
details to the question (plugins/chat/main.py), and only then.

The list lives in ``<config dir>/jobs.json`` (owner-only), last 50. It is
local data: nothing here is sent anywhere unless the user asks the AI
about a code. Summaries are the app's own words plus an error text, kept
printable and short. No Qt in here.
"""

from __future__ import annotations

import json
import os
import re
import secrets
import threading
import time
from typing import Callable, Optional

from utils import settings
from utils.logger import logger

ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"  # no I, O, 0, 1
CODE_RE = re.compile(r"\bPX-([A-Z2-9]{4})\b")
MAX_JOBS = 50
RUNNING, DONE, FAILED = "running", "done", "failed"
_SUMMARY_MAX = 300

_lock = threading.Lock()
_jobs: Optional[list] = None
_listeners: list[Callable[[dict], None]] = []


def _path() -> str:
    return os.path.join(settings.get_config_dir(), "jobs.json")


def _plain(text, limit: int = _SUMMARY_MAX) -> str:
    s = "".join(ch if ch.isprintable() else " " for ch in str(text or ""))
    s = " ".join(s.split())
    return s if len(s) <= limit else s[:limit - 1] + "…"


def _load_locked() -> list:
    global _jobs
    if _jobs is not None:
        return _jobs
    try:
        with open(_path(), encoding="utf-8") as fh:
            data = json.load(fh)
        _jobs = [j for j in data.get("jobs", []) if isinstance(j, dict) and j.get("code")]
    except FileNotFoundError:
        _jobs = []
    except Exception as e:  # noqa: BLE001 - a bad file must not break the app
        logger.warning(f"[JOBS] store unreadable ({e}); starting empty")
        _jobs = []
    # A job still "running" from a previous start never ended.
    for j in _jobs:
        if j.get("status") == RUNNING:
            j["status"], j["ended_at"], j["summary"] = FAILED, j.get("started_at"), "The app closed before it finished."
    return _jobs


def _save_locked() -> None:
    tmp = f"{_path()}.tmp"
    try:
        if os.path.lexists(tmp):
            os.remove(tmp)
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump({"jobs": _jobs}, fh)
        os.replace(tmp, _path())
    except Exception as e:  # noqa: BLE001
        logger.warning(f"[JOBS] store not saved: {e}")


def new_code(taken=()) -> str:
    taken = set(taken)
    while True:
        code = "PX-" + "".join(secrets.choice(ALPHABET) for _ in range(4))
        if code not in taken:
            return code


def start(kind: str, title: str, detail: str = "") -> dict:
    """Register a job that just started; returns it (its "code" is the handle)."""
    with _lock:
        jobs = _load_locked()
        job = {"code": new_code(j["code"] for j in jobs), "kind": _plain(kind, 40),
               "title": _plain(title, 80), "detail": _plain(detail, 120),
               "status": RUNNING, "started_at": time.time(), "ended_at": None, "summary": ""}
        jobs.append(job)
        del jobs[:-MAX_JOBS]
        _save_locked()
    _notify(dict(job))
    return job


def finish(code: str, ok: bool = True, summary: str = "") -> Optional[dict]:
    """Record how the job ended. Unknown codes are ignored."""
    with _lock:
        job = next((j for j in _load_locked() if j["code"] == code), None)
        if job is None:
            return None
        job["status"] = DONE if ok else FAILED
        job["ended_at"] = time.time()
        job["summary"] = _plain(summary)
        _save_locked()
        out = dict(job)
    _notify(out)
    return out


def find(code: str) -> Optional[dict]:
    with _lock:
        job = next((j for j in _load_locked() if j["code"] == code), None)
        return dict(job) if job else None


def recent(limit: int = 20) -> list:
    """Newest first."""
    with _lock:
        return [dict(j) for j in reversed(_load_locked()[-limit:])]


def codes_in(text: str) -> list:
    """The job codes mentioned in *text*, in order, once each."""
    return list(dict.fromkeys("PX-" + m for m in CODE_RE.findall(text or "")))


def _ago(seconds: float) -> str:
    seconds = max(0, int(seconds))
    if seconds < 60:
        return "just now"
    if seconds < 3600:
        return f"{seconds // 60} min ago"
    if seconds < 86400:
        return f"{seconds // 3600} h ago"
    return f"{seconds // 86400} d ago"


def _state(job: dict, now: float) -> str:
    if job["status"] == RUNNING:
        return f"running since {_ago(now - job['started_at'])}".replace("since just now", "just now")
    when = _ago(now - (job.get("ended_at") or job["started_at"]))
    return f"{'finished' if job['status'] == DONE else 'failed'} {when}"


def describe(job: dict, now: Optional[float] = None) -> str:
    """"Antivirus scan (files) · finished 3 min ago · 0 threats in 1,234 files"."""
    now = now or time.time()
    head = job["title"] + (f" ({job['detail']})" if job.get("detail") else "")
    parts = [head, _state(job, now)]
    if job.get("summary"):
        parts.append(job["summary"])
    return " · ".join(parts)


def context_for(codes, now: Optional[float] = None) -> str:
    """What the chat prepends when the user asks about a code: the local
    details of each known code, one line per job. Unknown codes are named
    as unknown, so the model doesn't invent them."""
    lines = []
    for code in codes:
        job = find(code)
        if job is None:
            lines.append(f"[Phoenix job {code}: no such job on this machine]")
        else:
            lines.append(f"[Phoenix job {code}: {describe(job, now)}]")
    return "\n".join(lines)


def subscribe(fn: Callable[[dict], None]) -> None:
    with _lock:
        if fn not in _listeners:
            _listeners.append(fn)


def unsubscribe(fn: Callable[[dict], None]) -> None:
    with _lock:
        if fn in _listeners:
            _listeners.remove(fn)


def _notify(job: dict) -> None:
    with _lock:
        fns = list(_listeners)
    for fn in fns:
        try:
            fn(job)
        except Exception as e:  # noqa: BLE001
            logger.warning(f"[JOBS] listener failed: {e}")


def _reset_for_tests() -> None:
    global _jobs
    with _lock:
        _jobs = None
        _listeners.clear()
