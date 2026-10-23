"""Living mitigations: the posture card's structured to-do items, checked on
this machine.

Each item from the server (LLMAgent-api, phoenix.posture.v1 "mitigations")
names what to fix, the evidence, and a condition from a closed vocabulary:

  package_version_changed  the vulnerable package version is no longer
                           installed (upgraded or removed)
  service_running          the Endpoint agent service runs
  server                   only the next daily scan can tell

The app checks what it can locally and shows each item as to fix, fixed
here (the next scan confirms it and the item disappears), can't check here,
or decided by the next scan. The server is never trusted to run anything:
items are re-validated here against the same strict shapes, unknown kinds
and checks are dropped, and probes are fixed argv lists (no shell) with the
package name as one validated argument. Nothing is ever fixed automatically.

No Qt in here; check() runs on a worker thread.
"""

from __future__ import annotations

import os
import platform
import re
import shutil
import subprocess  # nosec B404 - fixed argv, no shell
import threading
import time
from typing import Optional

from utils.logger import logger

PACKAGE_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9.+_~:-]{0,127}")
VERSION_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9.+_~:-]{0,63}")
CVE_RE = re.compile(r"(CVE|GHSA|RHSA|USN|DSA)-[A-Za-z0-9-]{1,40}")
_KINDS = {"package_update", "agent_connection", "cis_checks"}
_SEVERITIES = {"critical", "high", "medium", "low"}
_MAX_ITEMS = 10
PROBE_TIMEOUT_S = 5
RECHECK_AFTER_S = 300

# Item states
OPEN, FIXED_HERE, UNKNOWN, SERVER, REMOTE = "open", "fixed_here", "unknown", "server", "remote"

_results: dict = {}   # item id -> (state, checked_at)
_lock = threading.Lock()


# --------------------------------------------------------------------------
# Validation (the server's output is untrusted input here)
# --------------------------------------------------------------------------

def _int(v) -> int:
    try:
        return max(0, int(v))
    except (TypeError, ValueError):
        return 0


def _plain(v, limit: int) -> str:
    s = "".join(ch if ch.isprintable() else " " for ch in str(v or ""))
    return " ".join(s.split())[:limit]


def validate(raw) -> Optional[dict]:
    """A clean item, or None when anything about it is unexpected."""
    if not isinstance(raw, dict):
        return None
    item_id, kind, sev = raw.get("id"), raw.get("kind"), raw.get("severity")
    check = raw.get("check") if isinstance(raw.get("check"), dict) else {}
    if not (isinstance(item_id, str) and re.fullmatch(r"[0-9a-f]{16}", item_id)
            and kind in _KINDS and sev in _SEVERITIES):
        return None
    ctype = check.get("type")
    if ctype == "package_version_changed":
        pkg, ver = check.get("package"), check.get("version")
        if not (isinstance(pkg, str) and PACKAGE_RE.fullmatch(pkg)
                and isinstance(ver, str) and VERSION_RE.fullmatch(ver)):
            return None
        ptype = check.get("package_type") if check.get("package_type") in ("deb", "rpm") else ""
        check = {"type": ctype, "package": pkg, "version": ver, "package_type": ptype}
    elif ctype == "service_running" and check.get("service") == "endpoint_agent":
        check = {"type": ctype, "service": "endpoint_agent"}
    elif ctype == "server":
        check = {"type": "server"}
    else:
        return None
    ev = raw.get("evidence") if isinstance(raw.get("evidence"), dict) else {}
    fixed = ev.get("fixed_version")
    evidence = {
        "critical": _int(ev.get("critical")), "high": _int(ev.get("high")),
        "cves": [c for c in (ev.get("cves") or [])[:5] if isinstance(c, str) and CVE_RE.fullmatch(c)],
        "fixed_version": fixed if isinstance(fixed, str) and VERSION_RE.fullmatch(fixed) else None,
        "fix_available": bool(ev.get("fix_available", True)),
        "failed_checks": _int(ev.get("failed_checks")), "checks": _int(ev.get("checks")),
    }
    return {"id": item_id, "kind": kind, "severity": sev, "title": _plain(raw.get("title"), 120),
            "evidence": evidence, "check": check}


def items_of(card: dict) -> list:
    raw = card.get("mitigations") if isinstance(card, dict) else None
    if not isinstance(raw, list):
        return []
    return [i for i in map(validate, raw[:_MAX_ITEMS]) if i]


# --------------------------------------------------------------------------
# Probes (closed set, fixed argv)
# --------------------------------------------------------------------------

def _run(argv: list) -> Optional[subprocess.CompletedProcess]:
    try:
        return subprocess.run(  # nosec B603 - absolute path from shutil.which, validated args, no shell
            argv, capture_output=True, text=True, timeout=PROBE_TIMEOUT_S,
            env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LC_ALL": "C"})
    except (OSError, subprocess.SubprocessError) as e:
        logger.debug(f"[MITIGATIONS] probe {argv[0]} failed: {e}")
        return None


def _strip_epoch0(v: str) -> str:
    return v[2:] if v.startswith("0:") else v


def _package_state(pkg: str, version: str, ptype: str) -> str:
    """OPEN while the vulnerable version is installed; FIXED_HERE once it isn't."""
    if platform.system() != "Linux" or ptype not in ("deb", "rpm"):
        return UNKNOWN
    if ptype == "deb":
        exe = shutil.which("dpkg-query")
        if not exe:
            return UNKNOWN
        r = _run([exe, "-W", "-f=${db:Status-Abbrev}|${Version}\n", pkg])
        if r is None:
            return UNKNOWN
        if r.returncode == 1 and "no packages found" in (r.stderr or "").lower():
            return FIXED_HERE  # removed
        if r.returncode != 0:
            return UNKNOWN
        installed = [line.split("|", 1)[1].strip() for line in r.stdout.splitlines()
                     if "|" in line and line.startswith("ii")]
    else:
        exe = shutil.which("rpm")
        if not exe:
            return UNKNOWN
        r = _run([exe, "-q", "--qf", "%{EPOCHNUM}:%{VERSION}-%{RELEASE}\n", pkg])
        if r is None:
            return UNKNOWN
        if r.returncode == 1 and "is not installed" in (r.stdout + r.stderr):
            return FIXED_HERE
        if r.returncode != 0:
            return UNKNOWN
        installed = [line.strip() for line in r.stdout.splitlines() if line.strip()]
    if not installed:
        return FIXED_HERE
    vulnerable = _strip_epoch0(version)
    return OPEN if any(_strip_epoch0(v) == vulnerable for v in installed) else FIXED_HERE


def _service_state() -> str:
    try:
        from plugins.wazuh.main import is_agent_running
        return FIXED_HERE if is_agent_running() else OPEN
    except Exception:  # noqa: BLE001
        return UNKNOWN


def _probe(item: dict) -> str:
    c = item["check"]
    if c["type"] == "package_version_changed":
        return _package_state(c["package"], c["version"], c["package_type"])
    if c["type"] == "service_running":
        return _service_state()
    return SERVER


# --------------------------------------------------------------------------
# Reconcile
# --------------------------------------------------------------------------

def check(card: dict, this_machine: bool, force: bool = False) -> list:
    """[(item, state)] for a card; probes only this machine's items, at most
    every RECHECK_AFTER_S per item unless forced."""
    out = []
    now = time.time()
    for item in items_of(card):
        if not this_machine:
            out.append((item, REMOTE))
            continue
        with _lock:
            cached = _results.get(item["id"])
        if cached and not force and now - cached[1] < RECHECK_AFTER_S:
            state = cached[0]
        else:
            state = _probe(item)
            with _lock:
                _results[item["id"]] = (state, now)
        out.append((item, state))
    return out


def cached(card: dict, this_machine: bool) -> list:
    """Like check() but never probes (for painting on the UI thread)."""
    out = []
    for item in items_of(card):
        if not this_machine:
            out.append((item, REMOTE))
        elif item["check"]["type"] == "server":
            out.append((item, SERVER))  # nothing to probe
        else:
            with _lock:
                hit = _results.get(item["id"])
            out.append((item, hit[0] if hit else None))
    return out


def summary(states: list) -> str:
    """'3 to fix · 1 fixed here' for the panel's row."""
    n_open = sum(1 for _, s in states if s == OPEN)
    n_fixed = sum(1 for _, s in states if s == FIXED_HERE)
    n_other = len(states) - n_open - n_fixed
    parts = []
    if n_open:
        parts.append(f"{n_open} to fix")
    if n_fixed:
        parts.append(f"{n_fixed} fixed here")
    if n_other:
        parts.append(f"{n_other} to review")
    return " · ".join(parts) or "Nothing to do"


def detail_line(item: dict) -> str:
    """Evidence as one plain line for the detail view."""
    ev, c = item["evidence"], item["check"]
    if item["kind"] == "package_update":
        bits = []
        if ev["critical"]:
            bits.append(f"{ev['critical']} critical")
        if ev["high"]:
            bits.append(f"{ev['high']} high")
        if ev["cves"]:
            bits.append(", ".join(ev["cves"][:3]) + ("…" if len(ev["cves"]) > 3 else ""))
        installed = f"installed {c['version']}"
        if ev["fixed_version"]:
            installed += f", fixed in {ev['fixed_version']}"
        elif not ev["fix_available"]:
            installed += ", no fix released yet"
        bits.append(installed)
        return " · ".join(bits)
    if item["kind"] == "cis_checks":
        return f"{ev['failed_checks']} of {ev['checks']} checks fail. The next daily scan re-checks them."
    if item["kind"] == "agent_connection":
        return "The Endpoint agent is not reporting to the Phoenix server."
    return ""


# --------------------------------------------------------------------------
# Detail view text and the "Ask AI" question
# --------------------------------------------------------------------------

_STATE_TEXT = {
    OPEN: "The vulnerable version is still installed here.",
    FIXED_HERE: "Fixed on this machine. The next daily scan confirms it and the item disappears.",
    UNKNOWN: "Phoenix can't check this item on this machine.",
    SERVER: "Only the next daily scan can tell whether this is fixed.",
    REMOTE: "Fix this on that machine; its next daily scan confirms it.",
    None: "Checking…",
}


def state_text(state) -> str:
    return _STATE_TEXT.get(state, _STATE_TEXT[None])


_DEB_KERNEL = re.compile(r"linux-(?:image(?:-unsigned)?|modules(?:-extra)?)-\d[A-Za-z0-9.+_~-]*")
_RPM_KERNEL = {"kernel", "kernel-core", "kernel-modules", "kernel-modules-core",
               "kernel-modules-extra", "kernel-default", "kernel-uek"}


def _is_kernel(c: dict) -> bool:
    return bool(_DEB_KERNEL.fullmatch(c.get("package", ""))) or c.get("package") in _RPM_KERNEL


def fix_steps(item: dict) -> list:
    """How to fix an item, as short plain lines (never run by Phoenix)."""
    c, ev = item["check"], item["evidence"]
    if item["kind"] == "package_update":
        pkg = c["package"]
        if ev["fix_available"] is False and not ev["fixed_version"]:
            steps = [f"No fixed version of {pkg} is released yet. Remove it if you don't need it, "
                     "or limit what can reach it until a fix ships."]
        elif c["package_type"] == "deb":
            steps = [f"sudo apt update && sudo apt install --only-upgrade {pkg}"]
        elif c["package_type"] == "rpm":
            steps = [f"sudo dnf upgrade {pkg}"]
        else:
            steps = [f"Update {pkg} where it was installed from: the system's software updater, "
                     "or the tool that installed it (pip, npm, a container image…)."]
        if _is_kernel(c):
            steps.append("Restart the machine afterwards to run the new kernel.")
        return steps
    if item["kind"] == "cis_checks":
        return ["Ask Phoenix AI which checks fail and how to fix each one on this machine.",
                "The next daily scan re-checks them."]
    if item["kind"] == "agent_connection":
        return ["Open Endpoint and check that the agent runs and is connected."]
    return []


def question(item: dict, hostname: str, this_machine: bool) -> str:
    """The "Ask AI" message for one item."""
    c, ev = item["check"], item["evidence"]
    where = "this machine" if this_machine else "my machine"
    host = f" ({hostname})" if hostname else ""
    if item["kind"] == "package_update":
        facts = [f"package {c['package']}, installed version {c['version']}"]
        if c["package_type"]:
            facts.append(f"{c['package_type']} package")
        if ev["fixed_version"]:
            facts.append(f"fixed in {ev['fixed_version']}")
        if ev["critical"] or ev["high"]:
            facts.append(f"{ev['critical']} critical and {ev['high']} high vulnerabilities")
        if ev["cves"]:
            facts.append("including " + ", ".join(ev["cves"]))
        return (f"The security posture of {where}{host} says: {item['title']} "
                f"({'; '.join(facts)}). How serious is this, and how do I fix it safely?")
    if item["kind"] == "cis_checks":
        return (f"{where[0].upper() + where[1:]}{host} fails {ev['failed_checks']} of "
                f"{ev['checks']} CIS/SCA checks. Which checks fail, which matter most, "
                "and how do I fix them? Skip checks that don't apply to this kind of machine.")
    return f"The security posture of {where}{host} says: {item['title']}. What should I do?"
