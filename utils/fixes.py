"""Fixes: the things Phoenix can put right on this machine, one at a time.

"Fix all" is not a new kind of repair. It is a queue of repairs that
already exist as plugin actions (start the Endpoint agent, re-enrol it,
update the antivirus signatures, connect the VPN, remove this machine's
earlier installs), each run by its own plugin, through its own function
and its own elevation. Nothing here builds a command; a fix has no
arguments, only an id from a closed set that its plugin resolves.

Rules the runner keeps:

* only fixes whose target is this machine run (``gate``): a fix from a
  fleet view about another host is dropped, never attempted;
* fixes run one after another, each as a job (utils/jobs.py); a failure
  does not stop the independent ones, and a fix whose prerequisite
  failed is skipped as "needs you";
* an admin prompt happens inside the fix's own function, once per fix,
  except where the platform's elevation helper caches it by itself.

No Qt in here.
"""

from __future__ import annotations

import socket
from dataclasses import dataclass, field
from typing import Callable, Iterable, Optional

from utils import jobs
from utils.logger import logger

TO_RUN, RUNNING, DONE, FAILED, SKIPPED = "to_run", "running", "done", "failed", "skipped"


@dataclass(frozen=True)
class Fix:
    id: str                 # one of the plugin's closed set of fix ids
    plugin: str             # the plugin that runs it (get_name())
    title: str              # "Start the Endpoint agent"
    why: str                # what is wrong now: "The agent is installed but stopped"
    host: str = ""          # the machine it is about (socket.gethostname() for a local fix)
    needs_admin: bool = False
    after: tuple = field(default_factory=tuple)   # fix ids that must have succeeded first
    undo: Optional[dict] = None                   # utils/jobs.py undo declaration

    @property
    def key(self) -> str:
        return f"{self.plugin}:{self.id}"


def this_host() -> str:
    return socket.gethostname()


def gate(items: Iterable[Fix], local_names: Iterable[str]) -> list:
    """The fixes that are about this machine. A fix with no host, or a
    host that is not one of this machine's names, is dropped and logged:
    the runner never tries a repair on another device."""
    names = {str(n).lower() for n in local_names if n}
    out = []
    for f in items:
        if not isinstance(f, Fix):
            continue
        if f.host and f.host.lower() in names:
            out.append(f)
        else:
            logger.info(f"[FIXES] {f.key} is about {f.host or 'no host'}: not this machine, skipped")
    return out


def plan(items: Iterable[Fix]) -> list:
    """Run order: dependencies first, otherwise the order given; a fix
    whose prerequisite is not in the set keeps its place (the runner then
    treats the missing prerequisite as not failed)."""
    uniq: dict = {}
    for f in items:
        uniq.setdefault(f.key, f)
    items = list(uniq.values())
    keys = set(uniq)
    ids = {f.id: f for f in items}
    out, seen = [], set()

    def visit(f: Fix, trail: tuple) -> None:
        if f.key in seen:
            return
        for dep in f.after:
            d = ids.get(dep)
            if d is not None and d.key not in trail and d.key in keys:
                visit(d, trail + (f.key,))
        seen.add(f.key)
        out.append(f)

    for f in items:
        visit(f, ())
    return out


def admin_prompts(items: Iterable[Fix]) -> int:
    return sum(1 for f in items if f.needs_admin)


def run(items: Iterable[Fix], run_one: Callable[[Fix], tuple],
        on_state: Optional[Callable[[Fix, str, str], None]] = None) -> dict:
    """Run the fixes in plan() order on the calling thread (a worker).

    ``run_one(fix)`` is the plugin's blocking ``run_fix``: (ok, summary).
    ``on_state(fix, state, text)`` is told about every change. Returns
    {fix.key: (state, text)}. Each fix is a job with a code."""
    results: dict = {}
    failed_ids: set = set()

    def tell(f: Fix, state: str, text: str) -> None:
        results[f.key] = (state, text)
        if on_state is not None:
            try:
                on_state(f, state, text)
            except Exception as e:  # noqa: BLE001
                logger.debug(f"[FIXES] on_state failed: {e}")

    for f in plan(items):
        blocked = [d for d in f.after if d in failed_ids]
        if blocked:
            tell(f, SKIPPED, "needs you: " + ", ".join(blocked) + " did not succeed")
            continue
        tell(f, RUNNING, "")
        job = jobs.start("fix", f.title, f.plugin, undo=f.undo)
        try:
            ok, summary = run_one(f)
        except Exception as e:  # noqa: BLE001
            ok, summary = False, f"{type(e).__name__}: {e}"
        summary = str(summary or "")
        jobs.finish(job["code"], ok=bool(ok), summary=summary)
        if ok:
            tell(f, DONE, summary or "done")
        else:
            failed_ids.add(f.id)
            tell(f, FAILED, summary or "failed")
    return results
