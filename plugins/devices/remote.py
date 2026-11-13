"""Background loader and cache for the Devices page's remote data.

One slot per dataset (vulnerability summary, per-device CVEs, detection
events, inventory summary, per-device inventory, SCA, hotfixes). Each slot
remembers its data, its last error and whether it has completed at least
once, so the tabs paint whatever is known and never block the UI thread.

Loads run on daemon threads, at most one per slot at a time; listeners are
told on the worker thread and must hop to the UI thread themselves
(the plugin does ``app.after(0, ...)``). A slot whose endpoint answers 404
is marked unavailable: the API does not provide it yet, and the tab says so
instead of retrying every few seconds.
"""

from __future__ import annotations

import threading
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed

from plugins.devices import api
from utils.logger import logger

EVENTS_WINDOW_HOURS = (
    168  # vuln-detection events are sparse; a week keeps the stream populated
)
SLOTS = ("vulns_summary", "vulns", "events", "inventory", "agents", "sca", "hotfixes")


class Slot:
    def __init__(self, empty):
        self.data = empty
        self.error = None
        self.ready = False
        self.loading = False
        self.loaded_at = 0.0

    @property
    def unavailable(self) -> bool:
        return self.error == api.NOT_AVAILABLE

    def set(self, data, error, now: float):
        if data is not None:
            self.data = data
        self.error = error
        self.ready = True
        self.loading = False
        self.loaded_at = now


class RemoteStore:
    """All remote slots for the account, shared by the plugin's tabs."""

    def __init__(self, clock=None):
        import time

        self._clock = clock or time.time
        self._lock = threading.Lock()
        self._listeners: list[Callable[[str], None]] = []
        self.slots = {
            "vulns_summary": Slot(None),
            "vulns": Slot([]),
            "events": Slot([]),
            "inventory": Slot([]),
            "agents": Slot([]),
            "sca": Slot([]),
            "hotfixes": Slot([]),
        }

    # ---- listeners ----------------------------------------------------------
    def subscribe(self, fn: Callable[[str], None]) -> None:
        with self._lock:
            if fn not in self._listeners:
                self._listeners.append(fn)

    def unsubscribe(self, fn: Callable[[str], None]) -> None:
        with self._lock:
            if fn in self._listeners:
                self._listeners.remove(fn)

    def _notify(self, slot: str) -> None:
        with self._lock:
            listeners = list(self._listeners)
        for fn in listeners:
            try:
                fn(slot)
            except Exception as e:  # noqa: BLE001 - one listener must not stop the rest
                logger.debug(f"[DEVICES] listener failed: {e}")

    # ---- state ----------------------------------------------------------------
    def slot(self, name: str) -> Slot:
        return self.slots[name]

    def api_unavailable(self) -> bool:
        """True once every completed slot says the endpoint is not deployed."""
        done = [s for s in self.slots.values() if s.ready]
        return bool(done) and all(s.unavailable for s in done)

    def _start(self, name: str) -> bool:
        with self._lock:
            s = self.slots[name]
            if s.loading:
                return False
            s.loading = True
            return True

    def _finish(self, name: str, data, error) -> None:
        with self._lock:
            self.slots[name].set(data, error, self._clock())
        if error and error != api.NOT_AVAILABLE:
            logger.warning(f"[DEVICES] {name}: {error}")
        self._notify(name)

    def _thread(self, name: str, target) -> None:
        if not self._start(name):
            return
        threading.Thread(target=target, name=f"devices-{name}", daemon=True).start()

    # ---- loaders --------------------------------------------------------------
    def kick_summary(self) -> None:
        """The cheap group-level datasets: vulnerability totals, SCA, hotfixes."""

        def summary():
            self._finish("vulns_summary", *api.fetch_vulnerabilities_summary())

        def sca():
            self._finish("sca", *api.fetch_sca())

        def hotfixes():
            self._finish("hotfixes", *api.fetch_hotfixes())

        self._thread("vulns_summary", summary)
        self._thread("sca", sca)
        self._thread("hotfixes", hotfixes)

    def kick_vulns(self, devices: list) -> None:
        """Every device's CVE list (``devices``: [{agent_id, agent_name}])."""

        def work():
            self._finish("vulns", *api.fetch_all_vulnerabilities(devices))

        self._thread("vulns", work)

    def kick_events(self, devices: list, hours: int = EVENTS_WINDOW_HOURS) -> None:
        """Detection events for every device, merged newest first."""

        def work():
            ids = [
                (str(d["agent_id"]), str(d.get("agent_name") or ""))
                for d in devices or []
                if d.get("agent_id")
            ]
            if not ids:
                self._finish("events", [], None)
                return
            merged, errors = [], []
            with ThreadPoolExecutor(
                max_workers=min(len(ids), api.MAX_PARALLEL_FETCHES)
            ) as ex:
                futs = {
                    ex.submit(
                        api.fetch_device_vulnerability_events, aid, name, hours=hours
                    ): aid
                    for aid, name in ids
                }
                for fut in as_completed(futs):
                    events, err = fut.result()
                    if err:
                        errors.append(err)
                        continue
                    merged.extend(events or [])
            merged.sort(key=lambda e: e.get("timestamp") or "", reverse=True)
            if errors and len(errors) == len(ids):
                err = (
                    api.NOT_AVAILABLE
                    if all(e == api.NOT_AVAILABLE for e in errors)
                    else errors[0]
                )
                self._finish("events", None, err)
            else:
                self._finish("events", merged, None)

        self._thread("events", work)

    def kick_inventory(self, fallback_devices: list) -> None:
        """Device summaries, then each device's detail, shaped for the
        Inventory tab (plugins.devices.tables.shape_inventory_agent)."""
        from plugins.devices import tables

        # What the posture cards already know about each agent (hostname, OS):
        # today's inventory endpoint lists agents as {id, name, status, ip}
        # only, so a device that arrives without a name or OS takes them from
        # here rather than showing "(unknown)" and "—".
        known = {
            str(d.get("agent_id")): d
            for d in fallback_devices or []
            if isinstance(d, dict) and d.get("agent_id")
        }

        def fill_from_posture(d: dict) -> dict:
            from plugins.devices.data import is_placeholder

            p = known.get(str(d.get("agent_id") or ""))
            if not p:
                return d
            # A posture "Unknown" is no name/OS at all: never copy it over.
            if not d.get("agent_name") and not is_placeholder(p.get("agent_name")):
                d = {**d, "agent_name": p["agent_name"]}
            if not isinstance(d.get("os"), dict) and not is_placeholder(p.get("os")):
                d = {**d, "os": {"name": p["os"], "version": ""}}
            return d

        def work():
            devices, err = api.fetch_inventory_full()
            if err:
                self._finish("inventory", None, err)
                self._finish("agents", None, err)
                return
            devices = [fill_from_posture(d) for d in devices]
            self._finish("inventory", devices, None)
            ided = [(str(d.get("agent_id")), d) for d in devices if d.get("agent_id")]
            details = {}
            if ided:
                with ThreadPoolExecutor(
                    max_workers=min(len(ided), api.MAX_PARALLEL_FETCHES)
                ) as ex:
                    futs = {
                        ex.submit(api.fetch_device_inventory, aid): aid
                        for aid, _ in ided
                    }
                    for fut in as_completed(futs):
                        detail, derr = fut.result()
                        if derr == api.NOT_AVAILABLE:
                            # Per-device detail is not deployed yet: expected,
                            # once per agent per refresh, so not a warning.
                            logger.debug(
                                f"[DEVICES] inventory detail for agent {futs[fut]} not available"
                            )
                        elif derr:
                            logger.warning(
                                f"[DEVICES] inventory for agent {futs[fut]}: {derr}"
                            )
                        details[futs[fut]] = detail
            agents = [
                tables.shape_inventory_agent(d, details.get(aid)) for aid, d in ided
            ]
            agents += [
                tables.shape_inventory_agent(d, None)
                for d in devices
                if not d.get("agent_id")
            ]
            self._finish("agents", agents, None)

        self._start("inventory")  # mark both busy under one thread
        if not self._start("agents"):
            with self._lock:
                self.slots["inventory"].loading = False
            return
        threading.Thread(target=work, name="devices-inventory", daemon=True).start()

    def refresh(self, devices: list) -> None:
        """Re-fetch every slot (a slot already loading keeps its run)."""
        self.kick_summary()
        self.kick_vulns(devices)
        self.kick_events(devices)
        self.kick_inventory(devices)


_store: RemoteStore | None = None
_store_lock = threading.Lock()


def store() -> RemoteStore:
    global _store
    with _store_lock:
        if _store is None:
            _store = RemoteStore()
        return _store
