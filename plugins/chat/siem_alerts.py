"""SIEM alerts from siemgent, delivered to this user over Matrix.

siemgent (nest-agent) sends each alert about a machine to the Matrix user who
owns that machine: ``@siem-bot`` creates an encrypted DM ("SIEM <box> — <user>"),
invites the user and posts that machine's alerts there. This module is the
app's side of that contract, kept free of Qt and nio so it is unit-testable:

  * which invites to accept — ONLY those sent by the alerts bot
    (``alerts_bot()``); any other invite is left alone, exactly like the chat
    transport never touches the user's other rooms;
  * which rooms are alert rooms (persisted, so the sync filter can include
    them from the first sync);
  * a small local store of received alerts (deduplicated by event id —
    every start re-syncs the rooms' recent timeline) and the listeners the
    chat UI subscribes with.

Listeners are called on the Matrix thread; the UI marshals to the Qt thread.
"""

from __future__ import annotations

import json
import os
import threading
import time
from typing import Callable, Optional

from utils import settings
from utils.logger import logger

ALERTS_BOT_DEFAULT = "@siem-bot:phoenix.exposed"
_NS = "chat"
MAX_ALERTS = 200
UNDECRYPTABLE = "🔒 This alert could not be decrypted on this device."


def alerts_bot() -> str:
    return settings.get(_NS, "alerts_bot") or ALERTS_BOT_DEFAULT


def is_alert_invite(invite_state: list, user_id: str, bot: str) -> bool:
    """True iff *invite_state* is an invite of *user_id* sent by *bot*."""
    for ev in invite_state or ():
        if (isinstance(ev, dict) and ev.get("type") == "m.room.member"
                and ev.get("state_key") == user_id
                and (ev.get("content") or {}).get("membership") == "invite"):
            return ev.get("sender") == bot
    return False


def alert_rooms() -> list[str]:
    rooms = settings.get(_NS, "alert_rooms") or []
    return [r for r in rooms if isinstance(r, str) and r]


def add_alert_room(room_id: str) -> None:
    rooms = alert_rooms()
    if room_id not in rooms:
        settings.set(_NS, "alert_rooms", rooms + [room_id])


class AlertStore:
    """Received alerts, newest last, persisted as JSON in the config dir."""

    def __init__(self, path: Optional[str] = None) -> None:
        self.path = path or os.path.join(settings.get_config_dir(), "siem_alerts.json")
        self._lock = threading.Lock()
        self._alerts: list[dict] = []
        self._unread = 0
        self._load()

    def _load(self) -> None:
        try:
            with open(self.path, encoding="utf-8") as fh:
                data = json.load(fh)
            self._alerts = [a for a in data.get("alerts", []) if isinstance(a, dict)]
            self._unread = int(data.get("unread", 0))
        except FileNotFoundError:
            pass
        except Exception as e:  # noqa: BLE001 — a bad file must not break chat
            logger.warning(f"[SIEM-ALERTS] store unreadable ({e}); starting empty")

    def _save(self) -> None:
        tmp = f"{self.path}.tmp"
        try:
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump({"alerts": self._alerts, "unread": self._unread}, fh)
            os.replace(tmp, self.path)
        except Exception as e:  # noqa: BLE001
            logger.warning(f"[SIEM-ALERTS] store not saved: {e}")

    def add(self, alert: dict) -> bool:
        """Store *alert*; False if its event id is already known."""
        with self._lock:
            eid = alert.get("event_id")
            if eid and any(a.get("event_id") == eid for a in self._alerts):
                return False
            self._alerts.append(alert)
            self._alerts = self._alerts[-MAX_ALERTS:]
            self._unread += 1
            self._save()
            return True

    def all(self) -> list[dict]:
        with self._lock:
            return list(self._alerts)

    @property
    def unread(self) -> int:
        return self._unread

    def mark_read(self) -> None:
        with self._lock:
            if self._unread:
                self._unread = 0
                self._save()


_store: Optional[AlertStore] = None
_listeners: list[Callable[[dict], None]] = []
_mod_lock = threading.Lock()


def store() -> AlertStore:
    global _store
    with _mod_lock:
        if _store is None:
            _store = AlertStore()
        return _store


def subscribe(fn: Callable[[dict], None]) -> None:
    with _mod_lock:
        if fn not in _listeners:
            _listeners.append(fn)


def unsubscribe(fn: Callable[[dict], None]) -> None:
    with _mod_lock:
        if fn in _listeners:
            _listeners.remove(fn)


def publish(room_id: str, event_id: str, body: str, ts_ms: Optional[int] = None) -> bool:
    """Record one alert and notify listeners. False if it was already known."""
    alert = {"room_id": room_id, "event_id": event_id, "body": body or "",
             "ts": (ts_ms / 1000.0) if ts_ms else time.time()}
    if not store().add(alert):
        return False
    with _mod_lock:
        listeners = list(_listeners)
    for fn in listeners:
        try:
            fn(alert)
        except Exception as e:  # noqa: BLE001 — one bad listener must not stop the rest
            logger.warning(f"[SIEM-ALERTS] listener failed: {e}")
    return True
