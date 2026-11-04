"""SIEM alerts from siemgent, delivered to this user over Matrix.

siemgent (nest-agent) sends each alert about a machine to the Matrix user who
owns that machine: ``@siem-bot`` creates an encrypted DM ("SIEM <box> — <user>"),
invites the user and posts that machine's alerts there. This module is the
app's side of that contract, kept free of Qt and nio so it is unit-testable:

  * which invites to accept — ONLY those sent by the alerts bot
    (``alerts_bot()``); any other invite is left alone, exactly like the chat
    transport never touches the user's other rooms;
  * which rooms are alert rooms (persisted, so the sync filter can include
    them from the first sync), including ones the user already joined in
    another client (``is_alert_room``);
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


def _localpart(user_id: str) -> str:
    return (user_id or "").lstrip("@").split(":", 1)[0].lower()


def is_alert_room(state_events: list, bot: str, user_id: str) -> bool:
    """True iff a room the user has ALREADY joined is THEIR alerts DM:
    created by *bot*, end-to-end encrypted, and named by *bot* for this user
    ("SIEM <box> — <localpart>"). Covers rooms joined in another client
    (Element), whose invite this app never saw; a room's creator is as
    trustworthy as an invite's sender (both are set by the homeserver).

    The name matters because a member can invite others into their own
    alerts DM: those others then share the room, but it is not theirs, and
    the alerts in it are about someone else's machines. Only the bot can
    set the name (members lack the power level)."""
    created_by = encrypted = named_for = None
    for ev in state_events or ():
        if not isinstance(ev, dict) or ev.get("state_key") != "":
            continue
        if ev.get("type") == "m.room.create":
            created_by = ev.get("sender")
        elif ev.get("type") == "m.room.encryption":
            encrypted = (ev.get("content") or {}).get("algorithm") == "m.megolm.v1.aes-sha2"
        elif ev.get("type") == "m.room.name" and ev.get("sender") == bot:
            name = str((ev.get("content") or {}).get("name") or "")
            named_for = name.rpartition("—")[2].strip().lower() if "—" in name else None
    return (bool(bot) and created_by == bot and bool(encrypted)
            and bool(_localpart(user_id)) and named_for == _localpart(user_id))


def add_alert_room(room_id: str, since: Optional[float] = None) -> None:
    """Remember *room_id* as an alerts room. *since* is when this device
    started listening there: alerts sent before it were never encrypted for
    this device, so they stay unreadable here (see alert_room_since)."""
    rooms = alert_rooms()
    if room_id not in rooms:
        settings.set(_NS, "alert_rooms", rooms + [room_id])
    if since is not None:
        sinces = settings.get(_NS, "alert_rooms_since") or {}
        if room_id not in sinces:
            settings.set(_NS, "alert_rooms_since", {**sinces, room_id: float(since)})


def forget_alert_room(room_id: str) -> None:
    """Stop treating *room_id* as an alerts room and delete its stored alerts
    (it was not, or is no longer, this user's)."""
    rooms = alert_rooms()
    if room_id in rooms:
        settings.set(_NS, "alert_rooms", [r for r in rooms if r != room_id])
    sinces = settings.get(_NS, "alert_rooms_since") or {}
    if room_id in sinces:
        settings.set(_NS, "alert_rooms_since", {k: v for k, v in sinces.items() if k != room_id})
    store().drop_room(room_id)


def alert_room_since(room_id: str) -> Optional[float]:
    v = (settings.get(_NS, "alert_rooms_since") or {}).get(room_id)
    return float(v) if isinstance(v, (int, float)) else None


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
        # Decrypted alerts name hosts, users and file paths: owner-only (0600),
        # created that way so there is no world-readable window.
        tmp = f"{self.path}.tmp"
        try:
            if os.path.lexists(tmp):
                os.remove(tmp)  # never follow a stale or planted temp file
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump({"alerts": self._alerts, "unread": self._unread}, fh)
            os.replace(tmp, self.path)
        except Exception as e:  # noqa: BLE001
            logger.warning(f"[SIEM-ALERTS] store not saved: {e}")

    def add(self, alert: dict) -> bool:
        """Store *alert*; False if its event id is already known.

        The one exception: an alert stored as UNDECRYPTABLE whose room key
        arrived later. The real text replaces the placeholder (same place,
        same time) and counts as new again."""
        with self._lock:
            eid = alert.get("event_id")
            known = next((a for a in self._alerts if eid and a.get("event_id") == eid), None)
            if known is not None:
                if known.get("body") != UNDECRYPTABLE or alert.get("body") == UNDECRYPTABLE:
                    return False
                known["body"] = alert.get("body", "")
                alert.update(known)
                self._unread += 1
                self._save()
                return True
            self._alerts.append(alert)
            self._alerts = self._alerts[-MAX_ALERTS:]
            self._unread += 1
            self._save()
            return True

    def drop_room(self, room_id: str) -> int:
        """Delete every alert from *room_id*; returns how many."""
        with self._lock:
            keep = [a for a in self._alerts if a.get("room_id") != room_id]
            dropped = len(self._alerts) - len(keep)
            if dropped:
                self._alerts = keep
                self._unread = min(self._unread, len(keep))
                self._save()
            return dropped

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
