"""Matrix transport for the chat plugin (Settings → Chat transport → Matrix).

The assistant is reached through an end-to-end encrypted Matrix DM with the
Phoenix bot (@secagent by default) instead of the OpenAI-compatible HTTPS API.
The server side is the matrix_bridge service of Phoenix-LLMAgent-api; its
message contract (docs/MATRIX_BRIDGE.md there):

  user → bot   m.text, ``net.resisti.request: {session}`` picks the server
               session (one per Desktop chat)
  bot → user   one reply (m.in_reply_to the prompt) grown by m.replace
               edits; every version carries ``net.resisti.turn: {status}``,
               and status != "running" ends the turn. An answer too large
               for one Matrix event continues in further replies to the
               prompt whose turn block carries ``part`` (1, 2, ...); the
               full text is the parts' bodies concatenated in order.

Identity is the Phoenix account the user signed in with (plugins/login/oidc:
MAS token + this install's device id); no separate Matrix login.

Threading: matrix-nio is asyncio. It runs on its own daemon thread with its
own event loop (no qasync, the Qt loop is never touched). StreamController's
worker thread drives a turn through ``MatrixTransport.stream_deltas()``,
which yields plain text deltas exactly like the OpenAI path, so everything
downstream (queue, 20 Hz GUI drain, bubbles) is shared.
"""

from __future__ import annotations

import asyncio
import os
import queue
import secrets
import threading
import time
from typing import Iterator, Optional

from plugins.chat import siem_alerts
from utils import settings
from utils.logger import logger

TURN_KEY = "net.resisti.turn"
REQUEST_KEY = "net.resisti.request"
DEFAULT_BOT = "@secagent:phoenix.exposed"
_NS = "chat"

_READY_TIMEOUT = 60       # login + first sync + DM ready
_SEND_TIMEOUT = 30
_FIRST_REPLY_TIMEOUT = 90  # no reply and the bot isn't typing → give up
_TURN_TIMEOUT = 15 * 60
_INVITE_POLL = 120         # seconds between checks for a new SIEM-alerts invite


class MatrixTransportError(Exception):
    """A Matrix turn failed. ``str(e)`` is safe to show to the user."""


# ---------------------------------------------------------------------------
# Turn assembly (pure; unit-tested)
# ---------------------------------------------------------------------------

def classify(content: dict, prompt_id: Optional[str], reply_id: Optional[str]) -> Optional[str]:
    """'reply' / 'edit' if *content* belongs to the turn, else None."""
    rel = content.get("m.relates_to") or {}
    if reply_id and rel.get("rel_type") == "m.replace" and rel.get("event_id") == reply_id:
        return "edit"
    if prompt_id and (rel.get("m.in_reply_to") or {}).get("event_id") == prompt_id:
        return "reply"
    return None


class TurnAssembler:
    """Turns the bot's growing message (reply + edits) into text deltas.

    Each version of a part carries that part's full text so far; the bridge
    only ever extends it, so the delta is the new suffix. A higher ``part``
    starts a new segment that continues the answer. A version that is not
    an extension (should not happen) is logged and its text dropped rather
    than garbling the bubble.
    """

    def __init__(self) -> None:
        self.text = ""
        self.status = "running"
        self.error: Optional[str] = None
        self.part = 0
        self._part_text = ""

    def feed(self, content: dict) -> str:
        """Feed one version (reply content or m.new_content); return the delta."""
        turn = content.get(TURN_KEY)
        status = turn.get("status", "final") if isinstance(turn, dict) else "final"
        if status == "error":
            self.status = "error"
            self.error = (turn or {}).get("error") or content.get("body") or "The assistant failed."
            return ""
        part = turn.get("part", 0) if isinstance(turn, dict) else 0
        if not isinstance(part, int) or part < self.part:
            return ""  # a late version of an earlier part
        if part > self.part:
            self.part, self._part_text = part, ""
        body = content.get("body") or ""
        if body.startswith(self._part_text):
            delta, self._part_text = body[len(self._part_text):], body
            self.text += delta
        else:
            logger.warning("[CHAT-MATRIX] reply version is not an extension of the previous one; dropped")
            delta = ""
        if status != "running":
            self.status = status
        return delta

    @property
    def done(self) -> bool:
        return self.status != "running"


# ---------------------------------------------------------------------------
# Matrix client on its own thread
# ---------------------------------------------------------------------------

def _store_key() -> str:
    key = settings.get_secret(_NS, "matrix_store_key")
    if not key:
        key = secrets.token_urlsafe(32)
        settings.set_secret(_NS, "matrix_store_key", key)
    return key


class MatrixService:
    """One encrypted Matrix session for this app, on a background thread."""

    def __init__(self, homeserver: str, user_id: str, device_id: str, bot: str) -> None:
        self.homeserver = homeserver
        self.user_id = user_id
        self.device_id = device_id
        self.bot = bot
        self.room_id: Optional[str] = None
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._thread: Optional[threading.Thread] = None
        self._ready = threading.Event()
        self._error: Optional[str] = None
        self._client = None
        self._turn_q: Optional[queue.Queue] = None
        self._stopping = False
        # SIEM alerts (plugins/chat/siem_alerts.py): DMs from the alerts bot.
        self.alerts_bot = siem_alerts.alerts_bot()
        self._alert_rooms: set[str] = set(siem_alerts.alert_rooms())
        self._full_state_next = False

    # -- lifecycle (any thread) -------------------------------------------

    def ensure_ready(self, timeout: float = _READY_TIMEOUT) -> None:
        if self._thread is None or not self._thread.is_alive():
            self._ready.clear()
            self._error = None
            self._thread = threading.Thread(target=self._run, name="matrix-chat", daemon=True)
            self._thread.start()
        if not self._ready.wait(timeout):
            raise MatrixTransportError(self._error or "Could not connect to the Matrix server in time.")
        if self._error:
            raise MatrixTransportError(self._error)

    def shutdown(self) -> None:
        self._stopping = True
        loop = self._loop
        if loop is not None and loop.is_running():
            loop.call_soon_threadsafe(lambda: [t.cancel() for t in asyncio.all_tasks(loop)])

    def run_coro(self, coro, timeout: float):
        if self._loop is None:
            raise MatrixTransportError("Matrix connection is not running.")
        return asyncio.run_coroutine_threadsafe(coro, self._loop).result(timeout)

    def begin_turn(self) -> queue.Queue:
        self._turn_q = queue.Queue()
        return self._turn_q

    def end_turn(self) -> None:
        self._turn_q = None

    def bot_typing(self) -> bool:
        room = self._client.rooms.get(self.room_id) if self._client and self.room_id else None
        return bool(room and self.bot in getattr(room, "typing_users", ()))

    # -- event loop thread ------------------------------------------------

    def _run(self) -> None:
        import logging

        # nio logs every event it can't decrypt at WARNING; not our concern.
        logging.getLogger("nio").setLevel(logging.ERROR)
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)
        try:
            self._loop.run_until_complete(self._main())
        except asyncio.CancelledError:
            pass
        except Exception as e:  # noqa: BLE001
            logger.error(f"[CHAT-MATRIX] connection failed: {e}")
            self._error = self._error or f"Matrix connection failed: {e}"
        finally:
            self._ready.set()  # never leave a waiter hanging
            client = self._client
            if client is not None:
                try:
                    self._loop.run_until_complete(client.close())
                except Exception:
                    pass
            self._loop.close()
            self._loop = None

    async def _main(self) -> None:
        import aiohttp
        from nio import (
            AsyncClient,
            AsyncClientConfig,
            MegolmEvent,
            RoomMessageNotice,
            RoomMessageText,
            WhoamiResponse,
        )

        from plugins.login import oidc

        token = await asyncio.get_running_loop().run_in_executor(None, oidc.refresh)
        if not token:
            self._error = "Sign in with your Phoenix account to use Matrix chat."
            return

        store = os.path.join(settings.get_config_dir(), "matrix-store")
        os.makedirs(store, mode=0o700, exist_ok=True)
        client = AsyncClient(
            self.homeserver, self.user_id, device_id=self.device_id, store_path=store,
            config=AsyncClientConfig(
                encryption_enabled=True,
                # Initial sync every start: it is what surfaces the saved DM
                # (room state is not persisted). Turns are request/response,
                # so nothing is lost by not resuming an old sync position.
                store_sync_tokens=False,
                pickle_key=_store_key(), max_timeouts=6, backoff_factor=0.5),
        )
        # Cloudflare's Browser Integrity Check rejects the default aiohttp UA.
        client.client_session = aiohttp.ClientSession(headers={"User-Agent": oidc._user_agent()})
        self._client = client
        client.restore_login(self.user_id, self.device_id, token)

        who = await client.whoami()
        if not isinstance(who, WhoamiResponse):
            self._error = f"The Matrix server rejected the session ({who})."
            return
        await self._ensure_device_keys_published()
        if client.should_upload_keys:
            await client.keys_upload()

        client.add_event_callback(self._on_message, (RoomMessageText, RoomMessageNotice))
        client.add_event_callback(self._on_undecryptable, MegolmEvent)
        sync_task = asyncio.create_task(self._sync_loop())
        await self._ensure_room()
        logger.info(f"[CHAT-MATRIX] ready: {self.user_id} ({self.device_id}) ↔ {self.bot} in {self.room_id}")
        self._ready.set()
        invites_task = asyncio.create_task(self._alert_invites_loop())
        try:
            await sync_task
        finally:
            invites_task.cancel()

    async def _ensure_device_keys_published(self) -> None:
        """Re-upload this device's identity keys if the server lost them.

        A revoked Phoenix session deletes the device, and its E2EE keys, on
        the server; signing in again recreates the same device id without
        keys. nio's store still says the account is shared, so it would never
        upload them again, and the bot, finding no keys for this device,
        never shares its reply keys with it (every reply undecryptable).
        """
        from nio import KeysQueryResponse

        client = self._client
        if not client.olm.account.shared:
            return  # first start: the normal keys_upload publishes them
        client.olm.users_for_key_query.add(self.user_id)
        resp = await client.keys_query()
        if not isinstance(resp, KeysQueryResponse):
            logger.warning(f"[CHAT-MATRIX] own device key check failed: {resp}")
            return
        published = (resp.device_keys.get(self.user_id) or {}).get(self.device_id) or {}
        ours = client.olm.account.identity_keys["ed25519"]
        if (published.get("keys") or {}).get(f"ed25519:{self.device_id}") == ours:
            return
        logger.info(f"[CHAT-MATRIX] server has no keys for device {self.device_id}; re-uploading")
        client.olm.account.shared = False
        await client.keys_upload()

    async def _sync_loop(self) -> None:
        """sync_forever with token refresh: MAS access tokens expire."""
        from nio import SyncError

        from plugins.login import oidc

        client = self._client
        backoff = 1.0
        while not self._stopping:
            full_state = client.next_batch is None or self._full_state_next
            self._full_state_next = False
            resp = await client.sync(
                timeout=30000, full_state=full_state,
                sync_filter=self._sync_filter())
            if isinstance(resp, SyncError):
                if resp.status_code == "M_UNKNOWN_TOKEN":
                    token = await asyncio.get_running_loop().run_in_executor(None, lambda: oidc.refresh(True))
                    if not token:
                        self._error = "Your Phoenix session ended. Sign in again to use Matrix chat."
                        self._ready.set()
                        return
                    client.access_token = token
                    continue
                logger.warning(f"[CHAT-MATRIX] sync failed: {resp}")
                await asyncio.sleep(backoff)
                backoff = min(backoff * 2, 60)
                continue
            backoff = 1.0
            # What sync_forever does between syncs: keep E2EE keys flowing.
            await client.send_to_device_messages()
            if client.should_upload_keys:
                await client.keys_upload()
            if client.should_query_keys:
                await client.keys_query()
            if client.should_claim_keys:
                await client.keys_claim(client.get_users_for_key_claiming())

    def _sync_filter(self) -> dict:
        """Only ever fetch the assistant DM and the SIEM-alert DMs.

        The account is the user's own Phoenix account, which has other rooms
        (other people's conversations). The chat transport must not pull, or
        try to decrypt, any of them. Until the DM is known only room state
        (memberships, encryption) is synced, no messages.
        """
        if self.room_id:
            rooms = [self.room_id] + sorted(self._alert_rooms - {self.room_id})
            return {"room": {"rooms": rooms}, "presence": {"not_types": ["*"]}}
        return {"room": {"timeline": {"limit": 0}, "ephemeral": {"not_types": ["*"]}},
                "presence": {"not_types": ["*"]}}

    async def _ensure_room(self) -> None:
        """Find the saved encrypted DM with the bot, or create one."""
        from nio import RoomCreateResponse, RoomPreset

        client = self._client
        room_id = settings.get(_NS, "matrix_room_id")
        if room_id and settings.get(_NS, "matrix_room_bot") == self.bot:
            for _ in range(40):  # wait for the first sync to surface it
                room = client.rooms.get(room_id)
                if room is not None:
                    break
                await asyncio.sleep(0.25)
            room = client.rooms.get(room_id)
            if room is not None and room.encrypted and self.bot in room.users:
                self.room_id = room_id
                return
            logger.info(f"[CHAT-MATRIX] saved room {room_id} unusable; creating a new DM")

        resp = await client.room_create(
            is_direct=True,
            preset=RoomPreset.trusted_private_chat,
            invite=[self.bot],
            name="Phoenix AI",
            initial_state=[{
                "type": "m.room.encryption", "state_key": "",
                "content": {"algorithm": "m.megolm.v1.aes-sha2"},
            }],
        )
        if not isinstance(resp, RoomCreateResponse):
            raise MatrixTransportError(f"Could not create the chat room ({resp}).")
        room_id = resp.room_id
        # Messages sent before the bot joins can never be decrypted by it.
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            room = client.rooms.get(room_id)
            if room is not None and self.bot in room.users:
                break
            await asyncio.sleep(0.5)
        else:
            raise MatrixTransportError(
                f"The assistant ({self.bot}) did not join the chat room. "
                "Is your account enrolled for Matrix chat?")
        settings.set(_NS, "matrix_room_id", room_id)
        settings.set(_NS, "matrix_room_bot", self.bot)
        self.room_id = room_id

    async def send_prompt(self, text: str, session: Optional[str]) -> str:
        from nio import RoomSendResponse

        client = self._client
        room = client.rooms.get(self.room_id)
        if room is not None and not room.members_synced:
            await client.joined_members(self.room_id)
        if client.should_query_keys:
            await client.keys_query()
        content = {"msgtype": "m.text", "body": text}
        if session:
            content[REQUEST_KEY] = {"session": session}
        resp = await client.room_send(self.room_id, "m.room.message", content, ignore_unverified_devices=True)
        if not isinstance(resp, RoomSendResponse):
            raise MatrixTransportError(f"Could not send the message ({resp}).")
        return resp.event_id

    async def _alert_invites_loop(self) -> None:
        """Accept SIEM-alert DM invites — ONLY those sent by the alerts bot.

        The main sync is filtered to known rooms, which also hides new
        invites, so they are looked up with a separate one-off sync that
        carries no messages (timeline limit 0, no room state; an invite's
        stripped state is always included).
        """
        import json

        from nio import JoinResponse

        client = self._client
        flt = {"room": {"timeline": {"limit": 0}, "state": {"not_types": ["*"]},
                        "ephemeral": {"not_types": ["*"]}, "account_data": {"not_types": ["*"]}},
               "presence": {"not_types": ["*"]}, "account_data": {"not_types": ["*"]}}
        url = f"{self.homeserver.rstrip('/')}/_matrix/client/v3/sync"
        while not self._stopping:
            try:
                async with client.client_session.get(
                        url, params={"filter": json.dumps(flt), "timeout": "0"},
                        headers={"Authorization": f"Bearer {client.access_token}"}) as r:
                    data = await r.json() if r.status == 200 else {}
                invites = ((data.get("rooms") or {}).get("invite") or {})
                for room_id, inv in invites.items():
                    state = (inv.get("invite_state") or {}).get("events") or []
                    if not siem_alerts.is_alert_invite(state, self.user_id, self.alerts_bot):
                        continue
                    resp = await client.join(room_id)
                    if isinstance(resp, JoinResponse):
                        self._alert_rooms.add(room_id)
                        siem_alerts.add_alert_room(room_id)
                        self._full_state_next = True
                        logger.info(f"[CHAT-MATRIX] joined SIEM alerts room {room_id} from {self.alerts_bot}")
                    else:
                        logger.warning(f"[CHAT-MATRIX] could not join SIEM alerts room {room_id}: {resp}")
            except asyncio.CancelledError:
                raise
            except Exception as e:  # noqa: BLE001 — retried on the next poll
                logger.warning(f"[CHAT-MATRIX] SIEM alerts invite check failed: {e}")
            await asyncio.sleep(_INVITE_POLL)

    def _is_alert(self, room, event) -> bool:
        return room.room_id in self._alert_rooms and event.sender == self.alerts_bot

    async def _on_message(self, room, event) -> None:
        if self._is_alert(room, event):
            siem_alerts.publish(room.room_id, event.event_id, getattr(event, "body", "") or "",
                                getattr(event, "server_timestamp", None))
            return
        q = self._turn_q
        if q is None or room.room_id != self.room_id or event.sender != self.bot:
            return
        q.put(("message", event.event_id, event.source.get("content") or {}))

    async def _on_undecryptable(self, room, event) -> None:
        if self._is_alert(room, event):
            logger.warning(f"[CHAT-MATRIX] cannot decrypt SIEM alert {event.event_id}")
            siem_alerts.publish(room.room_id, event.event_id, siem_alerts.UNDECRYPTABLE,
                                getattr(event, "server_timestamp", None))
            return
        q = self._turn_q
        if q is None or room.room_id != self.room_id or event.sender != self.bot:
            return
        logger.warning(f"[CHAT-MATRIX] cannot decrypt bot event {event.event_id}")
        q.put(("undecryptable", event.event_id, {}))


# ---------------------------------------------------------------------------
# Transport used by StreamController (worker thread)
# ---------------------------------------------------------------------------

_service: Optional[MatrixService] = None
_service_lock = threading.Lock()


def _get_service(homeserver: str, user_id: str, device_id: str, bot: str) -> MatrixService:
    global _service
    with _service_lock:
        s = _service
        if s is None or (s.homeserver, s.user_id, s.device_id, s.bot) != (homeserver, user_id, device_id, bot):
            if s is not None:
                s.shutdown()
            _service = s = MatrixService(homeserver, user_id, device_id, bot)
        return s


def start_background(bot: str = DEFAULT_BOT) -> None:
    """Connect the Matrix session now, not on the first chat message, so SIEM
    alerts arrive while the app is open. Failures only log: the chat screen
    reports problems itself when the user actually sends something."""
    try:
        t = MatrixTransport(bot)
        if not t.user_id:
            return
        service = _get_service(t.homeserver, t.user_id, t.device_id, t.bot)
    except Exception as e:  # noqa: BLE001
        logger.warning(f"[CHAT-MATRIX] background start skipped: {e}")
        return

    def _go() -> None:
        try:
            service.ensure_ready()
        except Exception as e:  # noqa: BLE001
            logger.warning(f"[CHAT-MATRIX] background start failed: {e}")

    threading.Thread(target=_go, name="matrix-start", daemon=True).start()


def shutdown_service() -> None:
    global _service
    with _service_lock:
        if _service is not None:
            _service.shutdown()
            _service = None


def available() -> bool:
    """matrix-nio with working E2EE (vodozemac on >=0.26, libolm before)."""
    try:
        from nio.crypto import ENCRYPTION_ENABLED
    except ImportError:
        return False
    return bool(ENCRYPTION_ENABLED)


class MatrixTransport:
    """The chat plugin's ``client`` when the Matrix transport is selected."""

    def __init__(self, bot: str = DEFAULT_BOT) -> None:
        from plugins.login import oidc

        self.bot = bot or DEFAULT_BOT
        self.homeserver = oidc.homeserver_url()
        self.user_id = settings.get("auth", "user_id")
        self.device_id = settings.get("auth", "device_id") or oidc.get_device_id()

    def describe(self) -> str:
        return f"Matrix {self.user_id} → {self.bot}"

    def stream_deltas(self, text: str, session: Optional[str], cancel: threading.Event) -> Iterator[str]:
        if not self.user_id:
            raise MatrixTransportError("Sign in with your Phoenix account to use Matrix chat.")
        service = _get_service(self.homeserver, self.user_id, self.device_id, self.bot)
        service.ensure_ready()
        q = service.begin_turn()
        try:
            prompt_id = service.run_coro(service.send_prompt(text, session), _SEND_TIMEOUT)
            yield from self._collect(service, q, prompt_id, cancel)
        finally:
            service.end_turn()

    def _collect(self, service: MatrixService, q: queue.Queue, prompt_id: str,
                 cancel: threading.Event) -> Iterator[str]:
        asm = TurnAssembler()
        reply_id: Optional[str] = None
        started = time.monotonic()
        last_life = started
        while not cancel.is_set():
            now = time.monotonic()
            if service.bot_typing():
                last_life = now
            if reply_id is None and now - last_life > _FIRST_REPLY_TIMEOUT:
                raise MatrixTransportError(
                    f"The assistant ({self.bot}) did not answer. It may be offline; try again or "
                    "switch Settings → Chat transport to OpenAI API.")
            if now - started > _TURN_TIMEOUT:
                raise MatrixTransportError("The assistant took too long to answer.")
            try:
                kind, event_id, content = q.get(timeout=0.25)
            except queue.Empty:
                continue
            if kind == "undecryptable":
                raise MatrixTransportError("Couldn't decrypt the assistant's reply on this device.")
            which = classify(content, prompt_id, reply_id)
            if which is None:
                continue
            if which == "reply":
                reply_id = event_id
                version = content
            else:
                version = content.get("m.new_content") or content
            last_life = time.monotonic()
            delta = asm.feed(version)
            if delta:
                yield delta
            if asm.done:
                if asm.status == "error":
                    raise MatrixTransportError(asm.error or "The assistant failed.")
                return
