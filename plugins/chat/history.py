"""Chat history persistence via the app settings system."""
from __future__ import annotations

import time
import uuid

from utils import settings

_NS = "chat_history"
_TITLE_LEN = 40

_UNSET = object()  # sentinel for "active_id cache not yet loaded"


class ChatHistoryManager:
    """Manage multiple chat sessions persisted in the settings store.

    Caches the session index and active id in memory so the hot read
    paths (sidebar refresh after every assistant reply) don't hit disk
    every time. Mutations write through to the settings store.
    """

    def __init__(self) -> None:
        # Lazy: populated on the first read so we don't pay startup cost
        # if chat is never opened.
        self._index_cache: list[dict] | None = None
        # _UNSET means "not yet loaded"; None is a valid loaded value
        # ("no active session"), so the two states must be distinct.
        self._active_id_cache: object = _UNSET

    # -- caching layer -----------------------------------------------------

    def _load_index(self) -> list[dict]:
        if self._index_cache is None:
            self._index_cache = settings.get(_NS, "index", default=[])
        return self._index_cache

    def _save_index(self, index: list[dict]) -> None:
        self._index_cache = index
        settings.set(_NS, "index", index)

    # -- public API --------------------------------------------------------

    def list_sessions(self) -> list[dict]:
        """Return session metadata sorted newest-first.

        Cleanup of orphan "New Chat" sessions is intentionally NOT done
        here — it used to load_messages for every empty session on every
        refresh, which is O(N) disk reads per sidebar update. Now
        cleanup_empty() is an explicit call invoked once at plugin
        construction.
        """
        return sorted(
            self._load_index(),
            key=lambda s: s.get("updated_at", 0),
            reverse=True,
        )

    def cleanup_empty(self) -> None:
        """Remove sessions that have no user messages. Call on app start;
        do NOT call from sidebar refresh."""
        index = list(self._load_index())
        active = self.get_active_id()
        to_remove: list[str] = []
        for meta in index:
            sid = meta["id"]
            if sid == active:
                continue
            if meta.get("title", "") != "New Chat":
                continue
            msgs = self.load_messages(sid)
            if not any(m.get("role") == "user" for m in msgs):
                to_remove.append(sid)
        if not to_remove:
            return
        new_index = [s for s in index if s["id"] not in to_remove]
        self._save_index(new_index)
        for sid in to_remove:
            try:
                settings.delete(_NS, f"msg_{sid}")
            except Exception:
                pass

    def get_active_id(self) -> str | None:
        if self._active_id_cache is _UNSET:
            self._active_id_cache = settings.get(_NS, "active_id")
        return self._active_id_cache  # type: ignore[return-value]

    def set_active_id(self, session_id: str | None) -> None:
        # Lazy-load the cache before comparing so a cold-start
        # set_active_id to the already-persisted value short-circuits the
        # disk write. Without this, the _UNSET sentinel never equals
        # session_id (it's a bare object()), so the first call after
        # construction always rewrites the namespace file.
        if self._active_id_cache is _UNSET:
            self._active_id_cache = settings.get(_NS, "active_id")
        if self._active_id_cache == session_id:
            return
        self._active_id_cache = session_id
        settings.set(_NS, "active_id", session_id)

    def create_session(self) -> dict:
        """Create a new empty session and return its metadata."""
        meta = {
            "id": uuid.uuid4().hex[:12],
            "title": "New Chat",
            "created_at": time.time(),
            "updated_at": time.time(),
        }
        index = list(self._load_index())
        index.append(meta)
        self._save_index(index)
        settings.set(_NS, f"msg_{meta['id']}", [])
        self.set_active_id(meta["id"])
        return meta

    def load_messages(self, session_id: str) -> list[dict]:
        """Load the message list for a session."""
        return settings.get(_NS, f"msg_{session_id}", default=[])

    def save_messages(self, session_id: str, messages: list[dict]) -> None:
        """Persist messages and update the session title / timestamp."""
        try:
            settings.set(_NS, f"msg_{session_id}", messages)
            index = list(self._load_index())
            changed = False
            for meta in index:
                if meta["id"] == session_id:
                    if meta["title"] == "New Chat":
                        first_user = next(
                            (m["content"] for m in messages
                             if m["role"] == "user"), None)
                        if first_user:
                            meta["title"] = first_user[:_TITLE_LEN].strip()
                            changed = True
                    meta["updated_at"] = time.time()
                    changed = True
                    break
            if changed:
                self._save_index(index)
        except Exception as e:
            from utils.logger import logger
            logger.error(f"Failed to save chat messages: {e}")

    def delete_session(self, session_id: str) -> None:
        """Remove a session and its messages."""
        try:
            index = [s for s in self._load_index() if s["id"] != session_id]
            self._save_index(index)
            settings.delete(_NS, f"msg_{session_id}")
            if self.get_active_id() == session_id:
                self.set_active_id(None)
        except Exception as e:
            from utils.logger import logger
            logger.error(f"Failed to delete chat session: {e}")
