"""Phoenix AI Chat plugin."""
from __future__ import annotations

import os

from plugins.base_plugin import BasePlugin
from utils import chat_endpoint as endpoint
from plugins.chat.bubble import BubbleRow
from plugins.chat.chat_ui import ChatUIMixin
from plugins.chat.fonts import RESISTINE_BLUE, _is_dark_mode
from plugins.chat.history import ChatHistoryManager
from plugins.chat.streaming import StreamController
from utils import settings
from utils.logger import logger

_SYSTEM_PROMPT = "You are SOC Copilot specialized in cybersecurity."
_ICON_DIR = os.path.dirname(os.path.realpath(__file__))
_SYS_MSG = {"role": "system", "content": _SYSTEM_PROMPT}

# Canned assistant message when the user navigates away from a chat
# (switch chat, + New, delete, leave plugin) while a response is still
# streaming. The partial response is discarded — only this short message
# is persisted to history, so revisiting the chat tells the user the
# response was interrupted instead of leaving a confusing truncated stub.
_NAV_AWAY_MSG = (
    "_(You switched chats before this response could finish. "
    "Please ask your question again.)_"
)


class Plugin(ChatUIMixin, BasePlugin):
    """Chat plugin -- lets users talk to an OpenAI-compatible AI assistant."""

    # Chat renders asynchronously after build (markdown bubbles self-resize via
    # after() timers, scroll-to-bottom, .place()'d input bar). Defer the swap
    # until that settles so switching to Chat doesn't tear mid-render.
    defer_reveal_until_settled = True

    def __init__(self, app):
        super().__init__(
            id="002", version="2025.01.01", order=2, name="Chat", status=None,
            description="This plugin allows you to chat with the AI assistant.",
            supported_systems=["Windows", "Linux", "Mac"],
            translations={"US": "Chat", "ES": "Chat", "FR": "Chat"},
            icon_light_path=os.path.join(_ICON_DIR, "chat_light.png"),
            icon_dark_path=os.path.join(_ICON_DIR, "chat_dark.png"))
        self.app = app
        self.client = None
        self.conversation_history: list[dict] = []
        self._bubble_rows: list[BubbleRow] = []
        self._stream_ctrl: StreamController | None = None
        self._welcome_frame: object | None = None
        self._history = ChatHistoryManager()
        # One-shot cleanup: removes "New Chat"-titled empty sessions left
        # over from previous runs. Used to fire on every list_sessions()
        # call from inside the sidebar refresh (load_messages per orphan
        # = N disk reads per refresh).
        self._history.cleanup_empty()
        self._sidebar_visible = False
        self._accumulated_text = ""
        self._response_persisted = False
        # Access-gate poller state (VPN + SIEM agent). See chat_ui.py.
        self._gate_poll_id = None
        self._gate_unlocked = False
        self.reinitialize_client()
        self.status = self.get_status()
        active_id = self._history.get_active_id()
        if active_id:
            saved = self._history.load_messages(active_id)
            if saved:
                if self.base_url:
                    saved = [m for m in saved
                             if m.get("role") != "system"]
                self.conversation_history = saved

    def check_status(self):
        # Chat is only usable when the client is configured AND the same gate
        # that unlocks the chat screen is satisfied (VPN connected + SIEM agent
        # running). Mirror that here so the dashboard tile isn't "OK" while chat
        # is actually locked.
        if not self.client:
            return "Warning"
        vpn_on, agent_on = self._chat_access_status()
        return "OK" if (vpn_on and agent_on) else "Warning"

    def reinitialize_client(self, notify: bool = False):
        """Rebuild the OpenAI client from the current settings."""
        api_key = settings.get_secret("chat", "openai_api_key")
        self.transport = endpoint.get_transport()
        self.base_url = endpoint.get_base_url()
        self.session_id = None
        if self.base_url:
            self.model, self.conversation_history = "ministral-3:14b", []
        else:
            self.model = "gpt-4o"
            self.conversation_history = [dict(_SYS_MSG)]
        if not api_key and not self.base_url:
            self.client = None
            return
        try:
            kwargs: dict = {"api_key": api_key or "unused"}
            if self.base_url:
                kwargs["base_url"] = self.base_url
                kwargs["http_client"] = endpoint.make_http_client(self.base_url)
            from openai import OpenAI
            self.client = OpenAI(**kwargs)
        except Exception as e:
            logger.error(f"Chat: client init failed: {e}")
            if notify:
                self.app.show_notification(
                    f"Chat Init Error: {e}", type="error")
            self.client = None

    def _save_current_session(self) -> None:
        active_id = self._history.get_active_id()
        if active_id and self.conversation_history:
            self._history.save_messages(active_id, self.conversation_history)

    def _ensure_session(self) -> None:
        if not self._history.get_active_id():
            self._history.create_session()

    def _finalize_in_flight_response(self, *, persist: bool = True) -> None:
        """Centralized cancel-and-persist for any code path that interrupts
        a stream.

        Persistence semantics (per user request): when the user navigates
        away mid-response, the PARTIAL response is discarded and a fixed
        canned message ("you switched chats…") is appended to history
        instead. Revisiting the chat then shows a clear "this was
        interrupted, ask again" marker instead of a confusing truncated
        stub.

        Critically: we do NOT call ``finalize_markdown`` here. Doing so
        ran ``MarkdownRenderer.render()`` synchronously on the
        about-to-be-destroyed bubble — a 200–800 ms freeze on the main
        thread for non-trivial partials. The destroy that follows in
        _rebuild_chat threw the rendered widget tree away within
        milliseconds anyway. Skipping the render is the single biggest
        win for the "freeze on chat-switch mid-stream" complaint.
        """
        ctrl = self._stream_ctrl
        if ctrl is not None and ctrl.is_active:
            ctrl.cancel()
        if (persist
                and not getattr(self, "_response_persisted", False)
                and self._current_asst_bubble is not None
                and self._accumulated_text.strip()):
            # Discard the partial; persist the canned marker. No
            # finalize_markdown — the bubble is about to be destroyed
            # in _rebuild_chat.
            self.conversation_history.append(
                {"role": "assistant", "content": _NAV_AWAY_MSG})
            self._response_persisted = True
        # Empty-thinking branch: user navigated away before any tokens
        # arrived. Drop the placeholder bubble silently — no canned
        # message to persist (the user's prompt was never answered at
        # all, but it IS in history as a user message; a canned
        # assistant reply would be noise).
        if self._current_asst_bubble is not None:
            try:
                self._current_asst_bubble._stop_thinking()
                self._current_asst_bubble.destroy()
            except Exception:
                pass
        self._current_asst_bubble = None
        # Reset the per-turn buffers and the idempotency latch. Without
        # this, a follow-up _clear_conversation -> _new_chat path would
        # see _response_persisted=True from the prior turn and
        # short-circuit incorrectly.
        self._accumulated_text = ""
        self._response_persisted = False
        # Unlock the send button so the next screen rebuild doesn't
        # leave it stuck in the "Stop" state.
        try:
            self._unlock_input()
        except Exception:
            pass

    def _clear_conversation(self) -> None:
        """Reset conversation and rebuild."""
        self._finalize_in_flight_response(persist=True)
        self.conversation_history = (
            [] if self.base_url else [dict(_SYS_MSG)])
        self.session_id = None
        self._bubble_rows.clear()
        if hasattr(self, "second_frame") and self.second_frame:
            self.second_frame.destroy()
        self.create_main_screen().grid(
            row=0, column=1, sticky="nsew")

    def _new_chat(self) -> None:
        self._finalize_in_flight_response(persist=True)
        # If the user is mashing "+ New" without sending any messages,
        # don't manufacture an empty-session orphan every click. Discard
        # the current session if it has no user message; otherwise
        # persist it.
        active_id = self._history.get_active_id()
        if active_id and not any(
                m.get("role") == "user"
                for m in self.conversation_history):
            self._history.delete_session(active_id)
        else:
            self._save_current_session()
        self.conversation_history = (
            [] if self.base_url else [dict(_SYS_MSG)])
        self.session_id = None
        self._history.create_session()
        self._rebuild_chat()

    def _select_chat(self, session_id: str) -> None:
        if session_id == self._history.get_active_id():
            return
        self._finalize_in_flight_response(persist=True)
        self._save_current_session()
        messages = self._history.load_messages(session_id)
        self.conversation_history = messages if messages else (
            [] if self.base_url else [dict(_SYS_MSG)])
        self._history.set_active_id(session_id)
        self._rebuild_chat()

    def _delete_chat(self, session_id: str) -> None:
        was_active = session_id == self._history.get_active_id()
        if was_active:
            self._finalize_in_flight_response(persist=False)
        self._history.delete_session(session_id)
        if was_active:
            self.conversation_history = (
                [] if self.base_url else [dict(_SYS_MSG)])
            remaining = self._history.list_sessions()
            if remaining:
                self._select_chat(remaining[0]["id"])
                return
            self._history.create_session()
        self._rebuild_chat()

    def _cancel_pending_chat_timers(self) -> None:
        """Cancel every chat-scoped after() timer before rebuilding.

        Each (widget_attr, after_attr) pair: the widget we registered
        the after on, and the attribute holding the after id. Stale ids
        in plugin attributes have caused permanent state-machine break
        (e.g. _scroll_dirty_pending sticking True when the chat_scroll
        it was scheduled against gets destroyed), plus stale layout
        passes firing 16 ms into the rebuild on the new widget tree.
        """
        pairs = (
            ("chat_scroll", "_resize_after"),
            ("chat_scroll", "_scroll_btn_after"),
            ("chat_scroll", "_scroll_redraw_after"),
            ("chat_scroll", "_restore_after"),
            ("second_frame", "_sf_cfg_after"),
            ("app", "_app_cfg_after"),
        )
        for widget_attr, after_attr in pairs:
            aid = getattr(self, after_attr, None)
            if aid is None:
                continue
            widget = getattr(self, widget_attr, None)
            if widget is not None:
                try:
                    widget.after_cancel(aid)
                except Exception:
                    pass
            setattr(self, after_attr, None)

    def _rebuild_chat(self) -> None:
        # If a stream is still in flight (e.g. _select_chat was called
        # before _finalize_in_flight_response landed), make a last-ditch
        # cancel — the helper already runs above this in normal paths.
        if self._stream_ctrl and self._stream_ctrl.is_active:
            self._stream_ctrl.cancel()
        # Cancel every pending after() timer that's keyed to a widget
        # we're about to destroy. Without this, the previous
        # _scroll_dirty_pending flag stays True forever (its widget dies
        # before the idle pump fires), permanently breaking
        # auto-scroll-to-bottom in the NEXT chat. Same risk for the
        # other debounces — stale ids are usually harmless on Tk but
        # accumulate and noisy on Windows.
        self._cancel_pending_chat_timers()
        self._current_asst_bubble = None
        self._accumulated_text = ""
        self._response_persisted = False
        self._scroll_dirty_pending = False
        self._bubble_rows.clear()
        if hasattr(self, "_chat_area") and self._chat_area:
            if hasattr(self, "chat_scroll") and self.chat_scroll:
                try:
                    self.chat_scroll.unbind("<Configure>")
                except Exception:
                    pass
            self._chat_area.destroy()
        self._chat_area = self.chat_scroll = self.chat_entry = None
        self.send_button = self._bottom_spacer = None
        self._build_chat_area(_is_dark_mode())
        self._refresh_sidebar()
        # The drawer is a sibling overlay that survives the rebuild; the new
        # chat area is created on top of it, so re-assert its z-order.
        if self._sidebar_visible:
            self._show_sidebar()

    def send_message(self) -> None:
        user_text = self.chat_entry.get().strip()
        if not user_text:
            return
        if len(user_text) > 15000:
            self.app.show_notification(
                "Message too long (15,000 character limit).",
                type="warning")
            return
        if self._stream_ctrl and self._stream_ctrl.is_active:
            self._stop_streaming()
            return
        if self.transport == endpoint.TRANSPORT_MATRIX:
            self.app.show_notification(
                "Matrix chat isn't available in this build yet. "
                "Switch Chat transport to OpenAI API in Settings.",
                type="warning")
            return
        self._ensure_session()
        if self._welcome_frame is not None:
            self._welcome_frame.destroy()
            self._welcome_frame = None
        self._show_header()
        self.chat_entry.delete(0, "end")
        is_dark = _is_dark_mode()
        self._add_user_bubble(user_text, is_dark)
        self._current_asst_bubble = self._add_assistant_bubble(is_dark)
        self.chat_scroll.after(50, self._scroll_to_last_user_bubble)
        self.chat_scroll.after(100, self._update_scrollbar_visibility)
        self.conversation_history.append(
            {"role": "user", "content": user_text})
        self.chat_entry.configure(state="disabled")
        self.send_button.configure(
            text="\u25a0", fg_color="#EF4444", hover_color="#DC2626",
            command=self._stop_streaming)
        self._accumulated_text = ""
        # Idempotency latch: _stop_streaming and _on_stream_done both
        # try to finalize and append to history. The latch ensures only
        # the first one wins even if they race.
        self._response_persisted = False
        self._stream_ctrl = StreamController(
            app=self.app, on_chunk=self._on_stream_chunk,
            on_done=self._on_stream_done, on_error=self._on_stream_error)
        msgs = ([{"role": "user", "content": user_text}]
                if self.base_url
                else list(self.conversation_history))
        extra = ({"session_id": self.session_id}
                 if self.base_url and self.session_id else None)
        self._stream_ctrl.start(
            client=self.client, model=self.model, messages=msgs,
            temperature=0.7, extra_body=extra, base_url=self.base_url)

    def _stop_streaming(self) -> None:
        if getattr(self, "_response_persisted", False):
            self._unlock_input()
            return
        if self._stream_ctrl and self._stream_ctrl.is_active:
            self._stream_ctrl.cancel()
        if (self._accumulated_text.strip()
                and self._current_asst_bubble):
            self._current_asst_bubble.finalize_markdown(
                self._accumulated_text)
            self.conversation_history.append(
                {"role": "assistant", "content": self._accumulated_text})
            self._response_persisted = True
        elif self._current_asst_bubble:
            self._current_asst_bubble._stop_thinking()
            self._current_asst_bubble.destroy()
        self._current_asst_bubble = None
        self._unlock_input()
        self._save_current_session()
        self._refresh_sidebar()

    def _on_stream_chunk(self, chunk_text: str) -> None:
        self._accumulated_text += chunk_text
        if self._current_asst_bubble is not None:
            # Constant-time append per chunk (vs the old O(N^2)
            # configure(text=full_accumulated)).
            self._current_asst_bubble.append_streaming_chunk(chunk_text)
        # Coalesce scroll work to one Tk idle cycle, no matter how many
        # chunks the poll just dispatched. Two yview() reads + a possible
        # place()/place_forget() per chunk used to spike CPU on long
        # responses.
        self._schedule_scroll_after_chunk()

    def _schedule_scroll_after_chunk(self) -> None:
        if getattr(self, "_scroll_dirty_pending", False):
            return
        self._scroll_dirty_pending = True
        try:
            self.chat_scroll.after_idle(self._flush_scroll_after_chunk)
        except Exception:
            self._scroll_dirty_pending = False

    def _flush_scroll_after_chunk(self) -> None:
        self._scroll_dirty_pending = False
        if self.chat_scroll is None:
            return
        try:
            near = self._is_near_bottom()
            if near:
                self._scroll_to_bottom()
            self._check_scroll_btn()
        except Exception:
            pass

    def _on_stream_done(self, full_text: str) -> None:
        if getattr(self, "_response_persisted", False):
            return
        if self._current_asst_bubble is not None:
            if not full_text.strip():
                # Server returned a 200 SSE stream with no content (e.g. the
                # inference backend is restarting). Surface it instead of
                # leaving a blank bubble, and don't store an empty turn — but
                # fall through to the common cleanup below so the input bar
                # unlocks and the send-arrow returns to its idle state. The
                # earlier early-return left those stuck in "response loading"
                # mode after an empty SSE, which made the chat look frozen.
                self._current_asst_bubble.finalize_markdown(
                    "No response received from the server. Please try again in a moment.")
                self._current_asst_bubble = None
                self.app.show_notification(
                    "The server returned an empty response.", type="warning")
                self._response_persisted = True
            else:
                self._current_asst_bubble.finalize_markdown(full_text)
                self._current_asst_bubble = None
                self.conversation_history.append(
                    {"role": "assistant", "content": full_text})
                self._response_persisted = True
        self._unlock_input()
        self._save_current_session()
        self._refresh_sidebar()
        # Only chase the last user bubble if the user is still near the
        # bottom — otherwise we'd yank them back from wherever they
        # scrolled to while the response was rendering.
        if self._is_near_bottom():
            self.chat_scroll.after(50, self._scroll_to_last_user_bubble)
            self.chat_scroll.after(200, self._scroll_to_last_user_bubble)
        self.chat_scroll.after(250, self._update_scrollbar_visibility)

    def _on_stream_error(self, error_msg: str) -> None:
        if getattr(self, "_response_persisted", False):
            return
        if (self._accumulated_text.strip()
                and self._current_asst_bubble is not None):
            self._current_asst_bubble.finalize_markdown(
                self._accumulated_text)
            self.conversation_history.append(
                {"role": "assistant", "content": self._accumulated_text})
            self._response_persisted = True
            self.app.show_notification(
                "Response may be incomplete.", type="warning")
        elif self._current_asst_bubble is not None:
            try:
                self._current_asst_bubble.set_streaming_text(
                    f"Error: {error_msg}")
            except Exception:
                pass
        self._current_asst_bubble = None
        self._unlock_input()
        self._save_current_session()

    def _unlock_input(self) -> None:
        try:
            self.chat_entry.configure(state="normal")
            self.send_button.configure(
                text="\u2191", state="normal",
                fg_color=RESISTINE_BLUE,
                hover_color="#1565B0",
                command=self.send_message)
            self.chat_entry.focus_set()
        except Exception:
            pass

    def _use_suggestion(self, text: str) -> None:
        self.chat_entry.delete(0, "end")
        self.chat_entry.insert(0, text)
        self.send_message()

    def destroy(self) -> None:
        """Plugin teardown — cancel any in-flight stream and flush state.

        Called by PluginManager on uninstall/reload, and (if the app
        teardown is wired through plugin_list, which is the right
        direction) on app shutdown. Today it at least guarantees a
        graceful uninstall: the worker thread sees cancel_event, the
        HTTP socket is released on a daemon thread, and any partial
        response gets the canned marker so a reopen shows the right
        state.
        """
        try:
            self._stop_gate_poller()
        except Exception:
            pass
        try:
            self._finalize_in_flight_response(persist=True)
        except Exception:
            pass
        try:
            self._save_current_session()
        except Exception:
            pass
        super().destroy()

    def _open_settings(self) -> None:
        try:
            sp = next((p for p in self.app.plugin_list if p.get_name() == "Settings"), None)
            if sp:
                self.app.select_frame_by_name("frame_Settings", button=sp.get_button())
        except Exception:
            pass
