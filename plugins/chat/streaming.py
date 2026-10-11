"""Stream controller for chat API responses.

Encapsulates the background-thread + queue.Queue + Tk polling pattern used
to stream OpenAI-compatible chat completions without blocking the GUI. A
non-HTTP transport (plugins/chat/matrix_transport.py) plugs into the same
pipeline by exposing ``stream_deltas()``.
"""

from __future__ import annotations

import queue
import re
import threading
import time
from typing import TYPE_CHECKING, Callable

from utils.logger import logger

if TYPE_CHECKING:
    from openai import OpenAI

_DONE = object()  # sentinel: stream finished
_CANCELLED = object()  # sentinel: stream cancelled
_POLL_MS = 50


class StreamController:
    """Manages a single streaming chat completion on a background thread.

    Callbacks (on_chunk, on_done, on_error) are always dispatched on the
    main Tk thread via ``app.after()``, so callers can safely touch widgets.
    """

    def __init__(
        self,
        app,
        on_chunk: Callable[[str], None],
        on_done: Callable[[str], None],
        on_error: Callable[[str], None],
    ) -> None:
        self._app = app
        self._on_chunk = on_chunk
        self._on_done = on_done
        self._on_error = on_error

        # Bounded queue: if the main thread is blocked (heavy markdown
        # render, modal) while the server streams thousands of tokens,
        # an unbounded queue would let memory grow with no backpressure
        # and then freeze the UI when draining. 4096 entries is plenty
        # for any reasonable burst before the poll catches up.
        self._queue: queue.Queue[tuple[str, object]] = queue.Queue(
            maxsize=4096)
        self._cancel_event = threading.Event()
        self._active = False
        self._accumulated = ""
        self._poll_id: str | None = None
        self._stream = None  # set in _worker so cancel() can close it

    # -- public API ----------------------------------------------------

    @property
    def is_active(self) -> bool:
        """True while the stream is in progress."""
        return self._active

    def start(
        self,
        client: OpenAI,
        model: str,
        messages: list[dict],
        temperature: float = 0.7,
        *,
        extra_body: dict | None = None,
        base_url: str | None = None,
    ) -> None:
        """Launch the streaming request in a daemon thread.

        *base_url* is only used for error messages (so the user sees which
        endpoint could not be reached).
        """
        if self._active:
            logger.warning("StreamController.start() called while already active")
            return

        self._active = True
        self._accumulated = ""
        self._cancel_event.clear()
        # Bounded — must match the maxsize set in __init__. The previous
        # `queue.Queue()` (no maxsize) silently re-introduced the
        # unbounded queue every send_message, defeating the backpressure
        # the __init__ change was supposed to give us.
        self._queue = queue.Queue(maxsize=4096)
        self._stream = None

        # A transport (Matrix) yields text deltas itself; anything else is an
        # OpenAI SDK client. Both feed the same queue → poll → callbacks path.
        if hasattr(client, "stream_deltas"):
            target, args = self._worker_transport, (client, messages, extra_body)
        else:
            target = self._worker
            args = (client, model, messages, temperature, extra_body, base_url)
        thread = threading.Thread(target=target, args=args, daemon=True)
        thread.start()
        self._schedule_poll()

    def cancel(self) -> None:
        """Request cancellation; the thread exits and no further callbacks fire.

        Closes the underlying HTTP response so the OpenAI client's
        `for chunk in stream` loop in the worker thread terminates on the
        next read instead of waiting until the next chunk arrives — that
        avoids the "user clicked Stop but tokens keep being billed" case.
        """
        if not self._active and not self._cancel_event.is_set():
            return
        self._active = False
        self._cancel_event.set()
        # Close the HTTP response on a daemon thread — response.close()
        # can block on a TCP close handshake (hundreds of ms with a
        # slow server). Doing it inline on the main thread is exactly
        # the kind of stall that compounds the "freeze on chat-switch"
        # complaint. The cancel_event short-circuits the worker so the
        # iterator will terminate when the OS times out either way;
        # main thread doesn't have to wait.
        stream = self._stream
        self._stream = None
        if stream is not None:
            threading.Thread(
                target=self._close_stream, args=(stream,),
                daemon=True,
            ).start()
        self._stop_polling()

    def _close_stream(self, stream) -> None:
        """Release the HTTP response on a stream, best-effort.

        Both cancel() and the worker's finally block call this so the
        TLS socket is freed even if the user clicks Stop mid-handshake.
        Both response.close() and stream.close() are idempotent in the
        current OpenAI SDK; calling both is intentional in case a
        future SDK version separates them.
        """
        if stream is None:
            return
        for closer in ("response", "_response"):
            resp = getattr(stream, closer, None)
            if resp is not None and hasattr(resp, "close"):
                try:
                    resp.close()
                except Exception:
                    pass
        if hasattr(stream, "close"):
            try:
                stream.close()
            except Exception:
                pass

    # -- background thread ---------------------------------------------

    def _worker(
        self,
        client: OpenAI,
        model: str,
        messages: list[dict],
        temperature: float,
        extra_body: dict | None,
        base_url: str | None,
    ) -> None:
        """Run the streaming API call, pushing results into the queue."""
        endpoint = base_url or "https://api.openai.com/v1"
        t0 = time.monotonic()
        # Per-stream diagnostics — the numbers that reveal whether the reply
        # actually streamed or arrived buffered (e.g. nginx proxy_buffering).
        ttfb = None          # time to first content chunk (s)
        n_chunks = 0
        n_chars = 0
        prev_t = t0
        max_gap = 0.0        # largest silence between chunks (s)
        raw_parts: list[str] = []  # full response text, logged at completion
        logger.info(
            f"[CHAT-STREAM] → POST {endpoint} model={model} "
            f"messages={len(messages)} session={(extra_body or {}).get('session_id')}")
        try:
            kwargs: dict = {
                "model": model,
                "messages": messages,
                "temperature": temperature,
                "stream": True,
            }
            if extra_body:
                kwargs["extra_body"] = extra_body

            stream = client.chat.completions.create(**kwargs)
            self._stream = stream
            # If cancel() fired between start() and the assignment above,
            # close the response immediately rather than entering the
            # iterator and reading at least one chunk. Otherwise a
            # tight cancel→TLS-handshake race leaks the socket.
            if self._cancel_event.is_set():
                self._close_stream(stream)
                self._safe_put(("cancel", _CANCELLED))
                return

            try:
                for chunk in stream:
                    if self._cancel_event.is_set():
                        self._safe_put(("cancel", _CANCELLED))
                        return
                    if chunk.choices and chunk.choices[0].delta.content:
                        now = time.monotonic()
                        content = chunk.choices[0].delta.content
                        n_chunks += 1
                        n_chars += len(content)
                        raw_parts.append(content)
                        if ttfb is None:
                            ttfb = now - t0
                            logger.info(
                                f"[CHAT-STREAM] first chunk after "
                                f"{ttfb * 1000:.0f}ms ({len(content)} chars)")
                        else:
                            max_gap = max(max_gap, now - prev_t)
                        prev_t = now
                        # Per-chunk trail (DEBUG so it's opt-in via OPENAI_LOG
                        # or a debug log level): elapsed-since-start + size.
                        logger.debug(
                            f"[CHAT-STREAM] +{(now - t0) * 1000:.0f}ms "
                            f"chunk#{n_chunks} {len(content)}ch")
                        self._safe_put(("chunk", content))
            finally:
                # Always release the HTTP response, even on early-exit
                # via cancel — the for-loop break above doesn't itself
                # close the iterator.
                self._close_stream(stream)
                if self._stream is stream:
                    self._stream = None

            total = time.monotonic() - t0
            rate = (n_chars / total) if total > 0 else 0
            if n_chunks == 0:
                # 200 OK but the server sent no content deltas — this is the
                # "No response received from the server" case the UI shows.
                # Almost always upstream (nginx buffering/timeout on :8002, a
                # tool-only turn with no text, or the model returning empty).
                logger.warning(
                    f"[CHAT-STREAM] ⚠ EMPTY response: 0 content chunks in "
                    f"{total:.2f}s from {endpoint} — server returned 200 but "
                    f"streamed no text (check nginx buffering / upstream).")
            else:
                # Heuristic: if the first byte took ~as long as the whole
                # response and everything landed in one burst, it was buffered
                # upstream (nginx/CDN) rather than truly streamed.
                buffered = (
                    n_chunks > 1 and ttfb is not None and total > 0
                    and ttfb / total > 0.9)
                logger.info(
                    f"[CHAT-STREAM] ✓ done: {n_chunks} chunks, {n_chars} chars "
                    f"in {total:.2f}s (ttfb={(ttfb or 0) * 1000:.0f}ms, "
                    f"max_gap={max_gap * 1000:.0f}ms, ~{rate:.0f} ch/s)"
                    + ("  ⚠ looks BUFFERED upstream (arrived in one burst, "
                       "not incrementally streamed)" if buffered else ""))
                # Full raw response text, verbatim (markdown source, incl. any
                # injected tool-status lines) — fenced so multi-line replies
                # are obvious in the log.
                raw = "".join(raw_parts)
                logger.info(
                    "[CHAT-STREAM] raw response text:\n"
                    "----- BEGIN RESPONSE -----\n"
                    f"{raw}\n"
                    "----- END RESPONSE -----")
            self._safe_put(("done", _DONE))

        except Exception as e:
            elapsed = time.monotonic() - t0
            # Cancellation teardown, not a failure. cancel() closes the HTTP
            # response from another thread, so the read we were blocked on
            # blows up mid-flight — on Windows as WinError 10038 ("not a
            # socket"), elsewhere as a generic ReadError. That's expected when
            # the user switches sessions / leaves chat / the stream is stopped;
            # surface it as a clean cancel, not a red error the user sees.
            if self._cancel_event.is_set():
                logger.debug(
                    f"[CHAT-STREAM] stream cancelled during teardown after "
                    f"{elapsed:.2f}s ({type(e).__name__})")
                self._safe_put(("cancel", _CANCELLED))
                return
            raw = re.sub(r'sk-[A-Za-z0-9]+', 'sk-***', str(e))
            status = getattr(e, "status_code", None)
            try:
                from openai import APIConnectionError

                is_conn = isinstance(e, APIConnectionError)
            except ImportError:
                is_conn = False

            if is_conn:
                msg = (
                    f"Could not reach {endpoint}. "
                    "Check that the host is reachable (VPN, DNS, firewall) "
                    "and the URL in Settings is correct."
                )
            elif status == 403 or "not authorized" in raw or "no agent" in raw:
                # The dashboard authorizes chat by the caller's source IP —
                # it must map to an enrolled agent. "no agent found" means the
                # IP the server sees has no registered endpoint agent.
                msg = (
                    "This device isn't authorized for chat yet: the server "
                    "found no enrolled agent for your current IP. Make sure "
                    "the VPN is on and the endpoint agent is enrolled/running, "
                    f"then retry. (server said: {raw})"
                )
            else:
                msg = f"{raw} (endpoint: {endpoint})"

            logger.error(
                f"[CHAT-STREAM] ✗ error after {elapsed:.2f}s"
                f"{f' (HTTP {status})' if status else ''}: {msg}")
            self._safe_put(("error", msg))

    def _worker_transport(self, transport, messages: list[dict],
                          extra_body: dict | None) -> None:
        """Run one turn through a non-HTTP transport (Matrix).

        The transport owns the server-side history (like the HTTPS agent
        endpoint), so only the newest user message is sent, plus the session.
        """
        t0 = time.monotonic()
        session = (extra_body or {}).get("session_id")
        text = messages[-1]["content"] if messages else ""
        logger.info(f"[CHAT-STREAM] → {transport.describe()} session={session}")
        n_chunks = n_chars = 0
        try:
            for delta in transport.stream_deltas(text, session, self._cancel_event):
                if self._cancel_event.is_set():
                    break
                n_chunks += 1
                n_chars += len(delta)
                self._safe_put(("chunk", delta))
            if self._cancel_event.is_set():
                self._safe_put(("cancel", _CANCELLED))
                return
            logger.info(
                f"[CHAT-STREAM] ✓ done: {n_chunks} updates, {n_chars} chars "
                f"in {time.monotonic() - t0:.2f}s")
            self._safe_put(("done", _DONE))
        except Exception as e:
            if self._cancel_event.is_set():
                self._safe_put(("cancel", _CANCELLED))
                return
            logger.error(
                f"[CHAT-STREAM] ✗ error after {time.monotonic() - t0:.2f}s: {e}")
            self._safe_put(("error", str(e)))

    def _safe_put(self, item: tuple[str, object]) -> None:
        """Bounded put that yields to the cancel signal on a full queue.

        If the main thread is stalled (e.g. mid-render of a long markdown
        block) we don't want the worker to block forever — that would
        leak threads and keep the HTTP request open. Wait briefly, then
        check cancel and try again. After a long stall, the burst is
        coalesced by _poll's batching so the user-facing UI cost is
        bounded.
        """
        while True:
            if self._cancel_event.is_set():
                return
            try:
                self._queue.put(item, timeout=0.25)
                return
            except queue.Full:
                continue

    # -- main-thread polling -------------------------------------------

    def _schedule_poll(self) -> None:
        self._poll_id = self._app.after(_POLL_MS, self._poll)

    def _stop_polling(self) -> None:
        if self._poll_id is not None:
            try:
                self._app.after_cancel(self._poll_id)
            except Exception as exc:
                logger.debug(
                    f"after_cancel({self._poll_id}) failed: {exc}")
            self._poll_id = None

    def _poll(self) -> None:
        """Drain the queue and dispatch callbacks on the main thread.

        Chunks are batched: all chunk messages drained in one tick are
        coalesced into a single on_chunk call. This caps GUI updates at
        ~20 Hz regardless of token rate and is the difference between
        a smooth render and a jittery one at 30-60 tok/s.

        Cancel is re-checked between every queue.get to drop any chunk/
        done/error that arrived after the user clicked Stop.
        """
        chunk_buf: list[str] = []
        terminal: tuple[str, object] | None = None
        try:
            while True:
                if self._cancel_event.is_set():
                    self._active = False
                    return
                msg_type, data = self._queue.get_nowait()
                if msg_type == "chunk":
                    chunk_buf.append(str(data))
                else:
                    terminal = (msg_type, data)
                    break
        except queue.Empty:
            pass

        # Single dispatch per tick — the bubble's append_streaming_chunk is
        # O(len(delta)), so one batched call beats N per-token calls.
        if chunk_buf and not self._cancel_event.is_set():
            batched = "".join(chunk_buf)
            self._accumulated += batched
            self._on_chunk(batched)

        if terminal is not None:
            msg_type, data = terminal
            if msg_type == "done":
                self._active = False
                self._on_done(self._accumulated)
                return
            if msg_type == "error":
                self._active = False
                self._on_error(data)
                return
            if msg_type == "cancel":
                self._active = False
                return

        if self._active and not self._cancel_event.is_set():
            self._schedule_poll()
