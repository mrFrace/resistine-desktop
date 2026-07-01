"""Stream controller for chat API responses.

Encapsulates the background-thread + queue.Queue + Tk polling pattern used
to stream OpenAI-compatible chat completions without blocking the GUI.
"""

from __future__ import annotations

import queue
import re
import threading
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

        thread = threading.Thread(
            target=self._worker,
            args=(client, model, messages, temperature, extra_body, base_url),
            daemon=True,
        )
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
                        self._safe_put(
                            ("chunk", chunk.choices[0].delta.content))
            finally:
                # Always release the HTTP response, even on early-exit
                # via cancel — the for-loop break above doesn't itself
                # close the iterator.
                self._close_stream(stream)
                if self._stream is stream:
                    self._stream = None

            self._safe_put(("done", _DONE))

        except Exception as e:
            endpoint = base_url or "https://api.openai.com/v1"
            try:
                from openai import APIConnectionError

                if isinstance(e, APIConnectionError):
                    msg = (
                        f"Could not reach {endpoint}. "
                        "Check that the host is reachable "
                        "(VPN, DNS, firewall) "
                        "and the URL in Settings is correct."
                    )
                else:
                    err = re.sub(r'sk-[A-Za-z0-9]+', 'sk-***', str(e))
                    msg = f"{err} (endpoint: {endpoint})"
            except ImportError:
                err = re.sub(r'sk-[A-Za-z0-9]+', 'sk-***', str(e))
                msg = f"{err} (endpoint: {endpoint})"

            logger.error(f"StreamController error: {msg}")
            self._safe_put(("error", msg))

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
