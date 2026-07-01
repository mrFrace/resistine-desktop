"""AssistantBubble widget for AI response rendering."""
from __future__ import annotations

import itertools
import tkinter as tk

import customtkinter

from plugins.chat.fonts import _BASE_SIZE, RESISTINE_BLUE, get_theme_colors, ui_family
from plugins.chat.markdown_renderer import MarkdownRenderer
from plugins.chat.markdown_utils import strip_streaming_md
from utils.logger import logger

# Streaming widget choice: CTkLabel + wraplength. Earlier this used tk.Text
# with insert("end", delta) for O(delta) per-chunk cost, but tk.Text's
# auto-sizing via count("displaylines") returns wrong values before the
# widget is mapped/laid out — for the first few chunks the widget thinks
# every char wraps (because width hasn't been resolved yet), reporting
# 30+ displaylines for a 30-char message and rendering as a huge empty
# black rectangle that takes up the entire chat area. CTkLabel handles
# height through wraplength automatically.
#
# The O(N^2) chunk-replay cost is acceptable because StreamController._poll
# batches every chunk drained in one tick into a single on_chunk call —
# so we get ~20 Hz updates regardless of token rate, and the total cost
# over an N-token response is O(N^2 / batch_size), roughly 50x cheaper
# than per-token at typical 50 tok/s.

# Animated thinking indicator: Braille spinner sequence. Smoother than the
# old dot-cycle ("Thinking", "Thinking.", "Thinking..", "Thinking...") and
# only changes one glyph per frame, so each tick is a single configure()
# rather than re-computing wraplength against a growing string.
_THINK_SPINNER = ("⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏")
_THINK_FRAME_MS = 80


class AssistantBubble(customtkinter.CTkFrame):
    """Left-aligned bubble for assistant responses.

    Two modes:
    - **Streaming:** ``set_streaming_text()`` updates a plain label.
    - **Finalized:** ``finalize_markdown()`` swaps the placeholder for
      a full MarkdownRenderer (or MarkdownBubble fallback).
    """

    _CORNER_RADIUS = 14

    def __init__(
        self, master: object,
        is_dark: bool = False, max_width: int = 700,
        **kwargs: object,
    ) -> None:
        colors = get_theme_colors(is_dark)
        self._bubble_bg = colors["bubble_bg"]
        self._bubble_fg = colors["bubble_fg"]

        kwargs.setdefault("fg_color", "transparent")
        kwargs.setdefault("corner_radius", 0)
        super().__init__(master, **kwargs)
        self.pack(side="left", fill="x", expand=True, padx=(12, 48))

        self._is_dark = is_dark
        self._max_width = max_width
        self._streaming_label: customtkinter.CTkLabel | None = None
        self._renderer: MarkdownRenderer | None = None
        self._thinking_label: customtkinter.CTkLabel | None = None
        self._thinking_iter = itertools.cycle(_THINK_SPINNER)
        self._thinking_after_id: str | None = None

        self._build_thinking_indicator()

    # -- thinking indicator -------------------------------------------------

    def _build_thinking_indicator(self) -> None:
        """Show a subtle animated braille spinner before the response arrives."""
        fg = "#9CA3AF" if self._is_dark else "#6B7280"
        self._thinking_label = customtkinter.CTkLabel(
            self, text=f"Thinking  {next(self._thinking_iter)}",
            fg_color="transparent", text_color=fg,
            font=customtkinter.CTkFont(
                family=ui_family(), size=14, slant="italic"),
            justify="left", anchor="w",
        )
        self._thinking_label.pack(
            fill="x", padx=16, pady=(10, 10), anchor="w")
        self._animate_thinking()

    def _animate_thinking(self) -> None:
        # Defensive: bubble may be destroyed mid-stream by a chat rebuild.
        # winfo_exists short-circuits avoid TclError from a dead widget.
        if self._thinking_label is None:
            return
        try:
            if not self._thinking_label.winfo_exists():
                return
            self._thinking_label.configure(
                text=f"Thinking  {next(self._thinking_iter)}")
            self._thinking_after_id = self.after(
                _THINK_FRAME_MS, self._animate_thinking)
        except tk.TclError:
            self._thinking_after_id = None
            self._thinking_label = None

    def _stop_thinking(self) -> None:
        if self._thinking_after_id is not None:
            try:
                self.after_cancel(self._thinking_after_id)
            except Exception:
                pass
            self._thinking_after_id = None
        if self._thinking_label is not None:
            try:
                self._thinking_label.destroy()
            except Exception:
                pass
            self._thinking_label = None

    # -- streaming ----------------------------------------------------------

    def _build_streaming_label(self) -> None:
        """CTkLabel-based streaming placeholder.

        wraplength auto-heights the label to fit the wrapped text, no
        manual sizing needed (which is what made the prior tk.Text
        version render as a huge empty rectangle before the widget was
        mapped). Each chunk replaces the label text — O(N) per call —
        but StreamController._poll batches all chunks drained in a tick
        into a single on_chunk dispatch, so the effective cost over N
        tokens is O(N^2 / batch_size), ~50x cheaper than per-token at
        50 tok/s and indistinguishable from native streaming to the eye.
        """
        self._streaming_label = customtkinter.CTkLabel(
            self, text="", fg_color="transparent",
            text_color=self._bubble_fg, wraplength=self._max_width,
            font=customtkinter.CTkFont(
                family=ui_family(), size=_BASE_SIZE),
            justify="left", anchor="nw",
        )
        self._streaming_label.pack(
            fill="x", padx=16, pady=(6, 8), anchor="w")

    def append_streaming_chunk(self, delta: str) -> None:
        """Append a chunk delta to the streaming placeholder.

        Displays the accumulated text with markdown syntax STRIPPED —
        so the user sees clean prose during streaming instead of literal
        ``**bold**`` markers. MarkdownRenderer takes over at finalize
        and applies the real formatting; the visual transition is a
        graceful upgrade (plain → bold/italic) rather than the previous
        jarring "raw → re-rendered" flip the user complained about.
        """
        if self._thinking_label is not None:
            self._stop_thinking()
            self._build_streaming_label()
            self._streamed_text = ""
        if self._streaming_label is None or not delta:
            return
        self._streamed_text = getattr(self, "_streamed_text", "") + delta
        try:
            self._streaming_label.configure(
                text=strip_streaming_md(self._streamed_text))
        except tk.TclError:
            self._streaming_label = None

    def set_streaming_text(self, text: str) -> None:
        """Replace the streaming placeholder with full text.

        Used by the error path to show 'Error: ...' in place of any
        streamed content. Chunk paths should use append_streaming_chunk.
        Skips the markdown strip — error messages aren't markdown.
        """
        if self._thinking_label is not None:
            self._stop_thinking()
            self._build_streaming_label()
        if self._streaming_label is None:
            return
        self._streamed_text = text
        try:
            self._streaming_label.configure(text=text)
        except tk.TclError:
            self._streaming_label = None

    # -- finalize -----------------------------------------------------------

    def finalize_markdown(self, markdown_text: str) -> None:
        """Replace the streaming placeholder with rendered markdown."""
        # Idempotent: ignore a second finalize (e.g. a stop/done race) so we
        # don't stack a duplicate response + Copy button.
        if getattr(self, "_renderer", None) is not None:
            return
        self._stop_thinking()
        if self._streaming_label is not None:
            try:
                self._streaming_label.destroy()
            except Exception:
                pass
            self._streaming_label = None
        # Keep the raw response so the whole thing (prose + tables + code) can
        # be copied in one click. Selecting across embedded table/code widgets
        # isn't possible in Tk (each is its own widget), so the Copy button is
        # the way to grab the entire response at once.
        self._markdown_text = markdown_text
        # The renderer calls pack_propagate(False) on its parent and freezes
        # that parent's height to exactly the content. Give it an inner frame
        # to own, so THIS bubble can still auto-size to (content + Copy button)
        # — otherwise the button would be clipped.
        self._content_frame = customtkinter.CTkFrame(
            self, fg_color="transparent")
        self._content_frame.pack(fill="x", expand=True)
        try:
            self._renderer = MarkdownRenderer(
                self._content_frame, markdown_text,
                self._is_dark, self._max_width)
        except Exception as exc:
            logger.warning(
                f"MarkdownRenderer failed, using fallback: {exc}")
            from plugins.chat.markdown_bubble import MarkdownBubble
            self._renderer = MarkdownBubble(
                self._content_frame, markdown_text, width=self._max_width)
            self._renderer.pack(fill="x", expand=True)
        self._build_copy_button()

    # -- copy whole response ------------------------------------------------

    def _build_copy_button(self) -> None:
        """'Copy' affordance below the response that copies the entire message
        (body text, tables and code) to the clipboard at once. Uses the app's
        blue (RESISTINE_BLUE) so it's clearly visible and on-brand."""
        self._copy_btn = customtkinter.CTkButton(
            self, text="Copy", width=58, height=24, corner_radius=6,
            fg_color=RESISTINE_BLUE, hover_color="#1565B0", text_color="#FFFFFF",
            font=customtkinter.CTkFont(family=ui_family(), size=12),
            command=self._copy_response,
        )
        self._copy_btn.pack(anchor="w", padx=14, pady=(2, 4))

    def _copy_response(self) -> None:
        try:
            self.clipboard_clear()
            self.clipboard_append(getattr(self, "_markdown_text", "") or "")
            self._copy_btn.configure(text="Copied!")

            def _restore():
                try:
                    if self._copy_btn.winfo_exists():
                        self._copy_btn.configure(text="Copy")
                except Exception:
                    pass
            self.after(1200, _restore)
        except Exception:
            logger.debug("Copy response to clipboard failed")

    # -- lifecycle ---------------------------------------------------------

    def destroy(self) -> None:
        # Cancel the thinking-spinner timer before our widget tree goes
        # away — Tk usually swallows after() callbacks on dead widgets,
        # but CTk's configure can raise on destroyed CTkLabels.
        if self._thinking_after_id is not None:
            try:
                self.after_cancel(self._thinking_after_id)
            except Exception:
                pass
            self._thinking_after_id = None
        super().destroy()

    # -- public API ---------------------------------------------------------

    def set_width(self, max_width: int) -> None:
        """Update content width on resize.

        ``_on_resize`` fires on every chat_scroll <Configure> -- including
        scroll-triggered ones where the width hasn't actually changed.
        Re-asserting widths on embedded tables/code blocks causes a
        single-frame reflow on each scroll tick, so short-circuit when
        the width is unchanged. UserBubble has the same guard.
        """
        if max_width == self._max_width:
            return
        self._max_width = max_width
        if self._streaming_label is not None:
            try:
                self._streaming_label.configure(wraplength=max_width)
            except Exception:
                pass
        if self._renderer is not None \
                and hasattr(self._renderer, "_update_width"):
            self._renderer._update_width(max_width)
