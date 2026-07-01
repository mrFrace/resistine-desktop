##@file plugins/chat/markdown_widgets.py
"""
Markdown Widgets — Standalone CTkFrame widgets for code blocks, tables,
and horizontal rules inside chat bubbles.

These replace the old window_create embedded widgets from MarkdownBubble,
providing self-contained components that can be pack()'d into any parent.

Author: P3 and the Resistine Team
Copyright (c) Resistine 2025
Licensed under the GNU General Public License v2 or later
"""

from __future__ import annotations

import sys
import tkinter as tk

import customtkinter

from plugins.chat.fonts import (
    RESISTINE_BLUE, get_fonts, get_theme_colors, ui_family, ui_size,
)
from plugins.chat.markdown_bubble import (
    _EMOJI_RE, _EMOJI_RENDER, MarkdownBubble, attach_emoji_copy,
)
from utils.logger import logger


def _cell_has_emoji(text: str) -> bool:
    """Linux-only check: cell text needs the image-emoji path."""
    return bool(
        _EMOJI_RENDER and _EMOJI_RE is not None and _EMOJI_RE.search(text))


def _make_emoji_cell_text(
    parent: tk.Widget, text: str, bg: str, fg: str, font,
) -> tk.Text:
    """A label-like tk.Text widget that renders inline colour emoji.

    Used in table cells on Linux when the cell text contains emoji
    codepoints — tk.Label can't fall back per-glyph to a colour-emoji
    font, but tk.Text supports inline images.
    """
    tw = tk.Text(
        parent, wrap="word", font=font, fg=fg, bg=bg,
        borderwidth=0, highlightthickness=0, relief="flat",
        insertwidth=0, cursor="", padx=10, pady=6,
        height=1, width=1,
    )
    photos: list[object] = []
    image_to_emoji: dict[str, str] = {}
    for i, part in enumerate(_EMOJI_RE.split(text)):
        if not part:
            continue
        if i % 2 == 1:
            for ch in MarkdownBubble._split_emoji_chars(part):
                photo = MarkdownBubble._render_emoji(ch)
                if photo:
                    photos.append(photo)
                    img_name = tw.image_create(
                        "end", image=photo, padx=1)
                    image_to_emoji[img_name] = ch
                else:
                    tw.insert("end", ch)
        else:
            tw.insert("end", part)
    tw._emoji_photos = photos  # type: ignore[attr-defined]
    tw._image_to_emoji = image_to_emoji  # type: ignore[attr-defined]
    attach_emoji_copy(tw, image_to_emoji)
    tw.configure(state="disabled")

    # Auto-size height to displayed lines as the column resizes.
    state = {"busy": False}

    def _autoheight(_event=None, w=tw, s=state):
        if s["busy"]:
            return
        s["busy"] = True
        try:
            # Measure in pixels. tk.Text's ``-height`` is in font-line
            # units, but an inline emoji image is typically taller than
            # the font's linespace, so a "one display line" cell ends up
            # shorter than the image and clips it. Compute the line count
            # that covers the actual rendered pixel height instead.
            import tkinter.font as tkfont
            font_obj = tkfont.Font(font=w.cget("font"))
            font_lh = max(1, font_obj.metrics("linespace"))
            yp = w.count("1.0", "end", "ypixels")
            if yp is None:
                new_h = 1
            else:
                content_px = yp[0] if isinstance(yp, (list, tuple)) else yp
                new_h = max(1, -(-int(content_px) // font_lh))
            if int(w.cget("height")) != new_h:
                w.configure(height=new_h)
        except Exception:
            pass
        finally:
            s["busy"] = False

    tw.bind("<Configure>", _autoheight, add="+")
    return tw

_COPY_MOD = 0x8 if sys.platform == "darwin" else 0x4  # Cmd on mac, Ctrl elsewhere


def _cell_readonly(event) -> str | None:
    """Block edits in a read-only cell while allowing copy / select-all."""
    if event.state & _COPY_MOD and event.keysym.lower() in ("c", "a"):
        return None
    return "break"


def _forward_cell_wheel(widget) -> None:
    """Forward vertical mouse-wheel over a table cell to the enclosing chat
    scroll frame.

    A selectable cell is a tk.Text, whose own wheel handling would otherwise
    swallow the scroll so the chat won't move while the pointer is over a
    table. Walk up to the CTkScrollableFrame and re-emit the wheel on its
    canvas (mirrors MarkdownRenderer._setup_scroll_redirect).
    """
    parent = widget
    while parent is not None:
        if isinstance(parent, customtkinter.CTkScrollableFrame):
            canvas = parent._parent_canvas

            def _fwd(e, c=canvas):
                try:
                    c.event_generate("<MouseWheel>", delta=e.delta)
                except Exception:
                    pass
                return "break"

            def _fwd_linux(e, c=canvas):
                try:
                    c.event_generate(
                        "<Button-4>" if e.num == 4 else "<Button-5>")
                except Exception:
                    pass
                return "break"

            widget.bind("<MouseWheel>", _fwd)
            widget.bind("<Button-4>", _fwd_linux)
            widget.bind("<Button-5>", _fwd_linux)
            return
        parent = getattr(parent, "master", None)


def _make_selectable_cell(
    parent: tk.Widget, text: str, bg: str, fg: str, font,
) -> tk.Text:
    """A label-like tk.Text table cell whose text can be highlighted + copied.

    Looks like the old tk.Label cell (single line, no wrap, left aligned, 10/6
    padding) but, being a tk.Text in the normal state, supports mouse selection
    and Ctrl/Cmd+C copy. Key edits are blocked so it stays read-only, and the
    mouse-wheel is forwarded so it never traps chat scrolling.
    """
    tw = tk.Text(
        parent, wrap="none", font=font, fg=fg, bg=bg,
        borderwidth=0, highlightthickness=0, relief="flat",
        insertwidth=0, cursor="xterm", padx=10, pady=6,
        height=1, width=1,
        selectbackground="#3A6DB5", selectforeground="#FFFFFF",
    )
    tw.insert("1.0", text)
    tw.bind("<Key>", _cell_readonly)
    _forward_cell_wheel(tw)
    return tw


# ---------------------------------------------------------------------------
# SelectableLabel
# ---------------------------------------------------------------------------

class SelectableLabel(tk.Text):
    """Read-only text widget that looks like a label but allows selection + copy."""

    def __init__(
        self, master, text: str, font, fg: str, bg: str,
        max_width: int = 600, **kwargs,
    ):
        kwargs.pop("padx", None)
        kwargs.pop("pady", None)
        super().__init__(
            master, wrap="word", font=font, fg=fg, bg=bg,
            borderwidth=0, highlightthickness=0, relief="flat",
            insertwidth=0, cursor="", selectbackground="#3A6DB5",
            selectforeground="#FFFFFF", height=1, **kwargs,
        )
        self.tag_configure("center", justify="center")
        self.insert("1.0", text)
        self.bind("<Key>", self._readonly)
        self._max_width = max_width
        self._in_autoheight = False
        self._fit_width(font, text, max_width)
        self._update_justify()
        self.bind("<Configure>", self._autoheight, add="+")

    def _fit_width(self, font, text: str, max_width: int) -> None:
        """Size the widget to HUG the text, up to max_width.

        A message that fits on one line gets a bubble exactly that wide. A
        message that wraps is sized to its LONGEST WRAPPED LINE rather than the
        full max_width — otherwise a right-aligned user bubble shows a wide
        empty band to the right of the shorter wrapped lines.
        """
        try:
            import tkinter.font as tkfont
            if hasattr(font, "actual"):
                measure_font = font
            else:
                measure_font = tkfont.Font(font=font)
            one_line_px = measure_font.measure(text.replace("\n", " "))
            if one_line_px + 4 <= max_width:
                width_px = one_line_px + 4
            else:
                longest = self._wrapped_max_line_px(
                    measure_font, text, max_width)
                width_px = min(longest + 4, max_width)
            avg_char = measure_font.measure("0") or 8
            char_width = max(1, -(-width_px // avg_char))
            self.configure(width=char_width)
        except Exception:
            pass

    @staticmethod
    def _wrapped_max_line_px(measure_font, text: str, max_width: int) -> int:
        """Greedy word-wrap *text* at *max_width* px (matching wrap="word");
        return the pixel width of the widest resulting line."""
        widest = 0
        for paragraph in text.split("\n"):
            cur = ""
            for word in paragraph.split(" "):
                trial = word if not cur else cur + " " + word
                if not cur or measure_font.measure(trial) <= max_width:
                    cur = trial
                else:
                    widest = max(widest, measure_font.measure(cur))
                    cur = word
            widest = max(widest, measure_font.measure(cur))
        return widest

    @staticmethod
    def _readonly(event) -> str | None:
        if event.state & _COPY_MOD and event.keysym.lower() in ("c", "a"):
            return None
        return "break"

    def _display_lines(self) -> int:
        """Number of display lines the text occupies.

        Tk's ``count -displaylines`` reports the number of line *breaks*
        between the two indices (N-1 for N display lines), so it reads one
        short. Add 1 to get the real line count — without this, every
        multi-line message rendered one line too short (and the old ``or 1``
        only happened to mask the single-line case).
        """
        try:
            result = self.count("1.0", "end-1c", "displaylines")
            n = result[0] if isinstance(result, (list, tuple)) else result
            return (int(n) + 1) if n is not None else 1
        except Exception:
            return 1

    def _autoheight(self, _event=None) -> None:
        if self._in_autoheight:
            return
        self._in_autoheight = True
        try:
            lines = self._displayline_count()
            new_h = max(1, lines)
            cur_h = int(self.cget("height"))
            if new_h != cur_h:
                self.configure(height=new_h)
            self._update_justify()
        except Exception:
            pass
        finally:
            self._in_autoheight = False

    def _update_justify(self) -> None:
        """Center text when it fits on one line, left-align otherwise."""
        try:
            if self._displayline_count() <= 1:
                self.tag_add("center", "1.0", "end")
            else:
                self.tag_remove("center", "1.0", "end")
        except Exception:
            pass

    def _displayline_count(self) -> int:
        """Number of rendered display lines from 1.0 to end-1c.

        Tk's ``count -displaylines`` returns the number of line
        *boundaries* crossed (newlines + wrap points), not the number of
        lines themselves -- so a 2-line message returns ``(1,)`` and a
        1-line message returns ``None``. Add 1 to get the actual count.
        """
        result = self.count("1.0", "end-1c", "displaylines")
        if result is None:
            return 1
        breaks = result[0] if isinstance(result, (list, tuple)) else result
        return int(breaks) + 1

    def set_width(self, max_width: int) -> None:
        if max_width == self._max_width:
            return
        self._max_width = max_width
        # Re-fit the widget so it actually grows/shrinks when the parent
        # chat area resizes (e.g. when chat_scroll lays out to full size
        # after the bubble has already been created).
        text = self.get("1.0", "end-1c")
        self._fit_width(self.cget("font"), text, max_width)


# ---------------------------------------------------------------------------
# CodeBlockWidget
# ---------------------------------------------------------------------------

class CodeBlockWidget(customtkinter.CTkFrame):
    """Fenced code block with language label, copy button, and monospace body.

    Constructor
    -----------
    master : widget
        Parent container (any tkinter or CTk widget).
    code_text : str
        The raw source code to display.
    language : str
        Optional language identifier shown in the header.
    is_dark : bool
        True for dark-mode palette, False for light.
    """

    def __init__(
        self,
        master,
        code_text: str,
        language: str = "",
        is_dark: bool = False,
        **kwargs,
    ):
        colors = get_theme_colors(is_dark)
        fonts = get_fonts(is_dark)

        muted_fg = "#888888"
        sb_color = "#3A3A3C" if is_dark else "#C8C8CC"
        sb_hover = "#555558" if is_dark else "#A8A8AC"

        super().__init__(
            master, fg_color=colors["code_bg"], corner_radius=12,
            **kwargs)

        self._code_text = code_text

        # -- Header row (flush with body, children have padding) ------------
        header = customtkinter.CTkFrame(
            self, fg_color=colors["code_header_bg"], corner_radius=0)
        header.pack(fill="x", padx=0, pady=0)

        if language:
            lang_label = customtkinter.CTkLabel(
                header, text=language.lower(),
                font=customtkinter.CTkFont(
                    family=ui_family(), size=ui_size(10, win_bump=2)),
                text_color=muted_fg, anchor="w",
            )
            lang_label.pack(side="left", padx=(14, 0), pady=6)

        self._copy_btn = customtkinter.CTkButton(
            header, text="Copy", width=56, height=24,
            font=customtkinter.CTkFont(family=ui_family(), size=ui_size(10, win_bump=2)),
            fg_color=RESISTINE_BLUE, hover_color="#1565B0",
            text_color="#FFFFFF",
            corner_radius=6, command=self._copy_to_clipboard,
        )
        self._copy_btn.pack(side="right", padx=(0, 10), pady=5)

        # -- Code body ------------------------------------------------------
        # code_block font is ~20% smaller than prose so the monospace text
        # doesn't visually dominate the conversation.
        mono_font = fonts["code_block"]
        self.pack_propagate(False)

        self._code_widget = tk.Text(
            self, wrap="none", width=1,
            bg=colors["code_bg"], fg=colors["code_fg"],
            font=mono_font, borderwidth=0,
            padx=14, pady=10, highlightthickness=0,
            relief="flat", insertwidth=0,
        )
        self._code_widget.insert("1.0", code_text)

        line_count = code_text.count("\n") + 1
        visible = min(line_count, 25)
        self._code_widget.configure(state="disabled", height=visible)

        # -- Horizontal scrollbar -------------------------------------------
        # Packed at the BOTTOM *before* the code body so it always keeps its
        # row; the body (packed after, expand=True) fills the space above it.
        # Packing the body first lets its expand swallow the whole frame and
        # squeeze the scrollbar out of view.
        scrollbar = customtkinter.CTkScrollbar(
            self, orientation="horizontal",
            command=self._code_widget.xview,
            height=10, corner_radius=5,
            fg_color=colors["code_bg"],
            button_color=sb_color,
            button_hover_color=sb_hover)
        self._code_widget.configure(xscrollcommand=scrollbar.set)
        scrollbar.pack(side="bottom", fill="x", padx=8, pady=(0, 4))

        self._code_widget.pack(
            side="top", fill="both", expand=True, padx=0, pady=(0, 0))

        # -- Frame height ---------------------------------------------------
        import tkinter.font as tkfont
        try:
            line_h = tkfont.Font(font=mono_font).metrics("linespace")
        except Exception:
            line_h = 20
        # The code body is a raw tk.Text (physical px, not CTk-scaled). The
        # header and scrollbar are CTk widgets whose physical height scales with
        # the display factor, so budget them in LOGICAL units (CTk re-applies the
        # factor) while converting the physical text height to logical. Using
        # fixed physical constants for the header/scrollbar under-budgeted them
        # on HiDPI (Windows >=125%) and clipped the scrollbar off the bottom.
        try:
            _s = customtkinter.ScalingTracker.get_widget_scaling(self) or 1.0
        except Exception:
            _s = 1.0
        code_h_physical = visible * line_h + 20       # tk.Text lines + pady*2
        header_sb_logical = 32 + 14 + 10              # header + scrollbar + buffer
        frame_h = header_sb_logical + int(round(code_h_physical / _s))
        self.configure(height=frame_h)

    # -- Clipboard ----------------------------------------------------------

    def _copy_to_clipboard(self) -> None:
        """Copy the code text and flash confirmation on the button."""
        try:
            self.clipboard_clear()
            self.clipboard_append(self._code_text)
            self._copy_btn.configure(text="Copied!")
            self.after(1200, lambda: self._copy_btn.configure(text="Copy"))
        except Exception as exc:
            logger.warning(f"Clipboard copy failed: {exc}")
            self._copy_btn.configure(text="Failed")
            self.after(1200, lambda: self._copy_btn.configure(text="Copy"))


# ---------------------------------------------------------------------------
# TableWidget
# ---------------------------------------------------------------------------

class TableWidget(customtkinter.CTkFrame):
    """Markdown table rendered as a single selectable tk.Text.

    Columns are aligned with pixel tab stops and rows are striped with text
    tags. Using ONE text widget (instead of a grid of per-cell widgets in a
    nested canvas) lets the whole table be drag-selected and copied, and
    avoids the Windows blit "tracers"/ghosting that the nested-canvas grid
    produced when the chat scrolled. Wide tables scroll horizontally via the
    text widget's own xview.
    """

    _LPAD = 10   # left/right inner padding of the table text (px)
    _SB_H = 12   # horizontal scrollbar height + a little breathing room

    def __init__(
        self,
        master,
        headers: list[str],
        rows: list[list[str]],
        is_dark: bool = False,
        **kwargs,
    ):
        colors = get_theme_colors(is_dark)
        border_clr = colors.get("table_header_bg", "#D4D4D8")
        canvas_bg = colors.get("table_alt_bg", border_clr)

        super().__init__(master, fg_color=border_clr, corner_radius=0,
                         **kwargs)

        # Hold the size we are told to be. Without this the frame propagates
        # to its canvas content, which fights the explicit width/height the
        # markdown renderer force-applies every reflow pass — the two
        # authorities disagree at some window widths and the table oscillates
        # wider/narrower forever. pack_propagate(False) makes our configured
        # size authoritative so the reflow converges to a fixed point.
        self.pack_propagate(False)

        self._num_cols = (max(len(headers), *(len(r) for r in rows))
                          if rows else len(headers))
        self._labels: list[tk.Widget] = []

        all_rows: list[tuple[list[str], bool]] = [(headers, True)]
        for r in rows:
            all_rows.append((r, False))
        self._num_rows = len(all_rows)

        # Tab-separated text used when this table is part of a larger selection
        # copied from the response bubble (attach_emoji_copy reads _copy_text).
        self._copy_text = "\n".join(
            "\t".join(
                (cells[j] if j < len(cells) else "")
                for j in range(self._num_cols))
            for cells, _h in all_rows)

        # Dedicated table fonts (~20% smaller than prose, matching code blocks)
        # so tabular content doesn't render larger than the conversation text.
        _tbl_fonts = get_fonts(is_dark)
        header_font = _tbl_fonts["table_bold"]
        body_font = _tbl_fonts["table"]

        # Per-column pixel width: widest cell measured in the font it ACTUALLY
        # renders in (the header is bold and wider). +24 for the gutter.
        col_w = [0] * self._num_cols
        for row_cells, is_header in all_rows:
            mfont = header_font if is_header else body_font
            for j in range(self._num_cols):
                txt = row_cells[j] if j < len(row_cells) else ""
                w = mfont.measure(txt)
                if _cell_has_emoji(txt):
                    w += self._emoji_extra_px(txt, body_font)
                col_w[j] = max(col_w[j], w)
        col_w = [max(w + 24, 60) for w in col_w]
        self._col_w = col_w
        self._natural_width = sum(col_w) + self._LPAD * 2

        # A left tab stop at the start of EVERY column, including the first.
        # The first stop (at _LPAD) gives the table a left inset; because each
        # row begins with a tab, that inset is part of the tagged line and is
        # filled by the row's background — so there is no bare widget-bg strip
        # ("dark bar") down the edges.
        tabs: list[int] = []
        acc = self._LPAD
        for j in range(self._num_cols):
            tabs.append(acc)
            acc += col_w[j]

        # ── One selectable text widget (NOT a grid of per-cell widgets in a
        # nested canvas). This lets the whole table be drag-selected/copied AND
        # avoids the Windows scroll "tracers"/ghosting that many embedded
        # tk.Text cells in a nested canvas produced. Columns align via pixel
        # tab stops; rows are striped with tags; wide tables scroll
        # horizontally via the text widget's own xview.
        self._emoji_photos: list[object] = []
        self._image_to_emoji: dict[str, str] = {}
        self._text = tk.Text(
            self, wrap="none", font=body_font,
            bg=canvas_bg, fg=colors["fg"],
            borderwidth=0, highlightthickness=0, relief="flat",
            insertwidth=0, cursor="xterm", padx=0, pady=0,
            spacing1=5, spacing3=6, height=self._num_rows, width=1,
            selectbackground="#3A6DB5", selectforeground="#FFFFFF",
            inactiveselectbackground="#3A6DB5",
        )
        if tabs:
            self._text.configure(tabs=tuple(str(t) for t in tabs))
        # The table shows every row, so it must NEVER scroll vertically —
        # otherwise drag-selecting to the bottom auto-scrolls and "displaces"
        # the table. Pin the view to the top.
        self._text.configure(yscrollcommand=self._lock_yview)

        normal_bg = colors["bubble_bg"]
        if normal_bg == "transparent":
            try:
                normal_bg = master.cget("bg")
            except Exception:
                normal_bg = self.winfo_toplevel().cget("bg")
        self._text.tag_configure(
            "header", font=header_font,
            foreground=colors["heading"],
            background=colors["table_header_bg"])
        self._text.tag_configure("even", background=colors["table_alt_bg"])
        self._text.tag_configure("odd", background=normal_bg)

        for idx, (row_cells, is_header) in enumerate(all_rows):
            for j in range(self._num_cols):
                # Leading tab on every column (incl. the first) so the row's
                # background fills the left inset — no bare edge strip.
                self._text.insert("end", "\t")
                cell = row_cells[j] if j < len(row_cells) else ""
                self._insert_cell(cell, body_font)
            self._text.insert("end", "\n")
            tag = "header" if is_header else (
                "even" if idx % 2 == 0 else "odd")
            self._text.tag_add(tag, f"{idx + 1}.0", f"{idx + 2}.0")

        # The row-background tags are created AFTER the built-in "sel" tag, so
        # they out-prioritize it and paint OVER the selection (highlight looks
        # invisible). Raise "sel" to the top so selecting a cell is visible.
        self._text.tag_raise("sel")

        # Read-only but selectable: block edit keys, allow copy/select-all.
        self._text.bind("<Key>", _cell_readonly)
        _forward_cell_wheel(self._text)

        sb_color = "#3A3A3C" if is_dark else "#C8C8CC"
        sb_hover = "#555558" if is_dark else "#A8A8AC"
        self._scrollbar = customtkinter.CTkScrollbar(
            self, orientation="horizontal", command=self._text.xview,
            height=10, corner_radius=5, fg_color=border_clr,
            button_color=sb_color, button_hover_color=sb_hover)
        self._text.configure(xscrollcommand=self._scrollbar.set)
        # Always reserve the scrollbar row so showing/hiding it can't reflow
        # the bubble height and oscillate; the thumb is full when it fits.
        self._scrollbar.pack(side="bottom", fill="x")
        self._scrollbar_visible = True
        self._text.pack(side="top", fill="both", expand=True)

        self._in_resize = False
        self._last_width = 0
        self.bind("<Configure>", self._on_configure)
        self.after(0, self._apply_initial_height)

    @staticmethod
    def _emoji_extra_px(text: str, body_font) -> int:
        """Approx extra px an inline color-emoji image adds over its text."""
        try:
            n = 0
            for i, part in enumerate(_EMOJI_RE.split(text)):
                if part and i % 2 == 1:
                    n += len(MarkdownBubble._split_emoji_chars(part))
            return int(n * body_font.metrics("linespace") * 0.4)
        except Exception:
            return 0

    def _insert_cell(self, text: str, body_font) -> None:
        """Insert a cell's text at the end of the widget. On Linux, render
        inline color emoji as images (tk can't fall back per-glyph there)."""
        if not (text and _cell_has_emoji(text)
                and sys.platform.startswith("linux")):
            if text:
                self._text.insert("end", text)
            return
        for i, part in enumerate(_EMOJI_RE.split(text)):
            if not part:
                continue
            if i % 2 == 1:
                for ch in MarkdownBubble._split_emoji_chars(part):
                    photo = MarkdownBubble._render_emoji(ch)
                    if photo:
                        self._emoji_photos.append(photo)
                        name = self._text.image_create(
                            "end", image=photo, padx=1)
                        self._image_to_emoji[name] = ch
                    else:
                        self._text.insert("end", ch)
            else:
                self._text.insert("end", part)

    def desired_height(self) -> int:
        """Pixel height to show every row plus the reserved scrollbar."""
        content = 0
        try:
            self._text.update_idletasks()
            yp = self._text.count("1.0", "end-1c", "ypixels")
            content = (yp[0] if isinstance(yp, (list, tuple)) else yp) or 0
        except Exception:
            content = 0
        if int(content) <= 1:
            try:
                import tkinter.font as _tkfont
                lh = _tkfont.Font(
                    font=self._text.cget("font")).metrics("linespace")
            except Exception:
                lh = 17
            content = self._num_rows * (lh + 11)
        return int(content) + (self._SB_H if self._scrollbar_visible else 0)

    def _apply_initial_height(self) -> None:
        try:
            self.configure(height=self.desired_height())
        except Exception:
            pass

    def _lock_yview(self, first, last) -> None:
        """Pin the vertical view to the top. The table shows every row, so it
        must not scroll vertically; without this, drag-selecting past the
        bottom edge auto-scrolls the text and visually displaces the table."""
        try:
            if float(first) > 0.0:
                self._text.yview_moveto(0.0)
        except Exception:
            pass

    def _on_configure(self, event) -> None:
        if event.width > 1 and event.width != self._last_width:
            self._resize_to_width(event.width)

    def _resize_to_width(self, width: int) -> None:
        """Kept for the renderer's contract. A single text widget needs no
        per-cell relayout — horizontal overflow is handled by its own xview and
        the always-on scrollbar — so just record the width."""
        if self._in_resize or width == self._last_width:
            return
        self._in_resize = True
        self._last_width = width
        try:
            pass
        finally:
            self._in_resize = False

    def _update_scrollbar(self) -> None:
        """No-op: the horizontal scrollbar is always packed (see __init__)."""
        return


# ---------------------------------------------------------------------------
# HorizontalRule
# ---------------------------------------------------------------------------

class HorizontalRule(customtkinter.CTkFrame):
    """Thin colored strip acting as a markdown horizontal rule (``---``).

    Constructor
    -----------
    master : widget
        Parent container.
    is_dark : bool
        True for dark-mode palette, False for light.
    """

    def __init__(
        self,
        master,
        is_dark: bool = False,
        **kwargs,
    ):
        colors = get_theme_colors(is_dark)
        hr_color = colors["hr"]

        super().__init__(master, fg_color="transparent", corner_radius=0,
                         height=14, **kwargs)

        # Thin visible line
        line = customtkinter.CTkFrame(
            self,
            fg_color=hr_color,
            height=2,
            corner_radius=0,
        )
        line.pack(fill="x", padx=8, pady=(6, 6))

        # Prevent the outer frame from collapsing
        self.pack_propagate(False)
