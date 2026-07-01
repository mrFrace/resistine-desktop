"""Chat bubble widgets: BubbleRow and UserBubble.

Self-contained CTkFrame widgets packed into a CTkScrollableFrame to form
the chat conversation.

Author: P3 and the Resistine Team
Copyright (c) Resistine 2025
Licensed under the GNU General Public License v2 or later
"""

from __future__ import annotations

import sys
import tkinter as tk

import customtkinter

from plugins.chat.assistant_bubble import AssistantBubble  # noqa: F401
from plugins.chat.fonts import _BASE_SIZE, get_theme_colors, ui_family
from plugins.chat.markdown_widgets import SelectableLabel

# ---------------------------------------------------------------------------
# Width constants
# ---------------------------------------------------------------------------

_ASST_RATIO, _ASST_MAX, _ASST_MIN = 0.72, 900, 200  # assistant bubble
_USER_RATIO, _USER_MAX, _USER_MIN = 0.75, 600, 200  # user bubble


def _clamp(value: int, lo: int, hi: int) -> int:
    return max(lo, min(hi, value))


def user_width(available: int) -> int:
    """Compute user bubble width from available scroll-frame width."""
    return _clamp(int(available * _USER_RATIO), _USER_MIN, _USER_MAX)


def assistant_width(available: int) -> int:
    """Compute assistant bubble width from available scroll-frame width."""
    return _clamp(int(available * _ASST_RATIO), _ASST_MIN, _ASST_MAX)


# ---------------------------------------------------------------------------
# BubbleRow
# ---------------------------------------------------------------------------

class BubbleRow(customtkinter.CTkFrame):
    """Transparent full-width row that holds a single chat bubble."""

    def __init__(self, master: object, **kwargs: object) -> None:
        kwargs.setdefault("fg_color", "transparent")
        super().__init__(master, **kwargs)
        self.pack(fill="x", padx=0, pady=4)


# ---------------------------------------------------------------------------
# UserBubble
# ---------------------------------------------------------------------------

class UserBubble(customtkinter.CTkFrame):
    """Right-aligned bubble for user messages.

    Args:
        master: Parent widget (usually a BubbleRow).
        text: Plain-text user message.
        is_dark: Dark-mode flag.
        max_width: Maximum pixel width for text wrap.
    """

    _CORNER_RADIUS = 18
    _PAD_X = 9
    _PAD_Y = 11

    def __init__(
        self, master: object, text: str,
        is_dark: bool = False, max_width: int = 600,
        **kwargs: object,
    ) -> None:
        colors = get_theme_colors(is_dark)
        self._bg = colors["user_bubble_bg"]
        self._fg = colors["user_bubble_fg"]

        kwargs.setdefault("fg_color", self._bg)
        kwargs.setdefault("corner_radius", self._CORNER_RADIUS)
        super().__init__(master, **kwargs)
        self.pack(side="right", padx=(0, 12))

        self._text = text
        self._is_dark = is_dark
        self._max_width = max_width
        self._emoji_widget: tk.Text | None = None
        self._label: customtkinter.CTkLabel | None = None

        if self._needs_emoji_path(text):
            self._build_emoji(text, max_width)
        else:
            self._build_label(text, max_width)

    # -- construction helpers -----------------------------------------------

    @staticmethod
    def _needs_emoji_path(text: str) -> bool:
        """True when emoji image rendering is needed (Linux only)."""
        if sys.platform != "linux":
            return False
        try:
            from plugins.chat.markdown_bubble import (
                _EMOJI_RE, _EMOJI_RENDER,
            )
            return bool(
                _EMOJI_RENDER and _EMOJI_RE and _EMOJI_RE.search(text))
        except ImportError:
            return False

    def _build_label(self, text: str, max_width: int) -> None:
        # SelectableLabel is a raw tk.Text — CTk's auto-scaling doesn't apply
        # to its font or to pack(). Scale these manually so the bubble's
        # visible size matches what the rest of the UI does at HiDPI.
        self._scale = getattr(self.winfo_toplevel(), "_hidpi_factor", 1.0)
        self._label = SelectableLabel(
            self, text=text, bg=self._bg, fg=self._fg,
            font=customtkinter.CTkFont(family=ui_family(), size=int(_BASE_SIZE * self._scale)),
            max_width=int(max_width * self._scale),
        )
        self._label.pack(
            padx=int(self._PAD_X * self._scale),
            pady=int(self._PAD_Y * self._scale),
        )
        # Force layout/font resolution before the bubble is measured by the
        # parent so autoheight can compute displaylines against the actual
        # widget size.
        self._label.update_idletasks()
        self.update_idletasks()

    def _build_emoji(self, text: str, max_width: int) -> None:
        """Linux emoji path: tk.Text with inline emoji images."""
        from plugins.chat.markdown_bubble import (
            MarkdownBubble, _EMOJI_RE, attach_emoji_copy,
        )

        # tk.Text doesn't get CTk's auto-scaling for its font, so the text
        # and emoji glyphs render too small on HiDPI. Scale ONLY the font and
        # emoji image size — the bubble's own dimensions (max_width, insets)
        # are already correct and must not be scaled.
        self._scale = getattr(self.winfo_toplevel(), "_hidpi_factor", 1.0)
        _user_font = customtkinter.CTkFont(
            family=ui_family(), size=int(_BASE_SIZE * self._scale))
        tw = tk.Text(
            self, bg=self._bg, fg=self._fg, font=_user_font,
            wrap="word", borderwidth=0, highlightthickness=0,
            padx=8, pady=1, cursor="xterm", insertwidth=0,
        )
        tw.configure(state="normal")

        emoji_size = int(20 * self._scale)
        emoji_photos: list[object] = []
        image_to_emoji: dict[str, str] = {}
        for i, part in enumerate(_EMOJI_RE.split(text)):
            if not part:
                continue
            if i % 2 == 1:
                for ch in MarkdownBubble._split_emoji_chars(part):
                    photo = MarkdownBubble._render_emoji(ch, size=emoji_size)
                    if photo:
                        emoji_photos.append(photo)
                        img_name = tw.image_create(
                            "end", image=photo, padx=1)
                        image_to_emoji[img_name] = ch
                    else:
                        tw.insert("end", ch)
            else:
                tw.insert("end", part)

        tw.configure(state="disabled")
        tags = tw.bindtags()
        tw.bindtags(tuple(t for t in tags if t != "Text"))
        tw._emoji_photos = emoji_photos  # type: ignore[attr-defined]
        tw._image_to_emoji = image_to_emoji  # type: ignore[attr-defined]
        attach_emoji_copy(tw, image_to_emoji)

        self._emoji_widget = tw
        self._layout_emoji(tw, max_width)

    def _layout_emoji(self, tw: tk.Text, max_width: int) -> None:
        """Measure and apply final dimensions for emoji text widget.

        ``tw`` is a raw tk.Text, so ``place(width=...)`` is in PHYSICAL px
        (its font is already scaled). ``self`` is a CTkFrame, so
        ``configure(width=...)`` is LOGICAL — CTk re-applies the scale factor.
        Place the text widget at the bubble's scaled inner width or it wraps
        at half-width and gets clipped on HiDPI.

        Height is measured via ``tw.count('ypixels')`` which only returns
        valid display-line info for a widget that's actually in the viewport,
        so we temporarily grow the bubble tall, measure, then shrink.
        """
        scale = getattr(self, "_scale", 1.0)
        inset = 10  # logical inset for the CTk bubble
        padx_val = int(str(tw.cget("padx") or 0))  # physical (raw tw)

        # 1. Natural (unwrapped) text width — physical, because tw's font is
        #    already scaled. Cap against max_width (logical) converted to px.
        #    ``count -xpixels`` across newlines returns the x-displacement of
        #    end-1c on *its own* line (often the last paragraph), not the
        #    max line width. Iterate lines and take the max so multi-line
        #    messages get an appropriately wide bubble.
        tw.configure(wrap="none")
        natural_w_phys = int(max_width * scale)
        try:
            last_line = int(tw.index("end-1c").split(".")[0])
            max_x = 0
            for line_no in range(1, last_line + 1):
                result = tw.count(
                    f"{line_no}.0", f"{line_no}.end", "xpixels")
                if result is None:
                    continue
                xpx = (result[0] if isinstance(result, (list, tuple))
                       else result)
                max_x = max(max_x, int(xpx))
            if max_x > 0:
                natural_w_phys = max_x + padx_val * 2
        except Exception:
            pass
        text_w_phys = min(natural_w_phys, int(max_width * scale))

        tw.configure(wrap="word")

        # 2. Measure wrapped height by rendering in the (mapped) bubble.
        import tkinter.font as tkfont
        content_h_phys = tkfont.Font(
            font=(ui_family(), int(18 * scale))).metrics("linespace") + 4
        tw.place(in_=self, x=int(inset * scale), y=int(inset * scale),
                 width=text_w_phys, height=int(500 * scale))
        self.configure(
            width=int(text_w_phys / scale + 2 * inset),
            height=int(500 + 2 * inset),
        )
        self.update_idletasks()
        try:
            result = tw.count("1.0", "end", "ypixels")
            val = (result[0] if isinstance(result, (list, tuple))
                   else result)
            if val:
                content_h_phys = int(val) + 4
        except Exception:
            pass

        # 3. Shrink to the measured height.
        tw.place_configure(height=content_h_phys)
        self.configure(height=int(content_h_phys / scale + 2 * inset))
        self.pack_propagate(False)

    # -- public API ---------------------------------------------------------

    def set_width(self, max_width: int) -> None:
        """Update wraplength on resize."""
        # Skip when the width hasn't changed. The emoji path's _layout_emoji
        # temporarily grows the bubble to 520 px to measure wrapped-text
        # height, which is visible to the user as a height flicker. Calling
        # it on every scroll-triggered <Configure> (where max_width is
        # unchanged) is wasted work and produces the visible blip.
        if max_width == self._max_width:
            return
        self._max_width = max_width
        if self._label is not None:
            # SelectableLabel was created with a scaled font and expects a
            # scaled max_width — apply the same factor here.
            scale = getattr(self, "_scale", 1.0)
            self._label.set_width(int(max_width * scale))
        elif self._emoji_widget is not None:
            # Emoji path: only the font/glyphs are scaled, not the bubble
            # dimensions, so max_width is passed through unscaled.
            self._layout_emoji(self._emoji_widget, max_width)
