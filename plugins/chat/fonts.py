"""Named tkFont.Font registry for the chat plugin.

Canonical source for every font and colour used in chat bubbles.
All font usage goes through named Font objects derived from a single
base size, which fixes the "oversized bold" bug.

Author: P3 and the Resistine Team
Copyright (c) Resistine 2025
Licensed under the GNU General Public License v2 or later
"""

from __future__ import annotations

import sys
import tkinter as _tk
import tkinter.font as tkFont

import customtkinter

RESISTINE_BLUE = "#0D5394"

# -- Base metrics (px) --------------------------------------------------------
# Body text size for AI responses (matched in bubble.py for user messages).
# Windows's default UI font renders denser at the same point size, so it gets
# a +3pt bump to roughly equalize perceived size against macOS's system font.
# Mac / Linux keep the historical 15pt baseline — bumping them across the
# board broke chat bubble widths, table reflow, and welcome-screen layout
# that had been tuned at that size.
# Code blocks / tables render ~1pt below body so monospace / tabular content
# doesn't visually dominate the prose.
# Heading sizes scale around the body so the hierarchy holds at either base.
if sys.platform.startswith("win"):
    _BASE_SIZE = 18
    _CODE_BLOCK_SIZE = 14
    _HEADING_SIZES = {"h1": 25, "h2": 23, "h3": 20, "h4": 19, "h5": 18, "h6": 17}
elif sys.platform.startswith("linux"):
    _BASE_SIZE = 18
    _CODE_BLOCK_SIZE = 14
    _HEADING_SIZES = {"h1": 25, "h2": 23, "h3": 20, "h4": 19, "h5": 18, "h6": 17}
else:  # Darwin
    _BASE_SIZE = 15
    _CODE_BLOCK_SIZE = 13
    _HEADING_SIZES = {"h1": 20, "h2": 18, "h3": 16, "h4": 15, "h5": 14, "h6": 13}

if sys.platform.startswith("win"):
    _MONO_FAMILY = "Consolas"
elif sys.platform.startswith("linux"):
    _MONO_FAMILY = "DejaVu Sans Mono"
else:
    _MONO_FAMILY = "Menlo"

# Resolved once, after a Tk root exists. The chat hard-coded "Inter" everywhere,
# but Inter is never installed or registered, so on Windows Tk silently falls
# back to a tiny default font. Resolve a real, installed UI family per OS.
_BODY_FAMILY: str | None = None

# -- Internal state -----------------------------------------------------------
_font_cache: dict[str, tkFont.Font] | None = None


def _is_dark_mode() -> bool:
    """Detect whether the current CTk appearance mode is dark."""
    mode = customtkinter.get_appearance_mode()
    if mode == "Dark":
        return True
    if mode == "Light":
        return False
    if sys.platform == "darwin":
        try:
            import subprocess

            result = subprocess.run(
                ["defaults", "read", "-g", "AppleInterfaceStyle"],
                capture_output=True,
                text=True,
            )
            return result.returncode == 0 and "Dark" in result.stdout
        except Exception:
            return False
    return False


def _named(name: str, **kw: object) -> tkFont.Font:
    """Create or retrieve a named Tk font."""
    try:
        return tkFont.Font(name=name, exists=True)
    except _tk.TclError:
        return tkFont.Font(name=name, exists=False, **kw)


def _resolve_family() -> str:
    """Return a real, installed UI font family for this platform.

    Requires a Tk root (``tkFont.families`` needs one); every caller runs
    inside widget construction, well after the App root exists. Result is
    cached so every chat widget shares one identical family.
    """
    global _BODY_FAMILY
    if _BODY_FAMILY is not None:
        return _BODY_FAMILY
    try:
        available = {f.lower() for f in tkFont.families()}
    except Exception:
        available = set()
    if sys.platform == "darwin":
        prefs = ["Inter", "SF Pro Text", "Helvetica Neue", ".AppleSystemUIFont"]
    elif sys.platform.startswith("win"):
        prefs = ["Inter", "Segoe UI"]
    else:
        prefs = ["Inter", "DejaVu Sans", "Noto Sans", "Cantarell"]
    chosen = next((p for p in prefs if p.lower() in available), None)
    # macOS hides system fonts from families(); fall back to the system UI font
    # name, which Tk resolves even though it isn't enumerated.
    if chosen is None and sys.platform == "darwin":
        chosen = ".AppleSystemUIFont"
    _BODY_FAMILY = chosen or (
        "Segoe UI" if sys.platform.startswith("win") else "TkDefaultFont")
    return _BODY_FAMILY


def ui_family() -> str:
    """Public accessor for the resolved chat UI body family."""
    return _resolve_family()


def ui_size(base: int, win_bump: int = 0) -> int:
    """Platform-aware font size.

    Bumps the size only on Windows (whose default UI font renders smaller /
    denser than macOS's system font at the same point size). macOS and Linux
    keep ``base`` unchanged so their already-good look is never altered.
    """
    if win_bump and sys.platform.startswith("win"):
        return base + win_bump
    return base


def get_fonts(is_dark: bool = False) -> dict[str, tkFont.Font]:
    """Return a dict of named ``tkFont.Font`` objects for the chat UI.

    Fonts are created once and cached.  Calling again returns the same
    objects so ``tag_configure`` can reference the name strings directly.
    """
    global _font_cache
    if _font_cache is not None:
        return _font_cache

    fam = _resolve_family()
    fonts: dict[str, tkFont.Font] = {
        "body": _named("chat_body", family=fam, size=_BASE_SIZE),
        "bold": _named("chat_bold", family=fam, size=_BASE_SIZE, weight="bold"),
        "italic": _named(
            "chat_italic", family=fam, size=_BASE_SIZE, slant="italic"),
        "bold_italic": _named(
            "chat_bold_italic", family=fam, size=_BASE_SIZE,
            weight="bold", slant="italic"),
        "code": _named("chat_code", family=_MONO_FAMILY, size=_BASE_SIZE),
        # Code-block body + table cells: ~20% smaller than prose so they don't
        # dwarf the conversation text (see _CODE_BLOCK_SIZE).
        "code_block": _named(
            "chat_code_block", family=_MONO_FAMILY, size=_CODE_BLOCK_SIZE),
        "table": _named("chat_table", family=fam, size=_CODE_BLOCK_SIZE),
        "table_bold": _named(
            "chat_table_bold", family=fam, size=_CODE_BLOCK_SIZE, weight="bold"),
        "link": _named(
            "chat_link", family=fam, size=_BASE_SIZE, underline=True),
        "strikethrough": _named(
            "chat_strike", family=fam, size=_BASE_SIZE, overstrike=True),
    }
    for tag, sz in _HEADING_SIZES.items():
        fonts[tag] = _named(
            f"chat_{tag}", family=fam, size=sz, weight="bold",
        )

    _font_cache = fonts
    return fonts


def get_theme_colors(is_dark: bool) -> dict[str, str]:
    """Return a dict of colour strings keyed by semantic role."""
    if is_dark:
        return {
            "bg": "transparent",
            "fg": "#e0e0e0",
            "bubble_bg": "#2E2E32",
            "bubble_fg": "#e0e0e0",
            "user_bubble_bg": "#0D5394",
            "user_bubble_fg": "#FFFFFF",
            "code_bg": "#2A2A2C",
            "code_fg": "#d4d4d4",
            "code_header_bg": "#252528",
            "link": "#60A5FA",
            "heading": "#FFFFFF",
            "blockquote_bar": "#9CA3AF",
            "hr": "#2A2A2A",
            "table_header_bg": "#252528",
            "table_alt_bg": "#1E1E20",
            "prose_bg": "#242424",
        }
    return {
        "bg": "transparent",
        "fg": "#1a1a1a",
        "bubble_bg": "#F7F7F9",
        "bubble_fg": "#1a1a1a",
        "user_bubble_bg": "#0D5394",
        "user_bubble_fg": "#FFFFFF",
        "code_bg": "#F5F5F7",
        "code_fg": "#333333",
        "code_header_bg": "#E8E8EA",
        "link": "#0D5394",
        "heading": "#111111",
        "blockquote_bar": "#6B7280",
        "hr": "#E5E7EB",
        "table_header_bg": "#E8E8EA",
        "table_alt_bg": "#F5F5F7",
        "prose_bg": "#EBEBEB",
    }
