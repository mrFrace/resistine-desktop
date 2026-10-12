"""Theme palette + Qt stylesheet generation.

Colour values follow the Phoenix brand tokens (see the PALETTE comment).
Each entry is a ``(light, dark)`` pair;
:func:`color` resolves the active one and :func:`build_qss` emits a single
application-wide stylesheet. A theme switch is one ``app.setStyleSheet(...)``
call that re-polishes the whole tree atomically — no per-widget recolour walk.

Author: Resistine Team
Copyright (c) Resistine 2025
Licensed under the GNU General Public License v2 or later
"""

from __future__ import annotations

# name -> (light, dark). Phoenix brand tokens: navy #0A1A33 / #0D2340
# surfaces, #1E6FD9 deep blue accent (white text stays >= 4.5:1), #39B4F2 /
# #5AC8FA primary/bright for highlights on dark.
PALETTE: dict[str, tuple[str, str]] = {
    "window_bg": ("#F4F7FB", "#0A1A33"),
    "card_bg": ("#FFFFFF", "#0D2340"),
    "sidebar_bg": ("#FFFFFF", "#0D2340"),
    "border": ("#DDE5EF", "#1B3558"),
    "divider": ("#DDE5EF", "#1B3558"),
    "text_primary": ("#0A1A33", "#FFFFFF"),
    "text_secondary": ("#5B6B80", "#9DB3CC"),
    "accent": ("#1E6FD9", "#1E6FD9"),
    "accent_hover": ("#185CB5", "#2A8FE0"),
    "on_accent": ("#FFFFFF", "#FFFFFF"),
    "sidebar_active_bg": ("#E3F1FC", "#12294A"),
    "sidebar_active_text": ("#1E6FD9", "#5AC8FA"),
    "sidebar_hover_bg": ("#EDF3FA", "#112645"),
    "input_bg": ("#FFFFFF", "#0D2340"),
    "track": ("#DDE5EF", "#1B3558"),
    "bubble_user_bg": ("#1E6FD9", "#1E6FD9"),
    "bubble_user_text": ("#FFFFFF", "#FFFFFF"),
    "bubble_ai_bg": ("#FFFFFF", "#0D2340"),
    "bubble_ai_text": ("#0A1A33", "#FFFFFF"),
    "scroll_handle": ("#AEBBCB", "#2E4A70"),
}

BADGE_BG: dict[str, tuple[str, str]] = {
    "ok": ("#DCFCE7", "#14532D"),
    "info": ("#DBEAFE", "#1E3A5F"),
    "warning": ("#FEF3C7", "#78350F"),
    "error": ("#FEE2E2", "#7F1D1D"),
    "critical": ("#FEE2E2", "#7F1D1D"),
}
BADGE_TEXT: dict[str, tuple[str, str]] = {
    "ok": ("#15803D", "#4ADE80"),
    "info": ("#1D4ED8", "#60A5FA"),
    "warning": ("#B45309", "#FBBF24"),
    "error": ("#DC2626", "#F87171"),
    "critical": ("#991B1B", "#F87171"),
}

_mode = "Dark"


def set_mode(mode: str) -> None:
    global _mode
    _mode = "Light" if mode == "Light" else "Dark"


def get_mode() -> str:
    return _mode


def is_dark() -> bool:
    return _mode != "Light"


def _idx() -> int:
    return 0 if _mode == "Light" else 1


def color(name: str) -> str:
    return PALETTE[name][_idx()]


def badge_colors(status: str) -> tuple[str, str]:
    key = (status or "").lower()
    i = _idx()
    bg = BADGE_BG.get(key, ("#F3F4F6", "#374151"))[i]
    fg = BADGE_TEXT.get(key, ("#6B7280", "#9CA3AF"))[i]
    return bg, fg


def build_qss() -> str:
    c = color
    badge_rules = []
    for key in ("ok", "info", "warning", "error", "critical"):
        bg, fg = badge_colors(key)
        badge_rules.append(
            f'QLabel[badge="{key}"] {{ background-color: {bg}; color: {fg}; '
            f"border-radius: 8px; padding: 3px 10px; font-weight: 600; "
            f"font-size: 11px; }}"
        )
    badge_qss = "\n".join(badge_rules)

    return f"""
* {{
    font-family: "Inter", "Segoe UI", "Helvetica Neue", Arial, sans-serif;
    font-size: 13px;
    outline: none;
}}
QWidget {{ background-color: {c('window_bg')}; color: {c('text_primary')}; }}
/* Labels are transparent by default — the QWidget rule above otherwise
   cascades a window-coloured rectangle behind every label's text. Badge
   labels re-set a background via their attribute selectors, which
   are more specific and so win over this rule. */
QLabel {{ background: transparent; }}
/* Plain container widgets opt out of the window-bg fill (which would otherwise
   paint a darker rectangle inside a lighter card) by setObjectName("Transparent").
   ID selector beats the QWidget type rule above. */
#Transparent {{ background: transparent; }}
#Divider {{ background-color: {c('divider')}; border: none; }}
QToolTip {{
    background-color: {c('card_bg')}; color: {c('text_primary')};
    border: 1px solid {c('border')}; border-radius: 6px; padding: 4px 8px;
}}

#Sidebar {{
    background-color: {c('sidebar_bg')};
    border-right: 1px solid {c('divider')};
}}
#NavButton {{
    background-color: transparent; border: none; border-radius: 12px;
    padding: 0;
}}
#NavButton:hover {{ background-color: {c('sidebar_hover_bg')}; }}
#NavButton:checked {{
    background-color: {c('sidebar_active_bg')};
    border-left: 3px solid {c('accent')};
}}

#Card {{
    background-color: {c('card_bg')}; border: 1px solid {c('border')};
    border-radius: 12px;
}}
#Card:hover {{ background-color: {c('sidebar_hover_bg')}; }}
#Surface {{
    background-color: {c('card_bg')}; border: 1px solid {c('border')};
    border-radius: 12px;
}}

QLabel#H1 {{ font-size: 24px; font-weight: 700; }}
QLabel#H2 {{ font-size: 18px; font-weight: 700; }}
QLabel#Muted {{ color: {c('text_secondary')}; }}
QLabel#CardTitle {{ font-size: 16px; font-weight: 700; }}

/* Flat page kit (gui/page_kit.py) */
QLabel#Section {{
    color: {c('text_secondary')}; font-size: 11px; font-weight: 700;
    letter-spacing: 1px;
}}
QLabel#Key {{ color: {c('text_secondary')}; }}
QLabel#Val {{ font-weight: 600; }}
QLabel#RowTitle {{ font-size: 14px; font-weight: 600; }}
QLabel#Hint {{ color: {c('text_secondary')}; font-size: 12px; }}
#MenuRow {{ background: transparent; border: none; border-radius: 12px; }}
#MenuRow:hover, #MenuRow:focus {{ background-color: {c('sidebar_hover_bg')}; }}
QLabel#RowTitle[danger="true"] {{ color: {badge_colors('error')[1]}; }}
QLabel#RowTitle:disabled {{ color: {c('text_secondary')}; }}
QLabel#MenuTile {{
    background-color: {c('sidebar_active_bg')}; border-radius: 10px;
}}
QPushButton#IconButton {{
    background: transparent; border: none; border-radius: 10px; padding: 0;
}}
QPushButton#IconButton:hover {{ background-color: {c('sidebar_hover_bg')}; }}

{badge_qss}

QPushButton {{
    background-color: {c('accent')}; color: {c('on_accent')};
    border: none; border-radius: 10px; padding: 9px 18px;
    font-size: 13px; font-weight: 600;
}}
QPushButton:hover {{ background-color: {c('accent_hover')}; }}
QPushButton:disabled {{ background-color: {c('track')}; color: {c('text_secondary')}; }}
QPushButton#Secondary {{
    background-color: transparent; color: {c('text_primary')};
    border: 1px solid {c('border')};
}}
QPushButton#Secondary:hover {{ background-color: {c('sidebar_hover_bg')}; }}
QPushButton#SurfaceBtn {{
    background-color: {c('card_bg')}; color: {c('text_primary')};
    border: 1px solid {c('border')}; border-radius: 10px; font-weight: 600;
}}
QPushButton#SurfaceBtn:hover {{ background-color: {c('sidebar_hover_bg')}; }}
QPushButton#Danger {{ background-color: #DC2626; }}
QPushButton#Danger:hover {{ background-color: #B91C1C; }}
QPushButton#Link {{
    background-color: transparent; color: {c('accent')};
    border: none; padding: 4px; font-weight: 600;
}}

QLineEdit, QComboBox, QPlainTextEdit, QTextEdit, QSpinBox {{
    background-color: {c('input_bg')}; color: {c('text_primary')};
    border: 2px solid {c('border')}; border-radius: 8px; padding: 7px 10px;
    selection-background-color: {c('accent')};
}}
QLineEdit:focus, QComboBox:focus, QPlainTextEdit:focus, QTextEdit:focus, QSpinBox:focus {{
    border: 2px solid {c('accent')};
}}
QComboBox::drop-down {{ border: none; width: 22px; }}
QComboBox QAbstractItemView {{
    background-color: {c('card_bg')}; color: {c('text_primary')};
    border: 1px solid {c('border')};
    selection-background-color: {c('accent')}; selection-color: #FFFFFF;
}}
QTextBrowser {{ background-color: transparent; border: none; }}

QProgressBar {{
    background-color: {c('track')}; border: none; border-radius: 6px;
    height: 10px; text-align: center; color: transparent;
}}
QProgressBar::chunk {{ background-color: {c('accent')}; border-radius: 6px; }}

QCheckBox {{ spacing: 8px; background: transparent; }}
QCheckBox::indicator {{
    width: 18px; height: 18px; border-radius: 5px;
    border: 2px solid {c('border')}; background-color: {c('input_bg')};
}}
QCheckBox::indicator:checked {{
    background-color: {c('accent')}; border-color: {c('accent')};
}}

QScrollArea {{ border: none; background-color: transparent; }}
QScrollBar:vertical {{ background: transparent; width: 12px; margin: 2px; }}
QScrollBar::handle:vertical {{
    /* radius must be <= half the handle width or Qt silently drops the
       rounding and paints square corners. */
    background: {c('scroll_handle')}; border-radius: 4px; min-height: 30px;
}}
QScrollBar::handle:vertical:hover {{ background: {c('accent')}; }}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{ height: 0; }}
QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical {{ background: none; }}
QScrollBar:horizontal {{ height: 0px; }}
"""
