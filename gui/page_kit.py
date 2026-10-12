"""Flat page kit: the shared look of every plugin screen.

No nested cards. A screen is a left-aligned column with even margins:

* a :class:`PageHeader`: title, status pill, one muted subtitle line and
  controls on the right (a gear, a toggle);
* small uppercase :func:`section_heading` labels;
* label/value rows split by hairlines (:class:`KVList`) and settings rows
  (:class:`SettingRow`) inside a :class:`RowList`;
* actions as :class:`MenuRow` — flat rows styled like the sidebar items
  (icon tile, title, hint, chevron) that highlight on hover.

Icons are Lucide line icons in ``resources/icons/ui`` (:func:`line_icon`).
The QSS for the object names used here lives in ``gui/theme.py``.

Author: Resistine Team
Copyright (c) Resistine 2025
Licensed under the GNU General Public License v2 or later
"""

from __future__ import annotations

import os

from PyQt6.QtCore import QByteArray, QRectF, QSize, Qt, pyqtSignal
from PyQt6.QtGui import QIcon, QPainter, QPixmap
from PyQt6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

from gui import theme
from gui.qt_widgets import resource, scroll_page, set_pill

PAGE_MAX_WIDTH = 760

_ICON_DIR = resource("resources", "icons", "ui")
_svg_cache: dict[str, str] = {}


def line_icon(name: str, color: str | None = None, size: int = 20) -> QPixmap:
    """Render the Lucide icon ``name`` at ``size`` px in ``color``
    (default: primary text colour), HiDPI-crisp."""
    from PyQt6.QtSvg import QSvgRenderer

    src = _svg_cache.get(name)
    if src is None:
        path = os.path.join(_ICON_DIR, f"{name}.svg")
        try:
            with open(path, encoding="utf-8") as f:
                src = f.read()
        except OSError:
            src = ""
        _svg_cache[name] = src
    ratio = 2
    pm = QPixmap(size * ratio, size * ratio)
    pm.fill(Qt.GlobalColor.transparent)
    if src:
        svg = src.replace("#000000", color or theme.color("text_primary"))
        renderer = QSvgRenderer(QByteArray(svg.encode()))
        p = QPainter(pm)
        renderer.render(p, QRectF(0, 0, size * ratio, size * ratio))
        p.end()
    pm.setDevicePixelRatio(ratio)
    return pm


def icon_button(name: str, tooltip: str, size: int = 20) -> QPushButton:
    """A borderless icon-only button (e.g. the settings gear in a header)."""
    btn = QPushButton()
    btn.setObjectName("IconButton")
    btn.setCursor(Qt.CursorShape.PointingHandCursor)
    btn.setToolTip(tooltip)
    btn.setAccessibleName(tooltip)
    btn.setIcon(QIcon(line_icon(name, theme.color("text_secondary"), size)))
    btn.setIconSize(QSize(size, size))
    btn.setFixedSize(size + 20, size + 20)
    return btn


def section_heading(text: str) -> QLabel:
    lbl = QLabel(text.upper())
    lbl.setObjectName("Section")
    return lbl


def hairline() -> QFrame:
    d = QFrame()
    d.setObjectName("Divider")
    d.setFixedHeight(1)
    return d


def muted(text: str, wrap: bool = True) -> QLabel:
    lbl = QLabel(text)
    lbl.setObjectName("Muted")
    lbl.setWordWrap(wrap)
    return lbl


class Page:
    """A scrolling, left-aligned content column.

    ``page.widget`` is what ``create_main_screen`` returns; add content with
    :meth:`add`, :meth:`add_layout`, :meth:`section` and finish with
    :meth:`stretch` (keeps content top-packed).
    """

    def __init__(self, max_width: int = PAGE_MAX_WIDTH):
        outer = QWidget()
        h = QHBoxLayout(outer)
        h.setContentsMargins(48, 36, 48, 32)
        h.setSpacing(0)
        self.column = QWidget()
        self.column.setObjectName("Transparent")
        self.column.setMaximumWidth(max_width)
        self.body = QVBoxLayout(self.column)
        self.body.setContentsMargins(0, 0, 0, 0)
        self.body.setSpacing(0)
        # The column grows up to max_width; the trailing stretch then takes
        # the rest, so wide windows keep the content against the left edge.
        h.addWidget(self.column, 1)
        h.addStretch(0)
        self.widget = scroll_page(outer)

    def add(self, widget: QWidget, stretch: int = 0) -> QWidget:
        self.body.addWidget(widget, stretch)
        return widget

    def add_layout(self, layout) -> None:
        self.body.addLayout(layout)

    def spacing(self, px: int) -> None:
        self.body.addSpacing(px)

    def section(self, title: str, top: int = 28) -> QLabel:
        """A section heading with breathing room above it."""
        self.body.addSpacing(top)
        lbl = section_heading(title)
        self.body.addWidget(lbl)
        self.body.addSpacing(8)
        return lbl

    def stretch(self) -> None:
        self.body.addStretch(1)


class PageHeader(QWidget):
    """Title + status pill on one line, a muted subtitle under it, and
    controls (gear, toggle, buttons) on the right."""

    def __init__(self, title: str, subtitle: str = "",
                 status: tuple[str, str] | None = None):
        super().__init__()
        self.setObjectName("Transparent")
        row = QHBoxLayout(self)
        row.setContentsMargins(0, 0, 0, 0)
        row.setSpacing(12)
        text = QVBoxLayout()
        text.setSpacing(4)
        line = QHBoxLayout()
        line.setSpacing(12)
        self.title = QLabel(title)
        self.title.setObjectName("H1")
        line.addWidget(self.title, 0, Qt.AlignmentFlag.AlignVCenter)
        self.pill = QLabel()
        self.pill.hide()
        line.addWidget(self.pill, 0, Qt.AlignmentFlag.AlignVCenter)
        line.addStretch(1)
        text.addLayout(line)
        self.subtitle = muted(subtitle)
        self.subtitle.setVisible(bool(subtitle))
        text.addWidget(self.subtitle)
        row.addLayout(text, 1)
        self._controls = QHBoxLayout()
        self._controls.setSpacing(8)
        row.addLayout(self._controls)
        if status:
            self.set_status(*status)

    def set_status(self, kind: str | None, text: str = "") -> None:
        """Pill colour by ``kind`` (ok/info/warning/error); None hides it."""
        if not kind:
            self.pill.hide()
            return
        set_pill(self.pill, kind, text)
        self.pill.show()

    def set_subtitle(self, text: str) -> None:
        self.subtitle.setText(text)
        self.subtitle.setVisible(bool(text))

    def add_control(self, widget: QWidget) -> QWidget:
        self._controls.addWidget(widget, 0, Qt.AlignmentFlag.AlignVCenter)
        return widget


class RowList(QWidget):
    """A vertical list of rows separated by hairlines."""

    def __init__(self):
        super().__init__()
        self.setObjectName("Transparent")
        self._lay = QVBoxLayout(self)
        self._lay.setContentsMargins(0, 0, 0, 0)
        self._lay.setSpacing(0)
        self._rows: list[QWidget] = []

    def add_row(self, widget: QWidget) -> QWidget:
        if self._rows:
            self._lay.addWidget(hairline())
        self._lay.addWidget(widget)
        self._rows.append(widget)
        return widget

    def clear(self) -> None:
        while self._lay.count():
            w = self._lay.takeAt(0).widget()
            if w is not None:
                w.deleteLater()
        self._rows = []

    def count(self) -> int:
        return len(self._rows)


class KVList(RowList):
    """Label/value rows; values are selectable and can be updated by key."""

    def __init__(self, rows=()):
        super().__init__()
        self.values: dict[str, QLabel] = {}
        self.set_rows(rows)

    def set_rows(self, rows) -> None:
        self.clear()
        self.values = {}
        for key, val in rows:
            self.add(key, val)

    def add(self, key: str, val: str) -> QLabel:
        row = QWidget()
        row.setObjectName("Transparent")
        h = QHBoxLayout(row)
        h.setContentsMargins(0, 9, 0, 9)
        h.setSpacing(24)
        k = QLabel(key)
        k.setObjectName("Key")
        h.addWidget(k, 0, Qt.AlignmentFlag.AlignTop)
        v = QLabel(str(val))
        v.setObjectName("Val")
        v.setWordWrap(True)
        v.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignTop)
        v.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        h.addWidget(v, 1)
        self.add_row(row)
        self.values[key] = v
        return v

    def set_value(self, key: str, val: str) -> None:
        lbl = self.values.get(key)
        if lbl is None:
            self.add(key, val)
        else:
            lbl.setText(str(val))


class MenuRow(QFrame):
    """A clickable action row styled like a sidebar item: icon tile, title,
    hint and a chevron. ``setText``/``text`` alias the title so it can stand
    in for a QPushButton."""

    clicked = pyqtSignal()

    def __init__(self, icon: str, title: str, hint: str = "",
                 on_click=None, danger: bool = False, chevron: bool = True):
        super().__init__()
        self.setObjectName("MenuRow")
        self.setAttribute(Qt.WidgetAttribute.WA_Hover, True)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
        self.setSizePolicy(QSizePolicy.Policy.Expanding,
                           QSizePolicy.Policy.Fixed)
        self._icon_name = icon
        self._danger = danger
        h = QHBoxLayout(self)
        h.setContentsMargins(12, 10, 12, 10)
        h.setSpacing(14)
        self._tile = QLabel()
        self._tile.setObjectName("MenuTile")
        self._tile.setFixedSize(36, 36)
        self._tile.setAlignment(Qt.AlignmentFlag.AlignCenter)
        h.addWidget(self._tile)
        text = QVBoxLayout()
        text.setSpacing(1)
        self._title = QLabel(title)
        self._title.setObjectName("RowTitle")
        self._title.setProperty("danger", danger)
        text.addWidget(self._title)
        self._hint = QLabel(hint)
        self._hint.setObjectName("Hint")
        self._hint.setWordWrap(True)
        self._hint.setVisible(bool(hint))
        text.addWidget(self._hint)
        h.addLayout(text, 1)
        self._chev = QLabel()
        self._chev.setPixmap(
            line_icon("chevron-right", theme.color("text_secondary"), 18))
        self._chev.setVisible(chevron)
        h.addWidget(self._chev)
        for w in (self._tile, self._title, self._hint, self._chev):
            w.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)
        self.setAccessibleName(title)
        self._paint_icon()
        if on_click is not None:
            self.clicked.connect(on_click)

    def _paint_icon(self) -> None:
        if not self.isEnabled():
            color = theme.color("text_secondary")
        elif self._danger:
            color = theme.badge_colors("error")[1]
        else:
            color = theme.color("sidebar_active_text")
        self._tile.setPixmap(line_icon(self._icon_name, color, 20))

    # QPushButton-compatible bits used by plugin code.
    def setText(self, text: str) -> None:  # noqa: N802 (Qt naming)
        self._title.setText(text)

    def text(self) -> str:
        return self._title.text()

    def set_hint(self, text: str) -> None:
        self._hint.setText(text)
        self._hint.setVisible(bool(text))

    def changeEvent(self, e):  # noqa: N802
        super().changeEvent(e)
        if e.type() == e.Type.EnabledChange:
            self._paint_icon()
            self.setCursor(Qt.CursorShape.PointingHandCursor if self.isEnabled()
                           else Qt.CursorShape.ArrowCursor)

    def mouseReleaseEvent(self, e):  # noqa: N802
        if (e.button() == Qt.MouseButton.LeftButton and self.isEnabled()
                and self.rect().contains(e.position().toPoint())):
            self.clicked.emit()
        super().mouseReleaseEvent(e)

    def keyPressEvent(self, e):  # noqa: N802
        if e.key() in (Qt.Key.Key_Return, Qt.Key.Key_Enter, Qt.Key.Key_Space):
            if self.isEnabled():
                self.clicked.emit()
            return
        super().keyPressEvent(e)


class SettingRow(QWidget):
    """A flat settings row: title + hint on the left, a control on the
    right. ``stacked=True`` puts a wide control (line edit, combo) under the
    text instead."""

    def __init__(self, title: str, hint: str = "", control: QWidget | None = None,
                 stacked: bool = False):
        super().__init__()
        self.setObjectName("Transparent")
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 10, 0, 10)
        outer.setSpacing(8)
        top = QHBoxLayout()
        top.setSpacing(16)
        text = QVBoxLayout()
        text.setSpacing(1)
        self.title = QLabel(title)
        self.title.setObjectName("RowTitle")
        text.addWidget(self.title)
        self.hint = QLabel(hint)
        self.hint.setObjectName("Hint")
        self.hint.setWordWrap(True)
        self.hint.setVisible(bool(hint))
        text.addWidget(self.hint)
        top.addLayout(text, 1)
        outer.addLayout(top)
        self.body = outer
        if control is not None:
            if stacked:
                outer.addWidget(control)
            else:
                top.addWidget(control, 0, Qt.AlignmentFlag.AlignVCenter)

    def set_hint(self, text: str) -> None:
        self.hint.setText(text)
        self.hint.setVisible(bool(text))
