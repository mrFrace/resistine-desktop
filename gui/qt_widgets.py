"""Reusable presentational widgets for the PyQt UI.

Small building blocks shared across plugin screens — a flow layout that reflows
cards on resize, status badges, section cards, an icon loader that picks the
light/dark PNG variant, and a couple of layout helpers.

Author: Resistine Team
Copyright (c) Resistine 2025
Licensed under the GNU General Public License v2 or later
"""

from __future__ import annotations

import os

from PyQt6.QtCore import QTimer, QPoint, QRect, QSize, Qt
from PyQt6.QtGui import QIcon, QPixmap
from PyQt6.QtWidgets import (
    QBoxLayout,
    QGridLayout,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLayout,
    QScrollArea,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

from gui import theme

_ROOT = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))


def resource(*parts: str) -> str:
    """Absolute path under the repo root (e.g. resource('resources','icons'))."""
    return os.path.join(_ROOT, *parts)


def load_icon(light_path: str, dark_path: str) -> QIcon:
    """Pick the icon variant matching the active appearance mode."""
    path = light_path if not theme.is_dark() else dark_path
    if path and os.path.isfile(path):
        return QIcon(path)
    return QIcon()


def pixmap(path: str, size: int) -> QPixmap:
    if path and os.path.isfile(path):
        return QPixmap(path).scaled(
            size, size,
            Qt.AspectRatioMode.KeepAspectRatio,
            Qt.TransformationMode.SmoothTransformation,
        )
    return QPixmap()


class StatusBadge(QLabel):
    """A small rounded pill coloured by status (ok/info/warning/error/...)."""

    def __init__(self, status: str | None, parent: QWidget | None = None):
        super().__init__(parent)
        self.set_status(status)

    def set_status(self, status: str | None) -> None:
        if not status:
            self.hide()
            return
        # Only explicitly show() when parented — show() on a parentless
        # widget makes it a visible TOP-LEVEL window, and on macOS spawning
        # a window while fullscreen kicks the app out of its Space (the
        # "window disappears when opening the Store" bug). Once added to a
        # layout the badge becomes visible with its parent anyway.
        if self.parent() is not None:
            self.show()
        self.setText(str(status).title())
        self.setProperty("badge", str(status).lower())
        self.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.setSizePolicy(QSizePolicy.Policy.Maximum, QSizePolicy.Policy.Fixed)
        self.style().unpolish(self)
        self.style().polish(self)


class Card(QFrame):
    """A bordered, rounded surface used for cards and panels."""

    def __init__(self, parent: QWidget | None = None, object_name: str = "Card"):
        super().__init__(parent)
        self.setObjectName(object_name)
        self.setFrameShape(QFrame.Shape.NoFrame)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(16, 16, 16, 16)
        lay.setSpacing(8)
        self.body = lay


def section_title(text: str) -> QLabel:
    lbl = QLabel(text)
    lbl.setObjectName("H2")
    return lbl


def heading(text: str) -> QLabel:
    lbl = QLabel(text)
    lbl.setObjectName("H1")
    return lbl


def muted(text: str) -> QLabel:
    lbl = QLabel(text)
    lbl.setObjectName("Muted")
    lbl.setWordWrap(True)
    return lbl


def scroll_page(inner: QWidget) -> QScrollArea:
    """Wrap content in a vertically scrolling page."""
    area = QScrollArea()
    area.setWidgetResizable(True)
    area.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
    area.setWidget(inner)
    return area


def centered(inner: QWidget, max_width: int = 760, min_width: int = 420) -> QWidget:
    """Constrain content to a centered column (mirrors AV/VPN layout)."""
    wrap = QWidget()
    h = QHBoxLayout(wrap)
    h.setContentsMargins(24, 20, 24, 24)
    h.addStretch(1)
    inner.setMaximumWidth(max_width)
    inner.setMinimumWidth(min_width)
    h.addWidget(inner, 3)
    h.addStretch(1)
    return wrap


class ResponsiveStack(QWidget):
    """Two-widget row that flips horizontal -> vertical below a breakpoint.

    Ported from design_test2's chart-row / list-detail stacking: at
    <680 px the children stack vertically (equal heights);
    above it they sit side by side with the given stretch factors. Uses
    QBoxLayout.setDirection so no rebuild (and no state loss) is needed —
    the flip is a pure relayout. Debounced so window drags relayout once.
    """

    def __init__(self, first, second, *, stretches=(1, 1),
                 breakpoint=680):
        super().__init__()
        self.setObjectName("Transparent")
        self._breakpoint = breakpoint
        self._stretches = stretches
        self._stacked = None
        self._box = QBoxLayout(QBoxLayout.Direction.LeftToRight, self)
        self._box.setContentsMargins(0, 0, 0, 0)
        self._box.setSpacing(12)
        self._box.addWidget(first, stretches[0])
        self._box.addWidget(second, stretches[1])
        self._debounce = QTimer(self)
        self._debounce.setSingleShot(True)
        self._debounce.setInterval(250)
        self._debounce.timeout.connect(self._apply)

    def resizeEvent(self, event):  # noqa: N802 - Qt override
        super().resizeEvent(event)
        self._debounce.start()

    def _apply(self):
        stacked = self.width() < self._breakpoint
        if stacked == self._stacked:
            return
        self._stacked = stacked
        if stacked:
            self._box.setDirection(QBoxLayout.Direction.TopToBottom)
            self._box.setStretch(0, 1)
            self._box.setStretch(1, 1)
        else:
            self._box.setDirection(QBoxLayout.Direction.LeftToRight)
            self._box.setStretch(0, self._stretches[0])
            self._box.setStretch(1, self._stretches[1])


class CardGrid(QWidget):
    """Responsive card grid: 1-4 columns by width, cells stretch to fill the
    page (no dead gutters). 200ms debounced relayout. Exposes a FlowLayout-
    compatible surface (addWidget/count/takeAt) so pages that add cards
    incrementally (Store) can drive it the same way.
    """

    # px of width per column. Sized so TWO columns fit at the minimum
    # window (820 - 250 sidebar - page margins ≈ 520px of grid width).
    _CARD_STEP = 250

    def __init__(self, parent=None):
        super().__init__(parent)
        self._cards: list = []
        self._cols = None
        self._grid = QGridLayout(self)
        self._grid.setContentsMargins(0, 0, 0, 0)
        self._grid.setSpacing(16)
        self._debounce = QTimer(self)
        self._debounce.setSingleShot(True)
        self._debounce.setInterval(200)
        self._debounce.timeout.connect(self._relayout)

    def resizeEvent(self, event):  # noqa: N802 - Qt override
        super().resizeEvent(event)
        self._debounce.start()

    # -- FlowLayout-compatible surface --
    def addWidget(self, w):  # noqa: N802 - Qt-style name
        self._cards.append(w)
        self._cols = None
        self._relayout()

    def count(self):
        return len(self._cards)

    def takeAt(self, index):
        if 0 <= index < len(self._cards):
            w = self._cards.pop(index)
            self._grid.removeWidget(w)
            self._cols = None
            self._relayout()

            class _Item:  # minimal QLayoutItem stand-in
                def __init__(self, widget):
                    self._w = widget

                def widget(self):
                    return self._w

            return _Item(w)
        return None

    def set_cards(self, cards):
        self._cards = list(cards)
        self._cols = None
        self._relayout()

    # -- layout --
    def _relayout(self):
        while self._grid.count():
            self._grid.takeAt(0)
        if not self._cards:
            return
        width = max(1, self.width())
        cols = max(1, min(4, width // self._CARD_STEP, len(self._cards)))
        self._cols = cols
        rows = (len(self._cards) + cols - 1) // cols
        for c in range(4):
            self._grid.setColumnStretch(c, 1 if c < cols else 0)
        for r in range(rows):
            self._grid.setRowStretch(r, 1)
        for i, card in enumerate(self._cards):
            self._grid.addWidget(card, i // cols, i % cols)


class FlowLayout(QLayout):
    """A reflowing layout — items wrap to the next row as width shrinks."""

    def __init__(self, parent=None, margin=0, spacing=16, center=False):
        super().__init__(parent)
        if parent is not None:
            self.setContentsMargins(margin, margin, margin, margin)
        self._spacing = spacing
        self._center = center
        self._items: list = []

    def addItem(self, item):
        self._items.append(item)

    def count(self):
        return len(self._items)

    def itemAt(self, index):
        return self._items[index] if 0 <= index < len(self._items) else None

    def takeAt(self, index):
        return self._items.pop(index) if 0 <= index < len(self._items) else None

    def expandingDirections(self):
        return Qt.Orientation(0)

    def hasHeightForWidth(self):
        return True

    def heightForWidth(self, width):
        return self._do_layout(QRect(0, 0, width, 0), test_only=True)

    def setGeometry(self, rect):
        super().setGeometry(rect)
        self._do_layout(rect, test_only=False)

    def sizeHint(self):
        return self.minimumSize()

    def minimumSize(self):
        size = QSize()
        for item in self._items:
            size = size.expandedTo(item.minimumSize())
        size += QSize(2 * self._spacing, 2 * self._spacing)
        return size

    def _do_layout(self, rect, test_only):
        # Group items into rows first, then position each row — centering it
        # horizontally within the available width when `center` is enabled.
        rows = []  # (items[(item, w, h)], row_width, row_height)
        cur, cur_w, cur_h = [], 0, 0
        for item in self._items:
            w = item.sizeHint().width()
            h = item.sizeHint().height()
            add_w = w if not cur else self._spacing + w
            if cur and cur_w + add_w > rect.width():
                rows.append((cur, cur_w, cur_h))
                cur, cur_w, cur_h = [], 0, 0
                add_w = w
            cur.append((item, w, h))
            cur_w += add_w
            cur_h = max(cur_h, h)
        if cur:
            rows.append((cur, cur_w, cur_h))

        y = rect.y()
        for items, row_w, row_h in rows:
            x = rect.x()
            if self._center:
                x += max(0, (rect.width() - row_w) // 2)
            for item, w, h in items:
                if not test_only:
                    item.setGeometry(QRect(QPoint(x, y), QSize(w, h)))
                x += w + self._spacing
            y += row_h + self._spacing
        return (y - self._spacing - rect.y()) if rows else 0
