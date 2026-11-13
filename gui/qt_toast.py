"""In-app toast notifications (PyQt6).

A lightweight, non-blocking banner shown over the bottom of the content area —
the Qt replacement for the CustomTkinter ``ToastNotification``. Used by
``AppWindow.show_notification``. A toast may carry one action ("Check
now"): then it takes clicks, stays longer, and goes away when the action
is taken.

Author: Phoenix Team
Copyright (c) Phoenix 2025
Licensed under the GNU General Public License v2 or later
"""

from __future__ import annotations

from typing import Callable, Optional

from PyQt6.QtCore import (
    QEasingCurve,
    QPropertyAnimation,
    Qt,
    QTimer,
)
from PyQt6.QtWidgets import (
    QFrame,
    QGraphicsOpacityEffect,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QWidget,
)

from gui import theme

_COLORS = {
    "info": "#16A34A",
    "warning": "#F59E0B",
    "error": "#DC2626",
}
SHOW_MS = 3200
SHOW_WITH_ACTION_MS = 9000


class Toast(QFrame):
    def __init__(self, parent: QWidget, text: str, kind: str = "info",
                 action: Optional[str] = None, on_action: Optional[Callable[[], None]] = None):
        super().__init__(parent)
        accent = _COLORS.get(kind, _COLORS["info"])
        bg = theme.color("card_bg")
        fg = theme.color("text_primary")
        self.setObjectName("Toast")
        self.setStyleSheet(
            f"QFrame#Toast {{ background-color: {bg}; color: {fg};"
            f"border: 1px solid {theme.color('border')};"
            f"border-left: 4px solid {accent};"
            f"border-radius: 10px; }}"
            f"QFrame#Toast QLabel {{ background: transparent; color: {fg}; font-size: 13px; }}"
        )
        row = QHBoxLayout(self)
        row.setContentsMargins(18, 12, 18, 12)
        row.setSpacing(14)
        self._label = QLabel(text)
        self._label.setWordWrap(True)
        self._label.setTextFormat(Qt.TextFormat.PlainText)
        row.addWidget(self._label, 1)
        self._button: Optional[QPushButton] = None
        self._on_action = on_action
        self._done = False
        if action:
            self._button = QPushButton(action)
            self._button.setObjectName("Link")
            self._button.setCursor(Qt.CursorShape.PointingHandCursor)
            self._button.clicked.connect(self._act)
            row.addWidget(self._button, 0, Qt.AlignmentFlag.AlignVCenter)
        else:
            self.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)
        self._effect = QGraphicsOpacityEffect(self)
        self.setGraphicsEffect(self._effect)
        self._effect.setOpacity(0.0)
        self.adjustSize()

    def text(self) -> str:
        return self._label.text()

    @property
    def action_button(self) -> Optional[QPushButton]:
        return self._button

    def show_for(self, msec: Optional[int] = None) -> None:
        if msec is None:
            msec = SHOW_WITH_ACTION_MS if self._button is not None else SHOW_MS
        self._reposition()
        self.show()
        self.raise_()
        self._fade(0.0, 1.0, 220)
        QTimer.singleShot(msec, self._dismiss)

    def _act(self) -> None:
        if self._done:
            return
        self._done = True
        try:
            if self._on_action is not None:
                self._on_action()
        finally:
            self._dismiss()

    def _dismiss(self) -> None:
        try:
            anim = self._fade(1.0, 0.0, 300)
        except RuntimeError:  # already gone
            return
        anim.finished.connect(self.deleteLater)

    def _fade(self, start: float, end: float, dur: int) -> QPropertyAnimation:
        anim = QPropertyAnimation(self._effect, b"opacity", self)
        anim.setStartValue(start)
        anim.setEndValue(end)
        anim.setDuration(dur)
        anim.setEasingCurve(QEasingCurve.Type.InOutQuad)
        anim.start(QPropertyAnimation.DeletionPolicy.DeleteWhenStopped)
        self._anim = anim
        return anim

    def _reposition(self) -> None:
        parent = self.parentWidget()
        if parent is None:
            return
        # A word-wrapped QLabel prefers a NARROW sizeHint, so short messages
        # ("Failed to start VPN") folded into a tall two-line pill. Size the
        # toast to its actual text width (plus padding and the action) and
        # only wrap when the message genuinely exceeds the max width.
        max_w = max(240, min(560, parent.width() - 80))
        text_w = self._label.fontMetrics().horizontalAdvance(self._label.text()) + 56
        if self._button is not None:
            text_w += self._button.sizeHint().width() + 14
        self.setFixedWidth(min(max_w, max(240, text_w)))
        self.adjustSize()
        x = (parent.width() - self.width()) // 2
        y = parent.height() - self.height() - 28
        self.move(max(20, x), max(20, y))
