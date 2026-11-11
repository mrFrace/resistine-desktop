"""In-app toast notifications (PyQt6).

A lightweight, non-blocking banner shown over the bottom of the content area —
the Qt replacement for the CustomTkinter ``ToastNotification``. Used by
``AppWindow.show_notification``.

Author: Phoenix Team
Copyright (c) Phoenix 2025
Licensed under the GNU General Public License v2 or later
"""

from __future__ import annotations

from PyQt6.QtCore import (
    QEasingCurve,
    QPropertyAnimation,
    Qt,
    QTimer,
)
from PyQt6.QtWidgets import QGraphicsOpacityEffect, QLabel, QWidget

from gui import theme

_COLORS = {
    "info": "#16A34A",
    "warning": "#F59E0B",
    "error": "#DC2626",
}


class Toast(QLabel):
    def __init__(self, parent: QWidget, text: str, kind: str = "info"):
        super().__init__(parent)
        accent = _COLORS.get(kind, _COLORS["info"])
        bg = theme.color("card_bg")
        fg = theme.color("text_primary")
        self.setText(f"  {text}")
        self.setWordWrap(True)
        self.setStyleSheet(
            f"background-color: {bg}; color: {fg};"
            f"border: 1px solid {theme.color('border')};"
            f"border-left: 4px solid {accent};"
            f"border-radius: 10px; padding: 12px 18px; font-size: 13px;"
        )
        self.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)
        self._effect = QGraphicsOpacityEffect(self)
        self.setGraphicsEffect(self._effect)
        self._effect.setOpacity(0.0)
        self.adjustSize()

    def show_for(self, msec: int = 3200) -> None:
        self._reposition()
        self.show()
        self.raise_()
        self._fade(0.0, 1.0, 220)
        QTimer.singleShot(msec, self._dismiss)

    def _dismiss(self) -> None:
        anim = self._fade(1.0, 0.0, 300)
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
        # toast to its actual text width (plus padding) and only wrap when
        # the message genuinely exceeds the max width.
        max_w = max(240, min(560, parent.width() - 80))
        text_w = self.fontMetrics().horizontalAdvance(self.text()) + 56
        self.setFixedWidth(min(max_w, max(240, text_w)))
        self.adjustSize()
        x = (parent.width() - self.width()) // 2
        y = parent.height() - self.height() - 28
        self.move(max(20, x), max(20, y))
