"""A small iOS-style toggle switch for PyQt6.

Stands in for the CustomTkinter ``CTkSwitch`` used by the VPN screen: a
checkable ``QAbstractButton`` painted as a sliding pill. Exposes the same
on/off semantics the original toggle relied on (``get()`` returns 1/0,
``select()``/``deselect()`` force a state without firing the callback).

Author: Resistine Team
Copyright (c) Resistine 2025
Licensed under the GNU General Public License v2 or later
"""

from __future__ import annotations

from PyQt6.QtCore import QSize, Qt
from PyQt6.QtGui import QColor, QPainter
from PyQt6.QtWidgets import QAbstractButton

from gui import theme


class ToggleSwitch(QAbstractButton):
    """A checkable pill switch matching the CTkSwitch on/off look."""

    _WIDTH = 52
    _HEIGHT = 28
    _MARGIN = 3

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setCheckable(True)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setFixedSize(self._WIDTH, self._HEIGHT)

    def sizeHint(self) -> QSize:
        return QSize(self._WIDTH, self._HEIGHT)

    # -- CTkSwitch-compatible helpers (no callback side effects) ----------
    def get(self) -> int:
        return 1 if self.isChecked() else 0

    def select(self) -> None:
        self.blockSignals(True)
        self.setChecked(True)
        self.blockSignals(False)
        self.update()

    def deselect(self) -> None:
        self.blockSignals(True)
        self.setChecked(False)
        self.blockSignals(False)
        self.update()

    # -- Painting ---------------------------------------------------------
    def paintEvent(self, _event) -> None:
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)

        on = self.isChecked()
        enabled = self.isEnabled()

        if on:
            track = QColor(theme.color("accent"))
        else:
            track = QColor(theme.color("track"))
        if not enabled:
            track.setAlpha(110)

        radius = self._HEIGHT / 2
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(track)
        p.drawRoundedRect(self.rect(), radius, radius)

        d = self._HEIGHT - 2 * self._MARGIN
        x = (self._WIDTH - self._MARGIN - d) if on else self._MARGIN
        knob = QColor("#FFFFFF")
        if not enabled:
            knob.setAlpha(180)
        p.setBrush(knob)
        p.drawEllipse(int(x), self._MARGIN, int(d), int(d))
        p.end()
