"""Devices page: interactive QPainter charts and list furniture.

Replacements for the old Overview's matplotlib figures: a severity donut,
a stacked bar chart (hourly or daily buckets) with hover tooltips and
click-to-filter, clickable severity pills, and a pager. All colours come
from gui/theme.py so they follow light/dark mode.
"""

from __future__ import annotations

import math

from PyQt6.QtCore import QPointF, QRectF, Qt
from PyQt6.QtGui import QColor, QFont, QPainter, QPainterPath, QPen
from PyQt6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QSizePolicy,
    QToolTip,
    QWidget,
)

from gui import theme
from plugins.devices.tables import SEVERITIES
from plugins.devices.widgets import _t, severity_color

DIM_ALPHA = 0.25


def _dim(color: QColor, dim: bool) -> QColor:
    c = QColor(color)
    if dim:
        c.setAlphaF(DIM_ALPHA)
    return c


class Donut(QWidget):
    """Severity breakdown ring with the total in the centre. Clicking a wedge
    calls ``on_toggle(severity)``; ``set_selected`` dims the other wedges."""

    def __init__(self, counts: dict, on_toggle=None, parent=None):
        super().__init__(parent)
        self._counts = {s: int(counts.get(s, 0) or 0) for s in SEVERITIES}
        self._on_toggle = on_toggle
        self._selected = None
        self._arcs: list = []  # (start_deg, span_deg, severity)
        self.setMinimumSize(150, 150)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        self.setCursor(
            Qt.CursorShape.PointingHandCursor
            if on_toggle
            else Qt.CursorShape.ArrowCursor
        )

    def set_counts(self, counts: dict) -> None:
        self._counts = {s: int(counts.get(s, 0) or 0) for s in SEVERITIES}
        self.update()

    def set_selected(self, sev) -> None:
        self._selected = sev
        self.update()

    def _geometry(self):
        side = min(self.width(), self.height()) - 8
        cx, cy = self.width() / 2, self.height() / 2
        return QRectF(cx - side / 2, cy - side / 2, side, side), side * 0.17

    def paintEvent(self, _e):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        rect, thickness = self._geometry()
        inner = rect.adjusted(thickness, thickness, -thickness, -thickness)
        total = sum(self._counts.values())
        self._arcs = []
        pen = QPen()
        pen.setCapStyle(Qt.PenCapStyle.FlatCap)
        pen.setWidthF(thickness)
        ring = rect.adjusted(
            thickness / 2, thickness / 2, -thickness / 2, -thickness / 2
        )
        if total <= 0:
            pen.setColor(QColor(theme.color("track")))
            p.setPen(pen)
            p.drawArc(ring, 0, 360 * 16)
        else:
            start = 90.0  # 12 o'clock, clockwise
            for s in SEVERITIES:
                n = self._counts[s]
                if not n:
                    continue
                span = 360.0 * n / total
                selected_here = self._selected == s
                pen.setColor(
                    _dim(
                        severity_color(s),
                        self._selected is not None and not selected_here,
                    )
                )
                pen.setWidthF(thickness * (1.18 if selected_here else 1.0))
                p.setPen(pen)
                p.drawArc(ring, int(start * 16), int(-span * 16))
                self._arcs.append((start, span, s))
                start -= span
        p.setPen(QColor(theme.color("text_primary")))
        f = QFont(p.font())
        f.setPointSize(16)
        f.setWeight(QFont.Weight.Bold)
        p.setFont(f)
        p.drawText(
            inner.adjusted(0, -8, 0, -8),
            Qt.AlignmentFlag.AlignCenter,
            f"{total:,}" if total else "0",
        )
        f.setPointSize(9)
        f.setWeight(QFont.Weight.Normal)
        p.setFont(f)
        p.setPen(QColor(theme.color("text_secondary")))
        p.drawText(
            inner.adjusted(0, 14, 0, 14),
            Qt.AlignmentFlag.AlignCenter,
            _t("donut_cves") if total else _t("donut_no_cves"),
        )
        p.end()

    def _hit(self, pos) -> str | None:
        rect, thickness = self._geometry()
        c = rect.center()
        dx, dy = pos.x() - c.x(), c.y() - pos.y()
        r = math.hypot(dx, dy)
        if not (rect.width() / 2 - thickness <= r <= rect.width() / 2):
            return None
        ang = math.degrees(math.atan2(dy, dx)) % 360  # 0 = 3 o'clock, counter-clockwise
        for start, span, sev in self._arcs:
            # arcs run clockwise from `start`: covered angles are (start-span, start]
            a = (start - ang) % 360
            if 0 <= a < span:
                return sev
        return None

    def mouseReleaseEvent(self, e):
        if self._on_toggle and e.button() == Qt.MouseButton.LeftButton:
            sev = self._hit(e.position())
            if sev:
                self._on_toggle(sev)
        super().mouseReleaseEvent(e)


class StackedBars(QWidget):
    """Buckets along x, each a stack of severity counts.

    ``buckets``: list of keys; ``counts``: {key: {severity: n}};
    ``labels``: {key: text} for the x axis (unlabelled keys get a tick only).
    ``on_bucket(key)`` is called when a bar is clicked; ``on_severity(sev)``
    when a segment is clicked (the first non-None wins). Hovering a segment
    shows a tooltip. ``set_selected_bucket`` / ``set_selected_severity`` dim
    the rest."""

    def __init__(
        self,
        buckets: list,
        counts: dict,
        labels: dict,
        on_bucket=None,
        on_severity=None,
        empty_text: str = "",
        parent=None,
    ):
        super().__init__(parent)
        self._buckets = list(buckets)
        self._counts = counts
        self._labels = labels
        self._on_bucket = on_bucket
        self._on_severity = on_severity
        self._empty_text = empty_text
        self._sel_bucket = None
        self._sel_sev = None
        self._segments: list = []  # (QRectF, key, severity, n)
        self.setMinimumHeight(150)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        self.setMouseTracking(True)
        if on_bucket or on_severity:
            self.setCursor(Qt.CursorShape.PointingHandCursor)

    def set_data(self, buckets: list, counts: dict, labels: dict) -> None:
        self._buckets, self._counts, self._labels = list(buckets), counts, labels
        self.update()

    def set_selected_bucket(self, key) -> None:
        self._sel_bucket = key
        self.update()

    def set_selected_severity(self, sev) -> None:
        self._sel_sev = sev
        self.update()

    def paintEvent(self, _e):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        f = p.font()
        f.setPointSizeF(max(7.0, f.pointSizeF() - 2))
        p.setFont(f)
        muted = QColor(theme.color("text_secondary"))
        grid = QColor(theme.color("border"))
        self._segments = []
        n = len(self._buckets)
        if not n:
            p.end()
            return
        left, right, top, bottom = 30.0, 6.0, 10.0, self.height() - 22.0
        plot_w, plot_h = self.width() - left - right, bottom - top
        peak = max(
            (sum(self._counts.get(b, {}).values()) for b in self._buckets), default=0
        )
        # y grid + labels: a "nice" max divisible by the step count, so the
        # ticks are uniform integers (0,3,6,9,12) instead of rounded
        # fractions of the peak (0,2,4,7,9).
        steps = 4
        tick = max(1, -(-peak // steps)) if peak else 1  # ceil(peak/steps)
        nice_max = tick * steps
        p.setPen(QPen(grid, 1, Qt.PenStyle.DashLine))
        for i in range(steps + 1):
            y = bottom - plot_h * i / steps
            p.drawLine(QPointF(left, y), QPointF(left + plot_w, y))
            p.setPen(muted)
            p.drawText(
                QRectF(0, y - 8, left - 6, 16),
                Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter,
                str(tick * i) if peak else "",
            )
            p.setPen(QPen(grid, 1, Qt.PenStyle.DashLine))
        if not peak:
            p.setPen(muted)
            p.drawText(
                QRectF(left, top, plot_w, plot_h),
                Qt.AlignmentFlag.AlignCenter,
                self._empty_text,
            )
        slot = plot_w / n
        bar_w = max(2.0, slot * 0.72)
        for i, key in enumerate(self._buckets):
            x = left + i * slot + (slot - bar_w) / 2
            total = sum(self._counts.get(key, {}).values())
            y = bottom
            if total and peak:
                h = plot_h * total / nice_max
                for s in ("low", "medium", "high", "critical"):
                    cnt = self._counts.get(key, {}).get(s, 0)
                    if not cnt:
                        continue
                    seg = h * cnt / total
                    rect = QRectF(x, y - seg, bar_w, seg)
                    dim = (
                        self._sel_bucket is not None and key != self._sel_bucket
                    ) or (self._sel_sev is not None and s != self._sel_sev)
                    p.setPen(Qt.PenStyle.NoPen)
                    p.setBrush(_dim(severity_color(s), dim))
                    p.drawRect(rect)
                    self._segments.append((rect, key, s, cnt))
                    y -= seg
            label = self._labels.get(key)
            if label:
                p.setPen(muted)
                p.drawText(
                    QRectF(x - 24, bottom + 4, bar_w + 48, 16),
                    Qt.AlignmentFlag.AlignCenter,
                    label,
                )
        p.setPen(QPen(grid, 1))
        p.drawLine(QPointF(left, bottom), QPointF(left + plot_w, bottom))
        p.end()

    def _segment_at(self, pos):
        for rect, key, sev, n in self._segments:
            if rect.contains(pos):
                return key, sev, n
        return None

    def mouseMoveEvent(self, e):
        hit = self._segment_at(e.position())
        if hit:
            key, sev, n = hit
            label = self._labels.get(key) or str(key)
            QToolTip.showText(e.globalPosition().toPoint(), f"{label}: {n} {sev}", self)
        else:
            QToolTip.hideText()
        super().mouseMoveEvent(e)

    def mouseReleaseEvent(self, e):
        if e.button() == Qt.MouseButton.LeftButton:
            hit = self._segment_at(e.position())
            if hit:
                key, sev, _n = hit
                if self._on_bucket:
                    self._on_bucket(key)
                elif self._on_severity:
                    self._on_severity(sev)
        super().mouseReleaseEvent(e)


class SeverityPills(QWidget):
    """Four clickable pills with counts; ``on_toggle(severity)`` on click.
    ``set_counts`` updates numbers, ``set_selected`` dims the others."""

    def __init__(self, counts: dict, on_toggle=None, parent=None):
        super().__init__(parent)
        self.setObjectName("Transparent")
        self._on_toggle = on_toggle
        self._counts = {s: int(counts.get(s, 0) or 0) for s in SEVERITIES}
        self._selected = None
        self._frames: dict = {}
        self._labels: dict = {}
        h = QHBoxLayout(self)
        h.setContentsMargins(0, 0, 0, 0)
        h.setSpacing(8)
        for s in SEVERITIES:
            frame = QFrame()
            frame.setObjectName("SeverityPill")
            frame.setCursor(Qt.CursorShape.PointingHandCursor)
            fh = QHBoxLayout(frame)
            fh.setContentsMargins(14, 8, 14, 8)
            name = QLabel(s.upper())
            name.setObjectName("Hint")
            fh.addWidget(name)
            fh.addStretch(1)
            count = QLabel(str(self._counts[s]))
            f = count.font()
            f.setPointSize(15)
            f.setWeight(QFont.Weight.Bold)
            count.setFont(f)
            fh.addWidget(count)
            for w in (name, count):
                w.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)
            frame.mouseReleaseEvent = lambda e, sev=s: self._click(e, sev)  # type: ignore[method-assign]
            h.addWidget(frame, 1)
            self._frames[s] = frame
            self._labels[s] = (name, count)
        self._paint()

    def _click(self, e, sev):
        if (
            e.button() == Qt.MouseButton.LeftButton
            and self._on_toggle
            and self._counts.get(sev, 0) > 0
        ):
            self._on_toggle(sev)

    def set_counts(self, counts: dict) -> None:
        self._counts = {s: int(counts.get(s, 0) or 0) for s in SEVERITIES}
        for s, (_name, count) in self._labels.items():
            count.setText(str(self._counts[s]))
        self._paint()

    def set_selected(self, sev) -> None:
        self._selected = sev
        self._paint()

    def _paint(self) -> None:
        for s, frame in self._frames.items():
            fg = severity_color(s)
            bg, _ = theme.badge_colors(
                {
                    "critical": "critical",
                    "high": "error",
                    "medium": "warning",
                    "low": "info",
                }[s]
            )
            selected = s == self._selected
            dim = self._selected is not None and not selected
            fg_hex = fg.name()
            frame.setStyleSheet(
                f"QFrame#SeverityPill {{ background-color: {bg}; border-radius: 10px; "
                f"border: 2px solid {fg_hex if selected else 'transparent'}; }}"
                + (
                    f"QFrame#SeverityPill QLabel {{ color: {fg_hex}; }}"
                    if not dim
                    else f"QFrame#SeverityPill QLabel {{ color: {theme.color('text_secondary')}; }}"
                )
            )
            frame.setCursor(
                Qt.CursorShape.PointingHandCursor
                if self._counts.get(s, 0) > 0
                else Qt.CursorShape.ArrowCursor
            )


class Pager(QWidget):
    """[◀] page X / Y [▶], hidden on a single page."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("Transparent")
        h = QHBoxLayout(self)
        h.setContentsMargins(0, 0, 0, 0)
        h.setSpacing(6)
        h.addStretch(1)
        from PyQt6.QtGui import QIcon

        from gui.page_kit import line_icon

        self._prev = QPushButton()
        self._next = QPushButton()
        for b, name in ((self._prev, "chevron-left"), (self._next, "chevron-right")):
            b.setObjectName("SurfaceBtn")
            b.setFixedSize(30, 28)
            b.setIcon(QIcon(line_icon(name, theme.color("text_secondary"), 16)))
            b.setCursor(Qt.CursorShape.PointingHandCursor)
        self._label = QLabel("")
        self._label.setObjectName("Hint")
        h.addWidget(self._prev)
        h.addWidget(self._label)
        h.addWidget(self._next)
        self._on_set = None
        self._page, self._total = 1, 1
        self._prev.clicked.connect(lambda: self._go(self._page - 1))
        self._next.clicked.connect(lambda: self._go(self._page + 1))

    def _go(self, page: int) -> None:
        if self._on_set and 1 <= page <= self._total:
            self._on_set(page)

    def set_state(self, page: int, total: int, on_set) -> None:
        self._page, self._total, self._on_set = page, total, on_set
        self._label.setText(f"{page} / {total}")
        self._prev.setEnabled(page > 1)
        self._next.setEnabled(page < total)
        self.setVisible(total > 1)


def legend_row(counts: dict) -> QWidget:
    """A compact "● 9 critical · ● 128 high …" line."""
    row = QWidget()
    row.setObjectName("Transparent")
    h = QHBoxLayout(row)
    h.setContentsMargins(0, 0, 0, 0)
    h.setSpacing(14)
    for s in SEVERITIES:
        lbl = QLabel(f"● {int(counts.get(s, 0) or 0):,} {s}")
        lbl.setStyleSheet(
            f"color: {severity_color(s).name()}; font-size: 11px; font-weight: 600;"
        )
        h.addWidget(lbl)
    h.addStretch(1)
    return row


def path_rounded(rect: QRectF, radius: float) -> QPainterPath:
    path = QPainterPath()
    path.addRoundedRect(rect, radius, radius)
    return path
