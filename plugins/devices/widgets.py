"""Devices page widgets: small QPainter charts and cards.

Drawn with the theme's palette (gui/theme.py) so they follow light/dark mode
and need no plotting library: the old Overview's matplotlib charts were the
reason that dependency existed, and it is gone.
"""

from __future__ import annotations

from PyQt6.QtCore import QRectF, Qt
from PyQt6.QtGui import QColor, QFont, QPainter
from PyQt6.QtWidgets import QHBoxLayout, QLabel, QSizePolicy, QVBoxLayout, QWidget

from gui import theme
from gui.qt_widgets import Card, set_pill
from plugins.devices.data import SEVERITIES, _t

# Severity -> the badge key whose text colour paints it.
SEVERITY_KIND = {
    "critical": "critical",
    "high": "error",
    "medium": "warning",
    "low": "info",
    "other": "info",
}


# Chart palette: fixed, hue-distinct colours. Deriving these from the badge
# TEXT colours tied chart readability to badge-contrast tuning (critical
# became pale pink and high near-white on dark backgrounds).
_SEVERITY_CHART = {
    "critical": "#EF4444",  # red
    "high": "#F97316",      # orange
    "medium": "#FBBF24",    # amber
    "low": "#60A5FA",       # blue
}


def severity_color(sev: str) -> QColor:
    hexval = _SEVERITY_CHART.get(sev)
    if hexval:
        return QColor(hexval)
    if sev == "other":
        return QColor(theme.color("text_secondary"))
    _bg, fg = theme.badge_colors(SEVERITY_KIND.get(sev, "info"))
    return QColor(fg)


class SeverityBar(QWidget):
    """A stacked horizontal bar of vulnerability counts by severity, with a
    legend line under it. Empty counts draw a quiet track."""

    def __init__(self, counts: dict, parent: QWidget | None = None):
        super().__init__(parent)
        self._counts = {s: int(counts.get(s, 0) or 0) for s in SEVERITIES}
        self.setFixedHeight(40)
        self.setMinimumWidth(140)
        total = sum(self._counts.values())
        self.setToolTip(
            " · ".join(f"{self._counts[s]} {s}" for s in SEVERITIES)
            if total
            else _t("sev_no_vulns")
        )

    def paintEvent(self, _e):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        w, bar_h, radius = self.width(), 10.0, 5.0
        total = sum(self._counts.values())
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(QColor(theme.color("track")))
        p.drawRoundedRect(QRectF(0, 0, w, bar_h), radius, radius)
        if total:
            x = 0.0
            for s in SEVERITIES:
                n = self._counts[s]
                if not n:
                    continue
                seg = max(3.0, w * n / total)
                p.setBrush(severity_color(s))
                p.drawRoundedRect(QRectF(x, 0, min(seg, w - x), bar_h), radius, radius)
                x += seg
        f = p.font()
        f.setPointSizeF(max(7.0, f.pointSizeF() - 2))
        p.setFont(f)
        x = 0.0
        for s in SEVERITIES:
            dot = QRectF(x, bar_h + 12, 7, 7)
            p.setBrush(severity_color(s))
            p.setPen(Qt.PenStyle.NoPen)
            p.drawEllipse(dot)
            p.setPen(QColor(theme.color("text_secondary")))
            label = f"{self._counts[s]:,} {s}"
            rect = QRectF(x + 11, bar_h + 4, 200, 20)
            p.drawText(
                rect, Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter, label
            )
            x += 11 + p.fontMetrics().horizontalAdvance(label) + 14
        p.end()


class DailyBars(QWidget):
    """Alerts per day over the last week, stacked by severity."""

    def __init__(self, buckets: list, parent: QWidget | None = None):
        super().__init__(parent)
        self._buckets = buckets or []
        self.setFixedHeight(120)
        self.setMinimumWidth(240)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        total = sum(sum(b["counts"].values()) for b in self._buckets)
        self.setToolTip(
            f"{total} alert{'s' if total != 1 else ''} in the last {len(self._buckets)} days"
        )

    def paintEvent(self, _e):
        if not self._buckets:
            return
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        f = p.font()
        f.setPointSizeF(max(7.0, f.pointSizeF() - 2))
        p.setFont(f)
        label_h = 18.0
        top, bottom = 8.0, self.height() - label_h - 6
        n = len(self._buckets)
        gap = 10.0
        slot = (self.width() - gap * (n - 1)) / n
        bar_w = min(36.0, slot * 0.6)
        peak = max((sum(b["counts"].values()) for b in self._buckets), default=0)
        track = QColor(theme.color("track"))
        muted = QColor(theme.color("text_secondary"))
        for i, b in enumerate(self._buckets):
            x = i * (slot + gap) + (slot - bar_w) / 2
            total = sum(b["counts"].values())
            p.setPen(Qt.PenStyle.NoPen)
            # Baseline tick so an empty day still reads as a day.
            p.setBrush(track)
            p.drawRoundedRect(QRectF(x, bottom - 3, bar_w, 3), 1.5, 1.5)
            if total and peak:
                h = max(4.0, (bottom - top) * total / peak)
                y = bottom
                for s in ("other", "low", "medium", "high", "critical"):
                    cnt = b["counts"].get(s, 0)
                    if not cnt:
                        continue
                    seg = h * cnt / total
                    y -= seg
                    p.setBrush(severity_color(s))
                    p.drawRect(QRectF(x, y, bar_w, seg))
                p.setPen(muted)
                p.drawText(
                    QRectF(x - 20, y - 18, bar_w + 40, 16),
                    Qt.AlignmentFlag.AlignCenter,
                    str(total),
                )
            p.setPen(muted)
            p.drawText(
                QRectF(x - 20, bottom + 2, bar_w + 40, label_h),
                Qt.AlignmentFlag.AlignCenter,
                b["label"],
            )
        p.end()


class StatCard(Card):
    """Title, one big value, a line of detail, and an optional chart under it."""

    def __init__(
        self,
        title: str,
        value: str,
        detail: str = "",
        kind: str | None = None,
        chart: QWidget | None = None,
    ):
        super().__init__()
        self.body.setSpacing(6)
        head = QHBoxLayout()
        head.setContentsMargins(0, 0, 0, 0)
        t = QLabel(title)
        t.setObjectName("CardTitle")
        head.addWidget(t, 1)
        if kind:
            pill = QLabel()
            set_pill(
                pill,
                kind,
                {
                    "ok": "OK",
                    "info": _t("stat_info"),
                    "warning": _t("stat_attention"),
                    "error": _t("stat_action"),
                    "critical": _t("stat_critical"),
                }.get(kind, ""),
            )
            head.addWidget(pill, 0, Qt.AlignmentFlag.AlignVCenter)
        self.body.addLayout(head)
        v = QLabel(value)
        v.setObjectName("H1")
        f = v.font()
        f.setPointSize(22)
        f.setWeight(QFont.Weight.DemiBold)
        v.setFont(f)
        v.setTextFormat(Qt.TextFormat.PlainText)
        self.body.addWidget(v)
        if detail:
            d = QLabel(detail)
            d.setObjectName("Muted")
            d.setWordWrap(True)
            d.setTextFormat(Qt.TextFormat.PlainText)
            self.body.addWidget(d)
        if chart is not None:
            self.body.addSpacing(4)
            self.body.addWidget(chart)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)


class GradeBadge(QWidget):
    """A big grade letter on its badge colour, with the score under it."""

    def __init__(self, grade: str, score, parent: QWidget | None = None):
        super().__init__(parent)
        self.setObjectName("Transparent")
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(2)
        from plugins.devices.data import grade_kind

        bg, fg = theme.badge_colors(grade_kind(grade))
        letter = QLabel(str(grade or "?"))
        letter.setAlignment(Qt.AlignmentFlag.AlignCenter)
        letter.setFixedSize(56, 56)
        f = letter.font()
        f.setPointSize(26)
        f.setWeight(QFont.Weight.Bold)
        letter.setFont(f)
        letter.setStyleSheet(
            f"background-color: {bg}; color: {fg}; border-radius: 14px;"
        )
        lay.addWidget(letter, 0, Qt.AlignmentFlag.AlignHCenter)
        sub = QLabel(f"{score}/100" if score is not None else "—")
        sub.setObjectName("Hint")
        sub.setAlignment(Qt.AlignmentFlag.AlignCenter)
        lay.addWidget(sub)
