"""Sidebar nav icons glow in their plugin's status colour."""

import os

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtCore import QSize, Qt  # noqa: E402
from PyQt6.QtGui import QColor, QIcon, QPainter, QPixmap  # noqa: E402
from PyQt6.QtWidgets import QApplication  # noqa: E402

from gui import app_window as aw  # noqa: E402


@pytest.fixture(scope="module")
def qapp():
    return QApplication.instance() or QApplication([])


def _square_icon():
    pm = QPixmap(48, 48)
    pm.fill(Qt.GlobalColor.transparent)
    p = QPainter(pm)
    p.fillRect(16, 16, 16, 16, QColor("white"))
    p.end()
    return QIcon(pm)


def _halo_alpha(icon):
    full = aw.NAV_ICON + 2 * aw.NAV_GLOW_PAD
    img = icon.pixmap(QSize(full, full), 2.0).toImage()
    # A pixel inside the padding, well outside the glyph.
    return img.pixelColor(int(img.width() * 0.5), int(img.height() * 0.22))


@pytest.mark.unit
class TestNavGlow:
    def test_status_colours(self):
        assert aw.STATUS_GLOW["OK"] == "#2CC985"
        assert aw.STATUS_GLOW["Warning"] == aw.STATUS_GLOW["Error"] == "#FF4040"
        assert "Info" not in aw.STATUS_GLOW and None not in aw.STATUS_GLOW

    def test_glow_adds_halo_in_colour(self, qapp):
        px = _halo_alpha(aw.glow_icon(_square_icon(), "#2CC985"))
        assert px.alpha() > 0
        assert px.green() > px.red()

    def test_no_glow_keeps_padding_clear(self, qapp):
        assert _halo_alpha(aw.glow_icon(_square_icon(), None)).alpha() == 0

    def test_icon_padded_to_canvas(self, qapp):
        full = aw.NAV_ICON + 2 * aw.NAV_GLOW_PAD
        sizes = aw.glow_icon(_square_icon(), None).availableSizes()
        assert sizes and sizes[0].width() == full * 2
