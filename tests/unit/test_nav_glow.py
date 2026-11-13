"""Sidebar nav icons glow in their plugin's status colour."""

import os
from unittest.mock import ANY

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
        # Unknown is its own colour: neither the green nor the red.
        amber = aw.STATUS_GLOW["Unknown"]
        assert amber not in (aw.STATUS_GLOW["OK"], aw.STATUS_GLOW["Error"])
        assert aw.AppWindow._GLOW["unknown"] == amber

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


@pytest.mark.unit
class TestNavCaption:
    """The rail's name label gets a second line: the status reason."""

    def _rail(self, qapp):
        from PyQt6.QtWidgets import QPushButton, QWidget

        host = QWidget()
        host.resize(300, 400)
        rail = aw.NavRail(host)
        btn = QPushButton(rail)
        btn.setFixedHeight(48)
        rail.add_label(btn, "VPN")
        self._host = host  # keep the parent alive for the test's duration
        return rail, btn

    def test_caption_shown_under_the_name_and_hidden_when_empty(self, qapp):
        rail, btn = self._rail(qapp)
        name, caption = rail._labels[btn]
        assert caption.isHidden() and name.y() > 0
        rail.set_caption(btn, "Not connected")
        assert caption.text() == "Not connected" and not caption.isHidden()
        assert caption.y() == name.y() + name.height()
        assert caption.textFormat() == Qt.TextFormat.PlainText
        rail.set_caption(btn, "")
        assert caption.isHidden() and name.y() == (btn.height() - name.height()) // 2

    def test_caption_on_unknown_button_is_ignored(self, qapp):
        from PyQt6.QtWidgets import QPushButton

        rail, _ = self._rail(qapp)
        rail.set_caption(QPushButton(), "x")  # no label registered: no error


@pytest.mark.unit
class TestApplyNavStatus:
    """_apply_nav_status repaints only on a changed label and always sets
    the caption from the reason."""

    def test_icon_only_when_label_changes_caption_always(self, qapp, monkeypatch):
        from unittest.mock import MagicMock

        from plugins.base_plugin import Status

        win = aw.AppWindow.__new__(aw.AppWindow)
        win._nav_status = {}
        win._unknown_since, win._unknown_told = {}, set()
        btn = MagicMock()
        win._nav_buttons = {"VPN": btn}
        plugin = MagicMock()
        win._plugin_by_name = lambda n: plugin
        win._nav_icon = lambda p: "icon"
        win.sidebar = MagicMock()
        win._nav_status_busy = True

        win._apply_nav_status({"VPN": Status("ok", "Connected")})
        assert btn.setIcon.call_count == 1
        win.sidebar.set_caption.assert_called_with(btn, "Connected")
        # Same kind, new reason: caption changes, icon does not.
        win._apply_nav_status({"VPN": Status("ok", "Connected · 10.42.20.14")})
        assert btn.setIcon.call_count == 1
        win.sidebar.set_caption.assert_called_with(btn, "Connected · 10.42.20.14")
        # Unknown: amber icon, reason as caption.
        win._apply_nav_status({"VPN": Status("unknown", "Last checked 3 h ago")})
        assert btn.setIcon.call_count == 2
        assert win._nav_status["VPN"].label == "Unknown"
        assert win._nav_status_busy is False


@pytest.mark.unit
class TestUnknownTooLong:
    """A plugin that sits in unknown past its limit gets one toast per
    episode, with the reason."""

    def _win(self, plugin):
        from unittest.mock import MagicMock
        win = aw.AppWindow.__new__(aw.AppWindow)
        win._nav_status = {}
        win._unknown_since, win._unknown_told = {}, set()
        win._nav_buttons = {"Endpoint": MagicMock()}
        win._plugin_by_name = lambda n: plugin
        win._nav_icon = lambda p: "icon"
        win.sidebar = MagicMock()
        win.show_notification = MagicMock()
        win._nav_status_busy = True
        return win

    def test_limit_from_freshness_window(self):
        from unittest.mock import MagicMock
        assert aw.unknown_limit(MagicMock(status_fresh_for=None)) == 3600
        assert aw.unknown_limit(MagicMock(status_fresh_for=600)) == 3600
        assert aw.unknown_limit(MagicMock(status_fresh_for=26 * 3600)) == 78 * 3600
        assert aw.unknown_limit(object()) == 3600

    def test_one_toast_per_episode(self, monkeypatch):
        from unittest.mock import MagicMock

        from plugins.base_plugin import Status
        plugin = MagicMock(status_fresh_for=None)
        plugin.get_display_name.return_value = "Endpoint"
        win = self._win(plugin)
        clock = [1000.0]
        monkeypatch.setattr(aw.time, "time", lambda: clock[0])
        unknown = {"Endpoint": Status("unknown", "Not checked yet")}
        win._apply_nav_status(unknown)
        clock[0] += 3599
        win._apply_nav_status(unknown)
        win.show_notification.assert_not_called()
        clock[0] += 1
        win._apply_nav_status(unknown)
        win.show_notification.assert_called_once_with(
            "Endpoint: Not checked yet.", "warning", action="Check now", on_action=ANY)
        clock[0] += 7200
        win._apply_nav_status(unknown)  # still unknown: told already
        assert win.show_notification.call_count == 1
        win._apply_nav_status({"Endpoint": Status("ok", "Running")})
        assert "Endpoint" not in win._unknown_since
        win._apply_nav_status(unknown)
        clock[0] += 3600
        win._apply_nav_status(unknown)  # a new episode: told again
        assert win.show_notification.call_count == 2

    def test_no_reason_says_status_unknown(self, monkeypatch):
        from unittest.mock import MagicMock

        from plugins.base_plugin import Status
        plugin = MagicMock(status_fresh_for=None)
        plugin.get_display_name.return_value = "VPN"
        win = self._win(plugin)
        monkeypatch.setattr(aw, "unknown_limit", lambda p: 0)
        win._apply_nav_status({"Endpoint": Status("unknown")})
        win.show_notification.assert_called_once_with(
            "VPN: Status unknown.", "warning", action="Check now", on_action=ANY)

    def test_check_now_opens_the_plugin_and_measures_again(self, monkeypatch):
        from unittest.mock import MagicMock

        from plugins.base_plugin import BasePlugin, Status
        plugin = MagicMock(status_fresh_for=None)
        plugin.get_display_name.return_value = "Endpoint"
        win = self._win(plugin)
        win.navigate = MagicMock()
        win.after = MagicMock()
        win._refresh_nav_status = MagicMock()
        clock = [1000.0]
        monkeypatch.setattr(aw.time, "time", lambda: clock[0])
        unknown = {"Endpoint": Status("unknown", "Not checked yet")}
        win._apply_nav_status(unknown)
        clock[0] += 3600
        win._apply_nav_status(unknown)
        on_action = win.show_notification.call_args.kwargs["on_action"]
        clock[0] += 10
        on_action()
        win.navigate.assert_called_once_with("Endpoint")
        plugin.recheck.assert_called_once_with()
        win.after.assert_called_once_with(1500, win._refresh_nav_status)
        # A new episode from now: told again only after another limit.
        assert win._unknown_since["Endpoint"] == clock[0]
        win._apply_nav_status(unknown)
        assert win.show_notification.call_count == 1
        clock[0] += 3600
        win._apply_nav_status(unknown)
        assert win.show_notification.call_count == 2
        # Plugins without a cache have nothing to re-measure.
        assert BasePlugin.recheck(MagicMock()) is False
