"""Clickable notifications: utils.notifications backends and the tray."""

from unittest.mock import MagicMock

import pytest

from utils.notifications import linux, manager, windows


@pytest.fixture
def qapp():
    import os
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    from PyQt6.QtWidgets import QApplication
    return QApplication.instance() or QApplication([])


@pytest.fixture(autouse=True)
def clean(monkeypatch):
    monkeypatch.setattr(linux, "_clicks", {})
    monkeypatch.setattr(windows, "_tray", None)


@pytest.mark.unit
class TestLinuxClicks:
    def test_default_action_runs_and_forgets_callback(self):
        hits = []
        linux._clicks[7] = lambda: hits.append(7)
        linux._dispatch_signal("ActionInvoked", (7, "other"))
        assert hits == [] and 7 in linux._clicks
        linux._dispatch_signal("ActionInvoked", (7, "default"))
        linux._dispatch_signal("ActionInvoked", (7, "default"))
        assert hits == [7] and 7 not in linux._clicks

    def test_closed_forgets_and_bad_signals_are_ignored(self):
        linux._clicks[8] = MagicMock()
        linux._dispatch_signal("NotificationClosed", (8, 2))
        assert linux._clicks == {}
        linux._dispatch_signal("ActionInvoked", ())
        linux._dispatch_signal("Other", (1, "default"))

    def test_failing_callback_is_contained(self):
        linux._clicks[9] = lambda: 1 / 0
        linux._dispatch_signal("ActionInvoked", (9, "default"))

    def test_notify_offers_default_action_and_registers(self, monkeypatch):
        from jeepney.low_level import MessageType
        sent = {}

        class Conn:
            def send_and_get_reply(self, msg):
                sent["body"] = msg.body
                reply = MagicMock()
                reply.header.message_type = MessageType.method_return
                reply.body = (42,)
                return reply

        monkeypatch.setattr(linux, "_get_connection", lambda: Conn())
        cb = MagicMock()
        assert linux._send_via_dbus("T", "B", 1, "icon", cb) is None
        assert sent["body"][5] == ["default", "Open"] and linux._clicks[42] is cb
        assert linux._send_via_dbus("T", "B", 1, "icon") is None
        assert sent["body"][5] == []


@pytest.mark.unit
def test_manager_passes_on_click_only_when_given(monkeypatch):
    backend = MagicMock()
    monkeypatch.setattr(manager, "_backend", backend)
    manager.send("T", "B")
    backend.send.assert_called_with("T", "B", "normal")
    cb = MagicMock()
    manager.send("T", "B", "bogus", on_click=cb)
    backend.send.assert_called_with("T", "B", "normal", on_click=cb)


@pytest.mark.unit
def test_windows_goes_through_the_tray():
    windows.send("T", "B")  # no tray: nothing, no error
    tray = MagicMock()
    windows.set_tray(tray)
    cb = MagicMock()
    windows.send("T", "B", "critical", on_click=cb)
    tray.notify.assert_called_once_with("T", "B", "critical", cb)


@pytest.mark.unit
def test_tray_message_click_runs_callback(qapp):
    from PyQt6.QtWidgets import QWidget

    from gui.system_tray import SystemTray
    window = QWidget()
    tray = SystemTray(window)
    tray._tray = MagicMock()
    cb = MagicMock()
    tray.notify("Critical alert", "x", "critical", cb)
    tray._tray.showMessage.assert_called_once()
    tray._message_clicked()
    cb.assert_called_once()
    tray._message_clicked()  # a later click without a callback just shows the window
    cb.assert_called_once()
