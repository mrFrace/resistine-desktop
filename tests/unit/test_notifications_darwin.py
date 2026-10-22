"""utils.notifications.darwin outside an app bundle (python main.py on macOS)."""

import pytest

from utils.notifications import darwin


@pytest.fixture(autouse=True)
def fresh_state(monkeypatch):
    monkeypatch.setattr(darwin, "_initialized", False)
    monkeypatch.setattr(darwin, "_authorized", False)


def test_init_skips_notification_center_without_a_bundle(monkeypatch):
    """currentNotificationCenter aborts the process when there is no bundle."""
    monkeypatch.setattr(darwin, "_in_app_bundle", lambda: False)

    def boom():
        raise AssertionError("UserNotifications must not be touched")

    monkeypatch.setattr(darwin, "_make_delegate", boom)
    darwin.init()
    assert darwin._initialized and not darwin._authorized


def test_send_falls_back_to_osascript(monkeypatch):
    monkeypatch.setattr(darwin, "_in_app_bundle", lambda: False)
    calls = []
    monkeypatch.setattr(darwin.subprocess, "Popen", lambda argv, **kw: calls.append(argv))
    darwin.init()
    darwin.send("Title", 'say "hi"\nnow')
    assert calls and calls[0][0] == "osascript"
