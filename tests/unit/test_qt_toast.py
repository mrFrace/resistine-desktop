"""Toasts (gui/qt_toast.py): text-only ones take no clicks; one with an
action carries a button that runs the action once and dismisses."""

import pytest

pytest.importorskip("PyQt6")

from PyQt6.QtCore import Qt  # noqa: E402
from PyQt6.QtWidgets import QApplication, QWidget  # noqa: E402

from gui import qt_toast  # noqa: E402

pytestmark = pytest.mark.unit


@pytest.fixture(scope="module")
def qapp():
    return QApplication.instance() or QApplication(["test"])


@pytest.fixture
def host(qapp):
    w = QWidget()
    w.resize(900, 600)
    yield w
    w.deleteLater()


def test_plain_toast_is_transparent_to_the_mouse(host):
    t = qt_toast.Toast(host, "Saved", "info")
    assert t.testAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)
    assert t.action_button is None and t.text() == "Saved"


def test_action_runs_once_and_dismisses(host, monkeypatch):
    calls = []
    t = qt_toast.Toast(host, "Endpoint: Not checked yet.", "warning",
                       action="Check now", on_action=lambda: calls.append(1))
    assert not t.testAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)
    assert t.action_button.text() == "Check now"
    dismissed = []
    monkeypatch.setattr(t, "_dismiss", lambda: dismissed.append(1))
    t.action_button.click()
    t.action_button.click()
    assert calls == [1] and dismissed == [1]


def test_action_toast_stays_longer(host, monkeypatch):
    waits = []
    monkeypatch.setattr(qt_toast.QTimer, "singleShot", lambda ms, fn: waits.append(ms))
    qt_toast.Toast(host, "x").show_for()
    qt_toast.Toast(host, "x", action="Go", on_action=lambda: None).show_for()
    qt_toast.Toast(host, "x").show_for(500)
    assert waits == [qt_toast.SHOW_MS, qt_toast.SHOW_WITH_ACTION_MS, 500]


def test_failing_action_still_dismisses(host, monkeypatch):
    def boom():
        raise RuntimeError("no")
    t = qt_toast.Toast(host, "x", action="Go", on_action=boom)
    dismissed = []
    monkeypatch.setattr(t, "_dismiss", lambda: dismissed.append(1))
    with pytest.raises(RuntimeError):
        t._act()
    assert dismissed == [1]
