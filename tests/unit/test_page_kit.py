"""Tests for gui/page_kit.py — the flat page widgets."""

import os

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtCore import Qt  # noqa: E402
from PyQt6.QtWidgets import QApplication, QLabel  # noqa: E402

from gui import page_kit as kit  # noqa: E402


@pytest.fixture(scope="module")
def qapp():
    return QApplication.instance() or QApplication([])


@pytest.mark.unit
class TestMenuRow:
    def test_click_and_disabled(self, qapp):
        hits = []
        row = kit.MenuRow("plus", "Add", "hint", on_click=lambda: hits.append(1))
        row.clicked.emit()
        assert hits == [1]
        row.setText("Adding…")
        assert row.text() == "Adding…"
        row.setEnabled(False)
        assert not row.isEnabled()

    def test_click_does_not_take_focus(self, qapp):
        # A clicked row kept the :focus highlight and looked hovered.
        row = kit.MenuRow("plus", "Add")
        assert row.focusPolicy() == Qt.FocusPolicy.TabFocus


@pytest.mark.unit
class TestKVList:
    def test_set_value_updates_or_adds(self, qapp):
        kv = kit.KVList([("Engine", "ClamAV")])
        kv.set_value("Engine", "Defender")
        kv.set_value("Signatures", "42")
        assert kv.values["Engine"].text() == "Defender"
        assert kv.values["Signatures"].text() == "42"
        assert kv.count() == 2


@pytest.mark.unit
class TestSlideStack:
    def _stack(self):
        stack = kit.SlideStack()
        a = kit.menu_list(QLabel("a"))
        b = kit.menu_list(QLabel("b"))
        stack.addWidget(a)
        stack.addWidget(b)
        stack.resize(400, 200)
        stack.show()
        return stack, a, b

    def test_push_and_back(self, qapp):
        stack, a, b = self._stack()
        stack.push(b)
        assert stack._anim is not None
        stack._anim.setCurrentTime(stack.DURATION_MS)
        assert stack.currentWidget() is b
        assert b.graphicsEffect() is None and b.pos().x() == 0
        stack.back()
        stack._anim.setCurrentTime(stack.DURATION_MS)
        assert stack.currentWidget() is a

    def test_interrupted_slide_lands_on_new_target(self, qapp):
        stack, a, b = self._stack()
        stack.push(b)
        stack.back(a)  # before the first slide finished
        stack._anim.setCurrentTime(stack.DURATION_MS)
        assert stack.currentWidget() is a
        assert b.graphicsEffect() is None

    def test_push_current_is_noop(self, qapp):
        stack, a, b = self._stack()
        stack.push(a)
        assert stack._anim is None
        assert stack.currentWidget() is a


@pytest.mark.unit
class TestAsOf:
    """Data has an age: "As of 2 min ago · next check 09:12"."""

    def test_text(self):
        import time

        now = 1_800_000_000.0
        assert kit.as_of_text(None, None, now) == "Not fetched yet"
        assert kit.as_of_text(now - 30, None, now) == "As of just now"
        assert kit.as_of_text(now - 5 * 60, None, now) == "As of 5 min ago"
        assert kit.as_of_text(now - 3 * 3600, None, now) == "As of 3 h ago"
        assert kit.as_of_text(now - 2 * 86400, None, now) == "As of 2 d ago"
        nxt = now + 600
        hhmm = time.strftime("%H:%M", time.localtime(nxt))
        assert kit.as_of_text(now - 120, nxt, now) == f"As of 2 min ago · next check {hhmm}"
        # A next check already in the past is not promised.
        assert kit.as_of_text(now - 120, now - 1, now) == "As of 2 min ago"

    def test_header_line(self, qapp):
        import time

        h = kit.PageHeader("Devices", "sub")
        assert h.as_of.isHidden()
        h.set_as_of(time.time() - 120, None)
        assert h.as_of.text() == "As of 2 min ago" and not h.as_of.isHidden()
        h.set_as_of(None, None, shown=False)
        assert h.as_of.isHidden() and h.as_of.text() == ""
