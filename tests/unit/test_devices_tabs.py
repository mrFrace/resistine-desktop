"""Construction smoke tests for the Devices tabs.

Regression guard: a shipped build crashed with "'EventsTab' object has no
attribute '_clear_sev'" because nothing ever constructed the tabs in tests —
the search-head widget block (with its severity-filter chip) exists in more
than one tab, and a handler added to only one of them broke the other at
build time. Every tab must at least construct and render its initial state.
"""

import pytest

pytest.importorskip("PyQt6")

from PyQt6.QtWidgets import QApplication, QWidget  # noqa: E402

from plugins.devices import tabs  # noqa: E402
from plugins.devices.remote import Slot  # noqa: E402


@pytest.fixture(scope="module")
def qapp():
    app = QApplication.instance() or QApplication(["test"])
    yield app


class _FakeApp:
    def after(self, ms, fn, *a):
        return None

    def after_cancel(self, token):
        pass


class _FakeStore:
    def __init__(self):
        self._slots = {}

    def slot(self, name):
        if name not in self._slots:
            self._slots[name] = Slot([])
        return self._slots[name]


class _FakeCtx:
    def __init__(self):
        self.app = _FakeApp()
        self.store = _FakeStore()

    @staticmethod
    def t(key, **fmt):
        from plugins.devices.main import _t
        return _t(key, **fmt)

    def rows(self):
        return []

    def scope(self):
        return None

    def scoped_rows(self):
        return []

    def alerts(self, hosts=None):
        return []


def _host_widget():
    host = QWidget()
    return host


@pytest.mark.parametrize("tab_cls", [tabs.VulnerabilitiesTab, tabs.EventsTab,
                                     tabs.InventoryTab])
def test_tab_constructs(qapp, tab_cls):
    """Every Devices tab builds against an empty store without raising."""
    tab = tab_cls(_FakeCtx())
    assert tab is not None


def test_vulns_tab_severity_chip_roundtrip(qapp):
    ctx = _FakeCtx()
    tab = tabs.VulnerabilitiesTab(ctx)
    tab._toggle_sev("medium")
    assert tab._sev == "medium"
    assert not tab.filter_chip.isHidden()
    tab._clear_sev()
    assert tab._sev is None


def test_events_tab_severity_chip_roundtrip(qapp):
    ctx = _FakeCtx()
    tab = tabs.EventsTab(ctx)
    tab._toggle_sev("high")
    assert tab._sev == "high"
    tab._clear_sev()
    assert tab._sev is None
