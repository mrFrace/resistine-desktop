"""The shell's "Check now" (BasePlugin.recheck) in the plugins that cache
their status: each measures again on its own thread, without doubling
its regular poll."""

from unittest.mock import MagicMock

import pytest

pytestmark = pytest.mark.unit


def test_devices_fetches_again_ignoring_the_throttle():
    from plugins.devices import main as dv
    p = dv.Plugin.__new__(dv.Plugin)
    p._destroyed = False
    p._kick_fetch = MagicMock()
    assert p.recheck() is True
    p._kick_fetch.assert_called_once_with(force=True)
    p._destroyed = True
    assert p.recheck() is False


def test_wazuh_reads_once_without_a_second_poll_chain(monkeypatch):
    from plugins.wazuh import main as wz
    monkeypatch.setattr(wz, "_platform_supported", True)
    p = wz.Plugin.__new__(wz.Plugin)
    p._destroyed = False
    order = []
    p._stop_status_polling = lambda: order.append("stop")
    p._poll_tick = lambda: order.append("tick")
    assert p.recheck() is True
    assert order == ["stop", "tick"]
    monkeypatch.setattr(wz, "_platform_supported", False)
    assert p.recheck() is False


def test_antivirus_reads_the_daemon_state_on_a_worker(monkeypatch):
    from plugins.antivirus import main as av
    started = []

    class T:
        def __init__(self, target, **kw):
            self.target = target

        def start(self):
            started.append(self.target)
    monkeypatch.setattr(av.threading, "Thread", T)
    p = av.Plugin.__new__(av.Plugin)
    p._poll_initial_status = lambda: None
    assert p.recheck() is True
    assert started == [p._poll_initial_status]
