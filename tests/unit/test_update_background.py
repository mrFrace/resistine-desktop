"""The quiet daily update check (utils/updates/background.py).

- next_delay: a day after the last answered check, never before the start-up
  delay, a clock set back does not postpone it for ever
- notice: one message per build / expiry, repeated at most weekly
- run_once: failures are silent and retried, a rollback is reported
- _tick: nothing is asked while switched off or signed out

No network, no timers: channel.check and the window are mocked.
"""
from unittest.mock import MagicMock

import pytest

from plugins.wazuh.agent import phoenix_packages as pp
from utils.updates import background, channel

NOW = 1_800_000_000.0
DAY = 24 * 3600


@pytest.fixture(autouse=True)
def state(monkeypatch):
    """The "updates" settings namespace as a dict; no remembered answer."""
    store = {}
    monkeypatch.setattr(background.settings, "get",
                        lambda ns, k, d=None: store.get((ns, k), d))
    monkeypatch.setattr(background.settings, "set",
                        lambda ns, k, v: store.__setitem__((ns, k), v))
    monkeypatch.setattr(background, "_last", None)
    return store


def _result(available=True, stale=False, build=202610221500, os_key="windows",
            expires="2026-10-01"):
    latest = MagicMock(build=build, expires=expires)
    return MagicMock(available=available, stale=stale, latest=latest, os_key=os_key)


def _low(a, b):
    return a


@pytest.mark.unit
class TestNextDelay:
    def test_first_run_waits_only_the_startup_delay(self):
        assert background.next_delay(NOW, _low) == background.FIRST_DELAY[0]

    def test_a_day_after_the_last_answer(self, state):
        state[("updates", "last_check")] = NOW - 3600
        assert background.next_delay(NOW, _low) == DAY - 3600

    def test_overdue_check_runs_after_the_startup_delay(self, state):
        state[("updates", "last_check")] = NOW - 3 * DAY
        assert background.next_delay(NOW, _low) == background.FIRST_DELAY[0]

    def test_clock_set_back_does_not_postpone_the_check(self, state):
        state[("updates", "last_check")] = NOW + 400 * DAY
        assert background.next_delay(NOW, lambda a, b: b) <= DAY + background.JITTER

    def test_garbage_in_settings_is_ignored(self, state):
        state[("updates", "last_check")] = "soon"
        assert background.next_delay(NOW, _low) == background.FIRST_DELAY[0]


@pytest.mark.unit
class TestNotice:
    def test_new_build_is_announced_once(self):
        text, kind = background.notice(_result(), NOW)
        assert "202610221500 is available" in text and "Settings" in text and kind == "info"
        assert background.notice(_result(), NOW + DAY) is None

    def test_same_build_is_mentioned_again_after_a_week(self):
        background.notice(_result(), NOW)
        assert background.notice(_result(), NOW + 8 * DAY) is not None

    def test_a_newer_build_is_announced_at_once(self):
        background.notice(_result(), NOW)
        assert background.notice(_result(build=202610230000), NOW + 60) is not None

    def test_linux_points_at_the_package_manager(self):
        text, _ = background.notice(_result(os_key="linux-deb"), NOW)
        assert "software updates" in text and "Settings" not in text

    def test_up_to_date_says_nothing(self):
        assert background.notice(_result(available=False), NOW) is None
        assert background.notice(None, NOW) is None

    def test_expired_channel_is_a_warning_even_when_up_to_date(self):
        text, kind = background.notice(_result(available=False, stale=True), NOW)
        assert "expired on 2026-10-01" in text and kind == "warning"
        assert background.notice(_result(available=False, stale=True), NOW + DAY) is None

    def test_release_without_this_os_says_nothing(self):
        r = _result()
        r.latest = None
        assert background.notice(r, NOW) is None


@pytest.mark.unit
@pytest.mark.security
class TestRunOnce:
    def test_answer_is_recorded_and_remembered(self, state, monkeypatch):
        r = _result()
        monkeypatch.setattr(channel, "check", lambda: r)
        answered, note = background.run_once(NOW)
        assert answered and note[1] == "info"
        assert state[("updates", "last_check")] == NOW and background.last_result() is r

    def test_unreachable_channel_is_silent_and_not_recorded(self, state, monkeypatch):
        def fail():
            raise pp.PackageError("Couldn't reach the Phoenix package server.")
        monkeypatch.setattr(channel, "check", fail)
        assert background.run_once(NOW) == (False, None)
        assert ("updates", "last_check") not in state

    def test_rollback_is_reported_once(self, monkeypatch):
        def fail():
            raise pp.PackageError("The update server offered an older Phoenix release "
                                  "than one it published before. It was not used.")
        monkeypatch.setattr(channel, "check", fail)
        answered, note = background.run_once(NOW)
        assert not answered and note[1] == "warning" and "older Phoenix release" in note[0]
        assert background.run_once(NOW + 3600) == (False, None)

    def test_unexpected_error_does_not_escape(self, monkeypatch):
        monkeypatch.setattr(channel, "check", MagicMock(side_effect=ValueError("boom")))
        assert background.run_once(NOW) == (False, None)

    def test_copy_outside_the_channel(self, state, monkeypatch):
        monkeypatch.setattr(channel, "check", lambda: None)
        assert background.run_once(NOW) == (True, None)


@pytest.mark.unit
class TestTick:
    @pytest.fixture
    def thread(self, monkeypatch):
        t = MagicMock()
        monkeypatch.setattr(background.threading, "Thread", t)
        return t

    def test_switched_off_asks_nothing(self, state, thread):
        state[("auth", "logged_in")] = True
        state[("updates", "auto_check")] = False
        window = MagicMock()
        background._tick(window)
        thread.assert_not_called()
        assert window.after.call_args.args[0] == background.RETRY * 1000

    def test_signed_out_asks_nothing(self, thread):
        window = MagicMock()
        background._tick(window)
        thread.assert_not_called()

    def test_signed_in_checks_off_the_gui_thread(self, state, thread):
        state[("auth", "logged_in")] = True
        background._tick(MagicMock())
        thread.return_value.start.assert_called_once()

    def test_notice_is_a_toast_that_opens_settings(self):
        window = MagicMock()
        window.isVisible.return_value = True
        background._show(window, "Phoenix build 1 is available.", "info")
        args, kw = window.show_notification.call_args
        assert args == ("Phoenix build 1 is available.", "info") and kw["action"] == "Open Settings"
        kw["on_action"]()
        window.navigate.assert_called_once_with("Settings")

    def test_on_by_default(self):
        assert background.enabled()
        background.set_enabled(False)
        assert not background.enabled()
