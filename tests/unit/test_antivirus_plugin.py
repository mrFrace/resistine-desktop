"""Tests for plugins.antivirus.main — Plugin class logic methods.

Covers: check_status, _on_action routing, _handle_scan_complete,
_offer_quarantine_batch, destroy, status state mapping, and auto-update scheduler.
"""

import os
import time
from unittest.mock import MagicMock, patch

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtWidgets import (  # noqa: E402
    QApplication,
    QLabel,
    QMessageBox,
    QPlainTextEdit,
    QProgressBar,
    QPushButton,
    QStackedWidget,
    QWidget,
)

from plugins.antivirus.main import Plugin  # noqa: E402
from plugins.antivirus.scanner import ScanResult  # noqa: E402


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def qapp():
    """Real (offscreen) QApplication so scan-UI widgets are genuine Qt widgets."""
    return QApplication.instance() or QApplication([])


@pytest.fixture()
def plugin(qapp):
    """Create a Plugin instance with a mocked app and real scan widgets."""
    with patch("plugins.antivirus.main.clamav") as mock_clamav, \
         patch("plugins.antivirus.main.threading"), \
         patch("plugins.antivirus.main.settings") as mock_settings, \
         patch("platform.system", return_value="Darwin"):
        mock_settings.get.return_value = False
        mock_clamav.get_realtime_status.return_value = {
            "state": "protected", "installed": True, "db_present": True,
            "approved": True, "fda_granted": True,
            "clamd_running": True, "clamonacc_running": True,
        }
        mock_clamav.is_clamav_installed.return_value = True

        app = MagicMock()
        p = Plugin(app)

        # Wire up real Qt widgets for scan-related tests (what qt_ui builds).
        p._scan_log = QPlainTextEdit()
        p._scan_progress = QProgressBar()
        p._scan_status_label = QLabel()
        p._action_buttons = {
            "scan": QPushButton("Scan"),
            "scan_computer": QPushButton("Scan Computer"),
            "cancel_scan": QPushButton("Cancel"),
            "update_sigs": QPushButton("Update"),
        }
        return p


# ---------------------------------------------------------------------------
# check_status
# ---------------------------------------------------------------------------

@pytest.mark.unit
class TestCheckStatus:
    def test_protected_returns_ok(self, plugin):
        plugin._last_state = "protected"
        assert plugin.check_status() == "OK"

    def test_error_returns_error(self, plugin):
        plugin._last_state = "error"
        assert plugin.check_status() == "Error"

    @pytest.mark.parametrize("state", [
        "not_installed", "no_database", "approval_required",
        "fda_required", None,
    ])
    def test_other_states_return_warning(self, plugin, state):
        plugin._last_state = state
        assert plugin.check_status() == "Warning"


# ---------------------------------------------------------------------------
# _on_action routing
# ---------------------------------------------------------------------------

@pytest.mark.unit
class TestOnAction:
    def test_routes_known_actions(self, plugin):
        for action_key, method in (
            ("scan", "_start_scan"),
            ("update_sigs", "_start_sig_update"),
            ("whitelist_add", "_add_whitelist_entry"),
        ):
            with patch.object(plugin, method) as mock_handler:
                plugin._on_action(action_key)
                mock_handler.assert_called_once()

    def test_unknown_action_no_crash(self, plugin):
        # Should silently ignore unknown actions
        plugin._on_action("nonexistent_action")


# ---------------------------------------------------------------------------
# _handle_scan_complete
# ---------------------------------------------------------------------------

@pytest.mark.unit
class TestHandleScanComplete:
    def test_clean_scan(self, plugin):
        plugin._last_state = "protected"
        plugin._scanning = True
        plugin._scan_handle = MagicMock()
        plugin._scan_progress.show()
        result = ScanResult(
            target="/tmp/test", scanned=10, infected=0,
            duration="2.5 sec",
        )
        plugin._handle_scan_complete(result)

        assert plugin._scanning is False
        assert plugin._scan_handle is None
        assert plugin._scan_progress.isHidden()
        assert plugin._scan_progress.value() == 1000
        assert plugin._scan_status_label.text() == "No threats found"
        log = plugin._scan_log.toPlainText()
        assert "10 files scanned, 0 infected" in log
        assert "Time: 2.5 sec" in log

    def test_infected_scan_offers_quarantine(self, plugin):
        plugin._last_state = "protected"
        result = ScanResult(
            target="/tmp/test", scanned=5, infected=2,
            infections=[
                "/tmp/test/virus1.exe: Win.Trojan FOUND",
                "/tmp/test/virus2.dll: Backdoor.Agent FOUND",
            ],
        )
        with patch.object(plugin, "_offer_quarantine_batch") as mock_offer, \
             patch("plugins.antivirus.threat_log.log_threat_detected") as mock_log, \
             patch("utils.notifications.send") as mock_notify:
            plugin._handle_scan_complete(result)
            mock_offer.assert_called_once()
            paths = mock_offer.call_args[0][0]
            assert "/tmp/test/virus1.exe" in paths
            assert "/tmp/test/virus2.dll" in paths
            assert mock_log.call_count == 2
            mock_notify.assert_called_once()
        assert plugin._scan_status_label.text() == "Threats found: 2"

    def test_scan_error(self, plugin):
        plugin._last_state = "protected"
        result = ScanResult(target="/tmp/test", error="ClamAV crashed")
        plugin._handle_scan_complete(result)
        assert plugin._scan_status_label.text() == "Scan failed"
        assert "Error: ClamAV crashed" in plugin._scan_log.toPlainText()
        assert plugin._scan_progress.value() == 0

    def test_scan_cancelled(self, plugin):
        plugin._last_state = "protected"
        result = ScanResult(target="/tmp/test", error="Scan cancelled.")
        plugin._handle_scan_complete(result)
        assert plugin._scan_status_label.text() == "Scan cancelled"
        assert "Scan cancelled." in plugin._scan_log.toPlainText()

    def test_buttons_reenabled_after_scan(self, plugin):
        plugin._last_state = "protected"
        plugin._set_scan_buttons_state("disabled")
        result = ScanResult(target="/tmp/test", scanned=1)
        plugin._handle_scan_complete(result)
        assert plugin._action_buttons["scan"].isEnabled()
        assert plugin._action_buttons["scan_computer"].isEnabled()

    @pytest.mark.parametrize("state", ["no_database", "not_installed"])
    def test_buttons_disabled_when_engine_unusable(self, plugin, state):
        plugin._last_state = state
        result = ScanResult(target="/tmp/test", scanned=0)
        plugin._handle_scan_complete(result)
        assert not plugin._action_buttons["scan"].isEnabled()
        assert not plugin._action_buttons["scan_computer"].isEnabled()

    def test_cancel_button_hidden_and_reset_after_scan(self, plugin):
        plugin._last_state = "protected"
        cancel = plugin._action_buttons["cancel_scan"]
        cancel.show()
        cancel.setEnabled(False)  # as left by _cancel_scan
        result = ScanResult(target="/tmp/test", scanned=1)
        plugin._handle_scan_complete(result)
        assert cancel.isHidden()
        assert cancel.isEnabled()


# ---------------------------------------------------------------------------
# _cancel_scan
# ---------------------------------------------------------------------------

@pytest.mark.unit
class TestCancelScan:
    def test_cancel_active_scan(self, plugin):
        handle = MagicMock()
        handle.cancelled = False
        plugin._scan_handle = handle
        plugin._cancel_scan()
        handle.cancel.assert_called_once()
        assert plugin._cancel_requested is True
        assert not plugin._action_buttons["cancel_scan"].isEnabled()
        assert "Cancelling scan..." in plugin._scan_log.toPlainText()

    def test_cancel_no_active_scan(self, plugin):
        plugin._scan_handle = None
        # Should not raise
        plugin._cancel_scan()

    def test_cancel_already_cancelled(self, plugin):
        handle = MagicMock()
        handle.cancelled = True
        plugin._scan_handle = handle
        plugin._cancel_scan()
        handle.cancel.assert_not_called()


# ---------------------------------------------------------------------------
# _offer_quarantine_batch
# ---------------------------------------------------------------------------

@pytest.mark.unit
class TestOfferQuarantineBatch:
    _YES = QMessageBox.StandardButton.Yes
    _NO = QMessageBox.StandardButton.No

    def test_user_accepts(self, plugin):
        with patch.object(QMessageBox, "question", return_value=self._YES), \
             patch("plugins.antivirus.main.clamav") as mock_clamav, \
             patch("plugins.antivirus.threat_log.log_threat_quarantined") as mock_log:
            mock_clamav.quarantine_file.return_value = (True, "/quarantine/virus.exe.quarantined")

            plugin._offer_quarantine_batch({"/tmp/virus.exe": "Win.Trojan"})

            mock_clamav.quarantine_file.assert_called_once_with("/tmp/virus.exe")
            mock_log.assert_called_once_with(
                "Win.Trojan", "/tmp/virus.exe", "/quarantine/virus.exe.quarantined")
        log = plugin._scan_log.toPlainText()
        assert "Quarantined: virus.exe" in log
        assert "Quarantined 1/1 files" in log

    def test_user_declines(self, plugin):
        with patch.object(QMessageBox, "question", return_value=self._NO), \
             patch("plugins.antivirus.main.clamav") as mock_clamav:
            plugin._offer_quarantine_batch({"/tmp/virus.exe": "Win.Trojan"})

            mock_clamav.quarantine_file.assert_not_called()

    def test_quarantine_failure_logged(self, plugin):
        with patch.object(QMessageBox, "question", return_value=self._YES), \
             patch("plugins.antivirus.main.clamav") as mock_clamav:
            mock_clamav.quarantine_file.return_value = (False, "Permission denied")
            mock_clamav.list_quarantined.return_value = []

            plugin._offer_quarantine_batch({"/tmp/virus.exe": "Win.Trojan"})

            mock_clamav.quarantine_file.assert_called_once()
        log = plugin._scan_log.toPlainText()
        assert "Quarantine failed (virus.exe): Permission denied" in log
        assert "Quarantined 0/1 files" in log

    def test_truncates_long_listing(self, plugin):
        """Message shows first 20 files and '... and N more'."""
        infections = {f"/tmp/virus{i}.exe": f"Sig.{i}" for i in range(25)}
        with patch.object(QMessageBox, "question", return_value=self._NO) as mock_q, \
             patch("plugins.antivirus.main.clamav"):
            plugin._offer_quarantine_batch(infections)
            msg = mock_q.call_args[0][2]
            assert "25 infected" in msg
            assert "virus19.exe" in msg
            assert "virus20.exe" not in msg
            assert "5 more" in msg


# ---------------------------------------------------------------------------
# _start_scan guards
# ---------------------------------------------------------------------------

@pytest.mark.unit
class TestScanGuards:
    def test_scan_blocked_while_scanning(self, plugin):
        plugin._scanning = True
        with patch.object(plugin, "_pick_scan_targets") as mock_pick:
            plugin._start_scan()
            mock_pick.assert_not_called()

    def test_scan_cancelled_dialog(self, plugin):
        plugin._scanning = False
        with patch.object(plugin, "_pick_scan_targets", return_value=[]), \
             patch.object(plugin, "_run_multi_scan") as mock_run:
            plugin._start_scan()
            mock_run.assert_not_called()

    def test_whitelisted_targets_skipped(self, plugin):
        plugin._scanning = False
        with patch.object(plugin, "_pick_scan_targets",
                          return_value=["/a", "/b", "/a"]), \
             patch("plugins.antivirus.main.clamav") as mock_clamav, \
             patch.object(QMessageBox, "information") as mock_info, \
             patch.object(plugin, "_run_multi_scan") as mock_run:
            mock_clamav.is_path_whitelisted.side_effect = lambda p: p == "/b"
            plugin._start_scan()
            mock_run.assert_called_once_with(["/a"], label="Scan")
            mock_info.assert_called_once()


# ---------------------------------------------------------------------------
# destroy
# ---------------------------------------------------------------------------

@pytest.mark.unit
class TestDestroy:
    def test_destroy_clears_banner_refs(self, plugin):
        plugin._banner_frame = MagicMock()
        plugin._banner_label = MagicMock()
        plugin._banner_subtitle = MagicMock()
        plugin._banner_action_btn = MagicMock()
        container = MagicMock()
        plugin.main_container = container

        with patch.object(plugin, "_stop_auto_update_scheduler") as mock_stop:
            plugin.destroy()
            mock_stop.assert_called_once()

        container.deleteLater.assert_called_once()
        assert plugin._destroyed is True

        assert plugin._banner_frame is None
        assert plugin._banner_label is None
        assert plugin._banner_subtitle is None
        assert plugin._banner_action_btn is None
        assert plugin.main_container is None

    def test_destroy_no_main_frame(self, plugin):
        plugin.main_frame = None
        # Should not raise
        with patch.object(plugin, "_stop_auto_update_scheduler"):
            plugin.destroy()


# ---------------------------------------------------------------------------
# _toggle_auto_update
# ---------------------------------------------------------------------------

@pytest.mark.unit
class TestToggleAutoUpdate:
    def test_toggle_on_non_darwin_starts_scheduler(self, plugin):
        # On Linux/Windows the in-process scheduler still drives updates.
        plugin._auto_update_switch = MagicMock()
        plugin._auto_update_switch.isChecked.return_value = True
        with patch("platform.system", return_value="Linux"), \
             patch("plugins.antivirus.main.settings") as mock_settings, \
             patch("plugins.antivirus.main.clamav") as mock_clamav, \
             patch.object(plugin, "_start_auto_update_scheduler") as mock_start:
            plugin._toggle_auto_update()
            assert plugin._auto_update_on is True
            mock_settings.set.assert_called_once_with(
                "antivirus", "auto_update_enabled", True,
            )
            mock_start.assert_called_once()
            # Linux/Windows must never touch the macOS freshclam daemon.
            mock_clamav.set_freshclam_daemon_enabled.assert_not_called()

    def test_toggle_off_non_darwin_stops_scheduler(self, plugin):
        plugin._auto_update_switch = MagicMock()
        plugin._auto_update_switch.isChecked.return_value = False
        with patch("platform.system", return_value="Linux"), \
             patch("plugins.antivirus.main.settings") as mock_settings, \
             patch("plugins.antivirus.main.clamav") as mock_clamav, \
             patch.object(plugin, "_stop_auto_update_scheduler") as mock_stop:
            plugin._toggle_auto_update()
            assert plugin._auto_update_on is False
            mock_settings.set.assert_called_once_with(
                "antivirus", "auto_update_enabled", False,
            )
            mock_stop.assert_called_once()
            mock_clamav.set_freshclam_daemon_enabled.assert_not_called()

    def test_toggle_is_noop_on_darwin(self, plugin):
        # macOS has no auto-update toggle — updates are always on via the OS
        # freshclam daemon. _toggle_auto_update must do nothing there: no
        # daemon call, no scheduler, no settings write.
        plugin._auto_update_switch = None
        with patch("platform.system", return_value="Darwin"), \
             patch("plugins.antivirus.main.settings") as mock_settings, \
             patch("plugins.antivirus.main.clamav") as mock_clamav, \
             patch.object(plugin, "_start_auto_update_scheduler") as mock_start, \
             patch.object(plugin, "_stop_auto_update_scheduler") as mock_stop:
            plugin._toggle_auto_update()

            mock_settings.set.assert_not_called()
            mock_start.assert_not_called()
            mock_stop.assert_not_called()
            mock_clamav.set_freshclam_daemon_enabled.assert_not_called()

    def test_toggle_noop_without_switch_widget(self, plugin):
        # Defensive: even on a non-Darwin platform, calling the handler
        # before the settings card built the switch must not crash.
        plugin._auto_update_switch = None
        with patch("platform.system", return_value="Linux"), \
             patch("plugins.antivirus.main.settings") as mock_settings, \
             patch.object(plugin, "_start_auto_update_scheduler") as mock_start:
            plugin._toggle_auto_update()  # must not raise
            mock_settings.set.assert_not_called()
            mock_start.assert_not_called()


# ---------------------------------------------------------------------------
# Auto-update scheduler
# ---------------------------------------------------------------------------

@pytest.mark.unit
class TestAutoUpdateInitGating:
    def _build(self, system, auto_on):
        """Construct a Plugin under a given platform + auto_update setting,
        capturing whether _start_auto_update_scheduler ran in __init__."""
        with patch("plugins.antivirus.main.clamav") as mock_clamav, \
             patch("plugins.antivirus.main.threading"), \
             patch("plugins.antivirus.main.settings") as mock_settings, \
             patch("platform.system", return_value=system), \
             patch.object(
                 Plugin, "_start_auto_update_scheduler",
             ) as mock_start:
            mock_settings.get.return_value = auto_on
            mock_clamav.get_realtime_status.return_value = {
                "state": "protected", "installed": True, "db_present": True,
                "approved": True, "fda_granted": True,
                "clamd_running": True, "clamonacc_running": True,
            }
            mock_clamav.is_clamav_installed.return_value = True
            Plugin(MagicMock())
            return mock_start

    def test_darwin_does_not_start_scheduler_even_when_enabled(self):
        # macOS: the OS freshclam daemon owns updates; the thread stays off.
        mock_start = self._build("Darwin", auto_on=True)
        mock_start.assert_not_called()

    def test_non_darwin_starts_scheduler_when_enabled(self):
        mock_start = self._build("Linux", auto_on=True)
        mock_start.assert_called_once()

    def test_non_darwin_skips_scheduler_when_disabled(self):
        mock_start = self._build("Linux", auto_on=False)
        mock_start.assert_not_called()


@pytest.mark.unit
class TestAutoUpdateScheduler:
    def test_start_creates_daemon_thread(self, plugin):
        with patch("plugins.antivirus.main.threading") as mock_threading:
            mock_thread = MagicMock()
            mock_thread.is_alive.return_value = False
            mock_threading.Thread.return_value = mock_thread
            mock_threading.Event.return_value = MagicMock()

            plugin._auto_update_timer = None
            plugin._auto_update_stop = mock_threading.Event()
            plugin._start_auto_update_scheduler()

            mock_threading.Thread.assert_called_once_with(
                target=plugin._auto_update_loop, daemon=True,
            )
            mock_thread.start.assert_called_once()

    def test_start_skips_if_already_running(self, plugin):
        mock_timer = MagicMock()
        mock_timer.is_alive.return_value = True
        plugin._auto_update_timer = mock_timer

        with patch("plugins.antivirus.main.threading") as mock_threading:
            plugin._start_auto_update_scheduler()
            mock_threading.Thread.assert_not_called()

    def test_stop_sets_event_and_joins_thread(self, plugin):
        stop_event = MagicMock()
        mock_timer = MagicMock()
        plugin._auto_update_stop = stop_event
        plugin._auto_update_timer = mock_timer
        plugin._stop_auto_update_scheduler()
        stop_event.set.assert_called_once()
        mock_timer.join.assert_called_once_with(timeout=2)
        assert plugin._auto_update_timer is None

    def test_seconds_until_next_run_positive(self, plugin):
        delay = plugin._seconds_until_next_run()
        assert delay >= 60  # Floor of 1 minute
        # Should be within 24h + jitter (max ~26 hours)
        assert delay < 26 * 3600

    @staticmethod
    def _run_loop(plugin, last_sig_update_ts):
        """Run _auto_update_loop until its second wait; return the clamav mock.

        The first wait "expires" (one scheduled update), the second stops the
        loop. Settings are mocked so the loop's stale-signature catch-up
        depends only on *last_sig_update_ts*, and a successful update can't
        write the timestamp into the real config.
        """
        waits = 0

        def fake_wait(timeout):
            nonlocal waits
            waits += 1
            return waits >= 2

        plugin._auto_update_stop = MagicMock()
        plugin._auto_update_stop.is_set.return_value = False
        plugin._auto_update_stop.wait.side_effect = fake_wait
        plugin._auto_update_on = True
        plugin.app = MagicMock()

        with patch("plugins.antivirus.main.clamav") as mock_clamav, \
             patch("plugins.antivirus.main.settings") as mock_settings, \
             patch.object(plugin, "_seconds_until_next_run", return_value=0):
            mock_settings.get.return_value = last_sig_update_ts
            mock_clamav.run_freshclam.return_value = (True, "Updated")
            plugin._auto_update_loop()
        return mock_clamav, mock_settings

    def test_auto_update_loop_calls_freshclam(self, plugin):
        """Fresh signatures: only the scheduled update runs."""
        mock_clamav, mock_settings = self._run_loop(plugin, time.time())
        mock_clamav.run_freshclam.assert_called_once()
        mock_settings.set.assert_called_once()
        assert mock_settings.set.call_args.args[:2] == (
            "antivirus", "last_sig_update_ts")

    def test_auto_update_loop_catches_up_when_stale(self, plugin):
        """Never-updated signatures: a catch-up runs before the scheduled one."""
        mock_clamav, _ = self._run_loop(plugin, 0)
        assert mock_clamav.run_freshclam.call_count == 2


# ---------------------------------------------------------------------------
# _set_scan_buttons_state
# ---------------------------------------------------------------------------

@pytest.mark.unit
class TestSetScanButtonsState:
    def test_enables_scan(self, plugin):
        for key in ("scan", "scan_computer"):
            plugin._action_buttons[key].setEnabled(False)
        plugin._set_scan_buttons_state("normal")
        assert plugin._action_buttons["scan"].isEnabled()
        assert plugin._action_buttons["scan_computer"].isEnabled()

    def test_disables_scan(self, plugin):
        plugin._set_scan_buttons_state("disabled")
        assert not plugin._action_buttons["scan"].isEnabled()
        assert not plugin._action_buttons["scan_computer"].isEnabled()
        # Only the scan buttons are toggled — not cancel / update.
        assert plugin._action_buttons["cancel_scan"].isEnabled()
        assert plugin._action_buttons["update_sigs"].isEnabled()

    def test_missing_button_no_crash(self, plugin):
        plugin._action_buttons = {}
        plugin._set_scan_buttons_state("normal")  # Should not raise


# ---------------------------------------------------------------------------
# View switching (main <-> settings)
# ---------------------------------------------------------------------------

@pytest.mark.unit
class TestViewSwitching:
    def test_view_swap_switches_stacked_page(self, plugin):
        plugin._view_stack = QStackedWidget()
        plugin._main_view = QWidget()
        plugin._settings_view = QWidget()
        plugin._view_stack.addWidget(plugin._main_view)
        plugin._view_stack.addWidget(plugin._settings_view)
        plugin._view_stack.setCurrentWidget(plugin._main_view)
        plugin._current_view = "main"
        plugin.app = MagicMock()

        plugin._show_settings_view()
        assert plugin._current_view == "settings"
        assert plugin._view_stack.currentWidget() is plugin._settings_view
        # Settings lists + SIEM switch are refreshed (deferred via app.after).
        scheduled = [c.args[1] for c in plugin.app.after.call_args_list]
        assert plugin._refresh_whitelist in scheduled
        assert plugin._refresh_exclusions in scheduled
        assert plugin._refresh_siem_switch in scheduled

        # Re-showing the current view is a no-op.
        plugin.app.after.reset_mock()
        plugin._show_settings_view()
        plugin.app.after.assert_not_called()

        plugin._show_main_view()
        assert plugin._current_view == "main"
        assert plugin._view_stack.currentWidget() is plugin._main_view
