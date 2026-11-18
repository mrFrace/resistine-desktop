"""The macOS agent install must end when its admin prompt is cancelled.

The installer only learns about progress from a status file the elevated
script writes. A prompt dismissed after the first two seconds, or a wrong
password, means the script never runs and the file never appears: the
Endpoint page then sat on "Installing…" for good.
"""
import json
from unittest.mock import MagicMock

import pytest

import plugins.wazuh.agent.wazuh_functions_darwin as wfd


def _launcher(rc, stderr=b""):
    proc = MagicMock()
    proc.poll.return_value = rc
    proc.stderr.read.return_value = stderr
    return proc


@pytest.fixture
def status(tmp_path, monkeypatch):
    monkeypatch.setattr(wfd, "_install_launcher", None)
    return str(tmp_path / "phoenix-wazuh-install-abc123.status")


@pytest.mark.unit
class TestNoStatusFile:
    def test_prompt_still_open_keeps_waiting(self, status, monkeypatch):
        monkeypatch.setattr(wfd, "_install_launcher", _launcher(None))
        assert wfd._poll_install_status(status) == (False, False, {})

    @pytest.mark.parametrize("stderr", [
        b"execution error: User canceled. (-128)",
        b"execution error: The administrator user name or password was incorrect. (-60005)",
        b"",
    ])
    def test_cancel_or_wrong_password_ends_the_install(self, status, monkeypatch, stderr):
        monkeypatch.setattr(wfd, "_install_launcher", _launcher(1, stderr))
        finished, success, details = wfd._poll_install_status(status)
        assert (finished, success) == (True, False)
        assert details["error"] == "user_canceled"

    def test_launcher_gone_without_a_result_is_a_failure(self, status, monkeypatch):
        monkeypatch.setattr(wfd, "_install_launcher", _launcher(0))
        finished, success, details = wfd._poll_install_status(status)
        assert (finished, success) == (True, False)
        assert details["error"] == "script_failed"

    def test_after_restart_a_live_install_is_left_alone(self, status, monkeypatch):
        """start_new_session keeps the elevated install alive across an app quit."""
        monkeypatch.setattr(wfd.subprocess, "run", lambda *a, **k: MagicMock(returncode=0))
        assert wfd._poll_install_status(status) == (False, False, {})

    def test_after_restart_a_dead_install_is_reported(self, status, monkeypatch):
        seen = []
        monkeypatch.setattr(wfd.subprocess, "run",
                            lambda cmd, **k: seen.append(cmd) or MagicMock(returncode=1))
        finished, success, details = wfd._poll_install_status(status)
        assert (finished, success) == (True, False)
        assert details["error"] == "no_status_file"
        assert seen[0][:2] == ["pgrep", "-f"] and seen[0][2] in status


@pytest.mark.unit
class TestStatusFileStillWins:
    @pytest.mark.parametrize("state,expected", [
        ("running", (False, False)), ("success", (True, True)), ("failed", (True, False))])
    def test_written_status_is_reported_as_before(self, status, monkeypatch, state, expected):
        # even with a launcher that already exited non-zero
        monkeypatch.setattr(wfd, "_install_launcher", _launcher(1, b"(-128)"))
        with open(status, "w") as f:
            json.dump({"status": state, "step": "x"}, f)
        assert wfd._poll_install_status(status)[:2] == expected

    def test_failure_reasons_have_a_message(self):
        """Every reason this can report is one the UI knows how to word."""
        import inspect
        from plugins.login import setup_steps
        from plugins.wazuh import main as wz_main

        for reason in ("user_canceled", "script_failed", "no_status_file"):
            assert f'"{reason}"' in inspect.getsource(setup_steps)
            assert f'"{reason}"' in inspect.getsource(wz_main)
