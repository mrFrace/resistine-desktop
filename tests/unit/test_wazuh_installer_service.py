"""
Unit tests for plugins/wazuh/agent/installer_service.py.

Focused on the failure-reason flow added to handle the postinstall script's
new enrollment-step errors (duplicate_name, manager_unreachable, enroll_rc_*).
Before this branch the script always proceeded to launchctl bootstrap even
when enrollment failed, producing a misleading "launchctl bootstrap failed"
error in the UI. The new contract: the script aborts at the enrollment step
with a specific error string, and installer_service surfaces it as the
failure_reason — which the UI maps to a useful message.
"""
import json
import os
import sys

import pytest
from unittest.mock import patch

# Skip Windows-only side-effects when importing the wazuh package on CI.
sys.modules.setdefault("AppKit", __import__("types").ModuleType("AppKit"))


@pytest.fixture(autouse=True)
def patch_settings(isolated_settings, monkeypatch):
    """Use isolated settings — both for installer_service AND the darwin module
    it imports inside its functions."""
    monkeypatch.setattr(
        "plugins.wazuh.agent.installer_service.settings", isolated_settings
    )


def _write_status(tmp_path, payload):
    p = tmp_path / "install.status"
    p.write_text(json.dumps(payload))
    return str(p)


@pytest.mark.unit
class TestPollMapsEnrollmentFailures:
    """Each failure string from the postinstall script should land in
    failure_reason exactly as the UI's _REASON_MSG dict expects."""

    @pytest.mark.parametrize("script_error", [
        "duplicate_name",
        "manager_unreachable",
        "enroll_failed",
        "enroll_rc_127",
    ])
    def test_enrollment_error_surfaces_as_failure_reason(
        self, tmp_path, isolated_settings, script_error
    ):
        from plugins.wazuh.agent import installer_service as svc

        # Simulate the postinstall script's failed-at-enrollment status file.
        status_file = _write_status(tmp_path, {
            "status": "failed",
            "step": "enrollment",
            "error": script_error,
            "attempted_name": "MacBook-AABB-1",
        })
        isolated_settings.set("wazuh", "install_status_file", status_file)
        isolated_settings.set("wazuh", "install_state", svc.STATE_INSTALLING)

        result = svc.poll_install_progress()

        assert result["finished"] is True
        assert result["success"] is False
        assert result["step"] == "enrollment"
        assert result["error"] == script_error
        # Reason is what main.py reads to choose the UI message.
        assert isolated_settings.get("wazuh", "failure_reason", "") == script_error
        assert isolated_settings.get("wazuh", "install_state", "") == (
            svc.STATE_INSTALL_FAILED
        )

    def test_launchd_failure_still_surfaces_distinctly(
        self, tmp_path, isolated_settings
    ):
        """The launchctl bootstrap branch must keep its own reason — it
        means agent-auth succeeded but the daemon couldn't load."""
        from plugins.wazuh.agent import installer_service as svc

        status_file = _write_status(tmp_path, {
            "status": "failed",
            "step": "launchd",
            "error": "launchctl bootstrap failed",
            "detail": "5: Input/output error",
        })
        isolated_settings.set("wazuh", "install_status_file", status_file)
        isolated_settings.set("wazuh", "install_state", svc.STATE_INSTALLING)

        result = svc.poll_install_progress()

        assert result["success"] is False
        assert result["step"] == "launchd"
        assert isolated_settings.get("wazuh", "failure_reason", "") == (
            "launchctl bootstrap failed"
        )


@pytest.mark.unit
class TestPollSuccessFlow:
    """Success path: enrolled or restored → STATE_READY; otherwise STATE_INSTALLED.
    The script now includes agent_name in the success payload so we can
    eventually show the suffix-promoted name in the UI."""

    @pytest.mark.parametrize("enrollment,expected_state", [
        ("enrolled", "ready"),
        ("restored", "ready"),
        ("none", "installed"),  # legacy no-enrollment path
    ])
    def test_success_transitions_to_correct_state(
        self, tmp_path, isolated_settings, enrollment, expected_state
    ):
        from plugins.wazuh.agent import installer_service as svc

        status_file = _write_status(tmp_path, {
            "status": "success",
            "step": "done",
            "enrollment": enrollment,
            "agent_name": "MacBook-AABB-1750000000-2",
        })
        isolated_settings.set("wazuh", "install_status_file", status_file)
        isolated_settings.set("wazuh", "install_state", svc.STATE_INSTALLING)
        isolated_settings.set("auth", "email", "user@example.com")

        result = svc.poll_install_progress()

        assert result["finished"] is True
        assert result["success"] is True
        assert result["enrollment"] == enrollment
        state = isolated_settings.get("wazuh", "install_state", "")
        assert state == expected_state


@pytest.mark.unit
class TestUIReasonMessages:
    """The UI must have a friendly message for every reason the script now
    emits — otherwise users see raw strings like 'duplicate_name'."""

    @pytest.mark.parametrize("reason", [
        "user_canceled",
        "script_failed",
        "pkg_corrupted",
        "no_status_file",
        "duplicate_name",
        "manager_unreachable",
        "enroll_failed",
    ])
    def test_every_known_reason_has_message(self, reason):
        # Pull the _REASON_MSG dict by importing the source — module-load
        # of plugins.wazuh.main triggers customtkinter which isn't safe in
        # CI, so we parse the source text instead.
        src = os.path.join(
            os.path.dirname(__file__), "..", "..", "plugins", "wazuh", "main.py"
        )
        with open(src) as f:
            content = f.read()
        # Trivial sanity: the friendly message must reference each reason key.
        assert f'"{reason}":' in content, (
            f"main.py is missing a UI message for reason {reason!r}"
        )

    def test_enroll_rc_pattern_has_generic_handler(self):
        src = os.path.join(
            os.path.dirname(__file__), "..", "..", "plugins", "wazuh", "main.py"
        )
        with open(src) as f:
            content = f.read()
        assert 'reason.startswith("enroll_rc_")' in content, (
            "main.py must catch enroll_rc_<N> reasons emitted by the script"
        )
