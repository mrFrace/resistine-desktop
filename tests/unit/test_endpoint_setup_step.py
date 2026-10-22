"""The Windows/Linux endpoint step stays incomplete until its install worker
returns: the agent package starts the service before the root script has
written the enrollment key, and the wizard used to finish on that
(plugins/login/setup_steps.py)."""

import threading

import pytest

from plugins.login import setup_steps


@pytest.mark.unit
def test_not_complete_while_install_runs(monkeypatch):
    release = threading.Event()
    monkeypatch.setattr(setup_steps, "_wazuh_installed", lambda: True)
    monkeypatch.setattr(setup_steps, "_wazuh_running", lambda: True)
    monkeypatch.setattr(setup_steps, "_wazuh_connection", lambda: "connected")
    monkeypatch.setattr(setup_steps, "_wazuh_activate",
                        lambda *_a: release.wait(5) or True)
    monkeypatch.setattr(setup_steps, "_maybe_forward_clamav", lambda _s: None)

    step = setup_steps._EndpointStepDirect(app=None)
    assert step.is_complete()  # already set up before the wizard ran
    done = threading.Event()
    monkeypatch.setattr(step, "_run_bg",
                        lambda fn: threading.Thread(target=lambda: (fn(), done.set())).start())
    step.begin(lambda _m: None)
    assert not step.is_complete()
    release.set()
    assert done.wait(5)
    assert step.is_complete()


def _running_agent(monkeypatch):
    monkeypatch.setattr(setup_steps, "_wazuh_installed", lambda: True)
    monkeypatch.setattr(setup_steps, "_wazuh_running", lambda: True)
    monkeypatch.setattr(setup_steps, "_wazuh_connection", lambda: "pending")
    monkeypatch.setattr(setup_steps, "_wazuh_activate", lambda *_a: True)
    monkeypatch.setattr(setup_steps, "_maybe_forward_clamav", lambda _s: None)


def _signed_in_as_new_device():
    from utils import settings
    settings.set("auth", "user_id", "@alice:phoenix.exposed")
    settings.set("auth", "device_id", "PHX_BBBBBBBBBBBBBBBB")
    # Enrolled before the last sign-out, as another device.
    settings.set("wazuh", "enrolled_device", "PHX_AAAAAAAAAAAAAAAA")
    settings.set("wazuh", "enrolled_device_account", "@alice:phoenix.exposed")


@pytest.mark.unit
def test_running_agent_from_an_earlier_sign_in_is_re_enrolled(monkeypatch):
    """After sign-out + sign-in the old agent still runs locally, but the
    server deleted it: the step is not done and re-enrolls."""
    from plugins.wazuh.agent import enrollment

    _running_agent(monkeypatch)
    _signed_in_as_new_device()
    calls = []

    def reenroll(_status):
        calls.append(1)
        enrollment.mark_enrolled("031")   # what request() does on success
        return True
    monkeypatch.setattr(setup_steps, "_wazuh_reenroll", reenroll)

    step = setup_steps._EndpointStepDirect(app=None)
    assert not step.is_complete()
    monkeypatch.setattr(step, "_run_bg", lambda fn: fn())
    step.begin(lambda _m: None)
    assert calls == [1]
    assert step._failed is None
    assert step.is_complete()


@pytest.mark.unit
def test_failed_re_enroll_is_reported(monkeypatch):
    _running_agent(monkeypatch)
    _signed_in_as_new_device()
    monkeypatch.setattr(setup_steps, "_wazuh_reenroll", lambda _s: False)

    step = setup_steps._EndpointStepDirect(app=None)
    monkeypatch.setattr(step, "_run_bg", lambda fn: fn())
    step.begin(lambda _m: None)
    assert step._failed and "enroll" in step._failed
    assert not step.is_complete()


@pytest.mark.unit
def test_agent_auth_fallback_still_completes(monkeypatch):
    """Re-enrolled through agent-auth (no API answer, so nothing recorded):
    the step records the sign-in itself instead of asking forever."""
    _running_agent(monkeypatch)
    _signed_in_as_new_device()
    monkeypatch.setattr(setup_steps, "_wazuh_reenroll", lambda _s: True)

    step = setup_steps._EndpointStepDirect(app=None)
    monkeypatch.setattr(step, "_run_bg", lambda fn: fn())
    step.begin(lambda _m: None)
    assert step.is_complete()
