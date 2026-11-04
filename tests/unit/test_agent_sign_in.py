"""
Unit tests for linking an agent installed some other way, and for the
background check after sign-in (plugins/wazuh/agent/sign_in.py).

- enrollment.link(): POST /v1/agent/link with an HMAC of the key's secret,
  never the secret itself; records the enrollment only when the server agrees
- sign_in: re-enrolls this app's agent, links anyone else's, asks once per
  sign-in, and stays out of the way while the setup wizard has to run
- sign-out keeps "this app installed the agent"

The HTTP client and the platform module are mocked.
"""
import hashlib
import hmac
from unittest.mock import MagicMock, patch

import pytest

from plugins.wazuh.agent import enrollment, sign_in
from utils import settings

USER, DEV = "@alice:phoenix.exposed", "PHX_AAAAAAAAAAAAAAAA"
SECRET = "ab" * 32
LINE = f"024 anubis any {SECRET}"


def _resp(status=200, body=None):
    r = MagicMock()
    r.status_code = status
    r.json.return_value = body
    return r


@pytest.fixture(autouse=True)
def _signed_in():
    settings.set("auth", "logged_in", True)
    settings.set("auth", "user_id", USER)
    settings.set("auth", "device_id", DEV)
    settings.set("setup", "complete", True)


@pytest.fixture
def api():
    with patch("plugins.vpn.provisioning._authorized_request") as req:
        yield req


@pytest.mark.unit
@pytest.mark.security
class TestLink:
    def test_sends_proof_not_secret(self, api):
        api.return_value = _resp(200, {"agent_id": "024", "agent_name": "anubis",
                                       "group": "u_alice"})
        assert enrollment.link(LINE)
        assert api.call_args.args == ("POST", "/v1/agent/link")
        body = api.call_args.kwargs["json"]
        want = hmac.new(SECRET.encode(), f"phoenix-agent-link\n{USER}\n{DEV}".encode(),
                        hashlib.sha256).hexdigest()
        assert body == {"agent_id": "024", "proof": want}
        assert SECRET not in repr(api.call_args)
        assert enrollment.enrolled_for_this_sign_in()
        assert enrollment.enrolled_group() == "u_alice"

    @pytest.mark.parametrize("status,body", [
        (403, {"detail": "the proof does not match"}),
        (503, {"detail": "down"}),
        (200, {"agent_id": "025", "agent_name": "x", "group": "u_alice"}),
        (200, {"detail": "x"}),
    ])
    def test_refused_or_odd_answer_records_nothing(self, api, status, body):
        api.return_value = _resp(status, body)
        assert not enrollment.link(LINE)
        assert not enrollment.enrolled_for_this_sign_in()

    @pytest.mark.parametrize("line", ["", "024 anubis any short", LINE + " extra",
                                      "024 a b any " + SECRET])
    def test_unusable_key_line(self, api, line):
        assert not enrollment.link(line)
        api.assert_not_called()


def _platform(monkeypatch, app_managed, key_line=LINE, reenroll=(True, "ok")):
    m = MagicMock()
    m.is_agent_installed.return_value = True
    m.is_app_managed_agent.return_value = app_managed
    m.read_agent_key_line.return_value = key_line
    m.reenroll_agent.return_value = reenroll
    monkeypatch.setattr(sign_in, "_wazuh_mod", lambda: m)
    return m


@pytest.mark.unit
class TestBackgroundCheck:
    def test_links_an_agent_installed_elsewhere(self, monkeypatch):
        m = _platform(monkeypatch, app_managed=False)
        with patch.object(enrollment, "link", return_value=True) as link:
            sign_in._check()
        link.assert_called_once_with(LINE)
        m.reenroll_agent.assert_not_called()

    def test_re_enrolls_this_apps_agent(self, monkeypatch):
        m = _platform(monkeypatch, app_managed=True)
        sign_in._check()
        m.reenroll_agent.assert_called_once()
        m.read_agent_key_line.assert_not_called()
        assert enrollment.enrolled_for_this_sign_in()

    def test_nothing_to_do_when_enrolled_for_this_sign_in(self, monkeypatch):
        m = _platform(monkeypatch, app_managed=False)
        enrollment.mark_enrolled("024")
        sign_in._check()
        m.read_agent_key_line.assert_not_called()

    def test_dismissed_prompt_is_not_asked_again_this_sign_in(self, monkeypatch):
        m = _platform(monkeypatch, app_managed=False, key_line=None)
        sign_in._check()
        sign_in._check()
        assert m.read_agent_key_line.call_count == 1
        settings.clear_namespace("wazuh")   # sign-out
        sign_in._check()
        assert m.read_agent_key_line.call_count == 2

    def test_server_down_is_retried(self, monkeypatch):
        m = _platform(monkeypatch, app_managed=False)
        with patch.object(enrollment, "link", return_value=False):
            sign_in._check()
            sign_in._check()
        assert m.read_agent_key_line.call_count == 2

    def test_failed_re_enroll_is_not_repeated(self, monkeypatch):
        m = _platform(monkeypatch, app_managed=True, reenroll=(False, "cancelled"))
        sign_in._check()
        sign_in._check()
        assert m.reenroll_agent.call_count == 1

    @pytest.mark.parametrize("ns,key,value", [("auth", "logged_in", False),
                                              ("setup", "complete", False)])
    def test_waits_for_sign_in_and_setup(self, monkeypatch, ns, key, value):
        m = _platform(monkeypatch, app_managed=False)
        settings.set(ns, key, value)
        sign_in._check()
        m.read_agent_key_line.assert_not_called()

    def test_no_agent(self, monkeypatch):
        m = _platform(monkeypatch, app_managed=False)
        m.is_agent_installed.return_value = False
        sign_in._check()
        m.read_agent_key_line.assert_not_called()


@pytest.mark.unit
def test_sign_out_keeps_app_installed(monkeypatch):
    from plugins.settings.main import Plugin
    settings.set("wazuh", "app_installed", True)
    settings.set("wazuh", "enrolled_device", DEV)
    monkeypatch.setattr("plugins.vpn.config_manager.VPNConfigManager", MagicMock(), raising=False)
    Plugin._clear_user_data(MagicMock())
    assert settings.get("wazuh", "app_installed") is True
    assert settings.get("wazuh", "enrolled_device") is None
    assert settings.get("auth", "user_id") is None
