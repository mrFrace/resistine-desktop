"""The macOS VPN setup step fails fast, with the reason, when this build
can't run the VPN or macOS refuses the extension, instead of sending the
user to System Settings and waiting five minutes (plugins/login/setup_steps.py)."""

from unittest.mock import MagicMock

import pytest

from plugins.login import setup_steps
from plugins.vpn.wireguard import vpn_functions_darwin as vfd


@pytest.fixture
def step(monkeypatch):
    s = setup_steps._VPNStepMac.__new__(setup_steps._VPNStepMac)
    s._failed = None
    s.cancelled = lambda: False
    s._open_settings = MagicMock()
    monkeypatch.setattr("time.sleep", lambda _s: None)
    return s


@pytest.mark.unit
def test_build_without_vpn(step, monkeypatch):
    monkeypatch.setattr(vfd, "vpn_unavailable_reason", lambda: vfd.NOT_BUNDLED)
    monkeypatch.setattr(vfd.VPNHelper, "activate_extension", staticmethod(lambda: pytest.fail("no request")))
    assert step._ensure_permission(lambda _m: None) is False
    assert step._failed == vfd.NOT_BUNDLED
    step._open_settings.assert_not_called()


@pytest.mark.unit
def test_macos_refuses_the_extension(step, monkeypatch):
    monkeypatch.setattr(vfd, "vpn_unavailable_reason", lambda: None)
    monkeypatch.setattr(vfd, "is_extension_enabled", lambda: False)
    monkeypatch.setattr(vfd.VPNHelper, "activate_extension", staticmethod(lambda: True))
    monkeypatch.setattr(vfd.VPNHelper, "activation_error",
                        staticmethod(lambda: "Missing entitlement com.apple.developer.system-extension.install"))
    assert step._ensure_permission(lambda _m: None) is False
    assert "Missing entitlement" in step._failed
    step._open_settings.assert_not_called()


@pytest.mark.unit
def test_needs_approval_opens_settings_and_waits(step, monkeypatch):
    checks = iter([False] * 10 + [True])
    monkeypatch.setattr(vfd, "vpn_unavailable_reason", lambda: None)
    monkeypatch.setattr(vfd, "is_extension_enabled", lambda: next(checks))
    monkeypatch.setattr(vfd.VPNHelper, "activate_extension", staticmethod(lambda: True))
    monkeypatch.setattr(vfd.VPNHelper, "activation_error", staticmethod(lambda: None))
    statuses = []
    assert step._ensure_permission(statuses.append) is True
    step._open_settings.assert_called_once()
    assert "System Settings" in statuses[0]
