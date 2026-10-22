"""Linux ClamAV daemon activation: NixOS uses the system config, no pkexec setup."""

import pytest

from plugins.antivirus import clamav_platform_linux as lin


@pytest.fixture
def nixos(monkeypatch):
    monkeypatch.setattr(lin, "_os_release", lambda: {"ID": "nixos"})
    monkeypatch.setattr(lin, "_has_systemd", lambda: True)
    calls = []
    monkeypatch.setattr(lin, "_run_privileged",
                        lambda cmd, timeout=300: calls.append(cmd) or (True, ""))
    monkeypatch.setattr(lin, "_install_packages_if_missing",
                        lambda: pytest.fail("NixOS: no package install"))
    return calls


@pytest.mark.unit
class TestNixOSActivation:
    def test_without_services_clamav_explains_config(self, nixos, monkeypatch):
        monkeypatch.setattr(lin, "_systemctl_has_unit", lambda svc: False)
        ok, msg = lin.activate_system_daemons()
        assert not ok
        assert "services.clamav.daemon.enable" in msg
        assert nixos == []  # no admin prompt for something that can't work

    def test_with_services_clamav_only_starts_units(self, nixos, monkeypatch):
        monkeypatch.setattr(lin, "_systemctl_has_unit", lambda svc: True)
        monkeypatch.setattr(lin.time, "sleep", lambda s: None)
        monkeypatch.setattr("plugins.antivirus.clamav_common._ping_socket", lambda s: True)
        monkeypatch.setattr(lin, "is_clamonacc_running", lambda: True)
        ok, _msg = lin.activate_system_daemons()
        assert ok
        script = nixos[0][-1]
        assert "systemctl start clamav-daemon" in script
        assert "enable" not in script and "/etc/" not in script
