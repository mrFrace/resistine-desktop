"""Linux build: child processes get the system libraries; root skips pkexec."""

import subprocess
import sys

import pytest

from utils import functions


@pytest.fixture
def frozen_linux(monkeypatch):
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "platform", "linux")


def test_restores_the_users_library_path(frozen_linux, monkeypatch):
    monkeypatch.setenv("LD_LIBRARY_PATH", "/opt/phoenix/_internal")
    monkeypatch.setenv("LD_LIBRARY_PATH_ORIG", "/home/me/lib")
    functions.restore_system_library_path()
    import os
    assert os.environ["LD_LIBRARY_PATH"] == "/home/me/lib"
    assert "LD_LIBRARY_PATH_ORIG" not in os.environ


def test_drops_the_bundle_path_when_the_user_had_none(frozen_linux, monkeypatch):
    monkeypatch.setenv("LD_LIBRARY_PATH", "/opt/phoenix/_internal")
    monkeypatch.delenv("LD_LIBRARY_PATH_ORIG", raising=False)
    functions.restore_system_library_path()
    import os
    assert "LD_LIBRARY_PATH" not in os.environ


def test_leaves_source_runs_alone(monkeypatch):
    monkeypatch.delattr(sys, "frozen", raising=False)
    monkeypatch.setenv("LD_LIBRARY_PATH", "/nix/store/x/lib")
    functions.restore_system_library_path()
    import os
    assert os.environ["LD_LIBRARY_PATH"] == "/nix/store/x/lib"


@pytest.mark.platform_linux
@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux only")
def test_root_runs_commands_without_pkexec(monkeypatch):
    from plugins.wazuh.agent import wazuh_functions_linux as wz

    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        return subprocess.CompletedProcess(cmd, 0, stdout="ok\n", stderr="")

    monkeypatch.setattr(wz.os, "geteuid", lambda: 0)
    monkeypatch.setattr(wz.subprocess, "run", fake_run)
    assert wz.run_privileged_command(["systemctl", "start", "wazuh-agent"]) == (True, "ok")
    assert calls == [["systemctl", "start", "wazuh-agent"]]


@pytest.mark.platform_linux
@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux only")
def test_root_vpn_commands_without_pkexec(monkeypatch):
    from plugins.vpn.wireguard import vpn_functions_linux as vpn

    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr(vpn.os, "geteuid", lambda: 0)
    monkeypatch.setattr(vpn.subprocess, "run", fake_run)
    assert vpn.run_privileged_command(["wg-quick", "up", "phoenix"]).returncode == 0
    assert calls == [["wg-quick", "up", "phoenix"]]
