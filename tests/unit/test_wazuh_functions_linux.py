"""
Unit tests for Linux Wazuh agent install detection.

Covers plugins/wazuh/agent/wazuh_functions_linux.py:
- _is_wazuh_dir: marker file or wazuh ownership
- get_install_info: search order, system-managed flag, systemd fallback
- remove_agent: refuses installs managed outside the app

Filesystem and subprocess calls are mocked — safe to run anywhere.
"""
import sys
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

pytestmark = pytest.mark.skipif(
    sys.platform == "win32", reason="uses pwd/grp, which Windows lacks")


@pytest.fixture()
def linux():
    from plugins.wazuh.agent import wazuh_functions_linux

    return wazuh_functions_linux


def _only_dirs(*present):
    """Patch _is_wazuh_dir so exactly *present* look like installs."""
    return patch(
        "plugins.wazuh.agent.wazuh_functions_linux._is_wazuh_dir",
        side_effect=lambda path: path in present,
    )


@pytest.mark.unit
class TestIsWazuhDir:
    def test_missing_dir(self, linux, tmp_path):
        assert linux._is_wazuh_dir(str(tmp_path / "nope")) is False

    def test_marker_file(self, linux, tmp_path):
        (tmp_path / "bin").mkdir()
        (tmp_path / "bin" / "wazuh-control").touch()
        assert linux._is_wazuh_dir(str(tmp_path)) is True

    def test_unreadable_dir_owned_by_wazuh(self, linux, tmp_path):
        with patch("pwd.getpwuid", return_value=SimpleNamespace(pw_name="wazuh")), \
                patch("grp.getgrgid", return_value=SimpleNamespace(gr_name="wazuh")):
            assert linux._is_wazuh_dir(str(tmp_path)) is True

    def test_unrelated_dir(self, linux, tmp_path):
        with patch("pwd.getpwuid", return_value=SimpleNamespace(pw_name="root")), \
                patch("grp.getgrgid", return_value=SimpleNamespace(gr_name="root")):
            assert linux._is_wazuh_dir(str(tmp_path)) is False


@pytest.mark.unit
class TestGetInstallInfo:
    def test_search_dirs(self, linux):
        assert linux.LINUX_WAZUH_SEARCH_DIRS == (
            "/var/ossec", "/opt/resistine", "/opt/phoenix-agent", "/opt/agent-phoenix")

    def test_app_install_is_not_system_managed(self, linux):
        with _only_dirs("/var/ossec", "/opt/resistine"):
            assert linux.get_install_info() == {
                "path": "/var/ossec", "system_managed": False}

    @pytest.mark.parametrize(
        "path", ["/opt/resistine", "/opt/phoenix-agent", "/opt/agent-phoenix"])
    def test_other_locations_are_system_managed(self, linux, path):
        with _only_dirs(path):
            assert linux.get_install_info() == {"path": path, "system_managed": True}

    def test_systemd_unit_fallback(self, linux):
        out = MagicMock(stdout=(
            "LoadState=loaded\n"
            "ExecStart={ path=/srv/wazuh/bin/wazuh-control ; argv[]=... }\n"))
        with _only_dirs(), patch("subprocess.run", return_value=out):
            assert linux.get_install_info() == {
                "path": "/srv/wazuh", "system_managed": True}

    def test_nothing_found(self, linux):
        out = MagicMock(stdout="LoadState=not-found\nExecStart=\n")
        with _only_dirs(), patch("subprocess.run", return_value=out):
            assert linux.get_install_info() == {"path": None, "system_managed": False}
            assert linux.is_agent_installed() is False


@pytest.mark.unit
class TestRemoveAgent:
    def test_refuses_system_managed(self, linux):
        with _only_dirs("/opt/phoenix-agent"), \
                patch.object(linux, "run_privileged_command") as run:
            assert linux.remove_agent() is False
        run.assert_not_called()
