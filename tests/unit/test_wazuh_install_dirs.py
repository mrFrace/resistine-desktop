"""
Unit tests for Linux Wazuh agent install-dir detection.

Covers plugins/wazuh/agent/wazuh_functions_linux.py:
- installed_agent_dir: candidate search order
- is_app_managed_agent: only the Phoenix .deb the app itself installed
  (/opt/phoenix-agent plus the wazuh.app_installed flag)

os.path.isdir and settings are mocked — safe to run anywhere.
"""
from contextlib import contextmanager
from unittest.mock import patch

import pytest

from plugins.wazuh.agent import wazuh_functions_linux as linux


@contextmanager
def _only_dirs(*present, app_installed=False):
    with patch(
        "plugins.wazuh.agent.wazuh_functions_linux.os.path.isdir",
        side_effect=lambda path: path in present,
    ), patch(
        "plugins.wazuh.agent.wazuh_functions_linux.settings.get",
        side_effect=lambda ns, key, default=None:
            app_installed if (ns, key) == ("wazuh", "app_installed") else default,
    ):
        yield


@pytest.mark.unit
class TestInstalledAgentDir:
    def test_candidates(self):
        assert linux.LINUX_WAZUH_DIR_CANDIDATES == (
            "/var/ossec", "/opt/resistine", "/opt/phoenix-agent", "/opt/agent-phoenix")

    @pytest.mark.parametrize("path", linux.LINUX_WAZUH_DIR_CANDIDATES)
    def test_each_location_is_found(self, path):
        with _only_dirs(path):
            assert linux.installed_agent_dir() == path
            assert linux.is_agent_installed() is True

    def test_first_match_wins(self):
        with _only_dirs("/opt/resistine", "/opt/agent-phoenix"):
            assert linux.installed_agent_dir() == "/opt/resistine"

    def test_nothing_installed(self):
        with _only_dirs():
            assert linux.installed_agent_dir() is None
            assert linux.is_agent_installed() is False

    @pytest.mark.parametrize(
        "path", ["/var/ossec", "/opt/resistine", "/opt/phoenix-agent", "/opt/agent-phoenix"])
    def test_other_installs_are_not_app_managed(self, path):
        with _only_dirs(path):
            assert linux.is_app_managed_agent() is False

    @pytest.mark.parametrize("path", ["/var/ossec", "/opt/resistine", "/opt/agent-phoenix"])
    def test_flag_alone_is_not_enough(self, path):
        with _only_dirs(path, app_installed=True):
            assert linux.is_app_managed_agent() is False

    def test_app_installed_phoenix_deb_is_app_managed(self):
        with _only_dirs("/opt/phoenix-agent", app_installed=True):
            assert linux.is_app_managed_agent() is True


@pytest.mark.unit
class TestRemoveScriptSparesSystemManagedAgent:
    """Logout (wipe_keys=True) must not tear down an agent the app didn't install."""

    @pytest.mark.parametrize(
        "path", ["/var/ossec", "/opt/resistine", "/opt/phoenix-agent", "/opt/agent-phoenix"])
    def test_only_key_backup_is_removed(self, path):
        with _only_dirs(path):
            script = linux.build_remove_script(wipe_keys=True)
        assert linux._KEY_BACKUP in script
        for forbidden in ("systemctl", "wazuh-control", "userdel", "groupdel",
                          "rm -rf", "remove -y", "wazuh-agent.service"):
            assert forbidden not in script

    def test_without_wipe_does_nothing(self):
        with _only_dirs("/opt/resistine"):
            assert linux.build_remove_script(wipe_keys=False).strip() == ""

    def test_app_install_is_still_torn_down(self):
        with _only_dirs("/opt/phoenix-agent", app_installed=True):
            script = linux.build_remove_script(wipe_keys=True)
        assert "rm -rf '/opt/phoenix-agent'" in script
        assert "wazuh-control' stop" in script

    def test_arch_install_is_removed_with_pacman(self):
        with _only_dirs("/opt/phoenix-agent", app_installed=True), \
                patch.object(linux, "_get_os_info", return_value="arch"):
            script = linux.build_remove_script(wipe_keys=True)
        assert "pacman -R --noconfirm wazuh-agent" in script
        assert "rm -rf '/opt/phoenix-agent'" in script
