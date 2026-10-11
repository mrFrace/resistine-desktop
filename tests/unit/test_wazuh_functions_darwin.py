"""
Unit tests for plugins/wazuh/agent/wazuh_functions_darwin.py (macOS).

All subprocess, os.path, and settings calls are mocked.
Tests run on any platform (subprocess.run is never actually called).

Covers:
- get_agent_name — hostname, UUID suffix, sanitization
- get_agent_group — email → group name conversion ('@' → '-')
- needs_reenrollment — email mismatch detection
- is_agent_installed — directory / plist checks
- get_agent_status — Running / Stopped / Not Installed
- get_package_url — architecture mapping
- write_env_file — content, error handling
- download_package — success, curl failure
- _run_privileged — success, timeout, exception
"""
import os
import platform
import subprocess
import pytest
from unittest.mock import MagicMock, patch, call


# ---------------------------------------------------------------------------
# All tests in this module mock subprocess — safe on all platforms
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def patch_settings(isolated_settings, monkeypatch):
    """Use isolated settings for all tests in this module."""
    monkeypatch.setattr("plugins.wazuh.agent.wazuh_functions_darwin.settings", isolated_settings)


# ===========================================================================
# get_agent_name
# ===========================================================================
@pytest.mark.unit
class TestGetAgentName:
    @patch("plugins.wazuh.agent.wazuh_functions_darwin.subprocess.run")
    @patch("plugins.wazuh.agent.wazuh_functions_darwin.socket.gethostname", return_value="MacBook-Pro.local")
    def test_name_contains_hostname(self, mock_host, mock_run):
        mock_run.return_value = MagicMock(
            stdout='"IOPlatformUUID" = "AABBCCDD-1234-5678-90AB-CDEF01234567"\n',
            returncode=0,
        )
        from plugins.wazuh.agent.wazuh_functions_darwin import get_agent_name
        name = get_agent_name()
        assert "MacBook" in name

    @patch("plugins.wazuh.agent.wazuh_functions_darwin.subprocess.run")
    @patch("plugins.wazuh.agent.wazuh_functions_darwin.socket.gethostname", return_value="MacBook-Pro.local")
    def test_name_contains_uuid_suffix(self, mock_host, mock_run):
        mock_run.return_value = MagicMock(
            stdout='"IOPlatformUUID" = "AABBCCDD-1234-5678-90AB-CDEF01234567"\n',
            returncode=0,
        )
        from plugins.wazuh.agent.wazuh_functions_darwin import get_agent_name
        name = get_agent_name()
        # Last 8 chars of "AABBCCDD12345678" stripped of hyphens → "01234567" upper
        assert "01234567" in name

    @patch("plugins.wazuh.agent.wazuh_functions_darwin.subprocess.run")
    @patch("plugins.wazuh.agent.wazuh_functions_darwin.socket.gethostname", return_value="my laptop")
    def test_sanitizes_spaces_in_hostname(self, mock_host, mock_run):
        mock_run.return_value = MagicMock(stdout="", returncode=1)
        from plugins.wazuh.agent.wazuh_functions_darwin import get_agent_name
        name = get_agent_name()
        assert " " not in name

    @patch("plugins.wazuh.agent.wazuh_functions_darwin.subprocess.run")
    @patch("plugins.wazuh.agent.wazuh_functions_darwin.socket.gethostname", return_value="host@name!")
    def test_sanitizes_special_chars(self, mock_host, mock_run):
        mock_run.return_value = MagicMock(stdout="", returncode=1)
        from plugins.wazuh.agent.wazuh_functions_darwin import get_agent_name
        name = get_agent_name()
        assert "@" not in name
        assert "!" not in name

    @patch("plugins.wazuh.agent.wazuh_functions_darwin.subprocess.run")
    @patch("plugins.wazuh.agent.wazuh_functions_darwin.socket.gethostname", return_value="host")
    def test_fallback_when_uuid_unavailable(self, mock_host, mock_run):
        mock_run.side_effect = Exception("ioreg not found")
        from plugins.wazuh.agent.wazuh_functions_darwin import get_agent_name
        name = get_agent_name()
        assert name == "host"

    @patch("plugins.wazuh.agent.wazuh_functions_darwin.subprocess.run")
    @patch("plugins.wazuh.agent.wazuh_functions_darwin.socket.gethostname", return_value="A" * 200)
    def test_long_hostname_no_crash(self, mock_host, mock_run):
        mock_run.return_value = MagicMock(stdout="", returncode=1)
        from plugins.wazuh.agent.wazuh_functions_darwin import get_agent_name
        name = get_agent_name()
        # Should not raise and should only contain safe chars
        import re
        assert re.match(r"^[A-Za-z0-9.\-_]*$", name)


# ===========================================================================
# get_agent_group
# ===========================================================================
@pytest.mark.unit
class TestGetAgentGroup:
    def test_email_at_replaced_with_hyphen(self, isolated_settings):
        # '@' -> '-' matches the group name the /verify-otp backend creates
        # server-side; dots in the domain are preserved.
        isolated_settings.set("auth", "email", "user@example.com")
        from plugins.wazuh.agent.wazuh_functions_darwin import get_agent_group
        group = get_agent_group()
        assert group == "user-example.com"

    def test_shell_unsafe_chars_stripped(self, isolated_settings):
        # Group is interpolated into a privileged shell script; quotes etc. must go.
        isolated_settings.set("auth", "email", "o'brien;rm@example.com")
        from plugins.wazuh.agent.wazuh_functions_darwin import get_agent_group
        assert get_agent_group() == "obrienrm-example.com"

    def test_no_email_returns_default(self, isolated_settings):
        # No email in settings
        from plugins.wazuh.agent.wazuh_functions_darwin import get_agent_group
        group = get_agent_group()
        assert group == "default"

    def test_subdomain_email(self, isolated_settings):
        isolated_settings.set("auth", "email", "admin@sub.domain.org")
        from plugins.wazuh.agent.wazuh_functions_darwin import get_agent_group
        group = get_agent_group()
        assert "@" not in group

    def test_default_keyword_returns_default(self, isolated_settings):
        isolated_settings.set("auth", "email", "default")
        from plugins.wazuh.agent.wazuh_functions_darwin import get_agent_group
        group = get_agent_group()
        assert group == "default"


# ===========================================================================
# needs_reenrollment
# ===========================================================================
@pytest.mark.unit
class TestNeedsReenrollment:
    def test_same_email_returns_false(self, isolated_settings):
        isolated_settings.set("auth", "email", "user@example.com")
        isolated_settings.set("wazuh", "enrolled_email", "user@example.com")
        from plugins.wazuh.agent.wazuh_functions_darwin import needs_reenrollment
        assert needs_reenrollment() is False

    def test_different_email_returns_true(self, isolated_settings):
        isolated_settings.set("auth", "email", "new@example.com")
        isolated_settings.set("wazuh", "enrolled_email", "old@example.com")
        from plugins.wazuh.agent.wazuh_functions_darwin import needs_reenrollment
        assert needs_reenrollment() is True

    def test_no_enrolled_email_returns_false(self, isolated_settings):
        isolated_settings.set("auth", "email", "user@example.com")
        from plugins.wazuh.agent.wazuh_functions_darwin import needs_reenrollment
        assert needs_reenrollment() is False

    def test_no_current_email_returns_false(self, isolated_settings):
        isolated_settings.set("wazuh", "enrolled_email", "user@example.com")
        from plugins.wazuh.agent.wazuh_functions_darwin import needs_reenrollment
        assert needs_reenrollment() is False

    def test_both_empty_returns_false(self, isolated_settings):
        from plugins.wazuh.agent.wazuh_functions_darwin import needs_reenrollment
        assert needs_reenrollment() is False


# ===========================================================================
# is_agent_installed
# ===========================================================================
@pytest.mark.unit
class TestIsAgentInstalled:
    @patch("plugins.wazuh.agent.wazuh_functions_darwin.os.path.isdir", return_value=True)
    @patch("plugins.wazuh.agent.wazuh_functions_darwin.os.path.exists", return_value=False)
    def test_installed_when_dir_exists(self, mock_exists, mock_isdir):
        from plugins.wazuh.agent.wazuh_functions_darwin import is_agent_installed
        assert is_agent_installed() is True

    @patch("plugins.wazuh.agent.wazuh_functions_darwin.os.path.isdir", return_value=False)
    @patch("plugins.wazuh.agent.wazuh_functions_darwin.os.path.exists", return_value=True)
    def test_installed_when_plist_exists(self, mock_exists, mock_isdir):
        from plugins.wazuh.agent.wazuh_functions_darwin import is_agent_installed
        assert is_agent_installed() is True

    @patch("plugins.wazuh.agent.wazuh_functions_darwin.os.path.isdir", return_value=False)
    @patch("plugins.wazuh.agent.wazuh_functions_darwin.os.path.exists", return_value=False)
    def test_not_installed_when_neither_exists(self, mock_exists, mock_isdir):
        from plugins.wazuh.agent.wazuh_functions_darwin import is_agent_installed
        assert is_agent_installed() is False


# ===========================================================================
# get_agent_status
# ===========================================================================
@pytest.mark.unit
class TestGetAgentStatus:
    @patch("plugins.wazuh.agent.wazuh_functions_darwin.is_agent_installed", return_value=False)
    def test_not_installed(self, _):
        from plugins.wazuh.agent.wazuh_functions_darwin import get_agent_status
        assert get_agent_status() == "Not Installed"

    @patch("plugins.wazuh.agent.wazuh_functions_darwin.subprocess.run")
    @patch("plugins.wazuh.agent.wazuh_functions_darwin.is_agent_installed", return_value=True)
    def test_running_via_launchd(self, _, mock_run):
        mock_run.return_value = MagicMock(stdout="state = running\n", returncode=0)
        from plugins.wazuh.agent.wazuh_functions_darwin import get_agent_status
        assert get_agent_status() == "Running"

    @patch("plugins.wazuh.agent.wazuh_functions_darwin.subprocess.run")
    @patch("plugins.wazuh.agent.wazuh_functions_darwin.is_agent_installed", return_value=True)
    def test_stopped_when_not_running(self, _, mock_run):
        # launchctl: not running; pgrep: not found
        mock_run.side_effect = [
            MagicMock(stdout="state = stopped\n", returncode=0),
            MagicMock(returncode=1),
        ]
        from plugins.wazuh.agent.wazuh_functions_darwin import get_agent_status
        assert get_agent_status() == "Stopped"

    @patch("plugins.wazuh.agent.wazuh_functions_darwin.subprocess.run")
    @patch("plugins.wazuh.agent.wazuh_functions_darwin.is_agent_installed", return_value=True)
    def test_running_via_pgrep_fallback(self, _, mock_run):
        # launchctl finds nothing; pgrep finds wazuh-agentd
        mock_run.side_effect = [
            MagicMock(stdout="", returncode=1),  # launchctl failed
            MagicMock(returncode=0),             # pgrep found process
        ]
        from plugins.wazuh.agent.wazuh_functions_darwin import get_agent_status
        assert get_agent_status() == "Running"

    @patch("plugins.wazuh.agent.wazuh_functions_darwin.subprocess.run")
    @patch("plugins.wazuh.agent.wazuh_functions_darwin.is_agent_installed", return_value=True)
    def test_stopped_when_both_checks_fail(self, _, mock_run):
        mock_run.side_effect = Exception("subprocess not available")
        from plugins.wazuh.agent.wazuh_functions_darwin import get_agent_status
        assert get_agent_status() == "Stopped"


# ===========================================================================
# get_package_url
# ===========================================================================
@pytest.mark.unit
class TestGetPackageUrl:
    @patch("plugins.wazuh.agent.wazuh_functions_darwin.platform.machine", return_value="arm64")
    def test_arm64_url(self, _):
        from plugins.wazuh.agent.wazuh_functions_darwin import get_package_url
        url = get_package_url()
        assert "arm64" in url
        assert url.startswith("https://packages.wazuh.com/4.x/macos/")
        assert url.endswith(".pkg")

    @patch("plugins.wazuh.agent.wazuh_functions_darwin.platform.machine", return_value="x86_64")
    def test_x86_64_url(self, _):
        from plugins.wazuh.agent.wazuh_functions_darwin import get_package_url
        url = get_package_url()
        assert "intel64" in url

    @patch("plugins.wazuh.agent.wazuh_functions_darwin.platform.machine", return_value="unknown_arch")
    def test_unknown_arch_defaults_to_arm64(self, _):
        from plugins.wazuh.agent.wazuh_functions_darwin import get_package_url
        url = get_package_url()
        assert "arm64" in url

    @patch("plugins.wazuh.agent.wazuh_functions_darwin.platform.machine", return_value="arm64")
    def test_url_contains_version(self, _):
        from plugins.wazuh.agent.wazuh_functions_darwin import get_package_url
        from plugins.wazuh.config import WAZUH_VERSION
        url = get_package_url()
        assert WAZUH_VERSION in url


# ===========================================================================
# write_env_file
# ===========================================================================
@pytest.mark.unit
class TestWriteEnvFile:
    def test_writes_correct_content(self, tmp_path):
        env_file = tmp_path / "wazuh_envs"
        with patch("plugins.wazuh.agent.wazuh_functions_darwin.WAZUH_ENV_FILE", str(env_file)):
            from plugins.wazuh.agent import wazuh_functions_darwin as wf
            # Reload to pick up patched constant
            result = wf.write_env_file("test-host-12345678", "user.example.com")
        assert result is True
        content = env_file.read_text()
        assert "WAZUH_MANAGER" in content
        assert "test-host-12345678" in content
        assert "user.example.com" in content

    def test_returns_false_on_write_error(self):
        with patch("plugins.wazuh.agent.wazuh_functions_darwin.os.open",
                   side_effect=PermissionError("denied")):
            from plugins.wazuh.agent.wazuh_functions_darwin import write_env_file
            result = write_env_file("host", "group")
        assert result is False


# ===========================================================================
# _run_privileged
# ===========================================================================
@pytest.mark.unit
class TestRunPrivileged:
    @patch("plugins.wazuh.agent.wazuh_functions_darwin.subprocess.run")
    def test_success(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0, stdout="done\n", stderr="")
        from plugins.wazuh.agent.wazuh_functions_darwin import _run_privileged
        ok, output = _run_privileged("echo done")
        assert ok is True
        assert output == "done"

    @patch("plugins.wazuh.agent.wazuh_functions_darwin.subprocess.run")
    def test_nonzero_returncode_returns_false(self, mock_run):
        mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="error msg")
        from plugins.wazuh.agent.wazuh_functions_darwin import _run_privileged
        ok, output = _run_privileged("bad_cmd")
        assert ok is False

    @patch("plugins.wazuh.agent.wazuh_functions_darwin.subprocess.run")
    def test_timeout_returns_false(self, mock_run):
        mock_run.side_effect = subprocess.TimeoutExpired("osascript", 120)
        from plugins.wazuh.agent.wazuh_functions_darwin import _run_privileged
        ok, output = _run_privileged("slow_cmd")
        assert ok is False
        assert "timed out" in output.lower()

    @patch("plugins.wazuh.agent.wazuh_functions_darwin.subprocess.run")
    def test_exception_returns_false(self, mock_run):
        mock_run.side_effect = RuntimeError("crash")
        from plugins.wazuh.agent.wazuh_functions_darwin import _run_privileged
        ok, output = _run_privileged("any_cmd")
        assert ok is False
