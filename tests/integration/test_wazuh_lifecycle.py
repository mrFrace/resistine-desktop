"""
Integration tests for the Wazuh agent lifecycle.

Covers the chain: email login → get_agent_group → create_wazuh_group →
get_agent_name → write_env_file → status checks.

All subprocess, os, and HTTP calls are mocked.
"""
import os
import pytest
from unittest.mock import MagicMock, patch


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------
@pytest.fixture(autouse=True)
def patch_wazuh_settings(isolated_settings, monkeypatch):
    monkeypatch.setattr(
        "plugins.wazuh.agent.wazuh_functions_darwin.settings", isolated_settings
    )


# ===========================================================================
# Agent identity
# ===========================================================================
@pytest.mark.integration
class TestAgentIdentity:
    @patch("plugins.wazuh.agent.wazuh_functions_darwin.subprocess.run")
    @patch("plugins.wazuh.agent.wazuh_functions_darwin.socket.gethostname", return_value="corp-laptop")
    def test_agent_name_unique_per_device(self, mock_host, mock_run, isolated_settings):
        """Two different hardware UUIDs must produce different agent names."""
        from plugins.wazuh.agent.wazuh_functions_darwin import get_agent_name

        mock_run.return_value = MagicMock(
            stdout='"IOPlatformUUID" = "AAAA-1111-2222-3333-4444444444AA"\n', returncode=0
        )
        name_a = get_agent_name()

        mock_run.return_value = MagicMock(
            stdout='"IOPlatformUUID" = "BBBB-1111-2222-3333-4444444444BB"\n', returncode=0
        )
        name_b = get_agent_name()

        assert name_a != name_b

    @patch("plugins.wazuh.agent.wazuh_functions_darwin.subprocess.run")
    @patch("plugins.wazuh.agent.wazuh_functions_darwin.socket.gethostname", return_value="my-mac")
    def test_agent_name_safe_chars_only(self, mock_host, mock_run):
        import re
        from plugins.wazuh.agent.wazuh_functions_darwin import get_agent_name

        mock_run.return_value = MagicMock(
            stdout='"IOPlatformUUID" = "ABCD-EF01-2345-6789-0123456789AB"\n', returncode=0
        )
        name = get_agent_name()
        # Only alphanumerics, hyphens, underscores, and dots allowed
        assert re.match(r"^[A-Za-z0-9.\-_]+$", name), f"Unsafe chars in: {name!r}"

    def test_agent_group_derived_from_email(self, isolated_settings):
        isolated_settings.set("auth", "email", "alice@acme.com")
        from plugins.wazuh.agent.wazuh_functions_darwin import get_agent_group
        group = get_agent_group()
        assert group == "alice.acme.com"

    def test_agent_group_no_at_symbol(self, isolated_settings):
        isolated_settings.set("auth", "email", "bob@security.company.io")
        from plugins.wazuh.agent.wazuh_functions_darwin import get_agent_group
        group = get_agent_group()
        assert "@" not in group


# ===========================================================================
# Re-enrollment detection
# ===========================================================================
@pytest.mark.integration
class TestReenrollment:
    def test_reenrollment_needed_on_email_change(self, isolated_settings):
        isolated_settings.set("auth", "email", "new.user@company.com")
        isolated_settings.set("wazuh", "enrolled_email", "old.user@company.com")
        from plugins.wazuh.agent.wazuh_functions_darwin import needs_reenrollment
        assert needs_reenrollment() is True

    def test_no_reenrollment_same_email(self, isolated_settings):
        isolated_settings.set("auth", "email", "user@company.com")
        isolated_settings.set("wazuh", "enrolled_email", "user@company.com")
        from plugins.wazuh.agent.wazuh_functions_darwin import needs_reenrollment
        assert needs_reenrollment() is False

    def test_restore_key_skips_on_reenrollment_needed(self, isolated_settings):
        """restore_client_key_if_needed must return False when re-enrollment required."""
        isolated_settings.set("auth", "email", "new@company.com")
        isolated_settings.set("wazuh", "enrolled_email", "old@company.com")

        with patch("plugins.wazuh.agent.wazuh_functions_darwin.os.path.exists", return_value=True):
            from plugins.wazuh.agent.wazuh_functions_darwin import restore_client_key_if_needed
            result = restore_client_key_if_needed()
        assert result is False


# ===========================================================================
# Group API integration
# ===========================================================================
@pytest.mark.integration
class TestWazuhGroupApi:
    @patch("requests.post")
    def test_group_created_on_first_install(self, mock_post, isolated_settings):
        isolated_settings.set("auth", "email", "user@example.com")
        mock_post.return_value = MagicMock(status_code=200, text="created")
        from plugins.wazuh.agent.wazuh_functions_darwin import (
            create_wazuh_group,
            get_agent_group,
        )
        group = get_agent_group()
        result = create_wazuh_group(group)
        assert result is True
        call_params = mock_post.call_args[1]["params"]
        assert call_params["name"] == "user.example.com"

    @patch("requests.post")
    def test_group_creation_idempotent(self, mock_post, isolated_settings):
        """Second call with same group name (409) should still succeed."""
        isolated_settings.set("auth", "email", "user@example.com")
        mock_post.return_value = MagicMock(status_code=409, text="already exists")
        from plugins.wazuh.agent.wazuh_functions_darwin import create_wazuh_group
        assert create_wazuh_group("user.example.com") is True

    @patch("requests.post")
    def test_group_fallback_to_default_on_failure(self, mock_post, isolated_settings):
        """full_install falls back to 'default' group if create_wazuh_group fails."""
        isolated_settings.set("auth", "email", "user@example.com")
        # Simulate create group failure
        mock_post.return_value = MagicMock(status_code=500, text="Internal Server Error")
        from plugins.wazuh.agent.wazuh_functions_darwin import create_wazuh_group, get_agent_group
        group = get_agent_group()
        result = create_wazuh_group(group)
        assert result is False
        # Caller (full_install) would use "default" as fallback


# ===========================================================================
# Status detection
# ===========================================================================
@pytest.mark.integration
class TestWazuhStatus:
    @patch("plugins.wazuh.agent.wazuh_functions_darwin.subprocess.run")
    @patch("plugins.wazuh.agent.wazuh_functions_darwin.os.path.isdir", return_value=True)
    @patch("plugins.wazuh.agent.wazuh_functions_darwin.os.path.exists", return_value=True)
    def test_status_running(self, mock_exists, mock_isdir, mock_run):
        mock_run.return_value = MagicMock(stdout="state = running\n", returncode=0)
        from plugins.wazuh.agent.wazuh_functions_darwin import get_agent_status
        assert get_agent_status() == "Running"

    @patch("plugins.wazuh.agent.wazuh_functions_darwin.subprocess.run")
    @patch("plugins.wazuh.agent.wazuh_functions_darwin.os.path.isdir", return_value=True)
    @patch("plugins.wazuh.agent.wazuh_functions_darwin.os.path.exists", return_value=True)
    def test_status_stopped(self, mock_exists, mock_isdir, mock_run):
        mock_run.side_effect = [
            MagicMock(stdout="state = stopped\n", returncode=0),
            MagicMock(returncode=1),
        ]
        from plugins.wazuh.agent.wazuh_functions_darwin import get_agent_status
        assert get_agent_status() == "Stopped"

    @patch("plugins.wazuh.agent.wazuh_functions_darwin.os.path.isdir", return_value=False)
    @patch("plugins.wazuh.agent.wazuh_functions_darwin.os.path.exists", return_value=False)
    def test_status_not_installed(self, mock_exists, mock_isdir):
        from plugins.wazuh.agent.wazuh_functions_darwin import get_agent_status
        assert get_agent_status() == "Not Installed"


# ===========================================================================
# env file writing
# ===========================================================================
@pytest.mark.integration
class TestEnvFileWriting:
    def test_env_file_has_manager_address(self, tmp_path):
        env_file = tmp_path / "wazuh_envs"
        with patch("plugins.wazuh.agent.wazuh_functions_darwin.WAZUH_ENV_FILE", str(env_file)):
            from plugins.wazuh.agent import wazuh_functions_darwin as wf
            wf.write_env_file("test-agent", "user.example.com")
        content = env_file.read_text()
        assert "WAZUH_MANAGER" in content
        from plugins.wazuh.config import WAZUH_MANAGER
        assert WAZUH_MANAGER in content

    def test_env_file_has_agent_name(self, tmp_path):
        env_file = tmp_path / "wazuh_envs"
        with patch("plugins.wazuh.agent.wazuh_functions_darwin.WAZUH_ENV_FILE", str(env_file)):
            from plugins.wazuh.agent import wazuh_functions_darwin as wf
            wf.write_env_file("my-unique-agent-ABC12345", "group")
        content = env_file.read_text()
        assert "my-unique-agent-ABC12345" in content

    def test_env_file_has_agent_group(self, tmp_path):
        env_file = tmp_path / "wazuh_envs"
        with patch("plugins.wazuh.agent.wazuh_functions_darwin.WAZUH_ENV_FILE", str(env_file)):
            from plugins.wazuh.agent import wazuh_functions_darwin as wf
            wf.write_env_file("host", "alice.corp.com")
        content = env_file.read_text()
        assert "alice.corp.com" in content
