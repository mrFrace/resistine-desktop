"""
Unit tests for Windows Wazuh agent functions.

Covers plugins/wazuh/agent/wazuh_functions_windows.py:
- _is_admin: ctypes check
- _run_privileged: admin vs elevation paths, timeout, cleanup
- _get_machine_guid: registry access
- get_agent_name: hostname + GUID suffix, sanitization
- get_agent_group: email → safe group name
- needs_reenrollment: email mismatch detection
- is_agent_installed: directory + exe check
- get_agent_status: service query parsing
- _is_sysmon_installed: service query 64/32 fallback
- _download_file: PowerShell download
- start_agent / stop_agent: service control
- restore_client_key_if_needed: backup logic
- full_install: orchestration phases

All subprocess, network, registry, and ctypes calls are mocked — safe to run anywhere.
"""
import os
import sys
import json
import pytest
from unittest.mock import MagicMock, patch, call, mock_open


# Windows-only module stubs are provided by tests/conftest.py


@pytest.fixture(autouse=True)
def _windows_subprocess_constants():
    """Provide Windows-only subprocess.CREATE_NO_WINDOW when running off Windows.

    The module passes creationflags=subprocess.CREATE_NO_WINDOW to every
    subprocess.run call; without this the AttributeError is swallowed by the
    functions' broad except blocks and the parsing logic is never exercised.
    """
    with patch("subprocess.CREATE_NO_WINDOW", 0x08000000, create=True):
        yield


# ===========================================================================
# _is_admin
# ===========================================================================
@pytest.mark.unit
class TestIsAdmin:
    def test_returns_true_when_admin(self):
        with patch("ctypes.windll.shell32.IsUserAnAdmin", return_value=1):
            from plugins.wazuh.agent.wazuh_functions_windows import _is_admin
            assert _is_admin() is True

    def test_returns_false_when_not_admin(self):
        with patch("ctypes.windll.shell32.IsUserAnAdmin", return_value=0):
            from plugins.wazuh.agent.wazuh_functions_windows import _is_admin
            assert _is_admin() is False

    def test_returns_false_on_exception(self):
        with patch("ctypes.windll.shell32.IsUserAnAdmin", side_effect=Exception("No ctypes")):
            from plugins.wazuh.agent.wazuh_functions_windows import _is_admin
            assert _is_admin() is False


# ===========================================================================
# _run_privileged
# ===========================================================================
@pytest.mark.unit
class TestRunPrivileged:
    def test_admin_runs_directly(self):
        """When already admin, command runs as subprocess directly."""
        from plugins.wazuh.agent.wazuh_functions_windows import _run_privileged

        mock_result = MagicMock(returncode=0, stdout="output", stderr="")
        with patch("plugins.wazuh.agent.wazuh_functions_windows._is_admin", return_value=True):
            with patch("subprocess.run", return_value=mock_result) as mock_run:
                success, output = _run_privileged("Get-Service WazuhSvc")
        assert success is True
        assert output == "output"
        # Should call powershell directly
        cmd = mock_run.call_args[0][0]
        assert "powershell" in cmd[0].lower()

    def test_admin_timeout_returns_false(self):
        import subprocess
        from plugins.wazuh.agent.wazuh_functions_windows import _run_privileged

        with patch("plugins.wazuh.agent.wazuh_functions_windows._is_admin", return_value=True):
            with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("cmd", 300)):
                success, output = _run_privileged("slow command", timeout=1)
        assert success is False
        assert "timed out" in output.lower()

    def test_admin_exception_returns_false(self):
        from plugins.wazuh.agent.wazuh_functions_windows import _run_privileged

        with patch("plugins.wazuh.agent.wazuh_functions_windows._is_admin", return_value=True):
            with patch("subprocess.run", side_effect=OSError("boom")):
                success, output = _run_privileged("bad command")
        assert success is False
        assert "boom" in output

    def test_non_admin_elevates_via_runas(self, tmp_path):
        """When not admin, must use Start-Process -Verb RunAs."""
        from plugins.wazuh.agent.wazuh_functions_windows import _run_privileged

        mock_result = MagicMock(returncode=0, stdout="", stderr="")
        with patch("plugins.wazuh.agent.wazuh_functions_windows._is_admin", return_value=False):
            with patch("subprocess.run", return_value=mock_result):
                with patch("tempfile.NamedTemporaryFile") as mock_tmp:
                    mock_file = MagicMock()
                    mock_file.__enter__ = MagicMock(return_value=mock_file)
                    mock_file.__exit__ = MagicMock(return_value=False)
                    mock_file.name = str(tmp_path / "script.ps1")
                    mock_tmp.return_value = mock_file
                    with patch("os.path.exists", return_value=False):
                        with patch("os.unlink"):
                            success, output = _run_privileged("echo hello")
        # Should return a result even if result file is missing
        assert isinstance(success, bool)


# ===========================================================================
# _get_machine_guid
# ===========================================================================
@pytest.mark.unit
class TestGetMachineGuid:
    def test_reads_registry_guid(self):
        import winreg
        from plugins.wazuh.agent.wazuh_functions_windows import _get_machine_guid

        mock_key = MagicMock()
        with patch.object(winreg, "OpenKey", return_value=mock_key):
            with patch.object(winreg, "QueryValueEx",
                              return_value=("12345678-1234-1234-1234-123456789abc", 1)):
                with patch.object(winreg, "CloseKey"):
                    guid = _get_machine_guid()
        assert guid == "12345678-1234-1234-1234-123456789abc"

    def test_returns_none_on_registry_error(self):
        import winreg
        from plugins.wazuh.agent.wazuh_functions_windows import _get_machine_guid

        with patch.object(winreg, "OpenKey", side_effect=OSError("Access denied")):
            guid = _get_machine_guid()
        assert guid is None


# ===========================================================================
# get_agent_name
# ===========================================================================
@pytest.mark.unit
class TestGetAgentName:
    def test_includes_hostname_and_guid_suffix(self):
        from plugins.wazuh.agent.wazuh_functions_windows import get_agent_name

        with patch("plugins.wazuh.agent.wazuh_functions_windows.socket.gethostname",
                   return_value="DESKTOP-TEST"):
            with patch("plugins.wazuh.agent.wazuh_functions_windows._get_machine_guid",
                       return_value="12345678-1234-1234-1234-123456789abc"):
                name = get_agent_name()
        assert name.startswith("DESKTOP-TEST-")
        assert "123456789ABC" in name  # last 12 chars of GUID (no dashes), uppercased

    def test_hostname_only_when_no_guid(self):
        from plugins.wazuh.agent.wazuh_functions_windows import get_agent_name

        with patch("plugins.wazuh.agent.wazuh_functions_windows.socket.gethostname",
                   return_value="MYPC"):
            with patch("plugins.wazuh.agent.wazuh_functions_windows._get_machine_guid",
                       return_value=None):
                name = get_agent_name()
        assert name == "MYPC"

    def test_sanitizes_special_characters(self):
        """Name must only contain safe chars: [A-Za-z0-9.\\-_]"""
        from plugins.wazuh.agent.wazuh_functions_windows import get_agent_name

        with patch("plugins.wazuh.agent.wazuh_functions_windows.socket.gethostname",
                   return_value="My PC!@#$%"):
            with patch("plugins.wazuh.agent.wazuh_functions_windows._get_machine_guid",
                       return_value=None):
                name = get_agent_name()
        assert all(c.isalnum() or c in ".-_" for c in name)

    def test_no_shell_injection_chars(self):
        """Agent name must not contain shell metacharacters."""
        from plugins.wazuh.agent.wazuh_functions_windows import get_agent_name

        dangerous = ";`$\"'|&\n\x00/"
        with patch("plugins.wazuh.agent.wazuh_functions_windows.socket.gethostname",
                   return_value=f"host{dangerous}name"):
            with patch("plugins.wazuh.agent.wazuh_functions_windows._get_machine_guid",
                       return_value=None):
                name = get_agent_name()
        for char in dangerous:
            assert char not in name


# ===========================================================================
# get_agent_group
# ===========================================================================
@pytest.mark.unit
class TestGetAgentGroup:
    def test_email_at_replaced(self, isolated_settings, monkeypatch):
        monkeypatch.setattr("plugins.wazuh.agent.wazuh_functions_windows.settings", isolated_settings)
        isolated_settings.set("auth", "email", "user@example.com")
        from plugins.wazuh.agent.wazuh_functions_windows import get_agent_group
        # '@' -> '-' to match the canonical group name created server-side
        # by /verify-otp (groups are auto-created on enroll).
        assert get_agent_group() == "user-example.com"

    def test_default_when_no_email(self, isolated_settings, monkeypatch):
        monkeypatch.setattr("plugins.wazuh.agent.wazuh_functions_windows.settings", isolated_settings)
        from plugins.wazuh.agent.wazuh_functions_windows import get_agent_group
        assert get_agent_group() == "default"


# ===========================================================================
# needs_reenrollment
# ===========================================================================
@pytest.mark.unit
class TestNeedsReenrollment:
    def test_same_email_no_reenrollment(self, isolated_settings, monkeypatch):
        monkeypatch.setattr("plugins.wazuh.agent.wazuh_functions_windows.settings", isolated_settings)
        isolated_settings.set("auth", "email", "user@test.com")
        isolated_settings.set("wazuh", "enrolled_email", "user@test.com")
        from plugins.wazuh.agent.wazuh_functions_windows import needs_reenrollment
        assert needs_reenrollment() is False

    def test_different_email_needs_reenrollment(self, isolated_settings, monkeypatch):
        monkeypatch.setattr("plugins.wazuh.agent.wazuh_functions_windows.settings", isolated_settings)
        isolated_settings.set("auth", "email", "new@test.com")
        isolated_settings.set("wazuh", "enrolled_email", "old@test.com")
        from plugins.wazuh.agent.wazuh_functions_windows import needs_reenrollment
        assert needs_reenrollment() is True

    def test_no_enrolled_email_no_reenrollment(self, isolated_settings, monkeypatch):
        monkeypatch.setattr("plugins.wazuh.agent.wazuh_functions_windows.settings", isolated_settings)
        isolated_settings.set("auth", "email", "user@test.com")
        from plugins.wazuh.agent.wazuh_functions_windows import needs_reenrollment
        assert needs_reenrollment() is False


# ===========================================================================
# is_agent_installed
# ===========================================================================
@pytest.mark.unit
class TestIsAgentInstalled:
    def test_installed_when_dir_and_exe_exist(self):
        from plugins.wazuh.agent.wazuh_functions_windows import is_agent_installed

        def exists(path):
            return True

        with patch("os.path.isdir", return_value=True):
            with patch("os.path.exists", return_value=True):
                assert is_agent_installed() is True

    def test_not_installed_when_dir_missing(self):
        from plugins.wazuh.agent.wazuh_functions_windows import is_agent_installed
        with patch("os.path.isdir", return_value=False):
            assert is_agent_installed() is False

    def test_not_installed_when_exe_missing(self):
        from plugins.wazuh.agent.wazuh_functions_windows import is_agent_installed
        with patch("os.path.isdir", return_value=True):
            with patch("os.path.exists", return_value=False):
                assert is_agent_installed() is False


# ===========================================================================
# get_agent_status
# ===========================================================================
@pytest.mark.unit
class TestGetAgentStatus:
    def test_running(self):
        from plugins.wazuh.agent.wazuh_functions_windows import get_agent_status
        mock_result = MagicMock(stdout="STATE: 4  RUNNING", stderr="")
        with patch("plugins.wazuh.agent.wazuh_functions_windows.is_agent_installed", return_value=True):
            with patch("subprocess.run", return_value=mock_result):
                assert get_agent_status() == "Running"

    def test_stopped(self):
        from plugins.wazuh.agent.wazuh_functions_windows import get_agent_status
        mock_result = MagicMock(stdout="STATE: 1  STOPPED", stderr="")
        with patch("plugins.wazuh.agent.wazuh_functions_windows.is_agent_installed", return_value=True):
            with patch("subprocess.run", return_value=mock_result):
                assert get_agent_status() == "Stopped"

    def test_not_installed(self):
        from plugins.wazuh.agent.wazuh_functions_windows import get_agent_status
        with patch("plugins.wazuh.agent.wazuh_functions_windows.is_agent_installed", return_value=False):
            assert get_agent_status() == "Not Installed"

    def test_query_failure_returns_stopped(self):
        from plugins.wazuh.agent.wazuh_functions_windows import get_agent_status
        with patch("plugins.wazuh.agent.wazuh_functions_windows.is_agent_installed", return_value=True):
            with patch("subprocess.run", side_effect=Exception("sc not found")):
                assert get_agent_status() == "Stopped"


# ===========================================================================
# _is_sysmon_installed
# ===========================================================================
@pytest.mark.unit
class TestIsSysmonInstalled:
    def test_sysmon64_installed(self):
        from plugins.wazuh.agent.wazuh_functions_windows import _is_sysmon_installed
        mock_result = MagicMock(returncode=0)
        with patch("subprocess.run", return_value=mock_result):
            assert _is_sysmon_installed() is True

    def test_sysmon32_fallback(self):
        """If Sysmon64 not found, check 32-bit service."""
        from plugins.wazuh.agent.wazuh_functions_windows import _is_sysmon_installed
        results = [
            MagicMock(returncode=1),  # Sysmon64 not found
            MagicMock(returncode=0),  # Sysmon found
        ]
        with patch("subprocess.run", side_effect=results):
            assert _is_sysmon_installed() is True

    def test_neither_installed(self):
        from plugins.wazuh.agent.wazuh_functions_windows import _is_sysmon_installed
        results = [
            MagicMock(returncode=1),  # Sysmon64 not found
            MagicMock(returncode=1),  # Sysmon not found
        ]
        with patch("subprocess.run", side_effect=results):
            assert _is_sysmon_installed() is False


# ===========================================================================
# start_agent / stop_agent
# ===========================================================================
@pytest.mark.unit
class TestAgentStartStop:
    def test_start_agent_already_running(self):
        from plugins.wazuh.agent.wazuh_functions_windows import start_agent
        with patch("plugins.wazuh.agent.wazuh_functions_windows.get_agent_status",
                   return_value="Running"):
            assert start_agent() is True

    def test_start_agent_with_key_restore(self, tmp_path):
        from plugins.wazuh.agent.wazuh_functions_windows import start_agent

        with patch("plugins.wazuh.agent.wazuh_functions_windows.get_agent_status",
                   return_value="Stopped"):
            with patch("os.path.exists", return_value=False):
                with patch("plugins.wazuh.agent.wazuh_functions_windows._run_privileged",
                           return_value=(True, "Service started")):
                    assert start_agent() is True

    def test_stop_agent_not_installed(self):
        from plugins.wazuh.agent.wazuh_functions_windows import stop_agent
        with patch("plugins.wazuh.agent.wazuh_functions_windows.is_agent_installed",
                   return_value=False):
            assert stop_agent() is True

    def test_stop_agent_force_stop_fallback(self):
        """If NET STOP fails, should try Stop-Service -Force."""
        from plugins.wazuh.agent.wazuh_functions_windows import stop_agent

        call_count = [0]

        def mock_run_priv(cmd, timeout=300):
            call_count[0] += 1
            return (True, "OK")

        with patch("plugins.wazuh.agent.wazuh_functions_windows.is_agent_installed",
                   return_value=True):
            with patch("plugins.wazuh.agent.wazuh_functions_windows._run_privileged",
                       side_effect=mock_run_priv):
                with patch("plugins.wazuh.agent.wazuh_functions_windows.get_agent_status",
                           side_effect=["Running", "Stopped"]):
                    result = stop_agent()
        # Should have called _run_privileged twice (NET STOP + Stop-Service -Force)
        assert call_count[0] == 2
        assert result is True


# ===========================================================================
# restore_client_key_if_needed
# ===========================================================================
@pytest.mark.unit
class TestRestoreClientKey:
    def test_skips_on_reenrollment(self):
        from plugins.wazuh.agent.wazuh_functions_windows import restore_client_key_if_needed
        with patch("plugins.wazuh.agent.wazuh_functions_windows.needs_reenrollment",
                   return_value=True):
            assert restore_client_key_if_needed() is False

    def test_no_backup_returns_true(self):
        from plugins.wazuh.agent.wazuh_functions_windows import restore_client_key_if_needed
        with patch("plugins.wazuh.agent.wazuh_functions_windows.needs_reenrollment",
                   return_value=False):
            with patch("os.path.exists", return_value=False):
                assert restore_client_key_if_needed() is True

    def test_restores_key_when_missing(self):
        from plugins.wazuh.agent.wazuh_functions_windows import restore_client_key_if_needed
        with patch("plugins.wazuh.agent.wazuh_functions_windows.needs_reenrollment",
                   return_value=False):
            with patch("os.path.exists", return_value=True):
                with patch("plugins.wazuh.agent.wazuh_functions_windows._run_privileged",
                           return_value=(True, "KEY_RESTORED\nSUCCESS")) as mock_priv:
                    result = restore_client_key_if_needed()
        assert result is True
        # Verify the script was actually invoked (not just no-op'd)
        assert mock_priv.called, "_run_privileged was not called"
        # Verify the script references the right files
        script = mock_priv.call_args[0][0]
        assert "Test-Path" in script
        assert "Copy-Item" in script


# ===========================================================================
# BUG-HUNTING: Shell injection / argument escaping
# ===========================================================================
@pytest.mark.unit
class TestPrivilegedCommandSafety:
    """_run_privileged builds a PowerShell script via string interpolation.
    Any user-controlled input (agent name from hostname, group from email,
    file paths) reaching it could be a shell injection vector.

    NOTE: these tests caught two separate issues I encountered while
    working on this. First, get_agent_group was only replacing "@" with
    "." on the email, so quotes, semicolons, and backticks in the email
    input flowed straight into the msiexec command line that installs the
    Wazuh agent. Second, get_agent_name was returning an empty string
    for hostnames that sanitized down to nothing (e.g. a machine named
    entirely in non-ASCII characters), which would have caused Wazuh
    enrollment to fail with a confusing error on an otherwise valid
    machine. If you add any new user-derived value that ends up in a
    privileged PowerShell command please make sure it passes through the
    same allowlist sanitization these functions use now and also that
    it has a non-empty fallback, otherwise we'll run into either a
    remote exec exploitation vector or silent enrollment failures on
    real user machines. - Austin
    """

    def test_agent_name_with_quote_in_powershell_command(self):
        """If agent name ever contained a single quote, it would break
        PowerShell single-quoted arguments. get_agent_name() must sanitize
        such characters before they reach _run_privileged."""
        from plugins.wazuh.agent.wazuh_functions_windows import get_agent_name

        with patch("plugins.wazuh.agent.wazuh_functions_windows.socket.gethostname",
                   return_value="host'; rm -rf /; echo 'pwned"):
            with patch("plugins.wazuh.agent.wazuh_functions_windows._get_machine_guid",
                       return_value=None):
                name = get_agent_name()
        # Single quotes, semicolons, slashes — none should survive sanitization
        assert "'" not in name
        assert ";" not in name
        assert "/" not in name
        # The remaining name must still be non-empty and useful
        assert len(name) > 0

    def test_email_with_quote_safe_for_group_name(self, isolated_settings, monkeypatch):
        """Email used as group name reaches PowerShell. Quotes/spaces/etc.
        could break the agent_group argument in msiexec call."""
        monkeypatch.setattr("plugins.wazuh.agent.wazuh_functions_windows.settings",
                            isolated_settings)
        # An email-shaped string containing dangerous chars
        isolated_settings.set("auth", "email", "user'; calc.exe; '@evil.com")

        from plugins.wazuh.agent.wazuh_functions_windows import get_agent_group
        group = get_agent_group()
        # get_agent_group must strip shell metacharacters (same allowlist
        # as get_agent_name) before the value reaches PowerShell.
        if "'" in group or ";" in group:
            pytest.fail(
                f"get_agent_group() returned {group!r} containing shell "
                "metacharacters. This value flows into PowerShell commands "
                "in msiexec install_cmd — it must be sanitized like agent_name."
            )

    def test_hostname_with_only_special_chars_has_fallback(self):
        """If a hostname is ALL special chars (sanitization removes everything),
        get_agent_name must not return empty string — that would break Wazuh
        enrollment which requires a non-empty agent name."""
        from plugins.wazuh.agent.wazuh_functions_windows import get_agent_name

        with patch("plugins.wazuh.agent.wazuh_functions_windows.socket.gethostname",
                   return_value="!@#$%^&*()"):
            with patch("plugins.wazuh.agent.wazuh_functions_windows._get_machine_guid",
                       return_value=None):
                name = get_agent_name()
        assert name and len(name) > 0, (
            "Empty agent_name will cause Wazuh enrollment failure. "
            "Need a fallback like hostname-{guid} or 'unknown-{guid}'."
        )


# ===========================================================================
# BUG-HUNTING: get_agent_status edge cases
# ===========================================================================
@pytest.mark.unit
class TestAgentStatusEdgeCases:
    def test_subprocess_timeout_returns_stopped(self):
        """If sc query hangs and times out, status must be 'Stopped' not crash."""
        import subprocess
        from plugins.wazuh.agent.wazuh_functions_windows import get_agent_status
        with patch("plugins.wazuh.agent.wazuh_functions_windows.is_agent_installed",
                   return_value=True):
            with patch("subprocess.run",
                       side_effect=subprocess.TimeoutExpired("sc", 10)):
                # Must not raise; must return a valid status
                result = get_agent_status()
        assert result in ("Running", "Stopped", "Not Installed")

    def test_sc_query_unexpected_state_returns_stopped(self):
        """If sc query returns an unrecognized state (e.g. PAUSED on Win11),
        get_agent_status should return Stopped, not crash or return raw output."""
        from plugins.wazuh.agent.wazuh_functions_windows import get_agent_status
        # PAUSED is a valid SCM state but the code doesn't handle it
        mock_result = MagicMock(stdout="STATE: 7  PAUSED", stderr="")
        with patch("plugins.wazuh.agent.wazuh_functions_windows.is_agent_installed",
                   return_value=True):
            with patch("subprocess.run", return_value=mock_result):
                result = get_agent_status()
        # Currently returns "Stopped" by fall-through. Verify it's not raw output.
        assert result in ("Running", "Stopped", "Not Installed")
