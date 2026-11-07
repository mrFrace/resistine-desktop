"""Linux Wazuh agent hardening.

- Values interpolated into privileged `sh -c` strings (deploy env, sed
  expressions) are re-checked locally against _SAFE_TOKEN_RE (defense in
  depth, mirroring wazuh_functions_darwin).
- The user-owned client.keys backup is re-validated against the enrollment
  key-line pattern before root copies it back into the agent.
"""

from unittest.mock import patch

import pytest

from plugins.wazuh.agent import wazuh_functions_linux as w


_GOOD_KEY = "001 agent-ABC123 any " + "a" * 64


# ===========================================================================
# _SAFE_TOKEN_RE guards on root sh -c interpolation
# ===========================================================================
@pytest.mark.unit
@pytest.mark.security
class TestSafeTokenGuards:
    def test_deploy_env_accepts_plain_tokens(self):
        env = w._deploy_env("host-1.example_2", "u_test")
        assert "WAZUH_AGENT_NAME='host-1.example_2'" in env
        assert "WAZUH_AGENT_GROUP='u_test'" in env

    @pytest.mark.parametrize("name,group", [
        ("host'; rm -rf / #", "u_test"),       # quote breakout
        ("host-1", "u_test$(id)"),             # command substitution
        ("host 1", "u_test"),                  # whitespace
        ("", "u_test"),                        # empty
        ("host-1", ""),                        # empty group
        ("host|1", "u_test"),                  # sed/shell metachar
    ])
    def test_deploy_env_rejects_unsafe_tokens(self, name, group):
        with pytest.raises(ValueError):
            w._deploy_env(name, group)

    @pytest.mark.parametrize("name,group", [
        ("a'; touch /pwned; '", "u_test"),
        ("host-1", "u|test"),
    ])
    def test_set_ossec_enrollment_rejects_unsafe_tokens(self, name, group):
        with pytest.raises(ValueError):
            w._set_ossec_enrollment("/opt/x/ossec.conf", name, group)

    def test_set_ossec_agent_name_rejects_unsafe_name(self):
        with pytest.raises(ValueError):
            w._set_ossec_agent_name("/opt/x/ossec.conf", "a|b")

    def test_full_install_refuses_unsafe_name_before_any_root_command(self):
        with patch.object(w, "download_package", return_value="/t/a.deb"), \
                patch.object(w, "get_agent_name", return_value="host'; rm -rf /"), \
                patch.object(w, "get_agent_group", return_value="u_test"), \
                patch.object(w.enrollment, "request", return_value=None), \
                patch.object(w.enrollment, "discard"), \
                patch.object(w, "run_privileged_command") as priv:
            assert w.full_install() is False
        priv.assert_not_called()

    def test_reenroll_refuses_unsafe_name_before_any_root_command(self):
        with patch.object(w, "is_agent_installed", return_value=True), \
                patch.object(w, "is_app_managed_agent", return_value=True), \
                patch.object(w, "get_agent_name", return_value="host$(id)"), \
                patch.object(w, "get_agent_group", return_value="u_test"), \
                patch.object(w.enrollment, "request", return_value=None), \
                patch.object(w.enrollment, "discard"), \
                patch.object(w, "run_privileged_command") as priv:
            ok, msg = w.reenroll_agent()
        assert ok is False and "Unsafe" in msg
        priv.assert_not_called()


# ===========================================================================
# _backup_key_is_valid: backup re-validated before root copies it back
# ===========================================================================
@pytest.mark.unit
@pytest.mark.security
class TestBackupKeyValidation:
    def _check(self, content, tmp_path):
        backup = tmp_path / "wazuh_client.keys"
        backup.write_text(content)
        with patch.object(w, "_KEY_BACKUP", str(backup)):
            return w._backup_key_is_valid()

    def test_valid_key_line_accepted(self, tmp_path):
        assert self._check(_GOOD_KEY + "\n", tmp_path) is True

    @pytest.mark.parametrize("bad", [
        "",                                            # empty
        "not a key",                                   # garbage
        "001 agent;reboot any " + "a" * 64,            # shell metacharacters
        _GOOD_KEY + "\n002 other any " + "b" * 64,     # multi-line
        "x" * 600,                                     # oversized (>512 cap)
        "#!/bin/sh\nreboot",                           # script masquerading
    ])
    def test_invalid_content_rejected(self, bad, tmp_path):
        assert self._check(bad, tmp_path) is False

    def test_unreadable_backup_rejected(self, tmp_path):
        with patch.object(w, "_KEY_BACKUP", str(tmp_path / "missing.keys")):
            assert w._backup_key_is_valid() is False

    def test_start_agent_skips_restore_for_invalid_backup(self, tmp_path):
        backup = tmp_path / "wazuh_client.keys"
        backup.write_text("evil content")
        calls = []
        with patch.object(w, "get_agent_status", return_value="Stopped"), \
                patch.object(w, "_KEY_BACKUP", str(backup)), \
                patch.object(w, "run_privileged_command",
                             side_effect=lambda c, **k: calls.append(c) or (True, "")):
            assert w.start_agent() is True
        # Falls back to a plain service start — no cp-from-backup shell script.
        assert calls == [["systemctl", "start", "wazuh-agent"]]

    def test_start_agent_restores_valid_backup(self, tmp_path):
        backup = tmp_path / "wazuh_client.keys"
        backup.write_text(_GOOD_KEY + "\n")
        calls = []
        with patch.object(w, "get_agent_status", return_value="Stopped"), \
                patch.object(w, "_KEY_BACKUP", str(backup)), \
                patch.object(w, "run_privileged_command",
                             side_effect=lambda c, **k: calls.append(c) or (True, "")):
            assert w.start_agent() is True
        assert calls and calls[0][:2] == ["sh", "-c"] and "cp " in calls[0][2]

    def test_restore_client_key_skips_invalid_backup(self, tmp_path):
        backup = tmp_path / "wazuh_client.keys"
        backup.write_text("tampered")
        with patch.object(w, "needs_reenrollment", return_value=False), \
                patch.object(w, "_KEY_BACKUP", str(backup)), \
                patch.object(w, "run_privileged_command") as priv:
            assert w.restore_client_key_if_needed() is True
        priv.assert_not_called()

    def test_restore_client_key_restores_valid_backup(self, tmp_path):
        backup = tmp_path / "wazuh_client.keys"
        backup.write_text(_GOOD_KEY + "\n")
        with patch.object(w, "needs_reenrollment", return_value=False), \
                patch.object(w, "_KEY_BACKUP", str(backup)), \
                patch.object(w, "run_privileged_command",
                             return_value=(True, "KEY_RESTORED")) as priv:
            assert w.restore_client_key_if_needed() is True
        assert priv.called
