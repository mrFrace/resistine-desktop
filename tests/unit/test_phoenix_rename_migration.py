"""The Resistine -> Phoenix rename must not strand existing installs.

Renaming launchd labels, support directories and Keychain entries is only
safe if the old ones are still cleaned up and still readable. These pin the
parts that would silently break an upgrade:

  * old daemon labels keep fighting the new ones over clamd's socket unless
    they are explicitly booted out,
  * a Wazuh agent enrolled before the rename keeps its key under the old
    Keychain service and the old backup path,
  * and a deliberately wiped identity must not be resurrectable from those
    legacy locations.
"""

import plugins.antivirus.clamav_platform_darwin as cad
import plugins.wazuh.agent.wazuh_functions_darwin as wfd


class TestClamAVNaming:
    def test_live_labels_are_phoenix(self):
        assert cad._FRESHCLAM_DAEMON_LABEL == "exposed.phoenix.desktop.freshclam"
        for plist in cad._DAEMON_PLISTS:
            assert plist.startswith("exposed.phoenix.desktop."), plist

    def test_support_dir_is_phoenix(self):
        assert cad._SYSTEM_CLAMAV_DIR == "/Library/Application Support/Phoenix/clamav"
        for path in (cad._SYSTEM_DB_DIR, cad._SYSTEM_LOG_DIR,
                     cad._SYSTEM_RUN_DIR, cad._SYSTEM_CLAMD_CONF,
                     cad._SYSTEM_FRESHCLAM_CONF):
            assert "/Resistine/" not in path, path

    def test_pre_rename_labels_are_still_booted_out(self):
        """Left registered, these fight the new labels over the same socket."""
        for label in ("com.resistine.desktop.clamd",
                      "com.resistine.desktop.clamonacc",
                      "com.resistine.desktop.freshclam"):
            assert label in cad._LEGACY_DAEMON_LABELS, label

    def test_oldest_labels_still_covered(self):
        for label in ("com.resistine.clamd", "com.resistine.clamonacc"):
            assert label in cad._LEGACY_DAEMON_LABELS, label


class TestWazuhKeyMigration:
    def test_live_names_are_phoenix(self):
        assert wfd._KC_SERVICE == "exposed.phoenix.wazuh.agent"
        assert wfd._KEY_BACKUP == "/Library/Application Support/Phoenix/wazuh_client.keys"

    def test_legacy_names_retained_for_reads(self):
        assert wfd._LEGACY_KC_SERVICE == "com.resistine.wazuh.agent"
        assert "Resistine" in wfd._LEGACY_KEY_BACKUP

    def test_restore_reads_both_keychain_services(self):
        # The restore chain is built inline as shell text, so assert on the
        # module source: the fallback cannot be dropped without this failing.
        import inspect
        src = inspect.getsource(wfd)
        assert "_LEGACY_KC_SERVICE" in src
        assert src.count("_LEGACY_KEY_BACKUP") >= 4, (
            "legacy backup must be read on restore and removed on both purge paths"
        )

    def test_purge_removes_legacy_copies(self):
        """A wiped identity must not be restorable from the pre-rename copies."""
        import inspect
        src = inspect.getsource(wfd)
        # Every delete-generic-password call site should have a legacy twin.
        assert src.count("delete-generic-password") >= 4, src.count("delete-generic-password")
        assert src.count("_sh(_LEGACY_KC_SERVICE)") >= 2

    def test_keychain_probe_accepts_either_service(self, monkeypatch):
        seen = []

        class _R:
            def __init__(self, rc): self.returncode = rc

        def fake_run(cmd, **kw):
            seen.append(cmd[cmd.index("-s") + 1])
            # only the legacy entry exists
            return _R(0 if cmd[cmd.index("-s") + 1] == wfd._LEGACY_KC_SERVICE else 1)

        monkeypatch.setattr(wfd.subprocess, "run", fake_run)
        assert wfd._has_keychain_entry() is True
        assert wfd._LEGACY_KC_SERVICE in seen
