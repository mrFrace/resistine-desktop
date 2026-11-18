"""The Windows VPN service was renamed from ResistineVPN to PhoenixVPN and its
data moved from %PROGRAMDATA%\\Resistine to %PROGRAMDATA%\\Phoenix.

These pin the new names and the migration the service runs at start. The
migration runs as SYSTEM in a directory any local user can write to, so the
refusal paths (not admin-owned, a link, script hooks) matter as much as the
happy path.
"""
import os
import re
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# win32 modules are stubbed centrally in tests/conftest.py
import plugins.vpn.wireguard.windows_vpn_service as svc

REPO = Path(__file__).resolve().parents[2]
CONF = "[Interface]\nPrivateKey = abc\nAddress = 10.0.0.2/32\n"


@pytest.fixture
def dirs(tmp_path):
    """A legacy tree and an empty new one, wired into the module."""
    legacy_root = tmp_path / "Resistine"
    legacy_wg = legacy_root / "wireguard"
    legacy_wg.mkdir(parents=True)
    new_wg = tmp_path / "Phoenix" / "wireguard"
    with patch.object(svc, "LEGACY_PROGRAMDATA_DIR", str(legacy_root)), \
         patch.object(svc, "LEGACY_CONFIG_BASE", str(legacy_wg)), \
         patch.object(svc, "CONFIG_BASE", str(new_wg)), \
         patch.object(svc, "status_tunnel", return_value="Not Installed"), \
         patch.object(svc, "run_cmd", return_value=MagicMock(stdout="", stderr="")), \
         patch.object(svc, "install_tunnel", return_value=(True, "Installed")) as install, \
         patch.object(svc, "uninstall_tunnel", return_value=(True, "Uninstalled")) as uninstall:
        yield {"legacy_root": legacy_root, "legacy_wg": legacy_wg, "new_wg": new_wg,
               "install": install, "uninstall": uninstall}


@pytest.mark.unit
class TestNames:
    def test_service_and_data_dir_are_phoenix(self):
        assert svc.SERVICE_NAME == "PhoenixVPN"
        assert Path(svc.CONFIG_BASE).parts[-2:] == ("Phoenix", "wireguard")
        assert hasattr(svc, "PhoenixVPNService")

    def test_legacy_names_kept_for_cleanup_only(self):
        assert svc.LEGACY_SERVICE_NAME == "ResistineVPN"
        assert Path(svc.LEGACY_CONFIG_BASE).parts[-2:] == ("Resistine", "wireguard")

    def test_clients_read_the_token_the_service_writes(self):
        """A mismatch here means every tray/GUI command fails authentication."""
        from gui import tray
        from plugins.vpn.wireguard import service_client

        tail = Path(svc.IPC_TOKEN_FILE).parts[-3:]
        assert tail == ("Phoenix", "wireguard", ".ipc_token")
        assert Path(service_client._IPC_TOKEN_FILE).parts[-3:] == tail
        assert Path(tray._IPC_TOKEN_FILE).parts[-3:] == tail


@pytest.mark.unit
class TestMigration:
    def test_moves_configs_and_removes_the_old_tree(self, dirs):
        (dirs["legacy_wg"] / "phoenix.conf").write_text(CONF)
        (dirs["legacy_wg"] / ".ipc_token").write_text("f" * 64)
        (dirs["legacy_root"] / "vpn_service.log").write_text("old log")

        svc._migrate_legacy_programdata()

        assert (dirs["new_wg"] / "phoenix.conf").read_text() == CONF
        assert not dirs["legacy_root"].exists()
        # the stale token is discarded, never carried over
        assert not (dirs["new_wg"] / ".ipc_token").exists()

    def test_noop_without_a_legacy_tree(self, dirs):
        dirs["legacy_wg"].rmdir()
        dirs["legacy_root"].rmdir()
        svc._migrate_legacy_programdata()
        assert not dirs["new_wg"].exists()

    def test_existing_config_is_not_overwritten(self, dirs):
        dirs["new_wg"].mkdir(parents=True)
        (dirs["new_wg"] / "phoenix.conf").write_text("current")
        (dirs["legacy_wg"] / "phoenix.conf").write_text(CONF)

        svc._migrate_legacy_programdata()

        assert (dirs["new_wg"] / "phoenix.conf").read_text() == "current"
        assert not dirs["legacy_root"].exists()

    def test_script_hooks_are_dropped_not_migrated(self, dirs):
        (dirs["legacy_wg"] / "evil.conf").write_text(CONF + "PostUp = calc.exe\n")

        svc._migrate_legacy_programdata()

        assert not (dirs["new_wg"] / "evil.conf").exists()
        assert not (dirs["legacy_wg"] / "evil.conf").exists()

    def test_tree_not_owned_by_an_admin_is_left_untouched(self, dirs):
        """Any local user can create %PROGRAMDATA%\\Resistine on a clean machine."""
        planted = dirs["legacy_wg"] / "phoenix.conf"
        planted.write_text(CONF)
        with patch.object(svc, "_is_privileged_owned", return_value=False):
            svc._migrate_legacy_programdata()

        assert planted.exists()
        assert not dirs["new_wg"].exists()

    def test_linked_legacy_dir_is_not_followed(self, dirs, tmp_path):
        """A junction there would point SYSTEM's deletes at another directory."""
        victim = tmp_path / "victim"
        victim.mkdir()
        (victim / "keep.conf").write_text(CONF)
        dirs["legacy_wg"].rmdir()
        os.symlink(victim, dirs["legacy_wg"], target_is_directory=True)

        svc._migrate_legacy_programdata()

        assert (victim / "keep.conf").exists()
        assert not dirs["new_wg"].exists()

    def test_unowned_entry_is_neither_migrated_nor_deleted(self, dirs):
        ours = dirs["legacy_wg"] / "phoenix.conf"
        planted = dirs["legacy_wg"] / "planted.conf"
        ours.write_text(CONF)
        planted.write_text(CONF)
        real = svc._is_privileged_owned
        with patch.object(svc, "_is_privileged_owned",
                          side_effect=lambda p: real(p) and not p.endswith("planted.conf")):
            svc._migrate_legacy_programdata()

        assert (dirs["new_wg"] / "phoenix.conf").exists()
        assert not (dirs["new_wg"] / "planted.conf").exists()
        assert planted.exists()  # and so the old tree stays, visibly

    def test_nothing_is_removed_recursively(self, dirs):
        """Only known files one level deep; an unexpected subtree survives."""
        extra = dirs["legacy_root"] / "something" / "else"
        extra.mkdir(parents=True)
        (extra / "data").write_text("x")

        svc._migrate_legacy_programdata()

        assert (extra / "data").exists()

    def test_acl_failure_keeps_the_legacy_copy(self, dirs):
        """Never leave a private key in a file whose ACL could not be locked."""
        legacy = dirs["legacy_wg"] / "phoenix.conf"
        legacy.write_text(CONF)
        with patch.object(svc, "_restrict_file_acl", return_value=False):
            svc._migrate_legacy_programdata()

        assert legacy.exists()
        assert list(dirs["new_wg"].iterdir()) == []


@pytest.mark.unit
class TestInstalledTunnel:
    """A tunnel service registered against the old path re-reads it on start."""

    def _run(self, dirs, state):
        (dirs["legacy_wg"] / "phoenix.conf").write_text(CONF)
        qc = MagicMock(stdout=f'BINARY_PATH_NAME : wireguard.exe /tunnelservice '
                              f'"{dirs["legacy_wg"]}{os.sep}phoenix.conf"', stderr="")
        with patch.object(svc, "status_tunnel", return_value=state), \
             patch.object(svc, "run_cmd", return_value=qc):
            svc._migrate_legacy_programdata()

    def test_running_tunnel_is_reinstalled_from_the_new_path(self, dirs):
        self._run(dirs, "Running")
        dirs["install"].assert_called_once_with(
            "phoenix", str(dirs["new_wg"] / "phoenix.conf"))
        assert not dirs["legacy_root"].exists()

    def test_stopped_tunnel_is_removed_not_started(self, dirs):
        """Reinstalling would connect a VPN the user had switched off."""
        self._run(dirs, "Stopped")
        dirs["install"].assert_not_called()
        dirs["uninstall"].assert_called_once_with("phoenix")

    def test_failed_reinstall_keeps_the_old_config(self, dirs):
        dirs["install"].return_value = (False, "boom")
        self._run(dirs, "Running")
        assert (dirs["legacy_wg"] / "phoenix.conf").exists()

    def test_tunnel_already_on_the_new_path_is_left_alone(self, dirs):
        (dirs["legacy_wg"] / "phoenix.conf").write_text(CONF)
        qc = MagicMock(stdout=f'/tunnelservice "{dirs["new_wg"]}{os.sep}phoenix.conf"', stderr="")
        with patch.object(svc, "status_tunnel", return_value="Running"), \
             patch.object(svc, "run_cmd", return_value=qc):
            svc._migrate_legacy_programdata()
        dirs["install"].assert_not_called()
        dirs["uninstall"].assert_not_called()


@pytest.mark.unit
class TestInstallerScripts:
    """Text-level checks: these scripts only run on Windows."""

    ISS = (REPO / "packaging/windows/PhoenixInstaller.iss").read_text(encoding="utf-8")
    SERVICE_BAT = (REPO / "scripts/install/install_service.bat").read_bytes().decode("utf-8")

    def test_installer_identity_is_phoenix(self):
        assert '#define AppId "PhoenixDesktop"' in self.ISS
        assert '#define VpnService "PhoenixVPN"' in self.ISS
        assert 'Subkey: "{#AppRegKey}"' in self.ISS
        assert 'Subkey: "Software\\Resistine"' not in self.ISS

    def test_installer_removes_the_old_service_before_registering_the_new(self):
        body = self.ISS[self.ISS.index("procedure CurStepChanged"):]
        assert body.index("StopAndDeleteService('{#LegacyVpnService}')") \
            < body.index("RunVpnServiceSetupRequired;")

    def test_installer_stays_silent_safe(self):
        """WinSparkle-style upgrades run it /VERYSILENT: a bare MsgBox hangs."""
        assert not re.search(r"(?<!Suppressible)MsgBox\(", self.ISS)

    def test_service_script_registers_phoenix_and_removes_legacy(self):
        assert "set SERVICE_NAME=PhoenixVPN" in self.SERVICE_BAT
        assert "%PROGRAMDATA%\\Phoenix\\wireguard" in self.SERVICE_BAT
        install = self.SERVICE_BAT.index("Installing Windows service")
        assert self.SERVICE_BAT.index("call :remove_legacy_vpn_service", install) \
            < self.SERVICE_BAT.index("install >", install)

    def test_batch_files_keep_crlf(self):
        """cmd.exe mis-parses labels and blocks in LF-only batch files."""
        for rel in ("scripts/install/install_service.bat",
                    "scripts/install/install.bat", "run.bat"):
            raw = (REPO / rel).read_bytes()
            assert b"\r\n" in raw and b"\n" not in raw.replace(b"\r\n", b""), rel
