"""Names the app registers things under on macOS and Windows.

These identifiers are shared between Python, shell, batch and installer
scripts that cannot import each other. A mismatch does not fail loudly: the
antivirus daemons never register, or every tray command fails authentication.
"""
from pathlib import Path

import pytest

import plugins.antivirus.clamav_platform_darwin as cad
import plugins.wazuh.agent.wazuh_functions_darwin as wfd
# win32 modules are stubbed centrally in tests/conftest.py
import plugins.vpn.wireguard.windows_vpn_service as svc

REPO = Path(__file__).resolve().parents[2]


def _text(rel):
    return (REPO / rel).read_bytes().decode("utf-8")


@pytest.mark.unit
class TestMacNames:
    def test_daemon_labels(self):
        assert cad._FRESHCLAM_DAEMON_LABEL == "exposed.phoenix.desktop.freshclam"
        for plist in cad._DAEMON_PLISTS:
            assert plist.startswith("exposed.phoenix.desktop."), plist

    def test_support_dir(self):
        assert cad._SYSTEM_CLAMAV_DIR == "/Library/Application Support/Phoenix/clamav"

    def test_postinstall_script_uses_the_same_support_dir_and_labels(self):
        script = _text("scripts/clamav-postinstall-darwin.sh")
        assert 'SUPPORT_DIR="/Library/Application Support/Phoenix"' in script
        for plist in cad._DAEMON_PLISTS:
            assert plist in script, plist

    def test_wazuh_key_locations_match_the_postinstall_script(self):
        """The script writes the key backup; the app reads it back."""
        script = _text("scripts/wazuh-postinstall-darwin.sh")
        assert wfd._KC_SERVICE == "exposed.phoenix.wazuh.agent"
        assert f'KC_SERVICE="{wfd._KC_SERVICE}"' in script
        assert wfd._KEY_BACKUP in script

    def test_uninstaller_removes_what_the_app_registers(self):
        src = _text("utils/uninstall/darwin.py")
        for plist in cad._DAEMON_PLISTS:
            assert plist in src, plist
        assert "/Library/Application Support/Phoenix" in src

    def test_build_requires_the_artifact_plists_by_these_names(self):
        build = _text("scripts/build/build-distribution.sh")
        assert "exposed.phoenix.desktop.$base.plist" in build
        assert "phoenix-vpn-cli" in build


@pytest.mark.unit
class TestWindowsNames:
    def test_service_and_data_dir(self):
        assert svc.SERVICE_NAME == "PhoenixVPN"
        assert Path(svc.CONFIG_BASE).parts[-2:] == ("Phoenix", "wireguard")
        assert hasattr(svc, "PhoenixVPNService")

    def test_clients_read_the_token_the_service_writes(self):
        """A mismatch here means every tray/GUI command fails authentication."""
        from gui import tray
        from plugins.vpn.wireguard import service_client

        tail = Path(svc.IPC_TOKEN_FILE).parts[-3:]
        assert tail == ("Phoenix", "wireguard", ".ipc_token")
        assert Path(service_client._IPC_TOKEN_FILE).parts[-3:] == tail
        assert Path(tray._IPC_TOKEN_FILE).parts[-3:] == tail

    def test_installer_identity(self):
        iss = _text("packaging/windows/PhoenixInstaller.iss")
        assert '#define AppId "PhoenixDesktop"' in iss
        assert f'#define VpnService "{svc.SERVICE_NAME}"' in iss
        assert '#define AppRegKey "Software\\Phoenix"' in iss
        assert 'Subkey: "{#AppRegKey}"' in iss

    def test_in_app_uninstall_looks_up_the_installer_identity(self):
        from utils.uninstall.windows import _APP_KEYS, _INNO_UNINSTALL_KEYS

        assert _INNO_UNINSTALL_KEYS[0].endswith("PhoenixDesktop_is1")
        assert _APP_KEYS == (r"Software\Phoenix",)

    def test_installer_stays_silent_safe(self):
        """Upgrades run it /VERYSILENT: a bare MsgBox would hang."""
        import re

        iss = _text("packaging/windows/PhoenixInstaller.iss")
        assert not re.search(r"(?<!Suppressible)MsgBox\(", iss)

    def test_batch_scripts_agree_on_the_service(self):
        for rel in ("scripts/install/install_service.bat",
                    "scripts/install/install.bat",
                    "scripts/uninstall/uninstall.bat"):
            assert f"set SERVICE_NAME={svc.SERVICE_NAME}" in _text(rel), rel
        assert "%PROGRAMDATA%\\Phoenix\\wireguard" in _text("scripts/install/install_service.bat")
        assert f"sc query {svc.SERVICE_NAME}" in _text("run.bat")

    def test_batch_files_keep_crlf(self):
        """cmd.exe mis-parses labels and blocks in LF-only batch files."""
        for rel in ("scripts/install/install_service.bat",
                    "scripts/install/install.bat", "run.bat"):
            raw = (REPO / rel).read_bytes()
            assert b"\r\n" in raw and b"\n" not in raw.replace(b"\r\n", b""), rel
