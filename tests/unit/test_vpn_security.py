"""
Security regression tests for the VPN plugin (ported from the March
drake/repo-cleaning hardening, re-applied to the PyQt6 code base).

Covers:
- config_validation helpers (newline/control-char injection, formats,
  comma-separated AllowedIPs/Address/DNS)
- parse_and_create_vpn_config on Linux, macOS and Windows: valid server
  configs are written unchanged, malicious ones are rejected and nothing is
  written
- VPNConfigManager path-traversal guards
- WireGuard directory permissions (0o700)
- Linux start/stop shell quoting and DNS PostUp sanitising
- plugins.vpn.main: `wg show interfaces` via subprocess.run, DNS_SERVER env

No test runs wg / wg-quick / privileged commands: subprocess is mocked.
"""

import importlib
import json
import os
import stat
import subprocess
import sys
from unittest.mock import MagicMock, patch

import pytest

from plugins.vpn.config_manager import RESISTINE_CONFIG_NAME, VPNConfigManager
from plugins.vpn.wireguard import config_validation as cv

POSIX = os.name == "posix"

PRIV = "aGVsbG8gd29ybGQgdGhpcyBpcyBhIHRlc3Qga2V5MTI="
SERVER_PUB = "c2VydmVyIHB1YmxpYyBrZXkgZm9yIHRlc3RzIG9ubHk="


def _server_config(**overrides):
    cfg = {
        "Interface": {
            "PrivateKey": "",
            "Address": "198.51.100.6",
            "DNS": ["198.51.100.53"],
        },
        "Peer": {
            "PublicKey": SERVER_PUB,
            "AllowedIPs": ["198.51.100.0/17", "198.51.100.128/25"],
            "Endpoint": "203.0.113.1:987",
        },
    }
    for dotted, value in overrides.items():
        section, key = dotted.split(".")
        cfg[section][key] = value
    return cfg


INJECTIONS = [
    ("Peer.PublicKey", SERVER_PUB + "\nPostUp = touch /tmp/pwned"),
    ("Peer.Endpoint", "203.0.113.1:987\nPostUp = touch /tmp/pwned"),
    ("Peer.AllowedIPs", ["0.0.0.0/0\n[Interface]\nPostUp = id"]),
    ("Peer.AllowedIPs", "0.0.0.0/0\rPostUp = id"),
    ("Interface.Address", "198.51.100.6\nPostUp = id"),
    ("Interface.DNS", ["198.51.100.53\nPostUp = id"]),
    ("Interface.DNS", ["1.1.1.1; rm -rf /"]),
    ("Peer.Endpoint", "203.0.113.1:99999"),
    ("Peer.Endpoint", "no-port-here"),
    ("Peer.AllowedIPs", ["not-an-ip"]),
    ("Peer.PublicKey", "key with spaces="),
]


# ===========================================================================
# Validation helpers
# ===========================================================================
@pytest.mark.unit
@pytest.mark.security
class TestValidators:
    def test_valid_server_config_passes(self):
        c = _server_config()
        cv.validate_server_config(
            c["Peer"]["PublicKey"], c["Peer"]["Endpoint"], c["Interface"]["Address"],
            c["Peer"]["AllowedIPs"], c["Interface"]["DNS"],
        )

    @pytest.mark.parametrize("value", [
        "198.51.100.0/17, 198.51.100.128/25",  # comma-separated (1720279 fix)
        "198.51.100.0/17,198.51.100.128/25",
        ["198.51.100.0/17", " 198.51.100.128/25 "],
        "0.0.0.0/0, ::/0",
        "198.51.100.6",
    ])
    def test_allowed_ips_accepts_lists_and_comma_strings(self, value):
        assert cv.validate_ip_list(value, "AllowedIPs") == value

    @pytest.mark.parametrize("value", [
        "", [], "198.51.100.0/17, bogus", ["198.51.100.0/33"], "a\nb",
    ])
    def test_allowed_ips_rejects_invalid(self, value):
        with pytest.raises(ValueError):
            cv.validate_ip_list(value, "AllowedIPs")

    @pytest.mark.parametrize("ep", [
        "203.0.113.1:51820", "vpn.example.com:51820", "[2001:db8::1]:51820",
    ])
    def test_endpoint_valid(self, ep):
        assert cv.validate_endpoint(ep) == ep

    @pytest.mark.parametrize("ep", [
        "203.0.113.1", "203.0.113.1:0", "203.0.113.1:65536", "203.0.113.1:abc",
        "bad host:51820", "203.0.113.1:51820\n", "$(id):51820", "",
    ])
    def test_endpoint_invalid(self, ep):
        with pytest.raises(ValueError):
            cv.validate_endpoint(ep)

    @pytest.mark.parametrize("ch", ["\n", "\r", "\x00", "\t", "\x1b", "\x7f"])
    def test_control_chars_rejected(self, ch):
        with pytest.raises(ValueError):
            cv.validate_wg_field(f"abc{ch}def", "X")

    def test_non_string_rejected(self):
        with pytest.raises(ValueError):
            cv.validate_wg_field(123, "X")

    @pytest.mark.parametrize("dns", [
        [], "", ["198.51.100.53"], "198.51.100.53, 2001:db8::53",
        ["198.51.100.53", "corp.example"],
    ])
    def test_dns_valid(self, dns):
        cv.validate_dns_list(dns)

    @pytest.mark.parametrize("dns", [["1.1.1.1 && id"], ["`id`"], "1.1.1.1\nPostUp=id"])
    def test_dns_invalid(self, dns):
        with pytest.raises(ValueError):
            cv.validate_dns_list(dns)

    @pytest.mark.parametrize("name", ["resistine", "my_vpn-2", "A1"])
    def test_config_name_valid(self, name):
        assert cv.validate_config_name(name) == name

    @pytest.mark.parametrize("name", [
        "..", "../evil", "a/b", "a\\b", "/etc/passwd", "", ".hidden",
        "-option", "name.conf", "x y", None, "x\n",
    ])
    def test_config_name_invalid(self, name):
        assert not cv.is_valid_config_name(name)
        with pytest.raises(ValueError):
            cv.validate_config_name(name)

    @pytest.mark.parametrize("key", ["PostUp", "postdown", "PreUp", "PREDOWN"])
    def test_section_entry_rejects_script_hooks(self, key):
        with pytest.raises(ValueError):
            cv.validate_section_entry("Interface", key, "touch /tmp/pwned")

    def test_section_entry_skips_unknown_keys(self):
        assert cv.validate_section_entry("Interface", "SaveConfig", "true") is False

    def test_section_entry_accepts_ints(self):
        assert cv.validate_section_entry("Interface", "MTU", 1420) is True
        assert cv.validate_section_entry("Peer", "PersistentKeepalive", 25) is True


# ===========================================================================
# parse_and_create_vpn_config — Linux / macOS
# ===========================================================================
EXPECTED_POSIX_CONF = f"""[Interface]
PrivateKey = {PRIV}
Address = 198.51.100.6
DNS = 198.51.100.53

[Peer]
PublicKey = {SERVER_PUB}
AllowedIPs = 198.51.100.0/17, 198.51.100.128/25
Endpoint = 203.0.113.1:987
"""


@pytest.fixture(params=["linux", "darwin"])
def posix_backend(request, tmp_path, monkeypatch):
    mod = importlib.import_module(f"plugins.vpn.wireguard.vpn_functions_{request.param}")
    wg_dir = tmp_path / "wireguard"
    wg_dir.mkdir()
    monkeypatch.setattr(mod, "get_wireguard_private_key", lambda: PRIV)
    monkeypatch.setattr(mod, "get_writable_wireguard_dir", lambda: str(wg_dir))
    return mod, wg_dir


@pytest.mark.unit
@pytest.mark.security
class TestPosixConfigWriting:
    def test_valid_config_written_unchanged(self, posix_backend):
        mod, wg_dir = posix_backend
        path = mod.parse_and_create_vpn_config(json.dumps(_server_config()), "resistine")
        assert path == str(wg_dir / "resistine.conf")
        with open(path) as f:
            assert f.read() == EXPECTED_POSIX_CONF

    def test_comma_separated_allowed_ips_string_accepted(self, posix_backend):
        mod, _ = posix_backend
        cfg = _server_config(**{"Peer.AllowedIPs": "198.51.100.0/17, 198.51.100.128/25"})
        path = mod.parse_and_create_vpn_config(cfg, "resistine")
        assert path is not None
        with open(path) as f:
            assert "AllowedIPs = 198.51.100.0/17, 198.51.100.128/25\n" in f.read()

    @pytest.mark.parametrize("field,value", INJECTIONS)
    def test_malicious_values_rejected(self, posix_backend, field, value):
        mod, wg_dir = posix_backend
        path = mod.parse_and_create_vpn_config(_server_config(**{field: value}), "resistine")
        assert path is None
        assert list(wg_dir.iterdir()) == []

    @pytest.mark.parametrize("name", ["../escape", "/tmp/abs", "a/b", ".."])
    def test_traversal_config_name_rejected(self, posix_backend, name):
        mod, wg_dir = posix_backend
        assert mod.parse_and_create_vpn_config(_server_config(), name) is None
        assert list(wg_dir.iterdir()) == []
        assert not (wg_dir.parent / "escape.conf").exists()


# ===========================================================================
# parse_and_create_vpn_config — Windows (generic key/value writer)
# ===========================================================================
@pytest.fixture()
def win_backend(tmp_path, monkeypatch):
    mod = importlib.import_module("plugins.vpn.wireguard.vpn_functions_windows")
    wg_dir = tmp_path / "wireguard"
    wg_dir.mkdir()
    monkeypatch.setattr(mod, "get_wireguard_private_key", lambda: PRIV)
    monkeypatch.setattr(mod, "get_writable_wireguard_dir", lambda: str(wg_dir))
    return mod, wg_dir


@pytest.mark.unit
@pytest.mark.security
class TestWindowsConfigWriting:
    def test_valid_config_written(self, win_backend):
        mod, wg_dir = win_backend
        cfg = _server_config()
        cfg["Interface"]["MTU"] = 1420
        cfg["Peer"]["PersistentKeepalive"] = 25
        path = mod.parse_and_create_vpn_config(json.dumps(cfg), "resistine")
        assert path == str(wg_dir / "resistine.conf")
        with open(path) as f:
            content = f.read()
        assert content == (
            "[Interface]\n"
            f"PrivateKey = {PRIV}\n"
            "Address = 198.51.100.6\n"
            "DNS = 198.51.100.53\n"
            "MTU = 1420\n"
            "\n"
            "[Peer]\n"
            f"PublicKey = {SERVER_PUB}\n"
            "AllowedIPs = 198.51.100.0/17, 198.51.100.128/25\n"
            "Endpoint = 203.0.113.1:987\n"
            "PersistentKeepalive = 25\n"
        )

    @pytest.mark.parametrize("field,value", INJECTIONS)
    def test_malicious_values_rejected(self, win_backend, field, value):
        mod, wg_dir = win_backend
        assert mod.parse_and_create_vpn_config(_server_config(**{field: value}), "resistine") is None
        assert list(wg_dir.iterdir()) == []

    @pytest.mark.parametrize("section,key", [
        ("Interface", "PostUp"), ("Interface", "predown"), ("Peer", "PostDown"),
    ])
    def test_script_hooks_rejected(self, win_backend, section, key):
        mod, wg_dir = win_backend
        cfg = _server_config()
        cfg[section][key] = "powershell -c evil"
        assert mod.parse_and_create_vpn_config(cfg, "resistine") is None
        assert list(wg_dir.iterdir()) == []

    def test_injected_key_name_rejected(self, win_backend):
        mod, wg_dir = win_backend
        cfg = _server_config()
        cfg["Interface"]["MTU\nPostUp"] = "id"
        assert mod.parse_and_create_vpn_config(cfg, "resistine") is None

    def test_unknown_key_skipped(self, win_backend):
        mod, _ = win_backend
        cfg = _server_config()
        cfg["Interface"]["SomethingNew"] = "x"
        path = mod.parse_and_create_vpn_config(cfg, "resistine")
        with open(path) as f:
            assert "SomethingNew" not in f.read()

    def test_traversal_config_name_rejected(self, win_backend):
        mod, wg_dir = win_backend
        assert mod.parse_and_create_vpn_config(_server_config(), "..\\..\\evil") is None
        assert list(wg_dir.iterdir()) == []


# ===========================================================================
# VPNConfigManager path traversal
# ===========================================================================
@pytest.fixture()
def mgr(wireguard_dir, isolated_settings):
    return VPNConfigManager(str(wireguard_dir))


@pytest.mark.unit
@pytest.mark.security
class TestConfigManagerTraversal:
    @pytest.mark.parametrize("name", [
        "../outside", "../../etc/passwd", "/etc/passwd", "sub/dir", "..", "",
    ])
    def test_set_active_config_rejects_traversal(self, mgr, wireguard_dir, isolated_settings, name):
        # Even if the target file exists, the name must be refused.
        (wireguard_dir.parent / "outside.conf").write_text("[Interface]\n")
        assert mgr.set_active_config(name) is False
        assert isolated_settings.get("vpn", "active_config") is None

    def test_set_active_config_valid_still_works(self, mgr, write_conf, isolated_settings):
        write_conf("work")
        assert mgr.set_active_config("work") is True
        assert isolated_settings.get("vpn", "active_config") == "work"

    def test_config_path_rejects_traversal(self, mgr):
        with pytest.raises(ValueError):
            mgr.config_path("../x")

    def test_tampered_active_setting_ignored(self, mgr, wireguard_dir, write_conf, isolated_settings):
        (wireguard_dir.parent / "outside.conf").write_text("[Interface]\n")
        write_conf(RESISTINE_CONFIG_NAME)
        isolated_settings.set("vpn", "active_config", "../outside")
        assert mgr.get_active_config_name() == RESISTINE_CONFIG_NAME
        assert mgr.get_active_config_path() == os.path.join(
            str(wireguard_dir), f"{RESISTINE_CONFIG_NAME}.conf"
        )

    def test_delete_config_rejects_traversal(self, mgr, wireguard_dir):
        victim = wireguard_dir.parent / "victim.conf"
        victim.write_text("keep me")
        ok, msg = mgr.delete_config("../victim")
        assert ok is False and msg
        assert victim.exists()

    def test_unsafe_filenames_not_listed(self, mgr, wireguard_dir, write_conf):
        write_conf("good")
        (wireguard_dir / ".resistine.compat.conf").write_text("x")
        (wireguard_dir / "bad name';id;'.conf").write_text("x")
        assert [c["name"] for c in mgr.list_configs()] == ["good"]


# ===========================================================================
# Directory permissions
# ===========================================================================
@pytest.mark.unit
@pytest.mark.security
@pytest.mark.skipif(not POSIX, reason="POSIX permissions")
class TestWireguardDirPermissions:
    def test_linux_dir_created_0700(self, tmp_path, monkeypatch):
        from plugins.vpn.wireguard import vpn_functions_linux as l
        monkeypatch.setattr("utils.settings.get_config_dir", lambda: str(tmp_path))
        path = l.get_writable_wireguard_dir()
        assert stat.S_IMODE(os.stat(path).st_mode) == 0o700

    def test_linux_existing_dir_tightened(self, tmp_path, monkeypatch):
        from plugins.vpn.wireguard import vpn_functions_linux as l
        (tmp_path / "wireguard").mkdir(mode=0o755)
        os.chmod(tmp_path / "wireguard", 0o755)
        monkeypatch.setattr("utils.settings.get_config_dir", lambda: str(tmp_path))
        path = l.get_writable_wireguard_dir()
        assert stat.S_IMODE(os.stat(path).st_mode) == 0o700

    def test_darwin_dir_created_0700(self, tmp_path, monkeypatch):
        from plugins.vpn.wireguard import vpn_functions_darwin as d
        monkeypatch.setattr(d.os.path, "expanduser", lambda _p: str(tmp_path))
        path = d.get_writable_wireguard_dir()
        assert path.startswith(str(tmp_path))
        assert stat.S_IMODE(os.stat(path).st_mode) == 0o700


# ===========================================================================
# Linux start/stop + DNS compat
# ===========================================================================
@pytest.mark.unit
@pytest.mark.security
class TestLinuxShellSafety:
    def test_start_rejects_unsafe_iface(self, tmp_path):
        from plugins.vpn.wireguard import vpn_functions_linux as l
        with patch.object(l, "run_privileged_command") as rpc:
            assert l.start_vpn(str(tmp_path / "x';id;'.conf")) is False
            assert l.stop_vpn(str(tmp_path / "x';id;'.conf")) is False
            rpc.assert_not_called()

    def test_start_valid_iface_quotes_paths(self, tmp_path):
        from plugins.vpn.wireguard import vpn_functions_linux as l
        weird_dir = tmp_path / "o'brien"
        weird_dir.mkdir()
        conf = weird_dir / "resistine.conf"
        conf.write_text("[Interface]\n")
        ok = MagicMock(returncode=0)
        with patch.object(l, "run_privileged_command", return_value=ok) as rpc, \
                patch.object(l, "make_dns_compatible_config", side_effect=lambda p: p):
            assert l.start_vpn(str(conf)) is True
        script = rpc.call_args[0][0][2]
        assert "wg-quick up resistine" in script
        assert "'\"'\"'" in script  # the apostrophe is shell-escaped

    def test_dns_compat_drops_unsafe_tokens(self, tmp_path):
        from plugins.vpn.wireguard import vpn_functions_linux as l
        conf = tmp_path / "imported.conf"
        conf.write_text("[Interface]\nDNS = 198.51.100.53, $(id)\n\n[Peer]\n")
        with patch.object(l.shutil, "which", side_effect=lambda n: "/usr/bin/resolvectl" if n == "resolvectl" else None), \
                patch("subprocess.run", return_value=MagicMock(returncode=0)):
            out = l.make_dns_compatible_config(str(conf))
        content = open(out).read()
        assert "resolvectl dns %i 198.51.100.53 ||" in content
        assert "$(id)" not in content


# ===========================================================================
# plugins.vpn.main — wg show interfaces, DNS_SERVER
# ===========================================================================
@pytest.mark.unit
class TestVpnMainHelpers:
    @pytest.fixture()
    def vpn_main(self):
        return importlib.import_module("plugins.vpn.main")

    def test_list_wg_interfaces_uses_subprocess_run(self, vpn_main):
        res = MagicMock(returncode=0, stdout="wg0 resistine\n", stderr="")
        with patch("subprocess.run", return_value=res) as run:
            assert vpn_main._list_wg_interfaces() == ["wg0", "resistine"]
        args, kwargs = run.call_args
        assert args[0] == ["wg", "show", "interfaces"]
        assert kwargs["capture_output"] is True and kwargs["text"] is True
        assert kwargs["timeout"] > 0

    @pytest.mark.parametrize("exc", [
        FileNotFoundError("wg"), subprocess.TimeoutExpired("wg", 5), PermissionError("x"),
    ])
    def test_list_wg_interfaces_errors(self, vpn_main, exc):
        with patch("subprocess.run", side_effect=exc):
            assert vpn_main._list_wg_interfaces() == []

    def test_list_wg_interfaces_nonzero(self, vpn_main):
        res = MagicMock(returncode=1, stdout="garbage", stderr="Operation not permitted")
        with patch("subprocess.run", return_value=res):
            assert vpn_main._list_wg_interfaces() == []

    def test_no_os_popen(self):
        import plugins.vpn.main as m
        with open(m.__file__, encoding="utf-8") as f:
            assert "os.popen" not in f.read()

    def test_dns_server_env_override(self, monkeypatch):
        import plugins.vpn.main as m
        default = "10.49.11.10"
        try:
            monkeypatch.setenv("RESISTINE_DNS_SERVER", "198.51.100.53")
            assert importlib.reload(m).DNS_SERVER == "198.51.100.53"
            monkeypatch.delenv("RESISTINE_DNS_SERVER")
            assert importlib.reload(m).DNS_SERVER == default
        finally:
            monkeypatch.delenv("RESISTINE_DNS_SERVER", raising=False)
            importlib.reload(sys.modules["plugins.vpn.main"])

    def test_conf_path_rejects_traversal(self, vpn_main):
        with pytest.raises(ValueError):
            vpn_main._conf_path("../../etc/x")
