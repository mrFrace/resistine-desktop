"""Linux VPN hardening: the stored WireGuard config is re-validated and
snapshotted into a private temp copy immediately before the privileged
bring-up, closing the TOCTOU window where user-level malware could insert a
``PostUp = <cmd>`` hook that wg-quick would execute as root."""

import os
import stat
from unittest.mock import patch

import pytest

from plugins.vpn.wireguard import vpn_functions_linux as v


_GOOD_CONF = """[Interface]
PrivateKey = aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa=
Address = 10.0.0.2/32
DNS = 1.1.1.1

[Peer]
PublicKey = bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb=
AllowedIPs = 0.0.0.0/0
Endpoint = vpn.example.com:51820
"""


def _write_conf(tmp_path, content, name="phoenix"):
    conf = tmp_path / f"{name}.conf"
    conf.write_text(content)
    return str(conf)


@pytest.mark.unit
@pytest.mark.security
class TestVettedPrivateCopy:
    def test_clean_config_is_copied_verbatim(self, tmp_path):
        conf = _write_conf(tmp_path, _GOOD_CONF)
        copy = v._write_vetted_private_copy(conf, "phoenix")
        try:
            assert copy != conf
            assert os.path.basename(copy) == "phoenix.conf"
            with open(copy) as f:
                assert f.read() == _GOOD_CONF
            assert stat.S_IMODE(os.stat(copy).st_mode) == 0o600
            assert stat.S_IMODE(os.stat(os.path.dirname(copy)).st_mode) == 0o700
        finally:
            import shutil
            shutil.rmtree(os.path.dirname(copy), ignore_errors=True)

    @pytest.mark.parametrize("hook", [
        "PostUp = rm -rf /",
        "postup = touch /pwned",
        "PreUp = /bin/sh -c id",
        "PostDown = curl evil",
        "PREDOWN = x",
        "  PostUp   =   x",  # leading/trailing whitespace
    ])
    def test_script_hooks_rejected_case_insensitively(self, tmp_path, hook):
        conf = _write_conf(tmp_path, _GOOD_CONF + hook + "\n")
        with pytest.raises(ValueError):
            v._write_vetted_private_copy(conf, "phoenix")


@pytest.mark.unit
@pytest.mark.security
class TestStartVpnUsesVettedCopy:
    def test_tampered_config_never_reaches_root(self, tmp_path):
        """A PostUp inserted after creation aborts before any pkexec call."""
        conf = _write_conf(tmp_path, _GOOD_CONF + "PostUp = touch /pwned\n")
        with patch.object(v, "run_privileged_command") as priv:
            assert v.start_vpn(conf) is False
        priv.assert_not_called()

    def test_root_copy_sources_the_vetted_temp_not_the_user_path(self, tmp_path):
        conf = _write_conf(tmp_path, _GOOD_CONF)
        captured = {}

        def fake_priv(args):
            captured["script"] = args[2]
            # The vetted source must still exist when root copies from it.
            src = captured["script"].split("cp ", 1)[1].split(" ", 1)[0]
            captured["src_exists"] = os.path.exists(src.strip("'"))
            from unittest.mock import MagicMock
            r = MagicMock()
            r.returncode = 0
            return r

        with patch.object(v, "_is_nixos", return_value=False), \
                patch.object(v, "make_dns_compatible_config", side_effect=lambda p: p), \
                patch.object(v, "run_privileged_command", side_effect=fake_priv):
            assert v.start_vpn(conf) is True
        script = captured["script"]
        assert conf not in script, "root command must never read the user-owned path"
        assert "/etc/wireguard/phoenix.conf" in script
        assert captured["src_exists"] is True

    def test_nixos_runs_wg_quick_on_the_vetted_copy(self, tmp_path):
        conf = _write_conf(tmp_path, _GOOD_CONF)
        scripts = []
        with patch.object(v, "_is_nixos", return_value=True), \
                patch.object(v, "run_privileged_command",
                             side_effect=lambda a: scripts.append(a[2]) or None):
            v.start_vpn(conf)
        assert scripts and conf not in scripts[0]
        assert scripts[0].rstrip("'").endswith("phoenix.conf")

    def test_temp_copy_is_cleaned_up(self, tmp_path):
        conf = _write_conf(tmp_path, _GOOD_CONF)
        seen = {}

        def fake_priv(args):
            # Remember the vetted source path while the command runs.
            src = args[2].split("cp ", 1)[1].split(" ", 1)[0].strip("'")
            seen["src"] = src
            return None  # simulate failure; cleanup must still happen

        with patch.object(v, "_is_nixos", return_value=False), \
                patch.object(v, "make_dns_compatible_config", side_effect=lambda p: p), \
                patch.object(v, "run_privileged_command", side_effect=fake_priv):
            assert v.start_vpn(conf) is False
        assert not os.path.exists(seen["src"])

    def test_invalid_interface_name_still_refused(self, tmp_path):
        conf = _write_conf(tmp_path, _GOOD_CONF, name="bad name!")
        with patch.object(v, "run_privileged_command") as priv:
            assert v.start_vpn(conf) is False
        priv.assert_not_called()
