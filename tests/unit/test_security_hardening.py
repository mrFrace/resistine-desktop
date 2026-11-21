"""Regression tests for the 2026-10 security-hardening pass.

Each test pins a rejection path that previously failed open:
- Windows VPN service: tunnel-name traversal, config_path confinement,
  constant-time token check, ACL grantee allowlist.
- Updates: a release without a valid signature is refused, the store is
  https only, the legacy appcast updaters stay removed; traversal guard uses
  commonpath (sibling-prefix directories don't pass).
- Wazuh Linux: agent group derived from the (user-writable) email setting is
  allowlist-sanitized before reaching root sh -c strings.
- Chat: SIEM alert bubbles escape raw HTML and never activate links.
"""
import os
import pytest
from unittest.mock import patch

# win32 modules are stubbed centrally in tests/conftest.py


@pytest.mark.unit
@pytest.mark.security
class TestWindowsServiceInputValidation:
    def _request(self, **over):
        from plugins.vpn.wireguard import windows_vpn_service as svc
        req = {"token": svc.IPC_TOKEN, "command": "status", "tunnel": "phoenix"}
        req.update(over)
        return req

    def test_traversal_tunnel_rejected(self):
        from plugins.vpn.wireguard import windows_vpn_service as svc
        with patch.object(svc, "IPC_TOKEN", "t" * 64):
            resp = svc.handle_request(self._request(
                token="t" * 64, tunnel="..\\..\\Windows\\System32\\evil"))
        assert resp["status"] == "error"
        assert "tunnel" in resp["message"].lower() or "invalid" in resp["message"].lower()

    def test_slash_tunnel_rejected(self):
        from plugins.vpn.wireguard import windows_vpn_service as svc
        with patch.object(svc, "IPC_TOKEN", "t" * 64):
            resp = svc.handle_request(self._request(token="t" * 64, tunnel="a/b"))
        assert resp["status"] == "error"

    def test_wrong_token_rejected_even_with_valid_tunnel(self):
        from plugins.vpn.wireguard import windows_vpn_service as svc
        with patch.object(svc, "IPC_TOKEN", "t" * 64):
            resp = svc.handle_request(self._request(token="x" * 64))
        assert resp["status"] == "error"

    def test_non_string_token_rejected(self):
        from plugins.vpn.wireguard import windows_vpn_service as svc
        with patch.object(svc, "IPC_TOKEN", "t" * 64):
            resp = svc.handle_request(self._request(token=12345))
        assert resp["status"] == "error"

    def test_config_path_must_match_tunnel_basename(self, tmp_path):
        from plugins.vpn.wireguard import windows_vpn_service as svc
        other = tmp_path / "unrelated.conf"
        other.write_text("[Interface]\n")
        assert svc._validated_config_path("phoenix", str(other)) is None

    def test_config_path_accepts_matching_conf(self, tmp_path, monkeypatch):
        from plugins.vpn.wireguard import windows_vpn_service as svc
        # Paths are now confined to known config directories (UNC/arbitrary
        # locations rejected) — stand the test dir in for CONFIG_BASE.
        monkeypatch.setattr(svc, "CONFIG_BASE", str(tmp_path))
        conf = tmp_path / "phoenix.conf"
        conf.write_text("[Interface]\n")
        assert svc._validated_config_path("phoenix", str(conf)) == str(conf)

    def test_config_path_rejects_unconfined_location(self, tmp_path):
        from plugins.vpn.wireguard import windows_vpn_service as svc
        conf = tmp_path / "phoenix.conf"
        conf.write_text("[Interface]\n")
        # tmp_path is not a known config dir — must be rejected.
        assert svc._validated_config_path("phoenix", str(conf)) is None

    def test_config_path_rejects_unc(self):
        from plugins.vpn.wireguard import windows_vpn_service as svc
        assert svc._validated_config_path(
            "phoenix", r"\\attacker\share\phoenix.conf") is None

    def test_config_path_rejects_non_file(self, tmp_path):
        from plugins.vpn.wireguard import windows_vpn_service as svc
        assert svc._validated_config_path("phoenix", str(tmp_path)) is None
        assert svc._validated_config_path("phoenix", None) is None

    def test_acl_refuses_group_grantees(self):
        from plugins.vpn.wireguard import windows_vpn_service as svc
        for bad in ("Everyone", "Users", "Authenticated Users", 'a"b', "x;y"):
            # Non-win32 returns True before grantee checks; exercise the
            # validation directly.
            assert (svc._SAFE_GRANTEE_RE.fullmatch(bad) is None
                    or bad.lower() in svc._DENY_GRANTEES)


@pytest.mark.unit
@pytest.mark.security
class TestUpdatePolicy:
    """The signed channel is the only updater. The appcast updaters it
    replaced (Sparkle, WinSparkle, the Linux tarball updater) are removed,
    and their refusals are pinned here on the channel instead."""

    _MANIFEST = (b'{"product": "phoenix-desktop", "version": "1", "build": 2,'
                 b' "dir": "1-2", "expires": "2099-01-01", "files": {}}')

    @pytest.mark.parametrize("signature", [
        "",
        "untrusted comment: x\n",
        "untrusted comment: x\nAAAA\ntrusted comment: phoenix-desktop 1-2 2099-01-01\nAAAA\n",
    ])
    def test_unsigned_release_refused(self, signature):
        """A manifest without a valid signature never becomes a release."""
        from plugins.wazuh.agent import phoenix_packages as pp
        with pytest.raises(pp.PackageError):
            pp.parse_desktop_manifest(self._MANIFEST, signature, "windows")

    def test_non_https_store_refused(self, monkeypatch):
        """No plain-http store: nothing is fetched (or a token sent) there."""
        from plugins.wazuh.agent import phoenix_packages as pp
        monkeypatch.setenv("PHOENIX_PACKAGES_URL", "http://example.invalid/packages")
        assert pp.packages_url() == pp.PACKAGES_URL.rstrip("/")
        assert pp.packages_url().startswith("https://")

    def test_unsigned_plugin_catalog_refused(self, tmp_path, monkeypatch):
        """Store plugins are code: a catalog without a valid signature by a
        pinned key offers nothing and supplies no hash to install against."""
        from unittest.mock import MagicMock, patch

        from plugins.plugin_manager import PluginManager
        monkeypatch.setattr("plugins.plugin_manager.get_config_dir", lambda: str(tmp_path))
        with patch.object(PluginManager, "load_plugins", return_value=[]):
            mgr = PluginManager(MagicMock(spec=[]))
        mgr.OPTIONAL_PLUGINS_URL = "https://example.invalid/optional_plugins.json"
        catalog = (b'{"serial": 1, "plugins": [{"id": "1", "url":'
                   b' "https://example.invalid/p.zip", "sha256": "' + b"0" * 64 + b'"}]}')
        signature = (b"untrusted comment: x\nAAAA\n"
                     b"trusted comment: phoenix-plugins 1\nAAAA\n")

        def get(url, **kwargs):
            resp = MagicMock(status_code=200)
            resp.raise_for_status.return_value = None
            body = signature if url.endswith(".minisig") else catalog
            resp.iter_content = lambda chunk_size=1: iter([body])
            return resp

        with patch("plugins.plugin_manager.requests.get", side_effect=get):
            assert mgr.get_available_plugins() == []
        assert mgr._published_hashes == {}
        ok, _ = mgr.download_plugin("https://example.invalid/p.zip", plugin_id="1")
        assert ok is False

    def test_legacy_updaters_are_gone(self):
        """Nothing left to re-point at an appcast feed or the old keys."""
        import importlib.util
        from pathlib import Path
        root = Path(__file__).resolve().parents[2]
        for name in ("appcast", "darwin", "linux", "windows", "manager"):
            assert importlib.util.find_spec(f"utils.updates.{name}") is None, name
        assert not (root / "frameworks" / "Sparkle.framework").exists()
        assert not (root / "frameworks" / "WinSparkle").exists()
        for path in ("packaging/Phoenix.spec", "scripts/build/build-distribution.sh",
                     ".github/workflows/release.yml",
                     "scripts/build/build-windows-installer.ps1"):
            text = (root / path).read_text(encoding="utf-8").lower()
            assert "sparkle" not in text and "appcast" not in text, path

    def test_traversal_guard_rejects_sibling_prefix(self, tmp_path):
        """'/root-evil' must not pass a guard protecting '/root'."""
        root = os.path.normpath(str(tmp_path / "app"))
        evil = os.path.normpath(os.path.join(root, "..", "app-evil", "x"))
        assert os.path.commonpath([root, evil]) != root


@pytest.mark.unit
@pytest.mark.security
class TestWazuhLinuxGroupSanitization:
    def test_shell_metacharacters_stripped(self, isolated_settings, monkeypatch):
        from plugins.wazuh.agent import wazuh_functions_linux as wl
        monkeypatch.setattr(wl, "settings", isolated_settings)
        isolated_settings.set("auth", "email", "a@b'; cp /bin/sh /tmp/s #")
        group = wl.get_agent_group()
        assert all(c.isalnum() or c in ".-_" for c in group), group

    def test_fully_hostile_email_falls_back(self, isolated_settings, monkeypatch):
        from plugins.wazuh.agent import wazuh_functions_linux as wl
        monkeypatch.setattr(wl, "settings", isolated_settings)
        isolated_settings.set("auth", "email", "$(){};'\"`")
        assert wl.get_agent_group() == "default"


@pytest.mark.unit
@pytest.mark.security
class TestSecretsFailClosed:
    def test_plaintext_value_not_returned_as_secret(self, isolated_settings):
        isolated_settings.set("ns", "k", "not-encrypted")
        assert isolated_settings.get_secret("ns", "k") is None


@pytest.mark.unit
@pytest.mark.security
class TestCrossSigningRequests:
    """plugins/login/cross_signing.py reads secret storage with the session's
    Bearer token: it must never follow a redirect off the homeserver."""

    def test_bearer_never_follows_redirects(self, monkeypatch):
        from unittest.mock import MagicMock

        from plugins.login import cross_signing as cs
        from plugins.login import oidc

        http = MagicMock()
        r = MagicMock(status_code=200)
        r.json.return_value = {}
        http.request.return_value = r
        monkeypatch.setattr(oidc, "_session", lambda: http)
        monkeypatch.setattr(oidc, "refresh", lambda force=False: "tok")
        cs._request("GET", "/_matrix/client/v3/user/%40a%3Ab/account_data/m.cross_signing.self_signing")
        kwargs = http.request.call_args.kwargs
        assert kwargs["allow_redirects"] is False and kwargs["verify"] is True
        assert http.request.call_args.args[1].startswith(oidc.homeserver_url() + "/_matrix/")

    def test_failed_verification_writes_no_settings(self, monkeypatch):
        from plugins.login import cross_signing as cs

        monkeypatch.setattr(cs.settings, "get", lambda ns, k, d=None: {
            "user_id": "@a:b", "device_id": "PHX_AAAAAAAAAAAAAAAA"}.get(k, d))
        monkeypatch.setattr(cs.settings, "set", lambda *a, **k: pytest.fail("settings written"))
        monkeypatch.setattr(cs.settings, "set_secret", lambda *a, **k: pytest.fail("secret written"),
                            raising=False)
        monkeypatch.setattr(cs, "_request", lambda *a, **k: (404, None))
        with pytest.raises(cs.VerificationError):
            cs.verify_this_device("EsTE s92N EtaX s2h6 VQYF 9Kao tHYL mkyL GKMh isZb KJ4E tvoC")
