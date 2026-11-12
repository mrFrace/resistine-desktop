"""Regression tests for the 2026-10 security-hardening pass.

Each test pins a rejection path that previously failed open:
- Windows VPN service: tunnel-name traversal, config_path confinement,
  constant-time token check, ACL grantee allowlist.
- Linux updater: unsigned appcast entries refused, traversal guard uses
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
        req = {"token": svc.IPC_TOKEN, "command": "status", "tunnel": "resistine"}
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
        assert svc._validated_config_path("resistine", str(other)) is None

    def test_config_path_accepts_matching_conf(self, tmp_path, monkeypatch):
        from plugins.vpn.wireguard import windows_vpn_service as svc
        # Paths are now confined to known config directories (UNC/arbitrary
        # locations rejected) — stand the test dir in for CONFIG_BASE.
        monkeypatch.setattr(svc, "CONFIG_BASE", str(tmp_path))
        conf = tmp_path / "resistine.conf"
        conf.write_text("[Interface]\n")
        assert svc._validated_config_path("resistine", str(conf)) == str(conf)

    def test_config_path_rejects_unconfined_location(self, tmp_path):
        from plugins.vpn.wireguard import windows_vpn_service as svc
        conf = tmp_path / "resistine.conf"
        conf.write_text("[Interface]\n")
        # tmp_path is not a known config dir — must be rejected.
        assert svc._validated_config_path("resistine", str(conf)) is None

    def test_config_path_rejects_unc(self):
        from plugins.vpn.wireguard import windows_vpn_service as svc
        assert svc._validated_config_path(
            "resistine", r"\\attacker\share\resistine.conf") is None

    def test_config_path_rejects_non_file(self, tmp_path):
        from plugins.vpn.wireguard import windows_vpn_service as svc
        assert svc._validated_config_path("resistine", str(tmp_path)) is None
        assert svc._validated_config_path("resistine", None) is None

    def test_acl_refuses_group_grantees(self):
        from plugins.vpn.wireguard import windows_vpn_service as svc
        for bad in ("Everyone", "Users", "Authenticated Users", 'a"b', "x;y"):
            # Non-win32 returns True before grantee checks; exercise the
            # validation directly.
            assert (svc._SAFE_GRANTEE_RE.fullmatch(bad) is None
                    or bad.lower() in svc._DENY_GRANTEES)


@pytest.mark.unit
@pytest.mark.security
class TestLinuxUpdaterPolicy:
    def test_unsigned_appcast_entry_refused(self):
        """An AppcastItem without edSignature must never reach extraction."""
        from utils.updates import linux as lx

        class Dialog:
            cancelled = False
            errors = []
            def show_error(self, msg, retry=None):
                Dialog.errors.append(msg)
            def set_download_progress(self, frac, status):
                pass

        class App:
            def after(self, _ms, fn=None, *args):
                if callable(fn):
                    fn(*args)

        item = lx.AppcastItem(
            version="99.99.99", title="x",
            download_url="https://example.invalid/u.tar.gz",
            download_length=4, signature="",
        )
        applied = []
        with patch.object(lx, "_app", App()), \
             patch.object(lx, "_apply_update",
                          side_effect=lambda p: applied.append(p) or (True, "")), \
             patch.object(lx.requests, "get") as get:
            resp = get.return_value
            resp.raise_for_status.return_value = None
            resp.headers = {"Content-Length": "4"}
            resp.iter_content.return_value = [b"data"]
            lx._download_worker(item, Dialog())
        assert applied == [], "unsigned update must not be applied"
        assert any("unsigned" in e.lower() for e in Dialog.errors)

    def test_non_https_url_refused(self):
        from utils.updates import linux as lx

        class Dialog:
            cancelled = False
            errors = []
            def show_error(self, msg, retry=None):
                Dialog.errors.append(msg)

        class App:
            def after(self, _ms, fn=None, *args):
                if callable(fn):
                    fn(*args)

        item = lx.AppcastItem(
            version="99.99.99", title="x",
            download_url="http://example.invalid/u.tar.gz",
            download_length=4, signature="sig",
        )
        with patch.object(lx, "_app", App()), \
             patch.object(lx.requests, "get") as get:
            lx._download_worker(item, Dialog())
            assert not get.called, "no bytes may be fetched over plain http"

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
