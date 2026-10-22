"""VPN provisioning via the Phoenix API (plugins/vpn/provisioning.py) and the
writer/key-storage changes it relies on. No network: requests and the OIDC
token helpers are mocked."""

import json
import os
from unittest.mock import MagicMock

import pytest

from plugins.vpn import provisioning as prov
from plugins.vpn.wireguard.config_validation import optional_peer_lines

SERVER_PUB = "u8909Yqge8GzXID9EPw5bEc0kN3PSC3AHvtbZagDeFo="
PSK = "aGVsbG8taGVsbG8taGVsbG8taGVsbG8taGVsbG8tMDE="
CONFIG = {
    "Interface": {"Address": "10.42.20.7/32", "DNS": ["10.42.20.1"]},
    "Peer": {
        "PublicKey": SERVER_PUB,
        "PresharedKey": PSK,
        "Endpoint": "vpn.phoenix.exposed:987",
        "AllowedIPs": ["10.42.10.250/32", "10.42.20.1/32"],
        "PersistentKeepalive": 25,
    },
}


def response(status=200, body=None):
    r = MagicMock()
    r.status_code = status
    r.ok = 200 <= status < 300
    r.json.return_value = body if body is not None else {}
    return r


@pytest.fixture
def api(monkeypatch):
    """Signed-in session whose HTTP calls go to ``api.http``."""
    from plugins.login import oidc

    http = MagicMock()
    tokens = {"refresh": ["tok-1"], "force": ["tok-2"]}
    monkeypatch.setattr(oidc, "_session", lambda: http)
    monkeypatch.setattr(
        oidc, "refresh",
        lambda force=False: (tokens["force"] if force else tokens["refresh"]).pop(0))
    monkeypatch.delenv("PHOENIX_API_URL", raising=False)
    http.tokens = tokens
    return http


@pytest.mark.unit
class TestRequestPeer:
    def test_posts_public_key_with_bearer_token(self, api):
        api.request.return_value = response(200, CONFIG)
        assert prov.request_peer("CLIENTPUB=", "laptop") == CONFIG
        method, url = api.request.call_args.args
        kw = api.request.call_args.kwargs
        assert (method, url) == ("POST", "https://api.phoenix.exposed/v1/vpn/peer")
        assert kw["headers"]["Authorization"] == "Bearer tok-1"
        assert kw["json"] == {"public_key": "CLIENTPUB=", "hostname": "laptop"}
        assert kw["verify"] is True and kw["timeout"]

    def test_api_url_override(self, api, monkeypatch):
        monkeypatch.setenv("PHOENIX_API_URL", "http://127.0.0.1:8099/")
        api.request.return_value = response(200, CONFIG)
        prov.request_peer("K=")
        assert api.request.call_args.args[1] == "http://127.0.0.1:8099/v1/vpn/peer"

    def test_retries_once_with_refreshed_token_on_401(self, api):
        api.request.side_effect = [response(401), response(200, CONFIG)]
        assert prov.request_peer("K=") == CONFIG
        assert api.request.call_args.kwargs["headers"]["Authorization"] == "Bearer tok-2"

    def test_session_gone_after_401(self, api):
        api.tokens["force"] = [None]
        api.request.return_value = response(401)
        with pytest.raises(prov.ProvisioningError, match="Sign in again"):
            prov.request_peer("K=")

    def test_not_signed_in(self, api):
        api.tokens["refresh"] = [None]
        with pytest.raises(prov.ProvisioningError, match="not signed in"):
            prov.request_peer("K=")
        api.request.assert_not_called()

    def test_no_vpn_entitlement(self, api):
        api.request.return_value = response(403, {"detail": "no VPN plan"})
        with pytest.raises(prov.ProvisioningError, match="doesn't include VPN"):
            prov.request_peer("K=")

    def test_server_error_detail(self, api):
        api.request.return_value = response(500, {"detail": "router unreachable"})
        with pytest.raises(prov.ProvisioningError, match="router unreachable"):
            prov.request_peer("K=")

    def test_network_error(self, api):
        api.request.side_effect = ConnectionError("dns")
        with pytest.raises(prov.ProvisioningError, match="Couldn't reach"):
            prov.request_peer("K=")

    @pytest.mark.parametrize("body", [
        [], {"Interface": {}}, {"Interface": {"Address": "10.0.0.2/32"}, "Peer": {}},
        {"Interface": {"Address": "10.0.0.2/32"},
         "Peer": {"PublicKey": SERVER_PUB, "Endpoint": "h:1"}},  # no AllowedIPs
    ])
    def test_rejects_malformed_config(self, api, body):
        api.request.return_value = response(200, body)
        with pytest.raises(prov.ProvisioningError):
            prov.request_peer("K=")


@pytest.fixture
def manager(monkeypatch):
    import plugins.vpn.main as vpnmain

    mgr = MagicMock()
    mgr.get_active_config_name.return_value = None
    mgr.get_active_config_path.return_value = None
    monkeypatch.setattr(vpnmain, "_config_manager", mgr)
    return mgr


@pytest.mark.unit
class TestEnsureVpnConfig:
    def test_reuses_existing_phoenix_config(self, manager, tmp_path, monkeypatch):
        conf = tmp_path / "phoenix.conf"
        conf.write_text("[Interface]\n")
        manager.get_active_config_name.return_value = "phoenix"
        manager.get_active_config_path.return_value = str(conf)
        monkeypatch.setattr(prov, "_vpn_backend", lambda: pytest.fail("no backend call"))
        assert prov.ensure_vpn_config() == ("phoenix", str(conf))

    def test_provisions_and_activates(self, manager, monkeypatch):
        backend = MagicMock()
        backend.setup_vpn_keys.return_value = "CLIENTPUB="
        backend.save_vpn_configuration.return_value = "/wg/phoenix.conf"
        monkeypatch.setattr(prov, "_vpn_backend", lambda: backend)
        monkeypatch.setattr(prov, "request_peer", lambda pub: CONFIG if pub == "CLIENTPUB=" else None)
        statuses = []

        assert prov.ensure_vpn_config(statuses.append) == ("phoenix", "/wg/phoenix.conf")
        backend.save_vpn_configuration.assert_called_once_with(CONFIG, "phoenix")
        manager.register_config.assert_called_once_with("phoenix", source="phoenix")
        manager.set_active_config.assert_called_once_with("phoenix")
        assert statuses == ["Creating your VPN keys…", "Getting your VPN configuration…"]

    def test_force_replaces_existing(self, manager, monkeypatch, tmp_path):
        conf = tmp_path / "phoenix.conf"
        conf.write_text("x")
        manager.get_active_config_name.return_value = "phoenix"
        manager.get_active_config_path.return_value = str(conf)
        backend = MagicMock(setup_vpn_keys=MagicMock(return_value="K="),
                            save_vpn_configuration=MagicMock(return_value="/new"))
        monkeypatch.setattr(prov, "_vpn_backend", lambda: backend)
        monkeypatch.setattr(prov, "request_peer", lambda pub: CONFIG)
        assert prov.ensure_vpn_config(force=True)[1] == "/new"

    def test_key_generation_failure(self, manager, monkeypatch):
        backend = MagicMock(setup_vpn_keys=MagicMock(return_value=None))
        monkeypatch.setattr(prov, "_vpn_backend", lambda: backend)
        with pytest.raises(prov.ProvisioningError, match="keys"):
            prov.ensure_vpn_config()

    def test_writer_rejection_is_reported(self, manager, monkeypatch):
        backend = MagicMock(setup_vpn_keys=MagicMock(return_value="K="),
                            save_vpn_configuration=MagicMock(return_value=None))
        monkeypatch.setattr(prov, "_vpn_backend", lambda: backend)
        monkeypatch.setattr(prov, "request_peer", lambda pub: CONFIG)
        with pytest.raises(prov.ProvisioningError, match="rejected"):
            prov.ensure_vpn_config()
        manager.set_active_config.assert_not_called()

    def test_vpn_missing_from_build_stops_before_any_key(self, manager, monkeypatch):
        backend = MagicMock(vpn_unavailable_reason=MagicMock(return_value="No VPN in this build."))
        monkeypatch.setattr(prov, "_vpn_backend", lambda: backend)
        monkeypatch.setattr(prov, "request_peer", lambda pub: pytest.fail("no peer registered"))
        with pytest.raises(prov.ProvisioningError, match="No VPN in this build"):
            prov.ensure_vpn_config()
        backend.setup_vpn_keys.assert_not_called()


@pytest.mark.unit
class TestReleaseDevice:
    def test_deletes_device(self, api):
        api.request.return_value = response(204)
        assert prov.release_device() is True
        assert api.request.call_args.args == ("DELETE", "https://api.phoenix.exposed/v1/device")

    def test_unknown_device_is_fine(self, api):
        api.request.return_value = response(404)
        assert prov.release_device() is True

    def test_failure_is_swallowed(self, api):
        api.request.side_effect = ConnectionError("offline")
        assert prov.release_device() is False


@pytest.mark.unit
class TestOptionalPeerLines:
    def test_psk_and_keepalive(self):
        assert optional_peer_lines({"PresharedKey": PSK, "PersistentKeepalive": 25}) == [
            f"PresharedKey = {PSK}", "PersistentKeepalive = 25"]

    def test_absent(self):
        assert optional_peer_lines({}) == []

    @pytest.mark.parametrize("peer", [
        {"PresharedKey": PSK + "\nPostUp = rm -rf /"},
        {"PresharedKey": "not a key"},
        {"PersistentKeepalive": "25\nPostUp = x"},
        {"PersistentKeepalive": "70000"},
        {"PersistentKeepalive": "-1"},
    ])
    def test_rejects_injection_and_bad_values(self, peer):
        with pytest.raises(ValueError):
            optional_peer_lines(peer)


@pytest.mark.unit
class TestLinuxWriterAndKeys:
    @pytest.fixture
    def linux(self, isolated_settings, tmp_path, monkeypatch):
        from plugins.vpn.wireguard import vpn_functions_linux as lx

        monkeypatch.setattr(lx, "KEYS_FILE_PATH", str(tmp_path / "keys.json"))
        monkeypatch.setattr(lx, "get_writable_wireguard_dir", lambda: str(tmp_path))
        return lx

    def test_config_includes_psk_and_keepalive(self, linux):
        assert linux.save_wireguard_keys("cHJpdmF0ZS1wcml2YXRlLXByaXZhdGUtcHJpdmF0ZTE=", "PUB=")
        path = linux.save_vpn_configuration(CONFIG, "phoenix")
        text = open(path).read()
        assert f"PresharedKey = {PSK}" in text
        assert "PersistentKeepalive = 25" in text
        assert "Endpoint = vpn.phoenix.exposed:987" in text
        assert "AllowedIPs = 10.42.10.250/32, 10.42.20.1/32" in text
        assert oct(os.stat(path).st_mode & 0o777) == "0o600"

    def test_bad_psk_writes_nothing(self, linux, tmp_path):
        linux.save_wireguard_keys("cHJpdmF0ZS1wcml2YXRlLXByaXZhdGUtcHJpdmF0ZTE=", "PUB=")
        bad = json.loads(json.dumps(CONFIG))
        bad["Peer"]["PresharedKey"] = PSK + "\nPostUp = touch /tmp/pwned"
        assert linux.save_vpn_configuration(bad, "phoenix") is None
        assert not (tmp_path / "phoenix.conf").exists()

    def test_keys_are_encrypted_not_plaintext(self, linux, isolated_settings, tmp_path):
        assert linux.save_wireguard_keys("PRIV=", "PUB=")
        assert not (tmp_path / "keys.json").exists()
        assert isolated_settings.get_secret("wireguard", "private_key") == "PRIV="
        assert linux.get_wireguard_private_key() == "PRIV="
        assert linux.delete_wireguard_keys()
        assert linux.get_wireguard_private_key() is None

    def test_legacy_keys_json_is_migrated_and_removed(self, linux, tmp_path):
        legacy = tmp_path / "keys.json"
        legacy.write_text(json.dumps({"private_key": "OLDPRIV=", "public_key": "OLDPUB="}))
        assert linux.get_wireguard_private_key() == "OLDPRIV="
        assert not legacy.exists()
        assert linux.get_wireguard_public_key() == "OLDPUB="
