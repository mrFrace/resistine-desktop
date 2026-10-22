"""
Integration tests for the full authentication flow.

Tests the LoginAPI → VPN key setup → VPN config save chain as it happens
on actual login. All external HTTP calls are mocked.

Flow:
1. generate WireGuard keys (setup_vpn_keys)
2. send_otp to backend
3. verify_otp with public_key → receive vpn_config
4. save_vpn_configuration → write .conf file to disk
5. settings store auth.logged_in + auth.email
"""
import json
import os
import pytest
from unittest.mock import MagicMock, patch

from plugins.login.api import LoginAPI


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------
@pytest.fixture()
def api(isolated_settings):
    return LoginAPI("https://test.resistine.work")


@pytest.fixture()
def server_vpn_config():
    return {
        "Interface": {
            "PrivateKey": "",
            "Address": "10.0.0.2",
            "DNS": ["10.0.0.53"],
        },
        "Peer": {
            "PublicKey": "serverPubKey123==",
            "AllowedIPs": ["10.0.0.0/24"],
            "Endpoint": "1.2.3.4:51820",
        },
    }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _mock_post(json_body, status_code=200):
    resp = MagicMock()
    resp.ok = (200 <= status_code < 300)
    resp.status_code = status_code
    resp.json.return_value = json_body
    resp.text = json.dumps(json_body)
    return resp


# ===========================================================================
# Step 1: WireGuard key generation
# ===========================================================================
@pytest.mark.integration
class TestWireguardKeySetup:
    def test_setup_vpn_keys_returns_public_key(self, isolated_settings, monkeypatch):
        monkeypatch.setattr(
            "plugins.vpn.wireguard.vpn_functions_darwin.settings", isolated_settings
        )
        from plugins.vpn.wireguard.vpn_functions_darwin import setup_vpn_keys
        pub_key = setup_vpn_keys()
        assert pub_key is not None
        assert len(pub_key) == 44  # base64-encoded 32-byte X25519 key

    def test_setup_vpn_keys_stores_both_keys(self, isolated_settings, monkeypatch):
        monkeypatch.setattr(
            "plugins.vpn.wireguard.vpn_functions_darwin.settings", isolated_settings
        )
        from plugins.vpn.wireguard.vpn_functions_darwin import (
            setup_vpn_keys,
            wireguard_keys_exist,
        )
        setup_vpn_keys()
        assert wireguard_keys_exist()


# ===========================================================================
# Step 2 & 3: OTP → verify → receive VPN config
# ===========================================================================
@pytest.mark.integration
class TestOtpFlow:
    @patch("plugins.login.api.requests.post")
    def test_send_otp_then_verify_success(self, mock_post, api):
        send_response = _mock_post({"status": "success", "message": "OTP sent"})
        verify_response = _mock_post({
            "status": "success",
            "vpn_config": json.dumps({
                "Interface": {"Address": "10.0.0.2", "DNS": ["10.0.0.53"]},
                "Peer": {"PublicKey": "spk==", "AllowedIPs": ["0.0.0.0/0"], "Endpoint": "1.2.3.4:51820"},
            }),
        })
        mock_post.side_effect = [send_response, verify_response]

        ok1, _, _ = api.send_otp("user@example.com")
        ok2, _, data = api.verify_otp("user@example.com", "123456", "clientPubKey==")

        assert ok1 is True
        assert ok2 is True
        assert "vpn_config" in data

    @patch("plugins.login.api.requests.post")
    def test_wrong_otp_stops_flow(self, mock_post, api):
        mock_post.return_value = _mock_post({"status": "failed", "message": "Invalid OTP"})
        ok, msg, _ = api.verify_otp("user@example.com", "000000", "clientPubKey==")
        assert ok is False

    @patch("plugins.login.api.requests.post")
    def test_verify_returns_vpn_config_string(self, mock_post, api, server_vpn_config):
        mock_post.return_value = _mock_post({
            "status": "success",
            "vpn_config": json.dumps(server_vpn_config),
        })
        ok, _, data = api.verify_otp("user@example.com", "123456", "pubkey==")
        assert ok is True
        vpn_json = json.loads(data["vpn_config"])
        assert "Interface" in vpn_json
        assert "Peer" in vpn_json


# ===========================================================================
# Step 4: Save VPN config to disk
# ===========================================================================
@pytest.mark.integration
class TestSaveVpnConfig:
    def test_save_vpn_configuration_creates_file(
        self, tmp_path, isolated_settings, monkeypatch, server_vpn_config
    ):
        monkeypatch.setattr(
            "plugins.vpn.wireguard.vpn_functions_darwin.settings", isolated_settings
        )
        from plugins.vpn.wireguard.vpn_functions_darwin import (
            save_wireguard_keys,
            save_vpn_configuration,
        )
        save_wireguard_keys("test_private_key_value", "test_public_key_value")

        with patch(
            "plugins.vpn.wireguard.vpn_functions_darwin.get_writable_wireguard_dir",
            return_value=str(tmp_path),
        ):
            path = save_vpn_configuration(json.dumps(server_vpn_config), "resistine")

        assert path is not None
        assert os.path.exists(path)

    def test_save_vpn_configuration_content_valid(
        self, tmp_path, isolated_settings, monkeypatch, server_vpn_config
    ):
        monkeypatch.setattr(
            "plugins.vpn.wireguard.vpn_functions_darwin.settings", isolated_settings
        )
        from plugins.vpn.wireguard.vpn_functions_darwin import (
            save_wireguard_keys,
            save_vpn_configuration,
        )
        save_wireguard_keys("priv_key_val", "pub_key_val")

        with patch(
            "plugins.vpn.wireguard.vpn_functions_darwin.get_writable_wireguard_dir",
            return_value=str(tmp_path),
        ):
            path = save_vpn_configuration(json.dumps(server_vpn_config))

        content = open(path).read()
        assert "[Interface]" in content
        assert "[Peer]" in content
        assert "10.0.0.2" in content
        assert "1.2.3.4:51820" in content

    def test_save_vpn_configuration_none_returns_none(
        self, isolated_settings, monkeypatch
    ):
        monkeypatch.setattr(
            "plugins.vpn.wireguard.vpn_functions_darwin.settings", isolated_settings
        )
        from plugins.vpn.wireguard.vpn_functions_darwin import save_vpn_configuration
        result = save_vpn_configuration(None)
        assert result is None


# ===========================================================================
# Step 5: Settings persistence after login
# ===========================================================================
@pytest.mark.integration
class TestAuthSettingsPersistence:
    def test_auth_logged_in_persists(self, isolated_settings):
        isolated_settings.set("auth", "logged_in", True)
        assert isolated_settings.get("auth", "logged_in", False) is True

    def test_auth_email_persists(self, isolated_settings):
        isolated_settings.set("auth", "email", "user@company.com")
        assert isolated_settings.get("auth", "email") == "user@company.com"

    def test_wazuh_enrolled_email_set_after_install(self, isolated_settings):
        isolated_settings.set("auth", "email", "user@company.com")
        isolated_settings.set("wazuh", "enrolled_email", isolated_settings.get("auth", "email"))
        assert isolated_settings.get("wazuh", "enrolled_email") == "user@company.com"


# ===========================================================================
# Full end-to-end login chain (mocked network + disk)
# ===========================================================================
@pytest.mark.integration
class TestFullLoginChain:
    @patch("plugins.login.api.requests.post")
    def test_full_chain_sends_public_key_to_verify(
        self, mock_post, isolated_settings, monkeypatch, tmp_path, server_vpn_config
    ):
        monkeypatch.setattr(
            "plugins.vpn.wireguard.vpn_functions_darwin.settings", isolated_settings
        )
        from plugins.vpn.wireguard.vpn_functions_darwin import setup_vpn_keys

        # Step 1: Generate keys
        public_key = setup_vpn_keys()
        assert public_key is not None

        # Step 2: Simulate verify_otp sending public_key
        mock_post.return_value = _mock_post({
            "status": "success",
            "vpn_config": json.dumps(server_vpn_config),
        })
        api = LoginAPI("https://test.resistine.work")
        ok, _, data = api.verify_otp("user@example.com", "123456", public_key)

        assert ok is True
        payload_sent = mock_post.call_args[1]["json"]
        assert payload_sent["client_public_key"] == public_key

    @patch("plugins.login.api.requests.post")
    def test_full_chain_saves_vpn_config_on_success(
        self, mock_post, isolated_settings, monkeypatch, tmp_path, server_vpn_config
    ):
        monkeypatch.setattr(
            "plugins.vpn.wireguard.vpn_functions_darwin.settings", isolated_settings
        )
        from plugins.vpn.wireguard.vpn_functions_darwin import (
            setup_vpn_keys,
            save_vpn_configuration,
        )

        public_key = setup_vpn_keys()
        mock_post.return_value = _mock_post({
            "status": "success",
            "vpn_config": json.dumps(server_vpn_config),
        })
        api = LoginAPI("https://test.resistine.work")
        ok, _, data = api.verify_otp("user@example.com", "123456", public_key)
        assert ok is True

        with patch(
            "plugins.vpn.wireguard.vpn_functions_darwin.get_writable_wireguard_dir",
            return_value=str(tmp_path),
        ):
            path = save_vpn_configuration(data["vpn_config"])

        assert path is not None
        assert os.path.exists(path)


# ===========================================================================
# P1-A: VPN onboarding security guarantees
# ===========================================================================
@pytest.mark.integration
@pytest.mark.security
class TestVpnOnboardingSecurityGuarantees:
    def test_private_key_stored_with_enc_prefix_after_setup(
        self, isolated_settings, monkeypatch, tmp_config_dir
    ):
        """Private key must be stored with ENC: prefix — never as plaintext."""
        monkeypatch.setattr(
            "plugins.vpn.wireguard.vpn_functions_darwin.settings", isolated_settings
        )
        from plugins.vpn.wireguard.vpn_functions_darwin import setup_vpn_keys
        setup_vpn_keys()

        wg_json = tmp_config_dir / "wireguard.json"
        assert wg_json.exists(), "wireguard.json must be created by setup_vpn_keys"
        raw = json.loads(wg_json.read_text())
        assert raw.get("private_key", "").startswith("ENC:"), (
            "Private key must be encrypted on disk — found plaintext"
        )

    def test_setup_then_save_produces_valid_conf_file(
        self, isolated_settings, monkeypatch, tmp_path, server_vpn_config
    ):
        """setup_vpn_keys followed by save_vpn_configuration must produce a valid .conf."""
        monkeypatch.setattr(
            "plugins.vpn.wireguard.vpn_functions_darwin.settings", isolated_settings
        )
        from plugins.vpn.wireguard.vpn_functions_darwin import (
            setup_vpn_keys,
            save_vpn_configuration,
        )
        setup_vpn_keys()
        with patch(
            "plugins.vpn.wireguard.vpn_functions_darwin.get_writable_wireguard_dir",
            return_value=str(tmp_path),
        ):
            path = save_vpn_configuration(json.dumps(server_vpn_config))

        assert path is not None
        assert os.path.exists(path)
        content = open(path).read()
        assert "[Interface]" in content
        assert "[Peer]" in content

    def test_no_conf_file_written_when_keygen_fails(
        self, isolated_settings, monkeypatch, tmp_path, server_vpn_config
    ):
        """If key generation fails, setup_vpn_keys must not produce a public key
        and no partial .conf file should be written."""
        monkeypatch.setattr(
            "plugins.vpn.wireguard.vpn_functions_darwin.settings", isolated_settings
        )
        from plugins.vpn.wireguard import vpn_functions_darwin as vfd

        with patch(
            "plugins.vpn.wireguard.vpn_functions_darwin.generate_wireguard_keys",
            side_effect=RuntimeError("crypto subsystem failure"),
        ):
            # setup_vpn_keys catches the error internally — it does NOT re-raise
            pub_key = vfd.setup_vpn_keys()

        # On key gen failure, no valid public key should be returned
        assert pub_key is None or pub_key == "", (
            f"Expected None/empty public key on failure, got: {pub_key!r}"
        )

        # No .conf files should have been written
        conf_files = list(tmp_path.glob("*.conf"))
        assert conf_files == [], (
            f"Partial .conf files must not be written on key gen failure: {conf_files}"
        )

    def test_save_config_failure_does_not_produce_corrupt_state(
        self, isolated_settings, monkeypatch, tmp_path, server_vpn_config
    ):
        """If save_vpn_configuration fails, no silently corrupted state is produced."""
        monkeypatch.setattr(
            "plugins.vpn.wireguard.vpn_functions_darwin.settings", isolated_settings
        )
        from plugins.vpn.wireguard.vpn_functions_darwin import (
            save_wireguard_keys,
            save_vpn_configuration,
        )
        save_wireguard_keys("priv_key", "pub_key")

        read_open = open  # keep reference to real open

        def selective_fail(path, *args, **kwargs):
            if str(path).endswith(".conf"):
                raise PermissionError("read-only filesystem")
            return read_open(path, *args, **kwargs)

        with patch(
            "plugins.vpn.wireguard.vpn_functions_darwin.get_writable_wireguard_dir",
            return_value=str(tmp_path),
        ):
            with patch("builtins.open", side_effect=selective_fail):
                try:
                    result = save_vpn_configuration(json.dumps(server_vpn_config))
                    # Acceptable: returns None on failure
                    assert result is None
                except (PermissionError, OSError):
                    pass  # Acceptable: exception propagated cleanly

        # Crucially: no half-written .conf files
        conf_files = list(tmp_path.glob("*.conf"))
        assert conf_files == [], "No corrupt partial .conf files should exist after write failure"
