"""
Security-focused tests for secrets storage.

Covers:
- Encrypted values never stored as plaintext
- ENC: prefix present on all secrets
- Master key not stored in settings JSON files
- Secrets survive decryption round-trip
- Wrong key → decryption fails gracefully (no crash, no plaintext leak)
- Fallback master key file has restricted permissions
- Deleting a secret removes it from disk
- Namespace isolation (secret in ns_a not visible in ns_b)
- WireGuard keys stored as secrets
"""
import json
import os
import platform
import stat
import pytest
from unittest.mock import MagicMock, patch

from cryptography.fernet import Fernet


# ===========================================================================
# Encrypted storage invariants
# ===========================================================================
@pytest.mark.security
class TestEncryptedStorageInvariants:
    def test_secret_stored_with_enc_prefix(self, isolated_settings, tmp_config_dir):
        isolated_settings.set_secret("auth", "token", "my_secret_token")
        raw = json.loads((tmp_config_dir / "auth.json").read_text())
        assert raw["token"].startswith("ENC:")

    def test_secret_value_not_plaintext_in_file(self, isolated_settings, tmp_config_dir):
        isolated_settings.set_secret("auth", "api_key", "DO_NOT_STORE_PLAINTEXT")
        raw = (tmp_config_dir / "auth.json").read_text()
        assert "DO_NOT_STORE_PLAINTEXT" not in raw

    def test_master_key_not_in_json_files(self, isolated_settings, tmp_config_dir):
        """The Fernet master key must never appear inside any settings JSON file."""
        import utils.settings as s
        # Get the master key
        key_str = None
        try:
            key_str = s._get_master_key().decode()
        except Exception:
            pass

        isolated_settings.set_secret("auth", "secret", "value")
        raw = (tmp_config_dir / "auth.json").read_text()
        if key_str:
            assert key_str not in raw

    def test_two_secrets_have_different_ciphertext(self, isolated_settings, tmp_config_dir):
        """The same plaintext encrypted twice must produce different ciphertext (Fernet is nonce-based)."""
        isolated_settings.set_secret("ns", "key_a", "same_value")
        isolated_settings.set_secret("ns", "key_b", "same_value")
        raw = json.loads((tmp_config_dir / "ns.json").read_text())
        assert raw["key_a"] != raw["key_b"]

    def test_secret_round_trip(self, isolated_settings):
        isolated_settings.set_secret("ns", "priv_key", "super_secret_wireguard_key==")
        result = isolated_settings.get_secret("ns", "priv_key")
        assert result == "super_secret_wireguard_key=="

    def test_tampered_ciphertext_returns_none(self, isolated_settings, tmp_config_dir):
        """Tampered ciphertext must not decrypt and must not crash."""
        isolated_settings.set_secret("ns", "tok", "original_value")
        # Tamper with the stored ciphertext
        raw = json.loads((tmp_config_dir / "ns.json").read_text())
        raw["tok"] = "ENC:invalidciphertext_TAMPERED"
        (tmp_config_dir / "ns.json").write_text(json.dumps(raw))
        result = isolated_settings.get_secret("ns", "tok")
        # Must return None (decryption failure) — not raise, not return garbage
        assert result is None

    def test_secret_deleted_from_disk(self, isolated_settings, tmp_config_dir):
        isolated_settings.set_secret("ns", "temp_tok", "temp_value")
        isolated_settings.delete("ns", "temp_tok")
        raw = json.loads((tmp_config_dir / "ns.json").read_text())
        assert "temp_tok" not in raw

    def test_namespace_isolation(self, isolated_settings):
        """Secrets in one namespace must not bleed into another."""
        isolated_settings.set_secret("ns_a", "key", "value_a")
        isolated_settings.set_secret("ns_b", "key", "value_b")
        assert isolated_settings.get_secret("ns_a", "key") == "value_a"
        assert isolated_settings.get_secret("ns_b", "key") == "value_b"


# ===========================================================================
# Master key fallback file permissions
# ===========================================================================
@pytest.mark.security
@pytest.mark.skipif(platform.system() == "Windows", reason="POSIX-only")
class TestMasterKeyFallbackPermissions:
    def test_fallback_file_permissions_600(self, tmp_config_dir, monkeypatch):
        """The .master.key fallback file must be created with mode 0o600."""
        import utils.settings as s
        monkeypatch.setattr(s, "get_config_dir", lambda: str(tmp_config_dir))

        key = Fernet.generate_key()
        s._save_master_key_fallback(key)

        key_file = tmp_config_dir / ".master.key"
        assert key_file.exists()
        mode = oct(stat.S_IMODE(os.stat(str(key_file)).st_mode))
        assert mode == oct(0o600), f"Expected 0o600, got {mode}"

    def test_fallback_file_not_world_readable(self, tmp_config_dir, monkeypatch):
        import utils.settings as s
        monkeypatch.setattr(s, "get_config_dir", lambda: str(tmp_config_dir))
        key = Fernet.generate_key()
        s._save_master_key_fallback(key)
        key_file = tmp_config_dir / ".master.key"
        mode = os.stat(str(key_file)).st_mode
        # World-readable bit must NOT be set
        assert not (mode & stat.S_IROTH), "Master key file is world-readable!"
        # Group-readable bit must NOT be set
        assert not (mode & stat.S_IRGRP), "Master key file is group-readable!"


# ===========================================================================
# WireGuard key storage security
# ===========================================================================
@pytest.mark.security
class TestWireguardKeyStorageSecurity:
    def test_wireguard_private_key_not_in_plaintext(self, isolated_settings, tmp_config_dir, monkeypatch):
        monkeypatch.setattr(
            "plugins.vpn.wireguard.vpn_functions_darwin.settings", isolated_settings
        )
        from plugins.vpn.wireguard.vpn_functions_darwin import save_wireguard_keys
        save_wireguard_keys("SECRET_PRIVATE_KEY_VALUE", "public_key")

        wg_file = tmp_config_dir / "wireguard.json"
        if wg_file.exists():
            raw = wg_file.read_text()
            assert "SECRET_PRIVATE_KEY_VALUE" not in raw

    def test_wireguard_keys_require_decryption(self, isolated_settings, tmp_config_dir, monkeypatch):
        monkeypatch.setattr(
            "plugins.vpn.wireguard.vpn_functions_darwin.settings", isolated_settings
        )
        from plugins.vpn.wireguard.vpn_functions_darwin import save_wireguard_keys
        save_wireguard_keys("priv_key_value", "pub_key_value")

        # Raw file should have ENC: prefix indicating encryption
        wg_file = tmp_config_dir / "wireguard.json"
        if wg_file.exists():
            raw = json.loads(wg_file.read_text())
            priv_raw = raw.get("private_key", "")
            assert priv_raw.startswith("ENC:"), f"Private key not encrypted: {priv_raw[:20]}"

    def test_wireguard_public_key_also_protected(self, isolated_settings, tmp_config_dir, monkeypatch):
        """Even the public key should be stored as ENC: (defense in depth)."""
        monkeypatch.setattr(
            "plugins.vpn.wireguard.vpn_functions_darwin.settings", isolated_settings
        )
        from plugins.vpn.wireguard.vpn_functions_darwin import save_wireguard_keys
        save_wireguard_keys("priv", "PUBLIC_KEY_SHOULD_ALSO_BE_ENC")
        wg_file = tmp_config_dir / "wireguard.json"
        if wg_file.exists():
            raw = json.loads(wg_file.read_text())
            pub_raw = raw.get("public_key", "")
            assert pub_raw.startswith("ENC:")


# ===========================================================================
# Keyring security check
# ===========================================================================
@pytest.mark.security
class TestKeyringSecurityCheck:
    def test_plaintext_keyring_rejected(self):
        from utils.encryption import is_keyring_secure, InsecureKeyringuException
        with patch("utils.encryption.keyring") as kr:
            backend = MagicMock()
            backend.__class__.__name__ = "PlaintextKeyring"
            backend.__class__.__module__ = "keyrings.alt.file"
            kr.get_keyring.return_value = backend
            with pytest.raises(InsecureKeyringuException):
                is_keyring_secure()

    def test_null_keyring_rejected(self):
        from utils.encryption import is_keyring_secure, InsecureKeyringuException
        with patch("utils.encryption.keyring") as kr:
            backend = MagicMock()
            backend.__class__.__name__ = "NullKeyring"
            backend.__class__.__module__ = "keyring.backends.null"
            kr.get_keyring.return_value = backend
            with pytest.raises(InsecureKeyringuException):
                is_keyring_secure()


# ===========================================================================
# P1-B: Windows VPN IPC token — no hardcoded placeholders anywhere
# ===========================================================================
# NOTE: the earlier version of this test just did
#   `from plugins.vpn.wireguard.service_client import IPC_TOKEN`
# and asserted it wasn't equal to "RESISTINE_INTERNAL_TOKEN_CHANGE_ME".
# That only covered one specific placeholder string at a specific
# import location, and it broke as soon as the module stopped exposing
# a module-level IPC_TOKEN constant at all. The pair of tests below
# instead check both the service_client and gui/tray sides and confirm
# both that no "CHANGE_ME"-style placeholder survives anywhere, and
# also that a _load_ipc_token loader exists that reads from the shared
# %PROGRAMDATA%\\Resistine\\ipc_token file. If you refactor the token
# loading code in either module please make sure both assertions below
# are correct, otherwise you'll notice ship-blocker authorization
# failures against the VPN service like the tray bug that was caught
# earlier in this same branch. - Austin
@pytest.mark.security
def test_service_client_has_no_hardcoded_token():
    """service_client must load the IPC token from the shared file (not a
    hardcoded placeholder). Token comes from %PROGRAMDATA%\\Resistine\\wireguard\\.ipc_token
    written by the service at first start.
    """
    import inspect
    from plugins.vpn.wireguard import service_client
    # Must not define a module-level IPC_TOKEN constant with a placeholder value
    assert not hasattr(service_client, "IPC_TOKEN") or "CHANGE_ME" not in getattr(service_client, "IPC_TOKEN", ""), (
        "service_client must not ship a hardcoded IPC token placeholder"
    )
    # Must expose a loader function that reads from the shared file
    assert hasattr(service_client, "_load_ipc_token")
    source = inspect.getsource(service_client._load_ipc_token)
    assert "ipc_token" in source


@pytest.mark.security
def test_windows_ipc_token_is_not_default():
    """IPC token loader must never return the factory-default placeholder."""
    from plugins.vpn.wireguard.service_client import _load_ipc_token

    token = _load_ipc_token()
    assert token != "RESISTINE_INTERNAL_TOKEN_CHANGE_ME", (
        "Default IPC token has not been changed — this is a security vulnerability"
    )


# ===========================================================================
# Config file contains no sensitive env info
# ===========================================================================
@pytest.mark.security
def test_settings_json_contains_no_environment_secrets(isolated_settings, tmp_config_dir):
    """Test that plain settings don't accidentally expose env variables."""
    import os
    # Sensitive env vars that should never end up in settings files
    potentially_sensitive = [v for k, v in os.environ.items()
                              if any(kw in k.upper() for kw in ("PASSWORD", "SECRET", "TOKEN", "KEY", "API"))]

    isolated_settings.set("app", "version", "1.0.0")
    isolated_settings.set("app", "debug", False)

    app_file = tmp_config_dir / "app.json"
    if app_file.exists():
        raw = app_file.read_text()
        for secret in potentially_sensitive:
            if len(secret) > 5:  # Only check non-trivial values
                assert secret not in raw
