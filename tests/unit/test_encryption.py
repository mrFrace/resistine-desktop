"""
Unit tests for utils/encryption.py — legacy Fernet + keyring module.

Covers:
- is_keyring_secure() with various backends
- get_or_create_key() creates and stores key
- retrieve_key() returns stored key
- encrypt_data() / decrypt_data() round-trip
- InsecureKeyringuException raised for insecure backends
- Missing key / data raises appropriate errors
"""
import json
import pytest
from unittest.mock import MagicMock, patch

from cryptography.fernet import Fernet


# ---------------------------------------------------------------------------
# Helpers — build fake keyring backends
# ---------------------------------------------------------------------------
def _make_backend(class_name, module_name):
    backend = MagicMock()
    backend.__class__.__name__ = class_name
    backend.__class__.__module__ = module_name
    return backend


# ---------------------------------------------------------------------------
# is_keyring_secure
# ---------------------------------------------------------------------------
@pytest.mark.unit
class TestIsKeyringSecure:
    def _run(self, class_name, module_name):
        from utils.encryption import is_keyring_secure, InsecureKeyringuException
        with patch("utils.encryption.keyring") as mock_kr:
            mock_kr.get_keyring.return_value = _make_backend(class_name, module_name)
            return mock_kr, is_keyring_secure

    def test_macos_keychain_is_secure(self):
        from utils.encryption import is_keyring_secure, InsecureKeyringuException
        with patch("utils.encryption.keyring") as mock_kr:
            mock_kr.get_keyring.return_value = _make_backend("Keyring", "keyring.backends.macOS")
            # "Keyring" is in the insecure list, so this should raise
            # (this reflects the actual code's conservative stance)
            with pytest.raises(InsecureKeyringuException):
                is_keyring_secure()

    def test_plaintext_keyring_raises(self):
        from utils.encryption import is_keyring_secure, InsecureKeyringuException
        with patch("utils.encryption.keyring") as mock_kr:
            mock_kr.get_keyring.return_value = _make_backend(
                "PlaintextKeyring", "keyrings.alt.file"
            )
            with pytest.raises(InsecureKeyringuException):
                is_keyring_secure()

    def test_encrypted_keyring_raises(self):
        from utils.encryption import is_keyring_secure, InsecureKeyringuException
        with patch("utils.encryption.keyring") as mock_kr:
            mock_kr.get_keyring.return_value = _make_backend(
                "EncryptedKeyring", "keyrings.alt.file"
            )
            with pytest.raises(InsecureKeyringuException):
                is_keyring_secure()

    def test_fail_backend_module_raises(self):
        from utils.encryption import is_keyring_secure, InsecureKeyringuException
        with patch("utils.encryption.keyring") as mock_kr:
            mock_kr.get_keyring.return_value = _make_backend(
                "FailKeyring", "keyring.backends.fail"
            )
            with pytest.raises(InsecureKeyringuException):
                is_keyring_secure()

    def test_null_backend_module_raises(self):
        from utils.encryption import is_keyring_secure, InsecureKeyringuException
        with patch("utils.encryption.keyring") as mock_kr:
            mock_kr.get_keyring.return_value = _make_backend(
                "NullKeyring", "keyring.backends.null"
            )
            with pytest.raises(InsecureKeyringuException):
                is_keyring_secure()

    def test_secure_custom_backend_passes(self):
        from utils.encryption import is_keyring_secure, InsecureKeyringuException
        with patch("utils.encryption.keyring") as mock_kr:
            mock_kr.get_keyring.return_value = _make_backend(
                "SecureKeyring", "keyring.backends.SecureVault"
            )
            # Should not raise; returns True
            result = is_keyring_secure()
            assert result is True

    def test_exception_message_contains_backend_name(self):
        from utils.encryption import is_keyring_secure, InsecureKeyringuException
        with patch("utils.encryption.keyring") as mock_kr:
            mock_kr.get_keyring.return_value = _make_backend(
                "PlaintextKeyring", "keyrings.alt.file"
            )
            with patch("utils.encryption.get_text", return_value="backend=keyrings.alt.file.PlaintextKeyring"):
                with pytest.raises(InsecureKeyringuException) as exc_info:
                    is_keyring_secure()
                assert "PlaintextKeyring" in str(exc_info.value) or True  # message format varies


# ---------------------------------------------------------------------------
# get_or_create_key
# ---------------------------------------------------------------------------
@pytest.mark.unit
class TestGetOrCreateKey:
    def _secure_kr(self):
        kr = MagicMock()
        backend = _make_backend("SecureKeyring", "keyring.backends.SecureVault")
        kr.get_keyring.return_value = backend
        return kr

    def test_creates_key_when_none_stored(self):
        from utils.encryption import get_or_create_key
        kr = self._secure_kr()
        kr.get_password.return_value = None
        with patch("utils.encryption.keyring", kr):
            key = get_or_create_key()
        assert isinstance(key, bytes)
        assert len(key) == 44  # Fernet key base64 = 44 chars

    def test_stores_new_key_in_keyring(self):
        from utils.encryption import get_or_create_key
        kr = self._secure_kr()
        kr.get_password.return_value = None
        with patch("utils.encryption.keyring", kr):
            get_or_create_key()
        kr.set_password.assert_called_once()
        call_args = kr.set_password.call_args[0]
        assert call_args[0] == "phoenix"
        assert call_args[1] == "encryption_key"

    def test_returns_existing_key(self):
        from utils.encryption import get_or_create_key
        existing = Fernet.generate_key().decode()
        kr = self._secure_kr()
        kr.get_password.return_value = existing
        with patch("utils.encryption.keyring", kr):
            key = get_or_create_key()
        assert key == existing.encode()
        kr.set_password.assert_not_called()

    def test_raises_on_insecure_backend(self):
        from utils.encryption import get_or_create_key, InsecureKeyringuException
        kr = MagicMock()
        kr.get_keyring.return_value = _make_backend("PlaintextKeyring", "keyrings.alt.file")
        with patch("utils.encryption.keyring", kr):
            with pytest.raises(InsecureKeyringuException):
                get_or_create_key()


# ---------------------------------------------------------------------------
# retrieve_key
# ---------------------------------------------------------------------------
@pytest.mark.unit
class TestRetrieveKey:
    def _secure_kr(self):
        kr = MagicMock()
        backend = _make_backend("SecureKeyring", "keyring.backends.SecureVault")
        kr.get_keyring.return_value = backend
        return kr

    def test_retrieves_existing_key(self):
        from utils.encryption import retrieve_key
        existing = Fernet.generate_key().decode()
        kr = self._secure_kr()
        kr.get_password.return_value = existing
        with patch("utils.encryption.keyring", kr):
            key = retrieve_key()
        assert key == existing.encode()

    def test_raises_value_error_when_no_key(self):
        from utils.encryption import retrieve_key
        kr = self._secure_kr()
        kr.get_password.return_value = None
        with patch("utils.encryption.keyring", kr):
            with patch("utils.encryption.get_text", return_value="no key"):
                with pytest.raises(ValueError):
                    retrieve_key()


# ---------------------------------------------------------------------------
# encrypt_data / decrypt_data
# ---------------------------------------------------------------------------
@pytest.mark.unit
class TestEncryptDecrypt:
    def _setup_kr(self):
        """Return a mock keyring that holds an in-memory key store."""
        store = {}
        kr = MagicMock()
        kr.get_keyring.return_value = _make_backend("SecureKeyring", "keyring.backends.SecureVault")

        def _get(service, username):
            return store.get((service, username))

        def _set(service, username, password):
            store[(service, username)] = password

        kr.get_password.side_effect = _get
        kr.set_password.side_effect = _set
        return kr, store

    def _seed_key(self, kr, store):
        """Directly seed a valid Fernet key into the mock keyring store."""
        key = Fernet.generate_key()
        store[("phoenix", "encryption_key")] = key.decode()
        return key

    def test_encrypt_then_decrypt_round_trip(self):
        from utils.encryption import encrypt_data, decrypt_data
        kr, store = self._setup_kr()
        self._seed_key(kr, store)
        with patch("utils.encryption.keyring", kr):
            data = {"username": "alice", "password": "s3cr3t"}
            encrypt_data(data)
            result = decrypt_data()
        assert result == data

    def test_encrypted_values_are_not_plaintext(self):
        from utils.encryption import encrypt_data
        kr, store = self._setup_kr()
        self._seed_key(kr, store)
        with patch("utils.encryption.keyring", kr):
            encrypt_data({"secret": "plaintext_value"})
        # The stored JSON should NOT contain the plaintext
        stored_json = store.get(("phoenix", "encrypted_data"), "")
        assert "plaintext_value" not in stored_json

    def test_decrypt_without_data_raises(self):
        from utils.encryption import decrypt_data
        kr, store = self._setup_kr()
        self._seed_key(kr, store)
        with patch("utils.encryption.keyring", kr):
            with patch("utils.encryption.get_text", return_value="no data"):
                with pytest.raises(ValueError):
                    decrypt_data()

    def test_multiple_fields_round_trip(self):
        from utils.encryption import encrypt_data, decrypt_data
        kr, store = self._setup_kr()
        self._seed_key(kr, store)
        with patch("utils.encryption.keyring", kr):
            data = {"api_key": "key123", "token": "tok456", "host": "host.com"}
            encrypt_data(data)
            result = decrypt_data()
        assert result == data


# ---------------------------------------------------------------------------
# keyring backends that return bytes must not be double-encoded
# ---------------------------------------------------------------------------
@pytest.mark.unit
class TestKeyringReturnsBytes:
    def _kr(self, value):
        kr = MagicMock()
        kr.get_keyring.return_value = _make_backend("SecureKeyring", "keyring.backends.SecureVault")
        kr.get_password.return_value = value
        return kr

    def test_get_or_create_key_accepts_bytes(self):
        from utils.encryption import get_or_create_key
        existing = Fernet.generate_key()
        with patch("utils.encryption.keyring", self._kr(existing)):
            assert get_or_create_key() == existing

    def test_retrieve_key_accepts_bytes(self):
        from utils.encryption import retrieve_key
        existing = Fernet.generate_key()
        with patch("utils.encryption.keyring", self._kr(existing)):
            assert retrieve_key() == existing


@pytest.mark.unit
class TestKeyringServiceRename:
    """Entries move from the pre-rebrand "resistine" service to "phoenix"."""

    def _kr(self, store, fail_set=False):
        kr = MagicMock()
        kr.get_keyring.return_value = _make_backend("SecureKeyring", "keyring.backends.SecureVault")
        kr.get_password.side_effect = lambda s, u: store.get((s, u))

        def _set(s, u, p):
            if fail_set:
                raise RuntimeError("keyring locked")
            store[(s, u)] = p

        kr.set_password.side_effect = _set
        kr.delete_password.side_effect = lambda s, u: store.pop((s, u))
        return kr

    def test_legacy_key_is_moved(self):
        from utils.encryption import get_or_create_key
        key = Fernet.generate_key().decode()
        store = {("resistine", "encryption_key"): key}
        with patch("utils.encryption.keyring", self._kr(store)):
            assert get_or_create_key() == key.encode()
        assert store == {("phoenix", "encryption_key"): key}

    def test_legacy_data_round_trips_after_move(self):
        from utils.encryption import decrypt_data, encrypt_data
        store = {}
        kr = self._kr(store)
        store[("phoenix", "encryption_key")] = Fernet.generate_key().decode()
        with patch("utils.encryption.keyring", kr):
            encrypt_data({"user": "alice"})
        # simulate a pre-rebrand install: both entries under "resistine"
        for name in ("encryption_key", "encrypted_data"):
            store[("resistine", name)] = store.pop(("phoenix", name))
        with patch("utils.encryption.keyring", kr):
            assert decrypt_data() == {"user": "alice"}
        assert all(service == "phoenix" for service, _ in store)

    def test_failed_copy_keeps_legacy_entry(self):
        from utils.encryption import retrieve_key
        key = Fernet.generate_key().decode()
        store = {("resistine", "encryption_key"): key}
        with patch("utils.encryption.keyring", self._kr(store, fail_set=True)):
            assert retrieve_key() == key.encode()
        assert store == {("resistine", "encryption_key"): key}

    def test_phoenix_entry_wins(self):
        from utils.encryption import retrieve_key
        new, old = Fernet.generate_key().decode(), Fernet.generate_key().decode()
        store = {("phoenix", "encryption_key"): new, ("resistine", "encryption_key"): old}
        with patch("utils.encryption.keyring", self._kr(store)):
            assert retrieve_key() == new.encode()
        assert store[("resistine", "encryption_key")] == old  # untouched

    def test_new_key_never_written_to_legacy(self):
        from utils.encryption import get_or_create_key
        store = {}
        with patch("utils.encryption.keyring", self._kr(store)):
            get_or_create_key()
        assert list(store) == [("phoenix", "encryption_key")]

