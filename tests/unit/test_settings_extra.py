"""Extra tests for utils.settings — error handling and fallback paths.

Supplements test_settings.py with coverage for:
- _load_json with corrupt JSON
- _save_json write failures
- _get_master_key keyring failure → fallback file
- _get_master_key_fallback file read
- _get_fernet fallback chain
- set_secret encryption failure
- get_secret decryption failure
- clear_namespace error handling
"""

from unittest.mock import patch

import pytest


# ---------------------------------------------------------------------------
# _load_json with corrupt JSON
# ---------------------------------------------------------------------------

@pytest.mark.unit
class TestLoadJsonErrors:
    def test_corrupt_json_returns_empty_dict(self, tmp_config_dir, mock_keyring):
        import utils.settings as s

        # Write corrupt JSON to a namespace file
        corrupt_path = tmp_config_dir / "bad_ns.json"
        corrupt_path.write_text("{invalid json!!!")

        result = s._load_json("bad_ns")
        assert result == {}

    def test_empty_file_returns_empty_dict(self, tmp_config_dir, mock_keyring):
        import utils.settings as s

        empty_path = tmp_config_dir / "empty_ns.json"
        empty_path.write_text("")

        result = s._load_json("empty_ns")
        assert result == {}

    def test_nonexistent_namespace_returns_empty_dict(self, tmp_config_dir, mock_keyring):
        import utils.settings as s

        result = s._load_json("never_existed")
        assert result == {}


# ---------------------------------------------------------------------------
# _save_json write failure
# ---------------------------------------------------------------------------

@pytest.mark.unit
class TestSaveJsonErrors:
    def test_save_to_readonly_returns_false(self, tmp_config_dir, mock_keyring):
        import utils.settings as s

        # Create a read-only directory
        ro_dir = tmp_config_dir / "readonly"
        ro_dir.mkdir()

        with patch.object(s, "get_config_dir", return_value=str(ro_dir)):
            # Make the file path point to a non-writable location
            with patch("builtins.open", side_effect=OSError("read-only fs")):
                result = s._save_json("test_ns", {"key": "val"})
        assert result is False


# ---------------------------------------------------------------------------
# Master key fallback
# ---------------------------------------------------------------------------

@pytest.mark.unit
class TestMasterKeyFallback:
    def test_keyring_get_fails_generates_new_key(self, isolated_settings, mock_keyring):
        import utils.settings as s

        mock_kr, store = mock_keyring
        # Make keyring.get_password raise
        mock_kr.get_password.side_effect = Exception("keyring broken")
        # Make set_password work (so key gets saved)
        mock_kr.set_password.side_effect = lambda svc, usr, val: store.__setitem__((svc, usr), val)

        key = s._get_master_key()
        assert key is not None
        assert len(key) > 0

    def test_keyring_set_also_fails_uses_file_fallback(self, tmp_config_dir, mock_keyring):
        import utils.settings as s

        mock_kr, _ = mock_keyring
        mock_kr.get_password.side_effect = Exception("get broken")
        mock_kr.set_password.side_effect = Exception("set broken")

        key = s._get_master_key()
        assert key is not None

        # Fallback file should exist
        key_file = tmp_config_dir / ".master.key"
        assert key_file.exists()
        assert key_file.read_bytes() == key

    def test_get_master_key_fallback_reads_file(self, tmp_config_dir, mock_keyring):
        import utils.settings as s

        key_file = tmp_config_dir / ".master.key"
        key_file.write_bytes(b"test-key-data")

        result = s._get_master_key_fallback()
        assert result == b"test-key-data"

    def test_get_master_key_fallback_no_file(self, tmp_config_dir, mock_keyring):
        import utils.settings as s

        result = s._get_master_key_fallback()
        assert result is None

    def test_get_master_key_fallback_read_error(self, tmp_config_dir, mock_keyring):
        import utils.settings as s

        key_file = tmp_config_dir / ".master.key"
        key_file.write_bytes(b"data")

        with patch("builtins.open", side_effect=OSError("disk error")):
            result = s._get_master_key_fallback()
        assert result is None


# ---------------------------------------------------------------------------
# _get_fernet fallback chain
# ---------------------------------------------------------------------------

@pytest.mark.unit
class TestGetFernetFallback:
    def test_fernet_from_keyring(self, isolated_settings, mock_keyring):
        import utils.settings as s
        from cryptography.fernet import Fernet

        # Store a valid key in mock keyring
        valid_key = Fernet.generate_key()
        mock_kr, store = mock_keyring
        store[("phoenix-master-key", "master-key")] = valid_key.decode()

        f = s._get_fernet()
        # Should be able to encrypt/decrypt
        token = f.encrypt(b"test")
        assert f.decrypt(token) == b"test"

    def test_fernet_from_fallback_file(self, tmp_config_dir, mock_keyring):
        import utils.settings as s
        from cryptography.fernet import Fernet

        mock_kr, _ = mock_keyring
        mock_kr.get_password.side_effect = Exception("keyring broken")
        mock_kr.set_password.side_effect = lambda *a: None

        # Write a valid key to fallback file
        valid_key = Fernet.generate_key()
        key_file = tmp_config_dir / ".master.key"
        key_file.write_bytes(valid_key)

        f = s._get_fernet()
        token = f.encrypt(b"data")
        assert f.decrypt(token) == b"data"


# ---------------------------------------------------------------------------
# set_secret / get_secret error paths
# ---------------------------------------------------------------------------

@pytest.mark.unit
class TestSecretErrors:
    def test_set_secret_encryption_failure(self, isolated_settings):
        import utils.settings as s

        with patch.object(s, "_get_fernet", side_effect=RuntimeError("no key")):
            result = s.set_secret("ns", "key", "value")
        assert result is False

    def test_get_secret_decryption_failure(self, isolated_settings):
        import utils.settings as s

        # Write an invalid encrypted value
        s.set("ns", "key", "ENC:invalid-encrypted-data")

        result = s.get_secret("ns", "key")
        assert result is None

    def test_get_secret_non_string_value(self, isolated_settings):
        import utils.settings as s

        s.set("ns", "key", 42)  # Not a string
        result = s.get_secret("ns", "key")
        assert result is None

    def test_get_secret_none_value(self, isolated_settings):
        import utils.settings as s

        result = s.get_secret("ns", "nonexistent")
        assert result is None

    def test_get_secret_unencrypted_legacy(self, isolated_settings):
        import utils.settings as s

        s.set("ns", "key", "plaintext-value")
        result = s.get_secret("ns", "key")
        assert result == "plaintext-value"


# ---------------------------------------------------------------------------
# clear_namespace error handling
# ---------------------------------------------------------------------------

@pytest.mark.unit
class TestClearNamespaceErrors:
    def test_clear_nonexistent_namespace(self, isolated_settings):
        import utils.settings as s

        result = s.clear_namespace("nonexistent")
        assert result is True  # No file to delete = success

    def test_clear_permission_error(self, isolated_settings):
        import utils.settings as s

        s.set("locked_ns", "key", "value")

        with patch("os.remove", side_effect=OSError("permission denied")):
            result = s.clear_namespace("locked_ns")
        assert result is False


# ---------------------------------------------------------------------------
# get_config_dir platform branches
# ---------------------------------------------------------------------------

@pytest.mark.unit
class TestGetConfigDir:
    def test_darwin(self, monkeypatch):
        import utils.settings as s

        monkeypatch.setattr("platform.system", lambda: "Darwin")
        path = s.get_config_dir()
        assert "Library/Application Support/Phoenix" in path

    def test_windows(self, monkeypatch):
        import utils.settings as s

        monkeypatch.setattr("platform.system", lambda: "Windows")
        monkeypatch.setenv("APPDATA", "/fake/appdata")
        path = s.get_config_dir()
        assert "Phoenix" in path

    def test_linux(self, monkeypatch):
        import utils.settings as s

        monkeypatch.setattr("platform.system", lambda: "Linux")
        path = s.get_config_dir()
        assert ".config/phoenix" in path


# ---------------------------------------------------------------------------
# Resistine -> Phoenix rebrand migration
# ---------------------------------------------------------------------------

@pytest.mark.unit
class TestLegacyMasterKey:
    def test_legacy_key_reused_and_copied(self, tmp_config_dir, mock_keyring):
        import utils.settings as s
        from cryptography.fernet import Fernet

        _, store = mock_keyring
        legacy = Fernet.generate_key().decode()
        store[("resistine-master-key", "master-key")] = legacy

        assert s._get_master_key() == legacy.encode()
        assert store[("phoenix-master-key", "master-key")] == legacy
        # Left in place so a rollback to a pre-rebrand build still decrypts.
        assert store[("resistine-master-key", "master-key")] == legacy

    def test_secret_written_before_rebrand_still_decrypts(self, tmp_config_dir, mock_keyring):
        import utils.settings as s
        from cryptography.fernet import Fernet

        _, store = mock_keyring
        legacy = Fernet.generate_key()
        store[("resistine-master-key", "master-key")] = legacy.decode()
        token = Fernet(legacy).encrypt(b"wg-private-key").decode()
        (tmp_config_dir / "vpn.json").write_text(
            '{"private_key": "%s%s"}' % (s.ENCRYPTED_PREFIX, token))

        assert s.get_secret("vpn", "private_key") == "wg-private-key"


@pytest.mark.unit
class TestMigrateLegacyConfigDir:
    @pytest.fixture()
    def dirs(self, tmp_path, monkeypatch):
        import utils.settings as s

        new, old = tmp_path / "Phoenix", tmp_path / "Resistine"
        monkeypatch.setattr(s, "get_config_dir", lambda: str(new))
        monkeypatch.setattr(s, "get_legacy_config_dir", lambda: str(old))
        return s, new, old

    def test_moves_everything_and_removes_old_dir(self, dirs):
        s, new, old = dirs
        (old / "wireguard").mkdir(parents=True)
        (old / "auth.json").write_text("{}")
        (old / "wireguard" / "resistine.conf").write_text("[Interface]\n")

        s.migrate_legacy_config_dir()

        assert (new / "auth.json").read_text() == "{}"
        assert (new / "wireguard" / "resistine.conf").exists()
        assert (new / ".migrated-from-resistine").exists()
        assert not old.exists()

    def test_never_overwrites_existing_entries(self, dirs):
        s, new, old = dirs
        old.mkdir()
        new.mkdir()
        (old / "ui.json").write_text("old")
        (old / "auth.json").write_text("{}")
        (new / "ui.json").write_text("new")

        s.migrate_legacy_config_dir()

        assert (new / "ui.json").read_text() == "new"
        assert (new / "auth.json").exists()
        assert (old / "ui.json").read_text() == "old"  # left behind, not lost

    def test_runs_once(self, dirs):
        s, new, old = dirs
        old.mkdir()
        s.migrate_legacy_config_dir()
        (old).mkdir(exist_ok=True)
        (old / "late.json").write_text("{}")

        s.migrate_legacy_config_dir()

        assert not (new / "late.json").exists()

    def test_no_legacy_dir_is_a_noop(self, dirs):
        s, new, _ = dirs
        s.migrate_legacy_config_dir()
        assert not new.exists()

    def test_get_config_dir_has_no_side_effects(self, tmp_path, monkeypatch):
        import utils.settings as s

        monkeypatch.setattr("platform.system", lambda: "Linux")
        monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
        (tmp_path / "resistine").mkdir()

        assert s.get_config_dir() == str(tmp_path / "phoenix")
        assert (tmp_path / "resistine").exists()
        assert not (tmp_path / "phoenix").exists()
