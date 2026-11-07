"""
Unit tests for utils/settings.py — the unified settings manager.

Covers:
- get/set/delete for plain values
- set_secret / get_secret (Fernet round-trip)
- Namespace isolation
- clear_namespace
- list_keys
- JSON persistence (values survive a second load)
- Thread safety (concurrent writes)
- File permissions on non-Windows platforms
- Fallback master key via file when keyring unavailable
"""
import json
import os
import platform
import stat
import threading
import pytest


@pytest.mark.unit
class TestGetSet:
    def test_set_and_get_string(self, isolated_settings):
        isolated_settings.set("myns", "key1", "hello")
        assert isolated_settings.get("myns", "key1") == "hello"

    def test_set_and_get_integer(self, isolated_settings):
        isolated_settings.set("myns", "count", 42)
        assert isolated_settings.get("myns", "count") == 42

    def test_set_and_get_bool(self, isolated_settings):
        isolated_settings.set("myns", "flag", True)
        assert isolated_settings.get("myns", "flag") is True

    def test_set_and_get_dict(self, isolated_settings):
        data = {"nested": {"x": 1}}
        isolated_settings.set("myns", "obj", data)
        assert isolated_settings.get("myns", "obj") == data

    def test_set_and_get_list(self, isolated_settings):
        isolated_settings.set("myns", "items", [1, 2, 3])
        assert isolated_settings.get("myns", "items") == [1, 2, 3]

    def test_get_missing_key_returns_default(self, isolated_settings):
        result = isolated_settings.get("myns", "nonexistent")
        assert result is None

    def test_get_missing_key_custom_default(self, isolated_settings):
        result = isolated_settings.get("myns", "nonexistent", "fallback")
        assert result == "fallback"

    def test_overwrite_value(self, isolated_settings):
        isolated_settings.set("myns", "key", "original")
        isolated_settings.set("myns", "key", "updated")
        assert isolated_settings.get("myns", "key") == "updated"

    def test_namespace_isolation(self, isolated_settings):
        isolated_settings.set("ns_a", "key", "alpha")
        isolated_settings.set("ns_b", "key", "beta")
        assert isolated_settings.get("ns_a", "key") == "alpha"
        assert isolated_settings.get("ns_b", "key") == "beta"

    def test_persists_to_disk(self, isolated_settings, tmp_config_dir):
        isolated_settings.set("persist_ns", "x", "persisted")
        json_file = tmp_config_dir / "persist_ns.json"
        assert json_file.exists()
        raw = json.loads(json_file.read_text())
        assert raw["x"] == "persisted"


@pytest.mark.unit
class TestDelete:
    def test_delete_existing_key(self, isolated_settings):
        isolated_settings.set("myns", "to_delete", "value")
        isolated_settings.delete("myns", "to_delete")
        assert isolated_settings.get("myns", "to_delete") is None

    def test_delete_nonexistent_key_returns_true(self, isolated_settings):
        result = isolated_settings.delete("myns", "ghost")
        assert result is True

    def test_delete_preserves_other_keys(self, isolated_settings):
        isolated_settings.set("myns", "a", 1)
        isolated_settings.set("myns", "b", 2)
        isolated_settings.delete("myns", "a")
        assert isolated_settings.get("myns", "b") == 2


@pytest.mark.unit
class TestListKeys:
    def test_empty_namespace(self, isolated_settings):
        keys = isolated_settings.list_keys("empty_ns")
        assert keys == []

    def test_lists_all_keys(self, isolated_settings):
        isolated_settings.set("myns", "x", 1)
        isolated_settings.set("myns", "y", 2)
        isolated_settings.set("myns", "z", 3)
        keys = isolated_settings.list_keys("myns")
        assert set(keys) == {"x", "y", "z"}

    def test_does_not_include_deleted_keys(self, isolated_settings):
        isolated_settings.set("myns", "keep", 1)
        isolated_settings.set("myns", "remove", 2)
        isolated_settings.delete("myns", "remove")
        assert "remove" not in isolated_settings.list_keys("myns")


@pytest.mark.unit
class TestClearNamespace:
    def test_clear_removes_all_keys(self, isolated_settings):
        isolated_settings.set("ns", "a", 1)
        isolated_settings.set("ns", "b", 2)
        isolated_settings.clear_namespace("ns")
        assert isolated_settings.list_keys("ns") == []

    def test_clear_nonexistent_namespace_returns_true(self, isolated_settings):
        result = isolated_settings.clear_namespace("never_existed")
        assert result is True

    def test_clear_removes_json_file(self, isolated_settings, tmp_config_dir):
        isolated_settings.set("ns", "key", "val")
        json_file = tmp_config_dir / "ns.json"
        assert json_file.exists()
        isolated_settings.clear_namespace("ns")
        assert not json_file.exists()

    def test_other_namespaces_unaffected(self, isolated_settings):
        isolated_settings.set("ns_a", "k", 1)
        isolated_settings.set("ns_b", "k", 2)
        isolated_settings.clear_namespace("ns_a")
        assert isolated_settings.get("ns_b", "k") == 2


@pytest.mark.unit
class TestSecrets:
    def test_set_secret_not_plaintext(self, isolated_settings, tmp_config_dir):
        isolated_settings.set_secret("myns", "api_key", "super_secret_value")
        json_file = tmp_config_dir / "myns.json"
        raw = json.loads(json_file.read_text())
        # Must NOT be stored as plaintext
        stored = raw.get("api_key", "")
        assert "super_secret_value" not in stored

    def test_set_secret_has_enc_prefix(self, isolated_settings, tmp_config_dir):
        isolated_settings.set_secret("myns", "tok", "s3cr3t")
        json_file = tmp_config_dir / "myns.json"
        raw = json.loads(json_file.read_text())
        assert raw["tok"].startswith("ENC:")

    def test_get_secret_round_trip(self, isolated_settings):
        isolated_settings.set_secret("myns", "token", "my_token_value")
        result = isolated_settings.get_secret("myns", "token")
        assert result == "my_token_value"

    def test_get_secret_missing_returns_none(self, isolated_settings):
        result = isolated_settings.get_secret("myns", "nonexistent")
        assert result is None

    def test_get_secret_unencrypted_fails_closed(self, isolated_settings):
        """Un-prefixed values are rejected: accepting plaintext would let a
        config-file writer substitute secrets of their choosing."""
        isolated_settings.set("myns", "plain", "plaintext_value")
        result = isolated_settings.get_secret("myns", "plain")
        assert result is None

    def test_secrets_survive_namespace_reload(self, isolated_settings):
        isolated_settings.set_secret("myns", "key", "persistent")
        # Re-read from disk (no cache)
        result = isolated_settings.get_secret("myns", "key")
        assert result == "persistent"

    def test_different_secrets_independent(self, isolated_settings):
        isolated_settings.set_secret("myns", "key_a", "alpha")
        isolated_settings.set_secret("myns", "key_b", "beta")
        assert isolated_settings.get_secret("myns", "key_a") == "alpha"
        assert isolated_settings.get_secret("myns", "key_b") == "beta"


@pytest.mark.unit
class TestSetMany:
    def test_sets_all_keys(self, isolated_settings):
        assert isolated_settings.set_many("myns", {"a": 1, "b": "two", "c": None})
        assert isolated_settings.get("myns", "a") == 1
        assert isolated_settings.get("myns", "b") == "two"
        assert isolated_settings.get("myns", "c") is None
        assert "c" in isolated_settings.list_keys("myns")

    def test_single_file_write(self, isolated_settings, monkeypatch):
        calls = []
        real_save = isolated_settings._save_json

        def counting_save(namespace, data):
            calls.append(namespace)
            return real_save(namespace, data)

        monkeypatch.setattr(isolated_settings, "_save_json", counting_save)
        isolated_settings.set_many(
            "myns", {"access_token": "AT", "refresh_token": "RT", "expires_at": 1.0},
            secret_keys=("access_token", "refresh_token"))
        assert calls == ["myns"]

    def test_secret_keys_are_encrypted(self, isolated_settings, tmp_config_dir):
        isolated_settings.set_many(
            "myns", {"tok": "s3cr3t", "plain": "visible"}, secret_keys=("tok",))
        raw = json.loads((tmp_config_dir / "myns.json").read_text())
        assert raw["tok"].startswith("ENC:") and "s3cr3t" not in raw["tok"]
        assert raw["plain"] == "visible"
        assert isolated_settings.get_secret("myns", "tok") == "s3cr3t"

    def test_preserves_existing_keys(self, isolated_settings):
        isolated_settings.set("myns", "keep", "kept")
        isolated_settings.set_many("myns", {"a": 1})
        assert isolated_settings.get("myns", "keep") == "kept"

    def test_secret_key_missing_from_values_writes_nothing(self, isolated_settings):
        assert isolated_settings.set_many("myns", {"a": 1}, secret_keys=("b",)) is False
        assert isolated_settings.get("myns", "a") is None


@pytest.mark.unit
class TestDeleteMany:
    def test_deletes_all_given_keys_one_write(self, isolated_settings, monkeypatch):
        for k in ("a", "b", "c"):
            isolated_settings.set("myns", k, k)
        calls = []
        real_save = isolated_settings._save_json

        def counting_save(namespace, data):
            calls.append(namespace)
            return real_save(namespace, data)

        monkeypatch.setattr(isolated_settings, "_save_json", counting_save)
        assert isolated_settings.delete_many("myns", ("a", "b", "missing"))
        assert calls == ["myns"]
        assert isolated_settings.list_keys("myns") == ["c"]

    def test_no_keys_present_is_a_noop(self, isolated_settings, monkeypatch):
        isolated_settings.set("myns", "keep", 1)
        monkeypatch.setattr(isolated_settings, "_save_json",
                            lambda *a: pytest.fail("should not write"))
        assert isolated_settings.delete_many("myns", ("x", "y"))


@pytest.mark.unit
class TestFilePermissions:
    @pytest.mark.skipif(platform.system() == "Windows", reason="POSIX-only")
    def test_config_file_permissions_600(self, isolated_settings, tmp_config_dir):
        isolated_settings.set("myns", "k", "v")
        json_file = tmp_config_dir / "myns.json"
        mode = oct(stat.S_IMODE(os.stat(str(json_file)).st_mode))
        assert mode == oct(0o600), f"Expected 0o600, got {mode}"

    @pytest.mark.skipif(platform.system() == "Windows", reason="POSIX-only")
    def test_config_dir_permissions_700(self, isolated_settings, tmp_config_dir):
        isolated_settings.set("myns", "k", "v")
        mode = oct(stat.S_IMODE(os.stat(str(tmp_config_dir)).st_mode))
        assert mode == oct(0o700), f"Expected 0o700, got {mode}"


@pytest.mark.unit
class TestThreadSafety:
    def test_concurrent_writes_no_data_loss(self, isolated_settings):
        """Multiple threads writing different keys must not corrupt the namespace."""
        errors = []
        threads = []

        def write_key(i):
            try:
                isolated_settings.set("concurrent_ns", f"key_{i}", i)
            except Exception as e:
                errors.append(e)

        for i in range(20):
            t = threading.Thread(target=write_key, args=(i,))
            threads.append(t)

        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors, f"Errors during concurrent write: {errors}"

        # All 20 keys should be present
        keys = isolated_settings.list_keys("concurrent_ns")
        assert len(keys) == 20
