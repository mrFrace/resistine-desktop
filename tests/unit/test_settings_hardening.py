"""Security hardening for utils.settings (ported from drake/repo-cleaning).

- Readers (get/list_keys/clear_namespace) take the module lock like writers.
- Master-key fallback file is written atomically with owner-only permissions,
  and restricted with icacls on Windows.
- Keyring values returned as bytes are not double-encoded.
"""

import os
import platform
import stat
import threading
from unittest.mock import patch

import pytest
from cryptography.fernet import Fernet


def _blocks_while_lock_held(s, fn):
    """Return True if fn() waits for settings._lock held by another thread."""
    holding, release, done = threading.Event(), threading.Event(), threading.Event()

    def holder():
        with s._lock:
            holding.set()
            release.wait(5)

    def caller():
        fn()
        done.set()

    t1 = threading.Thread(target=holder)
    t1.start()
    holding.wait(5)
    t2 = threading.Thread(target=caller)
    t2.start()
    blocked = not done.wait(0.2)
    release.set()
    t1.join(5)
    t2.join(5)
    assert done.is_set()
    return blocked


@pytest.mark.unit
class TestReadersTakeLock:
    def test_get_waits_for_lock(self, isolated_settings):
        s = isolated_settings
        s.set("ns", "k", 1)
        assert _blocks_while_lock_held(s, lambda: s.get("ns", "k"))

    def test_list_keys_waits_for_lock(self, isolated_settings):
        s = isolated_settings
        s.set("ns", "k", 1)
        assert _blocks_while_lock_held(s, lambda: s.list_keys("ns"))

    def test_clear_namespace_waits_for_lock(self, isolated_settings):
        s = isolated_settings
        s.set("ns", "k", 1)
        assert _blocks_while_lock_held(s, lambda: s.clear_namespace("ns"))

    def test_get_reentrant_inside_lock(self, isolated_settings):
        s = isolated_settings
        s.set("ns", "k", "v")
        with s._lock:
            assert s.get("ns", "k") == "v"


@pytest.mark.unit
class TestMasterKeyFallbackWrite:
    def test_writes_key_with_owner_only_mode(self, tmp_config_dir, mock_keyring):
        import utils.settings as s

        key = Fernet.generate_key()
        s._save_master_key_fallback(key)
        key_file = tmp_config_dir / ".master.key"
        assert key_file.read_bytes() == key
        assert not (tmp_config_dir / ".master.key.tmp").exists()
        if platform.system() != "Windows":
            assert stat.S_IMODE(os.stat(key_file).st_mode) == 0o600

    def test_temp_file_created_with_0600_atomically(self, tmp_config_dir, mock_keyring):
        import utils.settings as s

        calls = []
        real_open = os.open

        def spy_open(path, flags, mode=0o777, *a, **kw):
            calls.append((path, flags, mode))
            return real_open(path, flags, mode, *a, **kw)

        with patch("utils.settings.os.open", side_effect=spy_open):
            s._save_master_key_fallback(Fernet.generate_key())
        path, flags, mode = calls[0]
        assert path.endswith(".master.key.tmp")
        assert mode == 0o600
        assert flags & os.O_CREAT and flags & os.O_EXCL

    def test_uses_os_replace(self, tmp_config_dir, mock_keyring):
        import utils.settings as s

        with patch("utils.settings.os.replace", wraps=os.replace) as rep:
            s._save_master_key_fallback(Fernet.generate_key())
        src, dst = rep.call_args[0]
        assert src.endswith(".master.key.tmp") and dst.endswith(".master.key")

    def test_overwrites_existing_and_replaces_stale_temp(self, tmp_config_dir, mock_keyring):
        import utils.settings as s

        (tmp_config_dir / ".master.key").write_bytes(b"old")
        (tmp_config_dir / ".master.key.tmp").write_bytes(b"stale")
        key = Fernet.generate_key()
        s._save_master_key_fallback(key)
        assert (tmp_config_dir / ".master.key").read_bytes() == key
        assert not (tmp_config_dir / ".master.key.tmp").exists()

    def test_failed_write_keeps_old_key_and_cleans_temp(self, tmp_config_dir, mock_keyring):
        import utils.settings as s

        (tmp_config_dir / ".master.key").write_bytes(b"old")
        with patch("utils.settings.os.replace", side_effect=OSError("boom")):
            with pytest.raises(RuntimeError):
                s._save_master_key_fallback(Fernet.generate_key())
        assert (tmp_config_dir / ".master.key").read_bytes() == b"old"
        assert not (tmp_config_dir / ".master.key.tmp").exists()

    def test_round_trip_with_reader(self, tmp_config_dir, mock_keyring):
        import utils.settings as s

        key = Fernet.generate_key()
        s._save_master_key_fallback(key)
        assert s._get_master_key_fallback() == key

    def test_windows_uses_icacls(self, tmp_path, monkeypatch):
        import utils.settings as s

        monkeypatch.setattr(s.platform, "system", lambda: "Windows")
        monkeypatch.setenv("USERNAME", "alice")
        target = tmp_path / "f"
        target.write_bytes(b"x")
        with patch("subprocess.run") as run:
            s._restrict_file_permissions(str(target))
        args = run.call_args[0][0]
        assert args[0] == "icacls" and args[1] == str(target)
        assert "/inheritance:r" in args
        assert "alice:(R,W)" in args

    def test_windows_icacls_failure_is_not_fatal(self, tmp_path, monkeypatch):
        import utils.settings as s

        monkeypatch.setattr(s.platform, "system", lambda: "Windows")
        monkeypatch.setenv("USERNAME", "alice")
        with patch("subprocess.run", side_effect=OSError("no icacls")):
            s._restrict_file_permissions(str(tmp_path / "f"))  # no raise


@pytest.mark.unit
class TestKeyringBytes:
    def test_master_key_bytes_from_keyring(self, tmp_config_dir, mock_keyring):
        import utils.settings as s

        mock_kr, store = mock_keyring
        key = Fernet.generate_key()
        store[(s.MASTER_KEY_SERVICE, s.MASTER_KEY_USERNAME)] = key  # bytes
        assert s._get_master_key() == key
        assert s._get_fernet().decrypt(Fernet(key).encrypt(b"x")) == b"x"

    def test_legacy_master_key_bytes_from_keyring(self, tmp_config_dir, mock_keyring):
        import utils.settings as s

        mock_kr, store = mock_keyring
        key = Fernet.generate_key()
        store[(s.LEGACY_MASTER_KEY_SERVICE, s.MASTER_KEY_USERNAME)] = key
        assert s._get_master_key() == key
        assert store[(s.MASTER_KEY_SERVICE, s.MASTER_KEY_USERNAME)] == key.decode()
