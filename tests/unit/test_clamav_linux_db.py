"""ClamAV on Linux: where the CVD cert and the signature databases are read from."""

import os
from unittest.mock import MagicMock

import pytest


@pytest.mark.unit
def test_linux_certs_dir_finds_arch_etc_location(monkeypatch):
    """Arch's clamav package ships the CVD cert in /etc/clamav/certs."""
    from plugins.antivirus import clamav_platform_linux as linux

    monkeypatch.delenv("CVD_CERTS_DIR", raising=False)
    monkeypatch.setattr(linux, "find_binary", lambda name: None)
    monkeypatch.setattr(linux.os.path, "isfile",
                        lambda p: p == "/etc/clamav/certs/clamav.crt")
    assert linux.find_certs_dir() == "/etc/clamav/certs"


@pytest.mark.unit
class TestFresherDbDirWins:
    """freshclam updates the user dir when the system dir isn't writable;
    reading must then use the user dir, not the stale system copy."""

    def _dirs(self, tmp_path, monkeypatch, sys_age, user_age):
        import time as _time

        from plugins.antivirus import clamav_common

        sys_db, user_db = tmp_path / "sys", tmp_path / "user"
        for d, age in ((sys_db, sys_age), (user_db, user_age)):
            d.mkdir()
            if age is not None:
                f = d / "daily.cvd"
                f.write_bytes(b"x")
                t = _time.time() - age
                os.utime(f, (t, t))
        plat = MagicMock()
        plat.system_db_dir.return_value = str(sys_db)
        monkeypatch.setattr(clamav_common, "_get_platform", lambda: plat)
        monkeypatch.setattr(clamav_common, "_DB_DIR", str(user_db))
        return clamav_common, str(sys_db), str(user_db)

    def test_newer_user_dir_wins(self, tmp_path, monkeypatch):
        c, _, user_db = self._dirs(tmp_path, monkeypatch, sys_age=8 * 86400, user_age=60)
        assert c._effective_db_dir() == user_db

    def test_newer_system_dir_wins(self, tmp_path, monkeypatch):
        c, sys_db, _ = self._dirs(tmp_path, monkeypatch, sys_age=60, user_age=8 * 86400)
        assert c._effective_db_dir() == sys_db

    def test_system_dir_alone(self, tmp_path, monkeypatch):
        c, sys_db, _ = self._dirs(tmp_path, monkeypatch, sys_age=60, user_age=None)
        assert c._effective_db_dir() == sys_db

    def test_running_clamd_on_old_dir_is_restarted(self, tmp_path, monkeypatch):
        c, sys_db, user_db = self._dirs(tmp_path, monkeypatch, sys_age=8 * 86400, user_age=60)
        conf = tmp_path / "clamd.conf"
        conf.write_text(f"LocalSocket /x\nDatabaseDirectory {sys_db}\n")
        monkeypatch.setattr(c, "_CLAMD_CONF", str(conf))
        monkeypatch.setattr(c, "is_clamd_running", lambda: True)
        stop, start = MagicMock(), MagicMock()
        monkeypatch.setattr(c, "stop_clamd", stop)
        monkeypatch.setattr(c, "start_clamd", start)
        c._restart_clamd_if_db_moved()
        stop.assert_called_once()
        start.assert_called_once()

    def test_running_clamd_on_current_dir_is_left_alone(self, tmp_path, monkeypatch):
        c, _, user_db = self._dirs(tmp_path, monkeypatch, sys_age=8 * 86400, user_age=60)
        conf = tmp_path / "clamd.conf"
        conf.write_text(f"DatabaseDirectory {user_db}\n")
        monkeypatch.setattr(c, "_CLAMD_CONF", str(conf))
        monkeypatch.setattr(c, "is_clamd_running", lambda: True)
        stop = MagicMock()
        monkeypatch.setattr(c, "stop_clamd", stop)
        c._restart_clamd_if_db_moved()
        stop.assert_not_called()


@pytest.mark.unit
@pytest.mark.slow  # runs the generated shell (against a temp file only)
class TestClamonaccConfig:
    """clamonacc refuses to start unless an exclude UID/user is configured."""

    @pytest.fixture(autouse=True)
    def _real_sh(self, allow_subprocess):
        pass

    def _run(self, tmp_path, monkeypatch, body):
        import subprocess

        from plugins.antivirus import clamav_platform_linux as linux

        monkeypatch.setattr(linux, "_is_fedora_like", lambda: False)
        conf = tmp_path / "clamd.conf"
        conf.write_text(body)
        # Only the temp config is touched: sed -i and the unit lookup are stubbed.
        script = (linux._prepare_config_script()
                  .replace("/etc/clamav/clamd.conf", str(conf))
                  .replace("sed -i", "true")
                  .replace("systemctl cat clamav-clamonacc", "true"))
        for _ in range(2):  # re-running must not add lines twice
            subprocess.run(["sh", "-c", script], capture_output=True)
        return conf.read_text()

    def test_stock_config_gets_exclude_and_include(self, tmp_path, monkeypatch):
        out = self._run(tmp_path, monkeypatch, "User clamav\n")
        assert out.count("OnAccessExcludeUname clamav\n") == 1
        assert out.count("OnAccessIncludePath /home\n") == 1

    def test_admin_settings_are_kept(self, tmp_path, monkeypatch):
        out = self._run(tmp_path, monkeypatch,
                        "User clamscan\nOnAccessIncludePath /srv\nOnAccessExcludeRootUID yes\n")
        assert "OnAccessIncludePath /home" not in out
        assert "OnAccessExcludeUname" not in out

    def test_odd_user_value_is_not_interpolated(self, tmp_path, monkeypatch):
        out = self._run(tmp_path, monkeypatch, "User $(id)\n")
        assert "OnAccessExcludeUname clamav\n" in out


@pytest.mark.unit
def test_activation_creates_the_clamonacc_quarantine_dir():
    """Arch's unit runs clamonacc --move=/root/quarantine, which must exist."""
    from plugins.antivirus import clamav_platform_linux as linux

    script = linux._prepare_config_script()
    assert "systemctl cat clamav-clamonacc" in script
    assert "--move=" in script and 'mkdir -p "$d" && chmod 700 "$d"' in script
