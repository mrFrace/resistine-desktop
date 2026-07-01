"""Tests for scripts/clamav/freshclam-update.sh — the macOS freshclam
auto-update wrapper run by the LaunchDaemon.

The wrapper runs freshclam ONCE and exits; the 4h cadence is owned by
launchd's StartCalendarInterval, not a sleep-loop here. These drive the real bash
script with a PATH-shimmed `freshclam` so the run-once behavior, the
pre-update jitter, and the missing-binary guard are exercised without a real
ClamAV install. macOS/Linux only (needs bash).
"""

import os
import platform
import stat
import subprocess

import pytest

pytestmark = pytest.mark.skipif(
    platform.system() == "Windows",
    reason="freshclam-update.sh is a bash script (macOS/Linux only)",
)

_WRAPPER = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "scripts", "clamav", "freshclam-update.sh",
)


def _write_exec(path, body):
    path.write_text(body)
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


# These tests intentionally run the real bash wrapper, so every test method
# below requests the `allow_subprocess` fixture (conftest blocks real
# subprocess by default — see tests/conftest.py:_block_real_subprocess).


def _run_wrapper(tmp_path, env_extra, *, freshclam_body, conf_exists=True,
                 stamp_age=None):
    """Run the wrapper with FRESHCLAM/CONF/STAMP pointed at tmp shims.

    The wrapper hardcodes absolute /Applications paths, so we run a patched
    copy with FRESHCLAM/CONF/STAMP redefined to our shims. `sleep` is shimmed
    to record its argument and return instantly so the pre-update jitter never
    actually waits. The wrapper runs once and exits on its own.

    stamp_age: if set, seed the last-run stamp file to (now - stamp_age)
    seconds, to exercise the once-per-hour CDN rate-limit guard.
    """
    bindir = tmp_path / "bin"
    bindir.mkdir()

    fake_freshclam = tmp_path / "freshclam-bin"
    _write_exec(fake_freshclam, freshclam_body)

    conf = tmp_path / "freshclam.conf"
    if conf_exists:
        conf.write_text("# test conf\n")

    stamp = tmp_path / "freshclam-last-run"
    if stamp_age is not None:
        import time
        stamp.write_text(str(int(time.time()) - stamp_age))

    sleep_log = tmp_path / "sleep.log"
    # sleep shim: record the requested seconds and return instantly (never
    # actually sleep). The wrapper runs once and exits, so no kill needed.
    _write_exec(
        bindir / "sleep",
        f'#!/bin/bash\necho "$1" >> {sleep_log!s}\nexit 0\n',
    )

    # Patch the three hardcoded constants to point at our shims.
    src = open(_WRAPPER).read()
    src = src.replace(
        'FRESHCLAM="/Applications/Resistine.app/Contents/Helpers/freshclam"',
        f'FRESHCLAM="{fake_freshclam!s}"',
    )
    src = src.replace(
        'CONF="/Library/Application Support/Resistine/clamav/freshclam.conf"',
        f'CONF="{conf!s}"',
    )
    src = src.replace(
        'STAMP="/Library/Application Support/Resistine/clamav/run/freshclam-last-run"',
        f'STAMP="{stamp!s}"',
    )
    patched = tmp_path / "wrapper.sh"
    patched.write_text(src)

    env = os.environ.copy()
    env["PATH"] = f"{bindir!s}:{env['PATH']}"
    env.update(env_extra)

    proc = subprocess.run(
        ["bash", str(patched)],
        env=env, capture_output=True, text=True, timeout=30,
    )
    intervals = (
        [int(x) for x in sleep_log.read_text().split()]
        if sleep_log.exists() else []
    )
    return proc, intervals, stamp


@pytest.mark.unit
class TestFreshclamWrapperRunOnce:
    def test_runs_once_and_exits_zero(self, tmp_path, allow_subprocess):
        # The wrapper performs a single update and exits cleanly — launchd
        # (StartCalendarInterval) owns the cadence, so there is no loop here.
        proc, _, _ = _run_wrapper(
            tmp_path,
            {"RESISTINE_FRESHCLAM_INTERVAL": "1"},
            freshclam_body='#!/bin/bash\nexit 0\n',
        )
        assert proc.returncode == 0
        assert "freshclam update OK" in proc.stdout
        # Exactly one update attempt — no loop, so only one OK line.
        assert proc.stdout.count("freshclam update OK") == 1

    def test_invokes_freshclam_once_with_config_file(self, tmp_path, allow_subprocess):
        # Must call freshclam by absolute path WITH the conf, exactly once,
        # never a bare `freshclam`.
        count = tmp_path / "count"
        marker = tmp_path / "ran"
        proc, _, _ = _run_wrapper(
            tmp_path,
            {"RESISTINE_FRESHCLAM_INTERVAL": "1"},
            freshclam_body=(
                f'#!/bin/bash\necho "$@" > {marker!s}\necho x >> {count!s}\nexit 0\n'
            ),
        )
        assert marker.exists(), f"freshclam never invoked; stdout={proc.stdout}"
        assert "--config-file=" in marker.read_text()
        assert count.read_text().count("x") == 1, "freshclam called more than once"

    def test_jitter_skipped_in_test_mode(self, tmp_path, allow_subprocess):
        # With RESISTINE_FRESHCLAM_INTERVAL set (test mode), the pre-update
        # jitter sleep is skipped entirely — nothing recorded.
        _, intervals, _ = _run_wrapper(
            tmp_path,
            {"RESISTINE_FRESHCLAM_INTERVAL": "1"},
            freshclam_body='#!/bin/bash\nexit 0\n',
        )
        assert intervals == [], f"jitter should be skipped in test mode; got {intervals}"

    def test_jitter_present_and_bounded_in_production(self, tmp_path, allow_subprocess):
        # No override → exactly one pre-update jitter sleep in [0, 60).
        _, intervals, _ = _run_wrapper(
            tmp_path, {},
            freshclam_body='#!/bin/bash\nexit 0\n',
        )
        assert len(intervals) == 1, f"expected one jitter sleep; got {intervals}"
        assert 0 <= intervals[0] < 60

    def test_exits_zero_on_freshclam_failure(self, tmp_path, allow_subprocess):
        # A non-zero freshclam exit must still exit 0 (a hiccup is not a
        # crash); launchd retries on the next interval. A non-zero exit would
        # invite throttling/backoff.
        proc, _, _ = _run_wrapper(
            tmp_path,
            {"RESISTINE_FRESHCLAM_INTERVAL": "1"},
            freshclam_body='#!/bin/bash\nexit 47\n',
        )
        assert proc.returncode == 0
        assert "FAILED" in proc.stdout

    def test_stamps_last_run_before_invoking_freshclam(self, tmp_path, allow_subprocess):
        # The attempt must be recorded so the once-per-hour guard can see it.
        proc, _, stamp = _run_wrapper(
            tmp_path,
            {"RESISTINE_FRESHCLAM_INTERVAL": "1"},
            freshclam_body='#!/bin/bash\nexit 0\n',
        )
        assert proc.returncode == 0
        assert stamp.exists(), "last-run stamp not written"
        assert int(stamp.read_text().strip()) > 0


@pytest.mark.unit
class TestFreshclamWrapperRateLimit:
    """Guards against ClamAV's CDN 'once per hour' rule (429/cool-down)."""

    def test_skips_when_last_run_under_one_hour_ago(self, tmp_path, allow_subprocess):
        # Stamp says we ran 10 min ago → must skip without touching freshclam.
        marker = tmp_path / "ran"
        proc, _, _ = _run_wrapper(
            tmp_path, {},  # production mode (guard active)
            freshclam_body=f'#!/bin/bash\necho ran > {marker!s}\nexit 0\n',
            stamp_age=600,
        )
        assert proc.returncode == 0
        assert not marker.exists(), "freshclam ran despite <1h since last run"
        assert "skipping" in proc.stdout.lower()

    def test_runs_when_last_run_over_one_hour_ago(self, tmp_path, allow_subprocess):
        # Stamp says we ran 2h ago → guard passes, freshclam runs.
        marker = tmp_path / "ran"
        proc, _, _ = _run_wrapper(
            tmp_path, {},
            freshclam_body=f'#!/bin/bash\necho ran > {marker!s}\nexit 0\n',
            stamp_age=7200,
        )
        assert proc.returncode == 0
        assert marker.exists(), "freshclam should run when >1h since last run"
        assert "freshclam update OK" in proc.stdout

    def test_rate_limit_bypassed_in_test_mode(self, tmp_path, allow_subprocess):
        # Even a fresh stamp (1 min ago) must NOT block when the test override
        # is set — testing needs "run now".
        marker = tmp_path / "ran"
        proc, _, _ = _run_wrapper(
            tmp_path,
            {"RESISTINE_FRESHCLAM_INTERVAL": "1"},
            freshclam_body=f'#!/bin/bash\necho ran > {marker!s}\nexit 0\n',
            stamp_age=60,
        )
        assert marker.exists(), "test mode must bypass the rate-limit guard"


@pytest.mark.unit
class TestFreshclamWrapperGuard:
    def test_missing_conf_exits_nonzero_without_running(self, tmp_path, allow_subprocess):
        # No conf → guard branch: log + exit non-zero so launchd retries next
        # interval. Never invokes freshclam, never sleeps.
        marker = tmp_path / "ran"
        proc, intervals, _ = _run_wrapper(
            tmp_path,
            {"RESISTINE_FRESHCLAM_INTERVAL": "1"},
            freshclam_body=f'#!/bin/bash\necho ran > {marker!s}\nexit 0\n',
            conf_exists=False,
        )
        assert proc.returncode == 1
        assert not marker.exists(), "freshclam must not run when conf is missing"
        assert intervals == [], f"guard must not sleep; got {intervals}"
        assert "missing" in proc.stdout.lower()
