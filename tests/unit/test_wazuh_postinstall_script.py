"""
Integration tests for scripts/wazuh-postinstall-darwin.sh.

Drives the real shell script with fake `installer`, `sed`, `security`,
`launchctl`, `agent-auth`, and `wazuh-control` binaries injected via the
override env-vars the script reads (INSTALLER_BIN, AGENT_AUTH_BIN, …).

These tests cover the fix for the install-failure path observed on a real
mac install:

    2026/06/30 09:17:24 agent-auth: ERROR: Duplicate agent name: ...
    Bootstrap failed: 5: Input/output error

The script must:
  - retry agent-auth with a unique suffix on "Duplicate agent name" (≤ 3 tries)
  - on persistent enrollment failure, abort *before* launchctl bootstrap
    so we never throttle the daemon with no client.keys
  - retry launchctl bootstrap on transient I/O errors
"""
import json
import os
import shutil
import stat
import subprocess
import sys
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "wazuh-postinstall-darwin.sh"

# Skip on Windows runners — the script is bash-only.
pytestmark = pytest.mark.skipif(
    sys.platform.startswith("win"), reason="bash script — POSIX only"
)


def _fake_bin(path: Path, body: str) -> None:
    path.write_text("#!/bin/bash\n" + body)
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


@pytest.fixture
def harness(tmp_path, allow_subprocess):  # noqa: ARG001 — opts out of the subprocess block
    """Build a fake environment for one run of the postinstall script."""
    bins = tmp_path / "bin"
    bins.mkdir()

    pkg = tmp_path / "wazuh-agent.pkg"
    pkg.write_text("fake")

    ossec_conf = tmp_path / "ossec.conf"
    ossec_conf.write_text("<agent_name>placeholder</agent_name>\n")

    client_keys = tmp_path / "client.keys"
    key_backup = tmp_path / "key_backup" / "wazuh_client.keys"
    plist = tmp_path / "com.wazuh.agent.plist"
    plist.write_text("<plist/>")
    installer_plist = tmp_path / "com.resistine.wazuh-installer.plist"

    status_file = tmp_path / "install.status"
    log_file = tmp_path / "install.log"

    # Sentinel files the fake binaries write to record calls.
    launchctl_calls = tmp_path / "launchctl.calls"
    agent_auth_calls = tmp_path / "agent_auth.calls"

    # Defaults: every fake succeeds; tests override AGENT_AUTH_BODY /
    # LAUNCHCTL_BODY before invoking the script.
    _fake_bin(bins / "installer", 'exit 0\n')
    _fake_bin(bins / "sed", 'exec /usr/bin/sed "$@"\n')
    _fake_bin(bins / "security", 'exit 0\n')
    _fake_bin(bins / "wazuh-control", 'exit 0\n')

    return {
        "tmp_path": tmp_path,
        "bins": bins,
        "pkg": pkg,
        "ossec_conf": ossec_conf,
        "client_keys": client_keys,
        "key_backup": key_backup,
        "plist": plist,
        "installer_plist": installer_plist,
        "status_file": status_file,
        "log_file": log_file,
        "launchctl_calls": launchctl_calls,
        "agent_auth_calls": agent_auth_calls,
    }


def _install_agent_auth_script(harness, body: str) -> None:
    """Install a fake agent-auth that runs *body*. Body has access to:
      $AGENT_AUTH_CALLS - path to append call records to
      $CLIENT_KEYS      - path where it should write the key on success
      $@                - the argv agent-auth was invoked with
    """
    script = (
        f'AGENT_AUTH_CALLS={shquote(str(harness["agent_auth_calls"]))}\n'
        f'CLIENT_KEYS={shquote(str(harness["client_keys"]))}\n'
        'echo "call: $*" >> "$AGENT_AUTH_CALLS"\n'
        + body
    )
    _fake_bin(harness["bins"] / "agent-auth", script)


def _install_launchctl_script(harness, body: str) -> None:
    script = (
        f'LAUNCHCTL_CALLS={shquote(str(harness["launchctl_calls"]))}\n'
        'echo "call: $*" >> "$LAUNCHCTL_CALLS"\n'
        + body
    )
    _fake_bin(harness["bins"] / "launchctl", script)


def shquote(s: str) -> str:
    return "'" + s.replace("'", "'\\''") + "'"


def _run(harness, extra_env=None):
    env = os.environ.copy()
    env.update({
        "INSTALLER_BIN": str(harness["bins"] / "installer"),
        "SED_BIN": str(harness["bins"] / "sed"),
        "SECURITY_BIN": str(harness["bins"] / "security"),
        "LAUNCHCTL_BIN": str(harness["bins"] / "launchctl"),
        "AGENT_AUTH_BIN": str(harness["bins"] / "agent-auth"),
        "WAZUH_CONTROL_BIN": str(harness["bins"] / "wazuh-control"),
        "OSSEC_CONF_OVERRIDE": str(harness["ossec_conf"]),
        "CLIENT_KEYS_OVERRIDE": str(harness["client_keys"]),
        "KEY_BACKUP_OVERRIDE": str(harness["key_backup"]),
        "PLIST_OVERRIDE": str(harness["plist"]),
        "INSTALLER_PLIST_OVERRIDE": str(harness["installer_plist"]),
        # Keep retries cheap — script otherwise sleeps for many seconds.
        "BOOTSTRAP_SETTLE_SECONDS": "0",
        "BOOTSTRAP_RETRY_BACKOFF_SECONDS": "0",
    })
    if extra_env:
        env.update(extra_env)

    cmd = [
        "bash", str(SCRIPT),
        "--pkg-path", str(harness["pkg"]),
        "--agent-name", "MacBook-AABB",
        "--agent-group", "drake-gmail.com",
        "--manager", "dashboard.resisti.net",
        "--status-file", str(harness["status_file"]),
        "--log-file", str(harness["log_file"]),
    ]
    return subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=60)


def _read_status(harness) -> dict:
    return json.loads(harness["status_file"].read_text())


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

@pytest.mark.unit
class TestSuccessPath:
    def test_first_try_enrollment_succeeds(self, harness):
        _install_agent_auth_script(harness,
            'printf "agent key" > "$CLIENT_KEYS"\nexit 0\n')
        _install_launchctl_script(harness, 'exit 0\n')

        result = _run(harness)
        assert result.returncode == 0, result.stderr
        status = _read_status(harness)
        assert status == {
            "status": "success",
            "step": "done",
            "enrollment": "enrolled",
            "agent_name": "MacBook-AABB",
        }
        # agent-auth invoked once, no retry
        calls = harness["agent_auth_calls"].read_text().strip().splitlines()
        assert len(calls) == 1
        # client.keys was backed up
        assert harness["key_backup"].exists()

    def test_enable_runs_before_bootstrap(self, harness):
        """Regression test: the uninstall path issues `launchctl disable
        system/com.wazuh.agent` to dodge Wazuh's anti-tampering kernel module.
        The disabled flag persists across reboots, so every subsequent
        bootstrap fails with "5: Input/output error" until something re-enables
        the label. The postinstall script MUST issue `launchctl enable` before
        its bootstrap call, or fresh installs after an uninstall stay dead."""
        _install_agent_auth_script(harness,
            'printf "agent key" > "$CLIENT_KEYS"\nexit 0\n')
        _install_launchctl_script(harness, 'exit 0\n')

        result = _run(harness)
        assert result.returncode == 0, result.stderr

        calls = harness["launchctl_calls"].read_text().splitlines()
        enable_idx = next(
            (i for i, c in enumerate(calls)
             if c.startswith("call: enable system/com.wazuh.agent")), None
        )
        bootstrap_idx = next(
            (i for i, c in enumerate(calls) if c.startswith("call: bootstrap")),
            None,
        )
        assert enable_idx is not None, (
            "launchctl enable was never invoked — disabled-after-uninstall "
            f"state will block install. Calls: {calls}"
        )
        assert bootstrap_idx is not None
        assert enable_idx < bootstrap_idx, (
            "launchctl enable must precede the first bootstrap call"
        )


@pytest.mark.unit
class TestDuplicateNameRetry:
    def test_retries_with_suffix_when_first_attempt_duplicates(self, harness):
        # First call: duplicate. Second call: write key, succeed.
        _install_agent_auth_script(harness, '''
n=$(wc -l < "$AGENT_AUTH_CALLS" | tr -d ' ')
if [ "$n" = "1" ]; then
    echo "agent-auth: ERROR: Duplicate agent name: MacBook-AABB. Unable to add agent (from manager)"
    exit 1
fi
printf "agent key" > "$CLIENT_KEYS"
exit 0
''')
        _install_launchctl_script(harness, 'exit 0\n')

        result = _run(harness)
        assert result.returncode == 0, result.stderr
        status = _read_status(harness)
        assert status["status"] == "success"
        assert status["enrollment"] == "enrolled"
        # Suffixed name reported
        assert status["agent_name"].startswith("MacBook-AABB-")
        assert status["agent_name"] != "MacBook-AABB"
        # Exactly two attempts
        calls = harness["agent_auth_calls"].read_text().strip().splitlines()
        assert len(calls) == 2

    def test_all_attempts_duplicate_aborts_before_launchd(self, harness):
        _install_agent_auth_script(harness, '''
echo "agent-auth: ERROR: Duplicate agent name: MacBook-AABB. Unable to add agent (from manager)"
exit 1
''')
        _install_launchctl_script(harness, 'exit 0\n')

        result = _run(harness)
        assert result.returncode == 1
        status = _read_status(harness)
        assert status["status"] == "failed"
        assert status["step"] == "enrollment"
        assert status["error"] == "duplicate_name"
        # The crucial guarantee: launchctl was NEVER invoked, so we don't
        # produce the bogus "Bootstrap failed: 5: Input/output error" we
        # used to see in the field.
        assert not harness["launchctl_calls"].exists()


@pytest.mark.unit
class TestManagerUnreachable:
    @pytest.mark.parametrize("agent_auth_stderr", [
        "Unable to connect to dashboard.resisti.net:1515",
        "Connection refused",
        "Network is unreachable",
    ])
    def test_unreachable_manager_aborts_with_reason(
        self, harness, agent_auth_stderr
    ):
        _install_agent_auth_script(harness, f'''
echo {shquote(agent_auth_stderr)}
exit 1
''')
        _install_launchctl_script(harness, 'exit 0\n')

        result = _run(harness)
        assert result.returncode == 1
        status = _read_status(harness)
        assert status["status"] == "failed"
        assert status["step"] == "enrollment"
        assert status["error"] == "manager_unreachable"
        # No launchd call — agent has no key, so starting it is pointless.
        assert not harness["launchctl_calls"].exists()


@pytest.mark.unit
class TestLaunchdRetry:
    def test_transient_bootstrap_failure_retries_then_succeeds(self, harness):
        _install_agent_auth_script(harness,
            'printf "agent key" > "$CLIENT_KEYS"\nexit 0\n')
        # bootstrap fails the first 2 attempts, succeeds on the 3rd.
        _install_launchctl_script(harness, '''
if [ "$1" = "bootstrap" ]; then
    n=$(grep -c "^call: bootstrap " "$LAUNCHCTL_CALLS" || true)
    if [ "$n" -lt 3 ]; then
        echo "Bootstrap failed: 5: Input/output error" >&2
        exit 1
    fi
fi
exit 0
''')

        result = _run(harness)
        assert result.returncode == 0, result.stderr
        status = _read_status(harness)
        assert status["status"] == "success"
        # We expect at least 3 bootstrap attempts in the call log.
        bootstrap_calls = [
            line for line in harness["launchctl_calls"].read_text().splitlines()
            if line.startswith("call: bootstrap")
        ]
        assert len(bootstrap_calls) >= 3

    def test_persistent_bootstrap_failure_reports_launchd_error(self, harness):
        _install_agent_auth_script(harness,
            'printf "agent key" > "$CLIENT_KEYS"\nexit 0\n')
        _install_launchctl_script(harness, '''
if [ "$1" = "bootstrap" ]; then
    echo "Bootstrap failed: 5: Input/output error" >&2
    exit 1
fi
exit 0
''')

        result = _run(harness)
        assert result.returncode == 1
        status = _read_status(harness)
        assert status["status"] == "failed"
        assert status["step"] == "launchd"
        assert status["error"] == "launchctl bootstrap failed"
        # Detail field should preserve the underlying launchctl output.
        assert "Input/output error" in status.get("detail", "")
