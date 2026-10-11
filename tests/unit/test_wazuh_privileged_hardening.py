"""
Security tests for the Wazuh privileged-execution hardening.

Ports of the March security fixes (drake/repo-cleaning 92fa9e6, 3d4491f):
- macOS: osascript/AppleScript quoting + shell quoting of every interpolated value
- macOS: /tmp/wazuh_envs is never written unprivileged; root stages it atomically
- Windows: PowerShell single-quote escaping (_ps_escape_path) + -File execution
- Linux: package download has an explicit TLS context and a timeout

No privileged command is ever executed: osascript / powershell / pkexec are
mocked. The only real processes are plain `sh` invocations that exercise the
quoting / staging logic against throwaway paths under tmp_path.
"""
import os
import re
import shutil
import stat
import subprocess
import sys
from unittest.mock import MagicMock, patch

import pytest

MALICIOUS = [
    "x'; touch PWNED; echo '",
    'x" & (do shell script "touch PWNED") & "',
    "x`touch PWNED`",
    "x$(touch PWNED)",
    "x\\\"; touch PWNED; \\",
    "x\n touch PWNED",
    "O\u2019Brien'; touch PWNED; '",
]


# ===========================================================================
# helpers
# ===========================================================================
def _parse_applescript_literal(src):
    """Parse an AppleScript "..." literal at the start of src.

    Returns (value, rest). Only \\\\ and \\" are escapes that matter for
    termination; anything else is copied verbatim.
    """
    assert src[0] == '"'
    out, i = [], 1
    while i < len(src):
        c = src[i]
        if c == "\\":
            out.append(src[i + 1])
            i += 2
            continue
        if c == '"':
            return "".join(out), src[i + 1:]
        out.append(c)
        i += 1
    raise AssertionError("unterminated AppleScript literal")


def _decode_osascript(argv):
    """Return the shell script embedded in an osascript admin argv."""
    assert argv[0] == "osascript" and argv[1] == "-e"
    prefix = "do shell script "
    stmt = argv[2]
    assert stmt.startswith(prefix)
    value, rest = _parse_applescript_literal(stmt[len(prefix):])
    # Nothing may follow the literal except the privileges clause.
    assert rest == " with administrator privileges"
    return value


_PS_Q = "'\u2018\u2019\u201a\u201b"
_PS_LITERAL_RE = re.compile(f"[{_PS_Q}](?:[^{_PS_Q}]|[{_PS_Q}]{{2}})*[{_PS_Q}]")


def _ps_code_outside_literals(cmd):
    """Return the PowerShell text with every single-quoted literal removed."""
    return _PS_LITERAL_RE.sub("<LIT>", cmd)


def _parse_ps_literal(src):
    """Parse a PowerShell single-quoted literal at the start of src."""
    assert src[0] in _PS_Q
    out, i = [], 1
    while i < len(src):
        c = src[i]
        if c in _PS_Q:
            if i + 1 < len(src) and src[i + 1] in _PS_Q:
                out.append(c)
                i += 2
                continue
            return "".join(out), src[i + 1:]
        out.append(c)
        i += 1
    raise AssertionError("unterminated PowerShell literal")


needs_posix_sh = pytest.mark.skipif(
    sys.platform == "win32" or shutil.which("sh") is None, reason="needs POSIX sh"
)


# ===========================================================================
# macOS: AppleScript + shell quoting
# ===========================================================================
@pytest.mark.unit
@pytest.mark.security
class TestDarwinAppleScriptQuoting:
    @pytest.mark.parametrize("payload", MALICIOUS)
    def test_applescript_literal_roundtrips(self, payload):
        from plugins.wazuh.agent.wazuh_functions_darwin import _applescript_string

        value, rest = _parse_applescript_literal(_applescript_string(payload))
        assert value == payload
        assert rest == ""

    @pytest.mark.parametrize("payload", MALICIOUS)
    def test_run_privileged_passes_script_verbatim(self, payload):
        """The shell receives exactly the script — no AppleScript breakout,
        and $()/backticks are preserved for legit shell use (escaping them,
        as the March patch did, would break KC=$(security ...))."""
        from plugins.wazuh.agent import wazuh_functions_darwin as wf

        script = f'KC=$(echo hi); echo "$KC" {payload}'
        with patch.object(wf.subprocess, "run",
                          return_value=MagicMock(returncode=0, stdout="", stderr="")) as run:
            wf._run_privileged(script)
        assert _decode_osascript(run.call_args[0][0]) == script

    @needs_posix_sh
    @pytest.mark.parametrize("payload", MALICIOUS)
    def test_sh_quote_is_inert(self, payload, tmp_path, allow_subprocess):
        from plugins.wazuh.agent.wazuh_functions_darwin import _sh

        out = subprocess.run(["sh", "-c", f"printf %s {_sh(payload)}"],
                             cwd=tmp_path, capture_output=True, text=True, timeout=10)
        assert out.stdout == payload
        assert not (tmp_path / "PWNED").exists()

    def test_remove_agent_quotes_malicious_backup_path(self):
        from plugins.wazuh.agent import wazuh_functions_darwin as wf

        evil = "/Users/x'; touch /PWNED; '/keys"
        with patch.object(wf, "_KEY_BACKUP", evil), \
                patch.object(wf, "is_agent_installed", return_value=True), \
                patch.object(wf, "_run_privileged", return_value=(True, "")) as rp:
            wf.remove_agent()
        script = rp.call_args[0][0]
        assert wf._sh(evil) in script
        assert f"'{evil}'" not in script

    def test_reenroll_rejects_unsafe_name(self):
        from plugins.wazuh.agent import wazuh_functions_darwin as wf

        with patch.object(wf, "is_agent_installed", return_value=True), \
                patch.object(wf, "get_agent_name", return_value="host|s|x|;touch PWN"), \
                patch.object(wf, "get_agent_group", return_value="grp"), \
                patch.object(wf, "_run_privileged") as rp:
            ok, _ = wf.reenroll_agent()
        assert ok is False
        rp.assert_not_called()

    def test_launch_postinstall_quotes_and_stages_env(self, tmp_path):
        from plugins.wazuh.agent import wazuh_functions_darwin as wf

        evil_pkg = str(tmp_path / 'a"b$(touch PWNED)`x`.pkg')
        proc = MagicMock(pid=1)
        proc.wait.side_effect = subprocess.TimeoutExpired("osascript", 2)
        with patch("shutil.copy2"), patch("os.chmod"), \
                patch.object(wf.subprocess, "Popen", return_value=proc) as popen:
            ok, _ = wf._launch_postinstall(evil_pkg, "host-1", "grp", False)
        assert ok is True
        shell = _decode_osascript(popen.call_args[0][0])
        # pkg path is one shell word
        assert f"--pkg-path {__import__('shlex').quote(evil_pkg)}" in shell
        # env staged as root via mktemp+rename, removed afterwards
        assert "/usr/bin/mktemp /tmp/wazuh_envs." in shell
        assert "/bin/mv -f \"$T\" '/tmp/wazuh_envs'" in shell
        assert shell.rstrip().endswith("/bin/rm -f '/tmp/wazuh_envs'; exit $RC")
        assert "WAZUH_AGENT_GROUP=" in shell


# ===========================================================================
# macOS: env file handling
# ===========================================================================
@pytest.mark.unit
@pytest.mark.security
class TestDarwinEnvFile:
    def test_config_no_longer_uses_fixed_tmp_path(self):
        from plugins.wazuh import config

        assert config.WAZUH_ENV_FILE != "/tmp/wazuh_envs"

    @pytest.mark.skipif(sys.platform == "win32", reason="POSIX modes")
    def test_default_env_file_in_private_dir(self, tmp_path):
        from plugins.wazuh import config
        from plugins.wazuh.agent import wazuh_functions_darwin as wf

        with patch.object(config, "_private_env_file", None), \
                patch.object(config, "WAZUH_ENV_FILE", None), \
                patch.object(wf, "WAZUH_ENV_FILE", None), \
                patch("tempfile.tempdir", str(tmp_path)):
            assert wf.write_env_file("host-1", "grp") is True
            path = config.get_wazuh_env_file()
        d = os.path.dirname(path)
        assert os.path.dirname(d) == str(tmp_path)
        assert stat.S_IMODE(os.stat(d).st_mode) == 0o700
        assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
        assert "WAZUH_AGENT_NAME='host-1'" in open(path).read()

    @pytest.mark.skipif(not hasattr(os, "O_NOFOLLOW"), reason="needs O_NOFOLLOW")
    def test_write_refuses_symlink(self, tmp_path):
        from plugins.wazuh.agent import wazuh_functions_darwin as wf

        victim = tmp_path / "victim"
        victim.write_text("original")
        link = tmp_path / "wazuh_envs"
        link.symlink_to(victim)
        with patch.object(wf, "WAZUH_ENV_FILE", str(link)):
            assert wf.write_env_file("host-1", "grp") is False
        assert victim.read_text() == "original"

    def test_write_rejects_unsafe_identity(self, tmp_path):
        from plugins.wazuh.agent import wazuh_functions_darwin as wf

        with patch.object(wf, "WAZUH_ENV_FILE", str(tmp_path / "e")):
            assert wf.write_env_file("x'; touch PWNED; '", "grp") is False
        assert not (tmp_path / "e").exists()

    @pytest.mark.skipif(not sys.platform.startswith("linux"), reason="GNU stat/mktemp")
    @pytest.mark.parametrize("planted", ["symlink", "file", "none"])
    def test_stage_snippet_replaces_planted_target(self, tmp_path, planted, allow_subprocess):
        """Run the root staging snippet (paths rewritten to tmp_path, uid
        check rewritten to our uid) and verify it never follows a symlink."""
        from plugins.wazuh.agent import wazuh_functions_darwin as wf

        target = tmp_path / "wazuh_envs"
        victim = tmp_path / "victim"
        victim.write_text("original")
        if planted == "symlink":
            target.symlink_to(victim)
        elif planted == "file":
            target.write_text("WAZUH_MANAGER='evil'\n")
        content = "WAZUH_MANAGER='m'\nX='$(touch PWNED)`touch PWNED`'\n"
        snippet = (
            wf._stage_pkg_env_cmd(content)
            .replace("/usr/bin/mktemp /tmp/wazuh_envs.", f"mktemp {tmp_path}/wazuh_envs.")
            .replace("'/tmp/wazuh_envs'", wf._sh(str(target)))
            .replace("/usr/bin/stat -f %u", "stat -c %u")
            .replace('" = 0 ]', f'" = {os.getuid()} ]')
            .replace("/bin/", "")
        )
        rc = subprocess.run(["sh", "-c", f"if {snippet}; then echo OK; fi"],
                            cwd=tmp_path, capture_output=True, text=True, timeout=10)
        assert rc.stdout.strip() == "OK", rc.stderr
        assert not target.is_symlink()
        assert target.read_text() == content
        assert victim.read_text() == "original"
        assert not (tmp_path / "PWNED").exists()
        assert stat.S_IMODE(os.stat(target).st_mode) == 0o600


# ===========================================================================
# Windows: PowerShell quoting + -File execution
# ===========================================================================
@pytest.fixture
def _win_consts():
    with patch("subprocess.CREATE_NO_WINDOW", 0x08000000, create=True):
        yield


@pytest.mark.unit
@pytest.mark.security
@pytest.mark.usefixtures("_win_consts")
class TestWindowsPowerShellQuoting:
    def test_ps_escape_path_doubles_quotes(self):
        from plugins.wazuh.agent.wazuh_functions_windows import _ps_escape_path

        assert _ps_escape_path("C:\\Users\\O'Brien") == "C:\\Users\\O''Brien"
        assert _ps_escape_path("a\u2019b") == "a\u2019\u2019b"
        assert _ps_escape_path("$x `y` \"z\"") == "$x `y` \"z\""

    @pytest.mark.parametrize("payload", MALICIOUS)
    def test_ps_quote_roundtrips(self, payload):
        from plugins.wazuh.agent.wazuh_functions_windows import _ps_quote

        value, rest = _parse_ps_literal(_ps_quote(payload))
        assert value == payload
        assert rest == ""

    @pytest.mark.parametrize("payload", MALICIOUS)
    def test_download_file_escapes_url_and_dest(self, payload):
        from plugins.wazuh.agent import wazuh_functions_windows as wf

        with patch.object(wf.subprocess, "run",
                          return_value=MagicMock(returncode=1, stdout="", stderr="")) as run:
            wf._download_file(f"https://x/{payload}", f"C:\\T\\{payload}.msi")
        ps = run.call_args[0][0][-1]
        assert "PWNED" not in _ps_code_outside_literals(ps)
        uri, _ = _parse_ps_literal(ps.split("-Uri ", 1)[1])
        assert uri == f"https://x/{payload}"

    @pytest.mark.parametrize("payload", MALICIOUS)
    def test_install_script_escapes_all_paths(self, payload):
        from plugins.wazuh.agent import wazuh_functions_windows as wf

        sysmon = {"dir": f"C:\\T\\{payload}", "exe": f"C:\\T\\{payload}\\Sysmon64.exe",
                  "config": f"C:\\T\\{payload}\\cfg.xml"}
        with patch.object(wf, "_KEY_BACKUP", f"C:\\Users\\{payload}\\keys"):
            script = wf._build_install_script(
                sysmon, f"C:\\T\\{payload}\\w.msi", "host-1", "grp",
                f"C:\\Users\\{payload}")
        assert "PWNED" not in _ps_code_outside_literals(script)

    @pytest.mark.parametrize("payload", MALICIOUS)
    def test_agent_scripts_escape_key_backup(self, payload):
        from plugins.wazuh.agent import wazuh_functions_windows as wf

        evil = f"C:\\Users\\{payload}\\keys"
        with patch.object(wf, "_KEY_BACKUP", evil), \
                patch.object(wf, "is_agent_installed", return_value=True), \
                patch.object(wf, "needs_reenrollment", return_value=False), \
                patch.object(wf.os.path, "exists", return_value=True), \
                patch.object(wf, "get_agent_name", return_value="host-1"), \
                patch.object(wf, "get_agent_group", return_value="grp"), \
                patch.object(wf, "_run_privileged", return_value=(True, "")) as rp:
            wf.remove_agent()
            wf.remove_agent(wipe_keys=True)
            wf.restore_client_key_if_needed()
            wf.reenroll_agent()
        assert rp.call_count == 4
        for c in rp.call_args_list:
            assert "PWNED" not in _ps_code_outside_literals(c[0][0])

    def test_run_privileged_admin_uses_file_not_command(self):
        from plugins.wazuh.agent import wazuh_functions_windows as wf

        seen = {}

        def fake_run(argv, **kw):
            seen["argv"] = argv
            path = argv[argv.index("-File") + 1]
            with open(path, encoding="utf-8-sig") as f:
                seen["body"] = f.read()
            return MagicMock(returncode=0, stdout="ok", stderr="")

        cmd = "Write-Output 'x''; $(evil)'"
        with patch.object(wf, "_is_admin", return_value=True), \
                patch.object(wf.subprocess, "run", side_effect=fake_run):
            ok, out = wf._run_privileged(cmd)
        assert ok is True and out == "ok"
        assert "-Command" not in seen["argv"]
        assert seen["body"] == cmd
        assert not os.path.exists(seen["argv"][-1])  # temp script cleaned up

    def test_run_privileged_elevation_escapes_temp_paths(self, tmp_path):
        """A profile dir containing an apostrophe must not break the launcher."""
        from plugins.wazuh.agent import wazuh_functions_windows as wf

        tmp_dir = tmp_path / "O'Brien; touch PWNED"
        tmp_dir.mkdir()
        seen = {}

        def fake_run(argv, **kw):
            seen["argv"] = argv
            launcher = argv[-1]
            # Script path argument is a single, well-formed literal.
            lit, _ = _parse_ps_literal(launcher.split("'-File',", 1)[1])
            script_path = lit.strip('"')
            body = open(script_path, encoding="utf-8-sig").read()
            seen["body"] = body
            result_lit = body.split("-FilePath ", 1)[1]
            result_path, _ = _parse_ps_literal(result_lit)
            with open(result_path, "w", encoding="utf-8") as f:
                f.write("SUCCESS")
            return MagicMock(returncode=0, stdout="", stderr="")

        with patch.object(wf, "_is_admin", return_value=False), \
                patch("tempfile.tempdir", str(tmp_dir)), \
                patch.object(wf.subprocess, "run", side_effect=fake_run):
            ok, out = wf._run_privileged("Write-Output hi")
        assert ok is True and "SUCCESS" in out
        launcher = seen["argv"][-1]
        assert "PWNED" not in _ps_code_outside_literals(launcher)
        assert "PWNED" not in _ps_code_outside_literals(seen["body"])
        assert list(tmp_dir.iterdir()) == []  # script + result cleaned up


# ===========================================================================
# Linux: download has explicit TLS context + timeout
# ===========================================================================
@pytest.mark.unit
@pytest.mark.security
class TestLinuxDownload:
    def test_download_uses_timeout_and_tls_context(self, tmp_path):
        import ssl

        from plugins.wazuh.agent import wazuh_functions_linux as wf

        resp = MagicMock()
        resp.__enter__.return_value = resp
        resp.read.side_effect = [b"pkg", b""]
        with patch.object(wf, "get_package_url", return_value="https://x/wazuh.deb"), \
                patch.object(wf.tempfile, "mkdtemp", return_value=str(tmp_path)), \
                patch.object(wf.urllib.request, "urlopen", return_value=resp) as uo:
            path = wf.download_package()
        assert path == str(tmp_path / "wazuh.deb")
        kw = uo.call_args.kwargs
        assert kw["timeout"] > 0
        ctx = kw["context"]
        assert isinstance(ctx, ssl.SSLContext)
        assert ctx.verify_mode == ssl.CERT_REQUIRED and ctx.check_hostname
