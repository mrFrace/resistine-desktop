"""
Unit tests for plugins/wazuh/agent/enrollment.py and its use by the installers.

- request(): POST /v1/agent/enroll through the provisioning client; the key
  line must match the answer's agent; any failure -> None (agent-auth fallback)
- the private key file: 0600 in a fresh 0700 directory, removed by discard()
- Linux / Windows install scripts write the API key instead of running
  agent-auth, and fall back to agent-auth without it

The HTTP client and the privileged runners are mocked.
"""
import base64
import os
import stat
from unittest.mock import MagicMock, patch

import pytest

from plugins.wazuh.agent import enrollment

LINE = "012 laptop-1a2b any " + "ab" * 32


def _resp(status=200, body=None):
    r = MagicMock()
    r.status_code = status
    r.json.return_value = body
    return r


def _answer(line=LINE, agent_id="012", name="laptop-1a2b"):
    return {"agent_id": agent_id, "agent_name": name, "group": "u_alice",
            "manager": "dashboard.phoenix.exposed:1517",
            "key": base64.b64encode(line.encode()).decode()}


@pytest.fixture
def api():
    with patch("plugins.vpn.provisioning._authorized_request") as req:
        yield req


@pytest.mark.unit
@pytest.mark.security
class TestRequest:
    def test_success(self, api):
        api.return_value = _resp(200, _answer())
        e = enrollment.request("laptop-1a2b")
        try:
            assert (e.agent_id, e.agent_name, e.group, e.key_line) == \
                ("012", "laptop-1a2b", "u_alice", LINE)
            assert api.call_args.args == ("POST", "/v1/agent/enroll")
            assert api.call_args.kwargs["json"] == {"name": "laptop-1a2b"}
            with open(e.key_file) as f:
                assert f.read() == LINE + "\n"
            if os.name != "nt":  # POSIX modes; Windows ACLs are not comparable
                assert stat.S_IMODE(os.stat(e.key_file).st_mode) == 0o600
                assert stat.S_IMODE(os.stat(os.path.dirname(e.key_file)).st_mode) == 0o700
        finally:
            enrollment.discard(e)
        assert not os.path.exists(os.path.dirname(e.key_file))

    def test_server_keeps_earlier_name(self, api):
        line = "007 old-name any " + "cd" * 32
        api.return_value = _resp(200, _answer(line, "007", "old-name"))
        e = enrollment.request("laptop-1a2b-123456")
        enrollment.discard(e)
        assert e.agent_name == "old-name"

    @pytest.mark.parametrize("body", [
        _answer(agent_id="013"),                                   # key for another id
        _answer(name="other"),                                     # key for another name
        _answer(line="012 laptop-1a2b any short"),                 # not a key
        _answer(line=LINE + "\n013 x any " + "ab" * 32),           # two lines
        {**_answer(), "key": "%%%"},                               # not base64
        {"detail": "x"},                                           # wrong shape
        {**_answer(), "group": "u_a'; rm -rf /"},                  # unsafe group
    ])
    def test_bad_answers(self, api, body):
        api.return_value = _resp(200, body)
        assert enrollment.request("laptop-1a2b") is None

    @pytest.mark.parametrize("status", [401, 409, 422, 503])
    def test_http_errors_fall_back(self, api, status):
        api.return_value = _resp(status, {"detail": "nope"})
        assert enrollment.request("laptop-1a2b") is None

    def test_not_signed_in_falls_back(self, api):
        from plugins.vpn.provisioning import ProvisioningError
        api.side_effect = ProvisioningError("You're not signed in to Phoenix.")
        assert enrollment.request("laptop-1a2b") is None

    @pytest.mark.parametrize("name", ["", "a b", "x" * 65, "a;b"])
    def test_bad_name_no_call(self, api, name):
        assert enrollment.request(name) is None
        api.assert_not_called()


@pytest.mark.unit
class TestEnrolledGroup:
    """The server's group (u_<localpart>) replaces the email-derived one."""

    @pytest.fixture(autouse=True)
    def _signed_in(self):
        from utils import settings
        settings.set("auth", "user_id", "@alice:phoenix.exposed")
        settings.set("auth", "email", "alice@example.com")

    def test_none_before_enrollment(self):
        assert enrollment.enrolled_group() is None

    @pytest.mark.parametrize("user_id,group", [
        ("@alice:phoenix.exposed", "u_alice"),
        ("@Alice.B:phoenix.exposed", "u_alice.b"),        # lowercased, like the server
        ("@a=b/c:phoenix.exposed", "u_a_b_c"),           # chars Wazuh groups can't hold
    ])
    def test_user_group_like_the_server(self, user_id, group):
        from utils import settings
        settings.set("auth", "user_id", user_id)
        assert enrollment.user_group() == group == enrollment.agent_group()

    def test_no_email_group(self):
        from utils import settings
        settings.set("auth", "user_id", "")
        assert enrollment.agent_group() == "default"   # not alice-example.com

    def test_remembered_after_enrollment(self, api):
        api.return_value = _resp(200, _answer())
        enrollment.discard(enrollment.request("laptop-1a2b"))
        assert enrollment.enrolled_group() == "u_alice"

    def test_not_for_another_account(self, api):
        from utils import settings
        api.return_value = _resp(200, _answer())
        enrollment.discard(enrollment.request("laptop-1a2b"))
        settings.set("auth", "user_id", "@bob:phoenix.exposed")
        assert enrollment.enrolled_group() is None

    def test_failed_enrollment_keeps_previous(self, api):
        api.return_value = _resp(200, _answer())
        enrollment.discard(enrollment.request("laptop-1a2b"))
        api.return_value = _resp(503, {"detail": "down"})
        assert enrollment.request("laptop-1a2b") is None
        assert enrollment.enrolled_group() == "u_alice"

    @pytest.mark.parametrize("module", ["wazuh_functions_linux", "wazuh_functions_darwin",
                                        "wazuh_functions_windows"])
    def test_get_agent_group_prefers_it(self, api, module):
        import importlib
        mod = importlib.import_module(f"plugins.wazuh.agent.{module}")
        assert mod.get_agent_group() == "u_alice"           # derived before enrolling
        api.return_value = _resp(200, {**_answer(), "group": "u_alice2"})
        enrollment.discard(enrollment.request("laptop-1a2b"))
        assert mod.get_agent_group() == "u_alice2"          # the server's answer wins


def _enrolled(tmp_path):
    key_file = tmp_path / "client.keys"
    key_file.write_text(LINE + "\n")
    return enrollment.Enrollment("012", "laptop-1a2b", "u_alice", LINE, str(key_file))


@pytest.mark.unit
@pytest.mark.skipif(os.name == "nt", reason="Linux installer path uses os.getuid")
class TestLinuxInstall:
    def _script(self, enrolled, family="deb", pkg="/tmp/p.deb"):
        from plugins.wazuh.agent import wazuh_functions_linux as wl
        with patch.object(wl, "download_package", return_value=pkg), \
                patch.object(wl, "_get_os_info", return_value=family), \
                patch.object(wl, "get_agent_name", return_value="host-uuid"), \
                patch.object(wl, "get_agent_group", return_value="grp"), \
                patch.object(wl.enrollment, "request", return_value=enrolled), \
                patch.object(wl.enrollment, "discard") as discard, \
                patch.object(wl, "is_agent_installed", return_value=True), \
                patch.object(wl, "run_privileged_command", return_value=(True, "")) as run:
            assert wl.full_install() is True
        discard.assert_called_once_with(enrolled)
        return run.call_args.args[0][2]

    def test_api_key_replaces_agent_auth(self, tmp_path):
        e = _enrolled(tmp_path)
        script = self._script(e)
        assert "agent-auth" not in script
        assert e.key_file in script and enrollment.KEY_LINE_PATTERN in script
        assert "WAZUH_AGENT_NAME='laptop-1a2b'" in script  # the server's name
        assert "WAZUH_AGENT_GROUP='u_alice'" in script     # and its group
        assert "<groups>u_alice</groups>" in script and "'grp'" not in script
        assert LINE not in script  # the key itself never goes on a command line

    def test_arch_installs_the_package_with_pacman(self, tmp_path):
        # The Arch package runs the .deb's maintainer scripts, so it gets the
        # same deployment variables (endpoint, name, group) dpkg does.
        script = self._script(_enrolled(tmp_path), "arch", "/tmp/p.pkg.tar.zst")
        assert "WAZUH_MANAGER='dashboard.phoenix.exposed' WAZUH_MANAGER_PORT='1517'" in script
        assert "pacman -U --noconfirm '/tmp/p.pkg.tar.zst'" in script
        assert "<endpoint>dashboard.phoenix.exposed:1517</endpoint>" in script
        assert "bsdtar" not in script and "/var/ossec" not in script

    def test_fallback_agent_auth(self):
        script = self._script(None)
        assert "/bin/agent-auth' -m 'dashboard.phoenix.exposed' -p '1515'" in script
        assert "-A 'host-uuid' -G 'grp'" in script


@pytest.mark.unit
class TestWindowsInstall:
    def test_api_key_replaces_agent_auth(self, tmp_path):
        from plugins.wazuh.agent import wazuh_functions_windows as ww
        e = _enrolled(tmp_path)
        script = ww._build_install_script(None, r"C:\t\p.msi", "laptop-1a2b", "grp", r"C:\b", e)
        assert "agent-auth.exe" not in script
        assert e.key_file in script and enrollment.KEY_LINE_PATTERN in script
        assert LINE not in script
        assert "WAZUH_MANAGER_PORT=1517" in script

    def test_fallback_agent_auth(self):
        from plugins.wazuh.agent import wazuh_functions_windows as ww
        script = ww._build_install_script(None, r"C:\t\p.msi", "host", "grp", r"C:\b")
        assert "agent-auth.exe" in script
        assert "-G 'grp'" in script


@pytest.mark.unit
class TestMsiLog:
    def test_install_script_writes_a_verbose_msi_log(self):
        from plugins.wazuh.agent import wazuh_functions_windows as ww
        script = ww._build_install_script(None, r"C:\t\p.msi", "host", "grp", r"C:\b")
        # Start-Process does not quote -ArgumentList elements, so the paths
        # carry literal double quotes.
        assert r"""'/l*v','"C:\t\p-install.log"'""" in script
        assert r"""'/i','"C:\t\p.msi"'""" in script
        assert "-PassThru" in script and 'MSI_EXIT=' in script

    def test_summary_names_the_exit_code_and_failing_action(self, tmp_path):
        from plugins.wazuh.agent import wazuh_functions_windows as ww
        log = tmp_path / "p-install.log"
        log.write_text(
            "Action start 10:00:01: InstallFiles.\n"
            "Error 1920. Service 'Phoenix' (WazuhSvc) failed to start.\n"
            "Action ended 10:00:02: InstallFinalize. Return value 3.\n"
            "MSI (s) (A0:B4) [10:00:03:000]: MainEngineThread is returning 1603\n",
            encoding="utf-16")
        why = ww.msi_failure_summary(str(log))
        assert why.startswith("msiexec exit code 1603 (the installer hit a fatal error)")
        assert "Error 1920" in why

    def test_summary_is_empty_without_a_log(self, tmp_path):
        from plugins.wazuh.agent import wazuh_functions_windows as ww
        assert ww.msi_failure_summary(str(tmp_path / "missing.log")) == ""

    def test_uninstall_finds_the_phoenix_msi_by_name(self):
        from plugins.wazuh.agent import wazuh_functions_windows as ww
        ps = ww._PS_UNINSTALL_AGENT_MSI
        assert "$_.DisplayName -eq 'Phoenix Agent'" in ps
        assert "'/x', $_.PSChildName" in ps
        assert "Win32_Product" not in ps

    def test_install_clears_a_registration_without_files_first(self):
        from plugins.wazuh.agent import wazuh_functions_windows as ww
        script = ww._build_install_script(None, r"C:\t\p.msi", "host", "grp", r"C:\b")
        assert script.index(ww._PS_UNINSTALL_AGENT_MSI) < script.index("'/i'")


@pytest.mark.unit
@pytest.mark.security
class TestAgentName:
    """enrollment.agent_name_from / install_salt — the shared fallback that
    stops two machines computing the same manager-global bare-hostname name."""

    NAME_RE = __import__("re").compile(r"^[A-Za-z0-9._-]{1,64}$")

    def test_hardware_id_name_is_unchanged_legacy_format(self):
        # Must stay byte-for-byte identical to the old per-platform logic so
        # already-enrolled machines are not orphaned on the manager.
        name = enrollment.agent_name_from(
            "MacBook-Pro.local", "AABBCCDD-1234-5678-90AB-CDEF01234567")
        assert name == "MacBook-Pro.local-CDEF01234567"

    def test_fallback_uses_salt_not_bare_hostname(self):
        name = enrollment.agent_name_from("MacBook-Air", None)
        assert name != "MacBook-Air"
        assert name == f"MacBook-Air-{enrollment.install_salt()}"
        assert self.NAME_RE.match(name)

    def test_salt_is_stable_and_persisted(self):
        first = enrollment.install_salt()
        assert enrollment.install_salt() == first          # same process
        from utils import settings
        assert settings.get("wazuh", "install_salt") == first  # persisted
        # A later "restart" (fresh read) returns the stored value.
        assert enrollment.agent_name_from("host", None) == f"host-{first}"

    def test_two_machines_same_hostname_get_distinct_names(self):
        from utils import settings
        a = enrollment.agent_name_from("DESKTOP-XYZ", None)
        settings.delete("wazuh", "install_salt")   # the other install's config
        b = enrollment.agent_name_from("DESKTOP-XYZ", None)
        assert a != b and a.startswith("DESKTOP-XYZ-") and b.startswith("DESKTOP-XYZ-")

    def test_empty_or_all_special_hostname_falls_back_to_disambiguator(self):
        for host in ("", "!@#$%^&*()"):
            name = enrollment.agent_name_from(host, None)
            assert name == enrollment.install_salt()
            assert self.NAME_RE.match(name)

    def test_long_hostname_trimmed_within_64_keeping_disambiguator(self):
        name = enrollment.agent_name_from("A" * 200, "DEAD-BEEF-CAFE-0001-000000000002")
        assert len(name) <= 64
        assert self.NAME_RE.match(name)
        assert name.endswith("000000000002")  # disambiguator survives the trim

    def test_salt_is_within_name_charset(self):
        assert __import__("re").match(r"^[A-Za-z0-9._-]{1,12}$", enrollment.install_salt())

    @pytest.mark.parametrize("hw", ["----", ".", "-", ""])
    def test_hardware_id_that_strips_to_empty_falls_back_to_salt(self, hw):
        # A truthy-but-degenerate hardware id must NOT yield a name without a
        # disambiguator (bare/colliding) or an empty name — it falls back to the
        # salt, like a missing hardware id does.
        salt = enrollment.install_salt()
        assert enrollment.agent_name_from("host", hw) == f"host-{salt}"
        assert enrollment.agent_name_from("", hw) == salt
        assert self.NAME_RE.match(enrollment.agent_name_from("host", hw))


@pytest.mark.unit
class TestEnrolledForThisSignIn:
    """The enrollment is tied to the Matrix device + account it was made for:
    sign-out deletes the device's agent on the server, and the next sign-in is
    a new device, so the wizard must enroll again."""

    @pytest.fixture(autouse=True)
    def _signed_in(self):
        from utils import settings
        settings.set("auth", "user_id", "@alice:phoenix.exposed")
        settings.set("auth", "device_id", "PHX_AAAAAAAAAAAAAAAA")

    def test_not_before_enrollment(self):
        assert not enrollment.enrolled_for_this_sign_in()

    def test_after_api_enrollment(self, api):
        from utils import settings
        api.return_value = _resp(200, _answer())
        enrollment.discard(enrollment.request("laptop-1a2b"))
        assert enrollment.enrolled_for_this_sign_in()
        assert settings.get("wazuh", "enrolled_agent_id") == "012"

    def test_failed_enrollment_records_nothing(self, api):
        api.return_value = _resp(503, {"detail": "down"})
        assert enrollment.request("laptop-1a2b") is None
        assert not enrollment.enrolled_for_this_sign_in()

    def test_new_device_or_account_needs_enrollment(self):
        from utils import settings
        enrollment.mark_enrolled()
        assert enrollment.enrolled_for_this_sign_in()
        settings.set("auth", "device_id", "PHX_BBBBBBBBBBBBBBBB")
        assert not enrollment.enrolled_for_this_sign_in()
        settings.set("auth", "device_id", "PHX_AAAAAAAAAAAAAAAA")
        settings.set("auth", "user_id", "@bob:phoenix.exposed")
        assert not enrollment.enrolled_for_this_sign_in()

    def test_sign_out_clears_it(self):
        from utils import settings
        enrollment.mark_enrolled()
        settings.clear_namespace("wazuh")   # what logout does
        assert not enrollment.enrolled_for_this_sign_in()

    def test_nothing_to_compare_without_matrix_sign_in(self):
        from utils import settings
        settings.set("auth", "device_id", "")
        assert enrollment.enrolled_for_this_sign_in()
