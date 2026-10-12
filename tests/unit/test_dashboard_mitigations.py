"""Living mitigations (plugins/dashboard/mitigations.py): server items are
re-validated, checked locally with fixed argv probes, and shown in the
Dashboard's slide-in detail view. No real dpkg/rpm runs."""

import subprocess
from unittest.mock import MagicMock

import pytest

from plugins.dashboard import mitigations as mit

PKG_ITEM = {
    "id": "0123456789abcdef", "kind": "package_update", "severity": "critical", "title": "Update openssl",
    "evidence": {"critical": 2, "high": 1, "cves": ["CVE-2026-0001", "CVE-2026-0002"],
                 "fixed_version": "3.0.13-0ubuntu3.4", "fix_available": True},
    "check": {"type": "package_version_changed", "package": "openssl", "version": "3.0.13-0ubuntu3.1",
              "package_type": "deb"},
}
AGENT_ITEM = {"id": "1111111111111111", "kind": "agent_connection", "severity": "high",
              "title": "Reconnect the Endpoint agent", "evidence": {},
              "check": {"type": "service_running", "service": "endpoint_agent"}}
CIS_ITEM = {"id": "2222222222222222", "kind": "cis_checks", "severity": "medium",
            "title": "Remediate 35 failed CIS/SCA checks", "evidence": {"failed_checks": 35, "checks": 103},
            "check": {"type": "server"}}


def card(*items):
    return {"hostname": "anubisai", "mitigations": [dict(i) for i in items]}


def with_check(**kw):
    item = dict(PKG_ITEM)
    item["check"] = dict(PKG_ITEM["check"], **kw)
    return item


@pytest.fixture(autouse=True)
def fresh_results(monkeypatch):
    monkeypatch.setattr(mit, "_results", {})


# --------------------------------------------------------------------------- validation

@pytest.mark.unit
class TestValidate:
    def test_good_items(self):
        items = mit.items_of(card(PKG_ITEM, AGENT_ITEM, CIS_ITEM))
        assert [i["kind"] for i in items] == ["package_update", "agent_connection", "cis_checks"]

    @pytest.mark.parametrize("pkg", ["openssl; id", "-oFoo", "$(id)", "a b", "openssl\n", "", "x" * 200])
    def test_hostile_package_names_are_dropped(self, pkg):
        assert mit.items_of(card(with_check(package=pkg))) == []

    @pytest.mark.parametrize("ver", ["1;id", "-1", "1.0\n", ""])
    def test_hostile_versions_are_dropped(self, ver):
        assert mit.items_of(card(with_check(version=ver))) == []

    @pytest.mark.parametrize("change", [
        {"kind": "run"}, {"severity": "x"}, {"id": "ABC"},
        {"check": {"type": "shell", "cmd": "id"}},
        {"check": {"type": "service_running", "service": "sshd"}},
    ])
    def test_unknown_shapes_are_dropped(self, change):
        assert mit.items_of(card(dict(PKG_ITEM, **change))) == []

    def test_unknown_package_type_cannot_be_probed(self):
        assert mit.items_of(card(with_check(package_type="msi")))[0]["check"]["package_type"] == ""

    def test_evidence_is_retyped(self):
        item = dict(PKG_ITEM, title="Update\x00 openssl\n", evidence={
            "critical": "x", "cves": ["CVE-2026-1", "<b>"], "fixed_version": "1;id"})
        out = mit.items_of(card(item))[0]
        assert out["title"] == "Update openssl"
        assert out["evidence"]["critical"] == 0 and out["evidence"]["cves"] == ["CVE-2026-1"]
        assert out["evidence"]["fixed_version"] is None

    def test_not_a_list(self):
        assert mit.items_of({"mitigations": "nope"}) == [] and mit.items_of(None) == []


# --------------------------------------------------------------------------- probes

def completed(rc=0, out="", err=""):
    return subprocess.CompletedProcess([], rc, out, err)


@pytest.fixture
def linux(monkeypatch):
    calls = []
    answers = []
    monkeypatch.setattr(mit.platform, "system", lambda: "Linux")
    monkeypatch.setattr(mit.shutil, "which", lambda name: f"/usr/bin/{name}")

    def run(argv):
        calls.append(argv)
        a = answers.pop(0)
        return a

    monkeypatch.setattr(mit, "_run", run)
    return calls, answers


@pytest.mark.unit
class TestPackageProbe:
    def test_deb_still_vulnerable(self, linux):
        calls, answers = linux
        answers.append(completed(0, "ii |3.0.13-0ubuntu3.1\n"))
        assert mit._package_state("openssl", "3.0.13-0ubuntu3.1", "deb") == mit.OPEN
        assert calls == [["/usr/bin/dpkg-query", "-W", "-f=${db:Status-Abbrev}|${Version}\n", "openssl"]]

    def test_deb_upgraded(self, linux):
        linux[1].append(completed(0, "ii |3.0.13-0ubuntu3.4\n"))
        assert mit._package_state("openssl", "3.0.13-0ubuntu3.1", "deb") == mit.FIXED_HERE

    def test_deb_removed_or_config_only(self, linux):
        linux[1].extend([completed(1, "", "dpkg-query: no packages found matching openssl"),
                         completed(0, "rc |3.0.13-0ubuntu3.1\n")])
        assert mit._package_state("openssl", "3.0.13-0ubuntu3.1", "deb") == mit.FIXED_HERE
        assert mit._package_state("openssl", "3.0.13-0ubuntu3.1", "deb") == mit.FIXED_HERE

    def test_deb_multiarch_any_vulnerable_is_open(self, linux):
        linux[1].append(completed(0, "ii |3.0.13-0ubuntu3.4\nii |3.0.13-0ubuntu3.1\n"))
        assert mit._package_state("openssl", "3.0.13-0ubuntu3.1", "deb") == mit.OPEN

    def test_rpm_epoch_zero_matches(self, linux):
        calls, answers = linux
        answers += [completed(0, "0:3.0.7-27.el9\n"), completed(1, "package openssl is not installed\n")]
        assert mit._package_state("openssl", "3.0.7-27.el9", "rpm") == mit.OPEN
        assert calls[0][:3] == ["/usr/bin/rpm", "-q", "--qf"] and calls[0][-1] == "openssl"
        assert mit._package_state("openssl", "3.0.7-27.el9", "rpm") == mit.FIXED_HERE

    def test_errors_and_timeouts_are_unknown(self, linux, monkeypatch):
        linux[1].append(completed(2, "", "dpkg-query: error"))
        assert mit._package_state("openssl", "1", "deb") == mit.UNKNOWN

        linux[1].append(None)  # _run: timeout / OSError
        assert mit._package_state("openssl", "1", "deb") == mit.UNKNOWN

    def test_no_tool_or_other_os_is_unknown(self, monkeypatch):
        monkeypatch.setattr(mit.platform, "system", lambda: "Linux")
        monkeypatch.setattr(mit.shutil, "which", lambda name: None)
        assert mit._package_state("openssl", "1", "deb") == mit.UNKNOWN
        monkeypatch.setattr(mit.platform, "system", lambda: "Darwin")
        assert mit._package_state("openssl", "1", "deb") == mit.UNKNOWN
        monkeypatch.setattr(mit.platform, "system", lambda: "Linux")
        assert mit._package_state("openssl", "1", "") == mit.UNKNOWN


@pytest.mark.unit
def test_run_uses_no_shell_minimal_env_and_a_timeout(monkeypatch):
    seen = {}

    def fake(argv, **kw):
        seen.update(kw, argv=argv)
        return completed(0, "")
    monkeypatch.setattr(mit.subprocess, "run", fake)
    mit._run(["/usr/bin/dpkg-query", "-W", "openssl"])
    assert seen["argv"] == ["/usr/bin/dpkg-query", "-W", "openssl"]
    assert "shell" not in seen and seen["timeout"] == mit.PROBE_TIMEOUT_S
    assert set(seen["env"]) == {"PATH", "LC_ALL"} and seen["env"]["LC_ALL"] == "C"

    def boom(argv, **kw):
        raise subprocess.TimeoutExpired(argv, 5)
    monkeypatch.setattr(mit.subprocess, "run", boom)
    assert mit._run(["/usr/bin/rpm"]) is None


@pytest.mark.unit
class TestCheck:
    def test_states_and_cache(self, linux, monkeypatch):
        from plugins.wazuh import main as wz
        monkeypatch.setattr(wz, "is_agent_running", lambda: False, raising=False)
        calls, answers = linux
        answers.append(completed(0, "ii |3.0.13-0ubuntu3.1\n"))
        c = card(PKG_ITEM, AGENT_ITEM, CIS_ITEM)
        assert [s for _, s in mit.check(c, True)] == [mit.OPEN, mit.OPEN, mit.SERVER]
        assert [s for _, s in mit.check(c, True)] == [mit.OPEN, mit.OPEN, mit.SERVER]
        assert len(calls) == 1  # cached
        answers.append(completed(0, "ii |3.0.13-0ubuntu3.4\n"))
        assert mit.check(c, True, force=True)[0][1] == mit.FIXED_HERE

    def test_other_machines_are_never_probed(self, monkeypatch):
        monkeypatch.setattr(mit, "_probe", lambda item: pytest.fail("must not probe another machine"))
        assert [s for _, s in mit.check(card(PKG_ITEM), False)] == [mit.REMOTE]

    def test_cached_never_probes(self, monkeypatch):
        monkeypatch.setattr(mit, "_probe", lambda item: pytest.fail("cached() must not probe"))
        assert mit.cached(card(PKG_ITEM), True)[0][1] is None


@pytest.mark.unit
def test_summary_and_detail_lines():
    pkg, agent, cis = (mit.validate(i) for i in (PKG_ITEM, AGENT_ITEM, CIS_ITEM))
    assert mit.summary([(pkg, mit.OPEN), (agent, mit.FIXED_HERE), (cis, mit.SERVER)]) == (
        "1 to fix · 1 fixed here · 1 to review")
    assert mit.summary([]) == "Nothing to do"
    assert mit.detail_line(pkg) == ("2 critical · 1 high · CVE-2026-0001, CVE-2026-0002 · "
                                    "installed 3.0.13-0ubuntu3.1, fixed in 3.0.13-0ubuntu3.4")
    assert "35 of 103" in mit.detail_line(cis)


# --------------------------------------------------------------------------- detail view

@pytest.fixture
def qapp():
    import os
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    from PyQt6.QtWidgets import QApplication
    return QApplication.instance() or QApplication([])


@pytest.mark.unit
def test_detail_view_lists_this_and_other_machines(qapp, isolated_settings, monkeypatch):
    from PyQt6.QtWidgets import QLabel
    from plugins.dashboard.main import Plugin

    monkeypatch.setattr(Plugin, "refresh", lambda self: None)
    monkeypatch.setattr(Plugin, "_agent_installed", staticmethod(lambda: True))
    app = MagicMock()
    app.plugins = []
    plugin = Plugin(app)
    mine = dict(card(PKG_ITEM, CIS_ITEM), grade="B", score=86, computed_at="2026-10-12T22:50:31",
                schema="phoenix.posture.v1")
    other = dict(card(PKG_ITEM), hostname="francispc", grade="F", score=57, schema="phoenix.posture.v1")
    plugin._posture_view = ({"status": "ok", "cards": [mine, other], "error": None}, {"anubisai"})
    mit._results[PKG_ITEM["id"]] = (mit.OPEN, 1e12)
    screen = plugin.create_main_screen()  # keep a ref
    plugin._show_posture_detail()
    page, rows, header = plugin._detail
    texts = [w.text() for w in page.findChildren(QLabel) if w.text()]
    assert "THIS MACHINE" in texts and "FRANCISPC · GRADE F" in texts
    assert texts.count("Update openssl") == 2
    assert "To fix" in texts and "Next scan" in texts
    assert header.subtitle.text().startswith("This machine: anubisai · grade B · 86/100")
    plugin._hide_posture_detail()
    assert plugin._detail is None and screen is not None
    plugin.destroy()
