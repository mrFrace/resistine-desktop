"""Vulnerabilities as fixes (plugins/devices/fixes.py): posture package
items grouped by upgrade, and the first-seen ledger."""

from datetime import date

import pytest

from plugins.devices import fixes

TODAY = date(2026, 11, 11)


def pkg(item_id, package, version, fixed="3.0.13", sev="high", critical=0, high=1, cves=(),
        fix_available=True, ptype="deb"):
    return {"id": item_id, "kind": "package_update", "severity": sev, "title": f"Update {package}",
            "evidence": {"critical": critical, "high": high, "cves": list(cves),
                         "fixed_version": fixed, "fix_available": fix_available},
            "check": {"type": "package_version_changed", "package": package, "version": version,
                      "package_type": ptype}}


CIS = {"id": "2222222222222222", "kind": "cis_checks", "severity": "medium", "title": "Fix CIS checks",
       "evidence": {"failed_checks": 35, "checks": 103}, "check": {"type": "server"}}


def card(host, *items, agent=None, at="2026-11-10T06:04:37"):
    return {"hostname": host, "agent_id": agent or host[:3], "computed_at": at, "mitigations": list(items)}


FLEET = [
    card("anubisai",
         pkg("a000000000000001", "openssl", "3.0.11", sev="critical", critical=2, high=1,
             cves=["CVE-2026-0002", "CVE-2026-0001"]),
         pkg("a000000000000002", "curl", "8.5.0", fixed="8.5.0-2", sev="medium", high=0),
         CIS),
    card("DrakeHP",
         pkg("b000000000000001", "openssl", "3.0.2", sev="high", critical=1, high=3,
             cves=["CVE-2026-0001", "CVE-2026-0003"]),
         pkg("b000000000000002", "libtiff6", "4.5.1", fixed=None, fix_available=False, sev="high")),
    card("nas", pkg("c000000000000001", "openssl", "3.0.2", sev="high")),
]
MINE = {"anubisai"}


@pytest.mark.unit
class TestGroup:
    def test_one_row_per_package_fix_worst_first(self):
        gs = fixes.group(FLEET, MINE)
        assert [(g["package"], g["fixed_version"]) for g in gs] == [
            ("openssl", "3.0.13"), ("libtiff6", None), ("curl", "8.5.0-2")]

    def test_merges_machines_without_summing_counts(self):
        g = fixes.group(FLEET, MINE)[0]
        assert g["severity"] == "critical"
        assert (g["critical"], g["high"]) == (2, 3)   # worst machine's, not a sum
        assert g["cves"] == ["CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003"]
        assert g["installed"] == ["3.0.2", "3.0.11"]  # numeric, not text order
        assert [d["hostname"] for d in g["devices"]] == ["anubisai", "DrakeHP", "nas"]
        assert g["devices"][0]["this_machine"] and not g["devices"][1]["this_machine"]

    def test_text(self):
        gs = fixes.group(FLEET, MINE)
        assert fixes.title(gs[0]) == "openssl → 3.0.13"
        assert fixes.hint(gs[0]) == "installed 3.0.2, 3.0.11 · 2 critical · 3 high · on 3 machines, this one too"
        assert fixes.title(gs[1]) == "libtiff6 · no fix released yet"
        assert fixes.hint(gs[1]).endswith("on DrakeHP")
        assert fixes.hint(gs[2]) == "installed 8.5.0 · on this machine"
        assert fixes.summary(gs) == "3 fixes · 2 on this machine"
        assert fixes.summary([]) == "Nothing to fix"

    def test_unknown_fix_is_not_called_no_fix(self):
        g = fixes.group([card("x", pkg("d000000000000001", "zlib", "1.3", fixed=None, fix_available=None))], set())[0]
        assert not g["no_fix"] and fixes.title(g) == "zlib"

    def test_other_items_and_junk(self):
        assert [i["kind"] for _, i in fixes.other_items(FLEET)] == ["cis_checks"]
        bad = card("x", pkg("e000000000000001", "openssl; id", "1"), {"kind": "run"})
        assert fixes.group([bad, None, "junk"], set()) == []
        assert fixes.group("junk", set()) == [] and fixes.other_items(None) == []

    def test_only_the_first_ten_items_count(self):
        many = card("x", *[pkg(f"f0000000000000{i:02d}", f"p{i}", "1") for i in range(14)])
        assert len(fixes.group([many], set())) == 10


@pytest.mark.unit
class TestLedger:
    def test_stamps_the_computed_day_not_today(self):
        led = fixes.update_ledger({}, FLEET, TODAY)
        assert led["since"] == "2026-11-10"
        e = led["items"]["anu|openssl|3.0.11"]
        assert e == {"first": "2026-11-10", "last": "2026-11-10", "severity": "critical"}
        assert "anu|curl|8.5.0" in led["items"] and len(led["items"]) == 5  # CIS not stamped

    def test_new_items_count_as_detections_baseline_does_not(self):
        led = fixes.update_ledger({}, FLEET, TODAY)
        later = card("anubisai", pkg("a000000000000009", "sudo", "1.9.15", sev="high"), agent="anu",
                     at="2026-11-11T06:00:00")
        led = fixes.update_ledger(led, [later], TODAY)
        days = fixes.detections(led, TODAY)
        assert len(days) == fixes.LEDGER_DAYS and days[-1]["day"] == TODAY
        assert days[-1] == {"day": TODAY, "count": 1, "worst": "high"}
        assert sum(d["count"] for d in days) == 1

    def test_a_repeated_card_changes_nothing(self):
        led = fixes.update_ledger({}, FLEET, TODAY)
        assert fixes.update_ledger(led, FLEET, TODAY) == led

    def test_old_entries_expire_and_junk_is_dropped(self):
        led = {"since": "2026-09-01", "items": {
            "x|a|1": {"first": "2026-09-01", "last": "2026-09-30", "severity": "high"},
            "x|b|1": {"first": "2026-10-20", "last": "2026-11-01", "severity": "nope"},
            "x|c|1": {"first": "?", "last": "2026-11-01"}, "x|d|1": None}}
        out = fixes.update_ledger(led, [], TODAY)
        assert out["items"] == {"x|b|1": {"first": "2026-10-20", "last": "2026-11-01", "severity": "low"}}
        assert fixes.update_ledger("junk", None, TODAY) == {"since": None, "items": {}}

    def test_first_seen_text(self):
        led = fixes.update_ledger({}, FLEET, TODAY)
        later = card("anubisai", pkg("a000000000000001", "openssl", "3.0.12"), agent="anu",
                     at="2026-11-11T06:00:00")
        led = fixes.update_ledger(led, [later], TODAY)
        g = fixes.group(FLEET, MINE)[0]
        assert fixes.first_seen(led, g["devices"][0]) == "seen before 10 Nov"
        g2 = fixes.group([later], MINE)[0]
        assert fixes.first_seen(led, g2["devices"][0]) == "first seen 11 Nov"
        assert fixes.first_seen({}, g["devices"][0]) == ""

    def test_record_persists(self, isolated_settings):
        fixes.record(FLEET, TODAY)
        assert fixes.ledger()["since"] == "2026-11-10"
        assert len(fixes.ledger()["items"]) == 5
