"""Tests for the Devices page's API client normalisers and table helpers (no Qt)."""

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest

from plugins.devices import api, remote, tables


def _resp(status=200, body=None):
    r = MagicMock()
    r.status_code = status
    r.json.return_value = body
    return r


@pytest.mark.unit
class TestApiGet:
    def test_404_is_not_available(self):
        with patch(
            "plugins.vpn.provisioning._authorized_request", return_value=_resp(404)
        ):
            assert api.fetch_sca() == (None, api.NOT_AVAILABLE)
            assert api.fetch_vulnerabilities_summary() == (None, api.NOT_AVAILABLE)

    def test_ok_and_envelopes(self):
        with patch(
            "plugins.vpn.provisioning._authorized_request",
            return_value=_resp(
                200,
                {"data": {"affected_items": [{"name": "cis", "not_applicable": 3}]}},
            ),
        ):
            items, err = api.fetch_sca()
        assert err is None and items[0]["invalid"] == 3

    def test_inventory_accepts_the_wazuh_native_agent_shape(self):
        # phoenix-provisioning (AR-B7) answers with the manager's /agents
        # projection {id, name, status, ip} in a {data: {affected_items}}
        # envelope; the plugin reads the documented agent_* keys.
        with patch(
            "plugins.vpn.provisioning._authorized_request",
            return_value=_resp(
                200,
                {
                    "data": {
                        "affected_items": [
                            {"id": "029", "name": "DrakeHP", "status": "active", "ip": "10.0.0.5"},
                            {"id": 7, "name": "", "status": "disconnected", "ip": None},
                        ]
                    }
                },
            ),
        ):
            devices, err = api.fetch_inventory_full()
        assert err is None and len(devices) == 2
        assert devices[0]["agent_id"] == "029"
        assert devices[0]["agent_name"] == "DrakeHP"
        assert devices[0]["agent_ip"] == "10.0.0.5"
        assert devices[0]["status"] == "active"
        assert devices[1]["agent_id"] == "7" and not devices[1].get("agent_name")
        agent = tables.shape_inventory_agent(devices[0], None)
        assert agent["basic_info"]["id"] == "029"
        assert agent["basic_info"]["name"] == "DrakeHP"
        assert agent["basic_info"]["ip"] == "10.0.0.5"

    def test_inventory_documented_keys_win_over_aliases(self):
        d = api.normalize_inventory_device(
            {"agent_id": "1", "id": "9", "agent_name": "doc", "name": "alias", "hostname": "h"}
        )
        assert (d["agent_id"], d["agent_name"]) == ("1", "doc")
        d = api.normalize_inventory_device({"id": "2", "hostname": "h"})
        assert (d["agent_id"], d["agent_name"]) == ("2", "h")

    def test_signed_out_is_an_error_string(self):
        from plugins.vpn.provisioning import ProvisioningError

        with patch(
            "plugins.vpn.provisioning._authorized_request",
            side_effect=ProvisioningError("not signed in"),
        ):
            data, err = api.fetch_hotfixes()
        assert data is None and "not signed in" in err

    def test_paths_use_the_v1_me_prefix(self):
        with patch(
            "plugins.vpn.provisioning._authorized_request", return_value=_resp(200, {})
        ) as req:
            api.fetch_device_inventory("029")
        assert req.call_args.args == ("GET", "/v1/me/inventory/029")

    def test_device_vulnerabilities_paginate_and_normalise(self):
        pages = [
            _resp(
                200,
                {
                    "detected_at": "2026-11-01T00:00:00Z",
                    "vulnerabilities": [
                        {
                            "cve": f"CVE-{i}",
                            "severity": "High",
                            "cvss3_score": "7.5",
                            "package": "git",
                            "version": "2.4",
                        }
                        for i in range(2)
                    ],
                },
            ),
            _resp(200, {"vulnerabilities": []}),
        ]
        with patch("plugins.vpn.provisioning._authorized_request", side_effect=pages):
            cves, err = api.fetch_device_vulnerabilities("029", "host", page_size=2)
        assert err is None and [c["id"] for c in cves] == ["CVE-0", "CVE-1"]
        assert cves[0]["severity"] == "high" and cves[0]["cvss_score"] == 7.5
        assert cves[0]["first_detected_at"] == "2026-11-01T00:00:00Z"
        assert cves[0]["agent_name"] == "host" and cves[0]["source"] == "api"

    def test_fan_out_all_404_is_not_available(self):
        with patch(
            "plugins.vpn.provisioning._authorized_request", return_value=_resp(404)
        ):
            data, err = api.fetch_all_vulnerabilities(
                [{"agent_id": "1"}, {"agent_id": "2"}]
            )
        assert data is None and err == api.NOT_AVAILABLE


@pytest.mark.unit
class TestNormalisers:
    def test_level_to_severity(self):
        assert api.level_to_severity(15) == "critical"
        assert api.level_to_severity("12") == "high"
        assert api.level_to_severity(7) == "medium"
        assert api.level_to_severity("informational") == "low"
        assert api.level_to_severity(None) == "low"

    def test_event_from_opensearch_hit(self):
        ev = api.normalize_event(
            {
                "_id": "x1",
                "_source": {
                    "rule": {
                        "level": 12,
                        "id": "100",
                        "description": "d",
                        "mitre": {"id": ["T1"]},
                    },
                    "agent": {"name": "h", "ip": "10.0.0.1"},
                    "timestamp": "2026-11-01T00:00:00Z",
                },
            }
        )
        assert ev["severity"] == "high" and ev["mitre"] == ["T1"] and ev["host"] == "h"

    def test_text_is_cut_and_cleaned(self):
        cve = api.normalize_cve({"cve": "CVE-1\x1b", "description": "x" * 10000})
        assert "\x1b" not in cve["id"] and len(cve["description"]) == 4000


@pytest.mark.unit
class TestStore:
    def test_slots_and_unavailable(self):
        st = remote.RemoteStore(clock=lambda: 1.0)
        got = []
        st.subscribe(got.append)
        st._finish("sca", None, api.NOT_AVAILABLE)
        st._finish("hotfixes", None, api.NOT_AVAILABLE)
        assert st.api_unavailable() and got == ["sca", "hotfixes"]
        st._finish("vulns", [{"id": "CVE-1"}], None)
        assert not st.api_unavailable() and st.slot("vulns").data == [{"id": "CVE-1"}]

    def test_start_is_exclusive(self):
        st = remote.RemoteStore()
        assert st._start("vulns") and not st._start("vulns")

    def test_inventory_fills_name_and_os_from_posture(self):
        import time

        # The inventory endpoint knows {id, status, ip} only; hostname and OS
        # come from the posture cards the Devices screen already holds.
        st = remote.RemoteStore()
        with patch.object(
            api,
            "fetch_inventory_full",
            return_value=([{"agent_id": "029", "status": "active", "agent_ip": "10.0.0.5"}], None),
        ), patch.object(
            api, "fetch_device_inventory", return_value=(None, api.NOT_AVAILABLE)
        ):
            st.kick_inventory([{"agent_id": "029", "agent_name": "DrakeHP", "os": "Windows 11"}])
            deadline = time.monotonic() + 5
            while not st.slot("agents").ready and time.monotonic() < deadline:
                time.sleep(0.02)
        slot = st.slot("agents")
        assert slot.ready and slot.error is None
        bi = slot.data[0]["basic_info"]
        assert bi["name"] == "DrakeHP" and bi["id"] == "029"
        row = tables.inventory_rows(slot.data, [], [])[0]
        assert row["name"] == "DrakeHP" and row["os"] == "Windows 11"
        assert tables.last_seen_text(row) == "Active now"


@pytest.mark.unit
class TestTables:
    def test_filters_and_sort(self):
        vulns = [
            {"id": "CVE-A", "severity": "low", "cvss_score": 3.0, "package_name": "a"},
            {
                "id": "CVE-B",
                "severity": "critical",
                "cvss_score": 9.8,
                "package_name": "b",
            },
            {
                "id": "CVE-C",
                "severity": "high",
                "cvss_score": None,
                "package_name": "c",
            },
        ]
        assert [v["id"] for v in tables.filter_vulns(vulns)] == [
            "CVE-B",
            "CVE-A",
            "CVE-C",
        ]
        assert [v["id"] for v in tables.filter_vulns(vulns, "cve-c")] == ["CVE-C"]
        assert [v["id"] for v in tables.filter_vulns(vulns, severity="low")] == [
            "CVE-A"
        ]

    def test_scope_and_pages(self):
        recs = [{"agent_name": "A"}, {"agent_name": "b"}, {"agent_name": "A"}]
        assert len(tables.scope_records(recs, "agent_name", "a")) == 2
        assert tables.page_slice(list(range(55)), 9, 50) == ([50, 51, 52, 53, 54], 2, 2)

    def test_daily_and_hourly_buckets(self):
        today = datetime.now().astimezone().date()
        vulns = [
            {
                "severity": "high",
                "first_detected_at": datetime.now(timezone.utc).isoformat(),
            },
            {"severity": "low", "first_detected_at": "2000-01-01T00:00:00Z"},
        ]
        dates, counts = tables.bucket_vulns_daily(vulns, days=30, today=today)
        assert len(dates) == 30 and counts[today]["high"] == 1
        assert sum(sum(c.values()) for c in counts.values()) == 1
        now = datetime.now(timezone.utc)
        events = [
            {"severity": "critical", "timestamp": now.isoformat()},
            {
                "severity": "critical",
                "timestamp": (now - timedelta(hours=30)).isoformat(),
            },
        ]
        buckets, hc = tables.bucket_events_hourly(events, now=now)
        assert len(buckets) == 24 and sum(c["critical"] for c in hc.values()) == 1

    def test_posture_cves_and_alert_events(self):
        cards = [
            {
                "hostname": "h",
                "agent_id": "029",
                "computed_at": "2026-11-04T19:02:42",
                "mitigations": [
                    {
                        "kind": "package_update",
                        "severity": "critical",
                        "title": "Update pillow",
                        "evidence": {
                            "package": "pillow",
                            "version": "11.3.0",
                            "cves": ["CVE-2026-1", "CVE-2026-2"],
                            "fixed_version": None,
                            "fix_available": True,
                        },
                    },
                    {"kind": "cis_checks", "severity": "high", "evidence": {}},
                ],
            }
        ]
        cves = tables.posture_cves(cards)
        assert [c["id"] for c in cves] == ["CVE-2026-1", "CVE-2026-2"]
        assert cves[0]["package_name"] == "pillow" and cves[0]["source"] == "posture"
        events = tables.alerts_as_events(
            [
                {
                    "event_id": "e1",
                    "ts": 1_700_000_000,
                    "body": "b",
                    "info": {
                        "severity": "high",
                        "title": "t",
                        "host": "h",
                        "kind": "triage",
                    },
                }
            ]
        )
        assert (
            events[0]["severity"] == "high"
            and events[0]["rule_id"] == "triage"
            and events[0]["timestamp"]
        )

    def test_inventory_shaping(self):
        agent = tables.shape_inventory_agent(
            {
                "agent_id": "1",
                "agent_name": "h",
                "status": "active",
                "os": {"name": "Ubuntu", "version": "24.04"},
                "hardware": {
                    "cpu_name": "i7",
                    "cpu_cores": 8,
                    "ram_total_mb": 16777216,
                },
            },
            {
                "processes": [{"name": "bash", "pid": "1", "user": "root"}],
                "ports": [
                    {
                        "local_ip": "::",
                        "local_port": 22,
                        "protocol": "tcp",
                        "state": "listening",
                    }
                ],
                "network": {
                    "interfaces": [
                        {"name": "eth0", "state": "up", "rx_bytes": 1024, "tx_bytes": 0}
                    ],
                    "addresses": [
                        {"interface": "eth0", "address": "10.0.0.5", "proto": "ipv4"}
                    ],
                },
                "packages": [{"name": "git", "version": "2.4", "format": "deb"}],
            },
        )
        rows = tables.inventory_rows(
            [agent], [], [{"agent_name": "h", "severity": "high"}]
        )
        assert (
            rows[0]["threat"] == "high"
            and tables.cpu_ram_text(rows[0]) == "i7 (8c) · 16.0 GB"
        )
        ports = tables.inventory_counts_rows([agent], "Ports")
        assert ports[0]["count"] == 1 and tables.ports_listening(ports[0]) == "1"
        net = tables.inventory_counts_rows([agent], "Network")
        assert net[0]["items"][0]["ip_addresses"] == ["10.0.0.5"]
        assert tables.join_host_port("::", 22) == "[::]:22"
        assert (
            tables.format_bytes(1536) == "1.5 KB"
            and tables.format_ram("16777216") == "16.0 GB"
        )

    def test_devices_from_posture(self):
        rows = [
            {
                "agent_id": "029",
                "hostname": "h",
                "agent_status": "active",
                "os": "Windows 11",
                "computed_at": datetime(2026, 11, 4, 19, 2),
            }
        ]
        agents = tables.devices_from_posture(rows)
        assert (
            agents[0]["basic_info"]["name"] == "h" and agents[0]["syscollector"] == {}
        )
        assert tables.inventory_rows(agents, [], [])[0]["os"] == "Windows 11"
