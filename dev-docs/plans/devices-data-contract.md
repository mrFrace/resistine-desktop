# Devices page: what the old Endpoint page displayed, and the data it needs

Status: the desktop side is being rebuilt as `plugins/devices/` on this
branch. The old page (`plugins/wazuh_overview/`, removed in 65f7fb2, still on
`main`) read everything from the old company's dashboard service
(`http://dashboard.resisti.net:8899/api/v1/me/*`, identified by source IP).
That backend is gone. This document lists exactly what the page showed, down
to the field, so the same data can be produced by the Phoenix server, whatever
the transport (the desktop's data layer takes records, not endpoints:
`plugins/devices/remote.py` slots can be filled from HTTP or from Matrix).

The HTTP shapes below are the old contract verbatim (`api_client.py` on
`main`). A Matrix feed only needs to carry the same records; field names can
stay as they are, the client normalises them (`plugins/devices/api.py`).

## What already exists on the new system

The posture card (`GET /v1/me/posture`, schema `phoenix.posture.v1`) already
gives, per agent: hostname, agent_id, os, agent_status, computed_at, score,
grade, health, vulnerabilities {total, critical, high, medium, low, available,
reason}, compliance {score_pct, failed_checks, checks}, alerts {window_hours,
critical, high, available}, recommendations[], mitigations[] (kind, severity,
title, evidence {package, version, critical, high, cves[], fixed_version,
fix_available}, check). The SIEM alerts arrive over Matrix from siem-bot.

The new Overview tab is built on that. What follows is what the other three
tabs need beyond it.

## Global: the device selector

A dropdown at the top of the page: "All devices" + one entry per device on
the account (this machine pinned second and tagged "(this device)"), each
with a dot in the device's worst threat colour (worst of its event and CVE
severities). It filters the Overview, Events and Vulnerabilities tabs;
Inventory is fleet-wide. Device identity everywhere is `agent_id` +
`agent_name`.

## Tab: Vulnerabilities

### Data

Group summary (cheap, drove the Overview card):

```
GET /api/v1/me/vulnerabilities?top=5[&severity=critical|high|medium|low]
{ "total_devices": int, "total_vulnerabilities": int,
  "by_severity": {"critical": n, "high": n, "medium": n, "low": n},
  "devices": [ {"agent_id", "total", "by_severity": {...}, "top_cves": [cve...] } ] }
```

Per device, every CVE (paginated):

```
GET /api/v1/me/vulnerabilities/{agent_id}?limit=500&offset=0[&severity=]
{ "detected_at": "2026-11-04T19:02:42Z",      # scan time, once per response
  "vulnerabilities": [ {
      "cve": "CVE-2026-112393",
      "severity": "Critical|High|Medium|Low",
      "cvss3_score": 9.8,        # or cvss2_score
      "epss": 0.42,              # 0..1, optional
      "package": "pillow", "version": "11.3.0",
      "description": "...",      # free text, up to a few KB
      "status": "active|pending|solved", # optional
      "published": "2026-10-01T00:00:00Z", "updated": "2026-10-20T00:00:00Z",
      "first_detected_at": "..."  # optional; the timeline chart needs it
  } ] }
```

### Displayed

- **Severity breakdown donut**: one wedge per severity (critical, high,
  medium, low) with the total CVE count in the centre and a legend with the
  per-severity counts. Clicking a wedge filters the table to that severity;
  the other wedges dim.
- **Recent detection timeline**: 30 daily stacked bars (today at the right
  edge) of CVEs by `first_detected_at`, stacked by severity; hover shows
  "Nov 04, 2026 · 3 high threats"; clicking a segment filters by severity.
  "No detections in the last 30 days" when the field is absent.
- **Search**: matches CVE id, package name, package version, severity,
  status, description and device name. Count label "N vulnerabilities" or
  "shown/total".
- **Table** (50 per page, pager): SEV pill (CRIT/HIGH/MED/LOW) · CVE id with
  "modified X ago" under it · package name with version under it. Sorted by
  CVSS descending.
- **Detail card** for the selected row: severity pill, CVE id, "modified X
  ago"; headline "package version"; CVSS (coloured by severity), EPSS as a
  percentage (coloured ≥30 % warning, ≥70 % high), STATUS, DEVICE, FIRST
  DETECTED, PUBLISHED, LAST MODIFIED; DESCRIPTION in a scrolling box.

## Tab: Events

### Data

Per device, vulnerability-detection events in a window (paginated):

```
GET /api/v1/me/vulnerabilities/{agent_id}/events?limit=50&offset=0&hours=168[&severity=]
{ "events": [ {
      "id": "...", "timestamp": "2026-11-04T18:00:00Z",
      "rule_id": "23504", "rule_level": 12,     # or "severity": "High"
      "title": "CVE-2026-1 affects pillow",     # or rule.description
      "cve": "CVE-2026-1", "package": "pillow", "version": "11.3.0",
      "agent": {"name": "DrakeHP", "ip": "10.0.0.5"},
      "rule": {"mitre": {"id": ["T1190"]}},     # optional
      "full_log": "..."                          # or "data": {...}
  } ] }
```

Also accepted: OpenSearch hits (`hits.hits[]._source`) and the Wazuh
`data.affected_items` envelope. Rule level maps to severity: ≥14 critical,
≥12 high, ≥7 medium, else low.

### Displayed

- **Severity pills**: four clickable pills with counts (critical, high,
  medium, low); selecting one filters the stream, the others dim.
- **24-hour chart**: 24 hourly stacked bars (UTC hours, ending at the next
  hour boundary), stacked by severity; clicking an hour filters the stream
  to that hour.
- **Search**: rule id, description, ip, severity, MITRE ids. Count label.
- **Stream** (50 per page): severity dot · RULE id · METRIC (first MITRE id,
  else ip) · WHEN (local "Nov 04 18:00:00").
- **Detail card**: severity pill, "rule N", relative time; description as the
  headline; AGENT, HOST, IP, MITRE TECHNIQUES, HASH; RAW LOG in a monospace
  box.

The rebuilt tab also shows the SIEM alerts from the Matrix feed in the same
stream (source "siem"), so it is useful before detection events exist.

## Tab: Inventory

### Data

Device summaries (paginated):

```
GET /api/v1/me/inventory?limit=200&offset=0
{ "total_devices": int, "has_more": bool,
  "devices": [ {
      "agent_id": "029", "agent_name": "DrakeHP", "agent_ip": "10.0.0.5",
      "status": "active|disconnected",
      "os": {"name": "Microsoft Windows 11 Home", "version": "10.0.26200",
             "arch": "x86_64", "platform": "windows", "last_scan": "..."},
      "hardware": {"cpu_name": "Intel ...", "cpu_cores": 8,
                   "ram_total_mb": 16777216,   # NOTE: value is in KB despite the name
                   "ram_free_mb": 4000000, "ram_usage_pct": 76, "last_scan": "..."}
  } ] }
```

Per device detail:

```
GET /api/v1/me/inventory/{agent_id}
{ "processes": [ {"name", "pid", "ppid", "user", "command", "state"} ],
  "ports":     [ {"local_ip", "local_port", "remote_ip", "remote_port",
                  "protocol": "tcp|udp|tcp6|udp6", "state": "listening", "process", "pid"} ],
  "network":   { "interfaces": [ {"name", "state": "up|down", "mac", "rx_bytes", "tx_bytes"} ],
                 "addresses":  [ {"interface", "address", "proto": "ipv4|ipv6"} ] },
  "packages":  [ {"name", "version", "vendor", "format": "deb|rpm|win|pypi|...",
                  "architecture", "install_time"} ] }
```

### Displayed

A view dropdown (Devices, Processes, Ports, Network, Packages), a group
filter when the account spans several Wazuh groups, a count line, and a
device table (20 per page):

| View | Lead column | Per-device summary columns | Expanded item columns |
| --- | --- | --- | --- |
| Devices | threat pill (worst of events + CVEs) | OS · CPU / RAM ("Apple M2 Pro (12c) · 16.0 GB") · LAST SEEN ("Active now" or relative) | — |
| Processes | process count | UNIQUE names · USERS · TOP PROCESS ("svchost.exe ×24") | NAME, PID, PPID, USER, COMMAND |
| Ports | open port count | TCP / UDP · LISTENING · TOP PORTS | LOCAL ("[::]:135"), PROTOCOL, STATE, PROCESS, PID |
| Network | interface count | UP / DOWN · ADDRESSES · TOTAL RX / TX | NAME, STATE, IP ADDRESS, MAC, RX / TX |
| Packages | package count | FORMATS ("win 162 · pypi 4") · VENDORS · TOP VENDOR | NAME, VERSION, VENDOR, FORMAT, ARCH |

Every device row shows name with "id N · ip" under it. Rows on the non-Devices
views expand to the item table, 25 items at a time with "Show 25 more".

## Overview cards the old page also had

- Agent (`GET /api/v1/me/agent`): name, id, version, status, lastKeepAlive,
  disconnection_time, os {name, version, arch, platform}, ip, manager,
  node_name, group[], group_config_status. Shown as the device card and the
  "Agent is connected, last keep-alive X ago" bar.
- SCA (`GET /api/v1/me/sca`): policies [{name, score, pass, fail,
  not_applicable}]. Card: "26 % score · 124 pass · 350 fail".
- Hotfixes (`GET /api/v1/me/hotfixes`): [{hotfix, ...}]. Card: "N hotfixes
  installed" (Windows only).

The posture card now covers the agent status, the vulnerability counts and
the compliance score, so only SCA policy detail and hotfixes would be new.

## Priorities for the feed

1. Per-device CVE list (the Vulnerabilities table and timeline).
2. Per-device inventory detail (packages, ports, processes, interfaces).
3. Detection events; until then the SIEM alert feed fills the Events tab.
4. SCA policy detail and hotfixes (small cards only).
