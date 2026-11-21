# Key Facts

Important config, ports, quirks, and environment details worth remembering.

---

- **Python target:** 3.13
- **GUI framework:** PyQt6 (flat page kit in `gui/page_kit.py`; no dialogs, choices slide in place)
- **Config location (macOS):** `~/Library/Application Support/Phoenix`
- **Config location (Windows):** `%APPDATA%/Phoenix`
- **Config location (Linux):** `~/.config/phoenix` (a pre-rebrand `resistine` dir is migrated on first start)
- **Files beside the settings JSONs:** `logs/phoenix.log` (10 MB rotation, compressed after a week), `siem_alerts.json` (received SIEM alerts, 0600), `jobs.json` (the last 50 jobs with their `PX-XXXX` codes, 0600), `logs/trace-*.log` only with `--trace`
- **Secrets encryption:** Fernet, master key in system keyring, encrypted values prefixed `ENC:`
- **Plugin status kinds:** `ok / warning / error / off / unknown` (`plugins/base_plugin.py:Status`); unknown is amber, never a warning and never a stale green
- **Job codes:** `PX-` + 4 of `ABCDEFGHJKLMNPQRSTUVWXYZ23456789` (no I/O/0/1), `utils/jobs.py`
- **Posture:** `GET /v1/me/posture` on api.phoenix.exposed, refetched at most every 5 min (ETag), stale after 26 h
- **Alerts:** `@siem-bot:phoenix.exposed` DMs over Matrix; only the bot's Megolm-decrypted messages are stored
- **ClamAV communication:** Unix socket (PING/SCAN) + subprocess for `clamdscan`/`freshclam`
- **VPN artifacts:** Downloaded from `DatOneOPGuy/phoenix-vpn-macos` CI via `gh` CLI (`VPN_ARTIFACTS_REPO` overrides); the repo is not visible to the `mrFrace` gh account, the Mac that builds needs access
- **macOS signing:** team `KTKS453599`, App Group `group.exposed.phoenix.wireguard`, bundle IDs `exposed.phoenix.*`; entitlements are generated with plistlib at build time (plutil mis-parses dotted keys)
- **Inventory endpoint as served:** `GET /v1/me/inventory` (phoenix-provisioning, AR-B7) answers `{data: {affected_items: [{id, name, status, ip}]}}`, no `os`/`hardware`; `plugins/devices/api.normalize_inventory_device` maps it to the documented `agent_*` keys. `GET /v1/me/inventory/{id}` is not deployed (404), so the Inventory view dropdown is hidden
- **CVE lists:** `GET /v1/me/vulnerabilities` (totals per agent) and `GET /v1/me/vulnerabilities/{agent_id}?limit=&offset=&severity=` (worst first, paged) on api.phoenix.exposed, forwarded to LLMAgent-api which serves the posture run's stored per-agent report (`POSTURE_VULN_REPORT_LIMIT`, default 5000). Added 2026-11-21, deploy pending on both servers; until then the tab shows the ≤ 50 CVEs the posture mitigations name (critical/high packages only)
- **Severity `untriaged`:** a CVE rated with none of critical/high/medium/low; `tables.bucket_by_severity` and `data.vuln_totals` count it so the donut's centre equals the scan's total (the card's `vulnerabilities.total`), the legend shows the row only when it is non-zero
- **AR executions endpoint:** `GET /v1/me/active-response/executions` ignores `?agent_id=`; the Responses tab filters per device itself (`active_response_api.executions_for`)
- **Mitigation `action`:** a `package_update` item may carry `evidence.action: "remove"` (an old kernel still installed beside the running one, server ≥ 2026-11-20); anything else is an update. The server emits a package item only when a fix is known, so `fix_available` is `True` on new cards; `False`/absent still renders ("no fix released yet") for older snapshots
- **Posture placeholder:** an agent the posture service has no scan for arrives as hostname/os `"Unknown"`; `data.fleet_rows` names it from the inventory list (`names_by_agent`)
- **ClamAV artifacts:** Downloaded from the legacy `ClamAV-Mac` CI via `gh` CLI (being re-homed)
- **Update channel:** one minisign-signed manifest at `auth.phoenix.exposed/packages/desktop/current/`; the Sparkle/appcast updater is hard-disabled
- **Linting:** Trunk (ruff, black, isort, bandit, shellcheck, shfmt, markdownlint, prettier, trufflehog, checkov)
- **CI:** `python -m compileall` + pip-audit on push/PR (Python 3.13)
- **Tests:** `pytest -m unit tests/unit`; `tests/platform` has 17 long-standing failures (macOS/Windows config-dir and service tests run on Linux)
