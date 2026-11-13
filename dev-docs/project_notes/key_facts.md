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
- **VPN artifacts:** Downloaded from the legacy `resistine-vpn-macos` CI via `gh` CLI (being re-homed)
- **ClamAV artifacts:** Downloaded from the legacy `ClamAV-Mac` CI via `gh` CLI (being re-homed)
- **Update channel:** one minisign-signed manifest at `auth.phoenix.exposed/packages/desktop/current/`; the Sparkle/appcast updater is hard-disabled
- **Linting:** Trunk (ruff, black, isort, bandit, shellcheck, shfmt, markdownlint, prettier, trufflehog, checkov)
- **CI:** `python -m compileall` + pip-audit on push/PR (Python 3.13)
- **Tests:** `pytest -m unit tests/unit`; `tests/platform` has 17 long-standing failures (macOS/Windows config-dir and service tests run on Linux)
