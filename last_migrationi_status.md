# Migration status — Phoenix rebrand, Matrix chat, VPN provisioning

Session date: 2026-10-11. Written at the end of the session; covers everything
done, verified, and still open.

**Where things stand right now:** the backup of briareosai's Phoenix/Matrix
config and data is **done and verified** (§6). The router runs the current
`phoenix-peer` (PSK on stdin). Nothing has been switched on briareosai yet —
the next action is the switch (step 4 in [Next steps](#next-steps)).

---

## 1. Repositories and where the real work is

| Path | Remote | Branch | Notes |
|---|---|---|---|
| `~/REPOS/Resistine-Desktop` | GitLab `gitlab.phoenix.exposed/francis/Resistine-Desktop` (+ `github` remote, fetch only) | `feat/phoenix-rebrand` | **The real app (PyQt6).** All desktop work below. |
| `~/REPOS/resistine-desktop` (lowercase) | GitHub `DatOneOPGuy/resistine-desktop` | `old/ctk-rebuild` | My early CustomTkinter rebuild (`a4cfe5c`), made before the GitLab branch was found. **Obsolete, never pushed.** Running `nix run` here starts the old app (Store, VPN-gated chat). Do not use. |
| `~/REPOS/Resistine-LLMAgent-api` | GitLab (private) | `feat/wazuh5-port` | Chat API + Matrix bridge. |
| `~/flakes` | GitLab `francis/flakes` (private) | `main` | **Your NixOS config working copy.** Router script + provisioning service committed here. |
| `~/.flakes` | GitLab `francis/flakes` | `main` | My restore of the same repo (older, 153 commits). Redundant with `~/flakes`; safe to delete. |
| `~/REPOS/Resistine-Internal-Documentation` | GitLab (private) | — | Cloned (old, Feb 2025). |
| `~/REPOS/Resistine-ansibleplay-main` | — | — | Unzipped from `~/Downloads`. No migration info; deploys old OpenAI API only. |

Lost with the disk and **not found anywhere** (GitLab searched as admin): the
`Resistine-matrix-server` repo (`docs/PHOENIX-MAS.md`, `PHOENIX-MIGRATION.md`,
`ARCHITECTURE.md`, `register-bot.py`, `ADD-A-BOT.md`). The ai-bot code survives
as `~/flakes/packages/maubot-ai-bot` and is deployed on briareosai (maubot).

Research documents:
- `Resistine-Desktop/dev-docs/plans/phoenix-auth-rebrand.md` — MAS auth + rebrand plan (device model, target architecture, open questions).
- `Resistine-LLMAgent-api` branch `feat/wazuh5-port`: `MATRIX_FRONTEND_REWORK.md`, `docs/MATRIX_BRIDGE.md`.
- `Resistine-Desktop/dev-docs/plans/vpn-provisioning-api.md` — VPN provisioning contract (new, this session).

---

## 2. Resistine-Desktop (`feat/phoenix-rebrand`) — commits this session

Pushed to **GitLab only** (nothing to GitHub), unless marked *local*.

| Commit | What |
|---|---|
| `a1b6b77` | Wazuh agent searched in `/var/ossec`, `/opt/resistine`, `/opt/phoenix-agent`, `/opt/agent-phoenix` |
| `14adaf5` | `.gitlab-ci.yml` (stops Auto DevOps Heroku build): compileall + unit/security tests |
| `088e038` | **Fix:** logout no longer stops/removes a system-managed Wazuh agent (was: `systemctl disable`, unit deleted, `userdel wazuh` on NixOS) |
| `b9626cc` | Test suite ported to PyQt6 (140 failures + 21 errors → 0); CI tests blocking |
| `ed8cdde` | Antivirus auto-update test isolated from real settings |
| `3439374` | Chat: assemble Matrix answers delivered in parts |
| `f76002c` *local* | Security re-port: plugin downloads (SHA-256, safe redirects, zip-slip) |
| `480b16c` *local* | Security re-port: VPN config validation, path guards, 0700, no `os.popen`, DNS env |
| `65acea3` *local* | Security re-port: settings lock, atomic master-key fallback, key encoding, login log redaction, OTP backoff |
| `abe1283` *local* | Security re-port: shell/PowerShell quoting in privileged Wazuh scripts, env file not via `/tmp` |
| `f8d3b56` *local* | Chat default URL → `https://dashboard.phoenix.exposed:8002/v1` (shared `utils/chat_config.py`) |
| `961918c` *local* | Telemetry export off (`TELEMETRY_ENABLED=False`), endpoint `otel.phoenix.exposed` ready |
| `155c646` *local* | **VPN provisioning step** after Phoenix sign-in (see §4) |

Uncommitted: `last_migrationi_status.md` (this file). Untracked `result` symlink (nix build output).

Tests: 1187 passed (unit + security, Linux CI selection). GitLab pipeline green
up to `3439374` (895 tests at the time). Integration/platform suites (not in CI)
still have ~20 pre-existing failures (Windows-only tests on Linux, a stale
Wazuh group-name test).

**The 7 local commits are not pushed to GitLab yet.**

---

## 3. Matrix chat — long answers were truncated (fixed)

Symptom: multi-tool answers (e.g. remediation for 5 CVEs) stopped mid-text.
Cause: Matrix rejects events > 64 KiB; an encrypted edit carries the text 4×
(+⅓ base64), so the bridge's final edit failed past ~10 KB of text, after the
20 progress edits were used up. The failure was only logged.

Fix:
- `Resistine-LLMAgent-api` `feat/wazuh5-port` **`354e30f`** (pushed to GitLab): TurnStream seals a reply at a paragraph boundary once its event would exceed 40 KB and continues in new replies marked `net.resisti.turn.part = 1, 2, …`; error notice if the final message can't be delivered. Docs updated in `docs/MATRIX_BRIDGE.md`.
- Desktop `3439374`: `TurnAssembler` concatenates parts.
- Verified end-to-end (bridge code → desktop collector): 11 KB answer in 2 parts, largest event ~42 KB encrypted, rebuilt exactly.

**Needs deploy:** restart `phoenix-matrix-bridge` on the bridge host with the new code.
Not changed (reported): `truncate_messages_for_model` in the API can reorder messages and keep only the last tool result when context overflows.

---

## 4. VPN provisioning — desktop gets its WireGuard config after Phoenix sign-in

### Design (decided)
- Split tunnel: clients reach only the dashboard host `10.42.10.250` and DNS `10.42.20.1`.
- VPN server: OpenWrt router `10.42.10.1`, `wg0`, UDP **987**, `10.42.20.0/24`, server public key `u8909Yqge8GzXID9EPw5bEc0kN3PSC3AHvtbZagDeFo=`.
- Endpoint: `vpn.phoenix.exposed:987` — DNS-only record → router WAN `83.208.45.10` (**created and verified** from Cloudflare and Google DNS; firewall rule `Allow-WireGuard-987` already counting packets).
- API: `api.phoenix.exposed` on **briareosai** (`10.42.10.252`).
- Identity: device ID `PHX_` + 16 base32 chars (already used by the desktop OIDC code). User and device are read from the Matrix token, never the request body.
- Addresses: assigned by the API (no DHCP in WireGuard), kept per device like a DHCP reservation; pool starts at `.10` (`.2–.9` are the hand-made test peers).

### Desktop (`155c646`, local)
- `plugins/vpn/provisioning.py`: generate keypair locally → `POST /v1/vpn/peer` with MAS Bearer (refresh once on 401) → save via existing validated writers as "Phoenix (Default)". `DELETE /v1/device` on logout (before session revoke).
- Hooks: setup-wizard VPN step and the VPN toggle (covers signing in again).
- Linux/macOS writers add validated `PresharedKey` / `PersistentKeepalive`.
- Linux WireGuard keys moved from plaintext `keys.json` to encrypted settings (migrated on first read).
- `PHOENIX_API_URL` overrides the API base (default `https://api.phoenix.exposed`).
- Mock for local testing: `scripts/dev/mock_provisioning_api.py` (`PHOENIX_API_URL=http://127.0.0.1:8099`). Verified end-to-end against it.

### Router (`~/flakes` `7c2488d`, local; **installed on the router**)
- `/usr/libexec/phoenix-peer add <device_id> <pubkey> <ip> <psk> | del <device_id> | list`, listed in `/etc/sysupgrade.conf`.
- Only touches `PHX_` peers; refuses an IP or key held by another peer; applies live with `wg set` (no `ifup`).
- Tested live: add, key swap, conflict refusal, delete, idempotent delete; router state identical before/after.
- **Incident (resolved):** the first version's conflict check broke on `/` in values and briefly assigned `10.42.20.4` to a test peer, taking it from `test3` in the live tunnel (~1 min; test3 had not connected for 2 days). Restored immediately; check rewritten with exact string matching and re-tested.
- **Not done:** the restricted key line in `/etc/dropbear/authorized_keys` (needs briareosai's key, created on first service start):
  `command="/usr/libexec/phoenix-peer",no-pty,no-port-forwarding,no-agent-forwarding <key>`

### API service (`~/flakes` `705f785`, local; **not deployed**)
- `packages/phoenix-provisioning/` — stdlib Python, 24 tests passing.
- `modules/services/phoenix-provisioning.nix` — systemd service `127.0.0.1:8012`, nginx `api.phoenix.exposed` on `127.0.0.1:8452` (`/v1/`, `/healthz` only), hardened; creates its own router SSH key on first start; router host key pinned (`SHA256:F9F9qDTV7T0ZRXadQ0BtCuinE5/D6H1lqXBSo0ueh+Q`).
- Token check: `GET http://127.0.0.1:8009/_matrix/client/v3/account/whoami` on the phoenix Synapse (verified it validates MAS tokens: bogus token → "Token is not active"). No MAS config change needed.
- Imported in `machines/briareosai/default.nix`. Full briareosai config evaluates.
- **Outside Nix, still to do:** Cloudflare tunnel public hostname `api.phoenix.exposed` → HTTP `http://127.0.0.1:8452` (type HTTP, not TCP) + WAF rule skipping Browser Integrity Check.
- Later: revocation sync job (MAS admin API), request signing with the device ed25519 key, `/v1/wazuh/enroll`.

---

## 5. briareosai — pre-switch verification (read-only, done)

Compared `~/flakes` @ `93047aa` (before my changes) with the running system
(`/nix/store/m49r4jy4…-nixos-system-briareosai-26.05.20261008.7c8764b`):

- **Identical:** packages (system-path), kernel, initrd, firmware, users and groups, all `/etc` files except below, 113 of 115 unit configs — including every Phoenix/Matrix service: `matrix-synapse`, `container@phx-synapse`, `phoenix-mas`, `maubot`, `livekit`, `lk-jwt-service`, `matrix-to-pi-rpc`, `cloudflared-tunnel`, `nginx` (all vhosts), `postgresql`, `ollama`, omalovanky.
- **Different (already in the repo, committed by you today, not yet on briareosai):**
  1. `0a310cf` — trust **Cloudflare Origin CA instead of the Resistine root CA** (Resistine CA will be removed).
  2. `b330e42` — Wazuh agent `/opt/resistine` → **`/opt/phoenix-agent`** (moves the old tree incl. `client.keys`, no re-enroll intended).
- My change adds only the provisioning service, its nginx vhost and user.
- Not managed by NixOS (switch won't touch): user services `coms-net-server`, `tunnel-monitor` (`~/.config/systemd/user`), `pi`/`bun` processes, `screen` sessions; Docker not running.

**Decision (yours): deploy all three; Resistine CA goes.**

Note: `~/flakes` has uncommitted edits by someone else (`flake.lock`, `flake.nix`,
`modules/desktop/resistine-desktop.nix` — bumps anubis' Phoenix Desktop input to
`155c646`). Left untouched; commit or stash before deploying so it's clear what goes out.

---

## 6. Backup before the switch (DONE, verified)

Result: briareosai `~/backup/phoenix-matrix-20261011-214529/` (978 MB, `COMPLETE`
marker). Verified: all checksums OK, archives readable; 9 secrets in
`/etc/secrets`; TLS for `phoenix-auth`, `matrix-internal`, `matrix-phoenix`;
container config; saved CA bundle still contains the Resistine root CA
(for rollback); signing keys + media of both Synapse instances; maubot DB;
`/opt/resistine/etc/client.keys`; Postgres dump complete (`matrix-synapse`
156 MB, `synapse_phoenix` 51 MB, `matrix-authentication-service` 11 MB,
`omalovanky`, `postgres`). Recorded system: `m49r4jy4…-nixos-system-briareosai`.

First run was stopped: it also archived `/var/lib/private` (ollama's models).
`backup-phoenix-matrix-v2.sh` excludes it and uses zstd.

Original plan of the script:

Script: briareosai `~/backup/backup-phoenix-matrix.sh`
(sha256 `675e28149b1dc8540da10b5348106667b893bcd95cebf429f2ea8ad7603ebbc2`, shellcheck clean).

Writes `/home/francis/backup/phoenix-matrix-<timestamp>/` (owner francis, 0700):
- `etc.tar.gz` — whole `/etc` incl. `/etc/secrets`, `/etc/ssl/matrix-internal`, `matrix-phoenix`, `phoenix-auth`, container config, CA bundle
- `etc-services-deref.tar.gz` — the same service files as real copies, plus unit files
- `state.tar.gz` — `/var/lib/matrix-synapse`, `/var/lib/nixos-containers/phx-synapse`, `/var/lib/maubot`, `/var/lib/private`, `/var/www/phoenix.exposed`, `/srv/omalovanky`, `/opt/resistine` (Wazuh agent + keys)
- `postgres-all.sql.gz` (+ `postgres-phx-synapse.sql.gz` if the container has its own Postgres), `postgres-databases.txt`
- `metadata.txt` (current system path, generations, services, ports), `SHA256SUMS`

Disk: 812 GB free on `/`.

---

## 7. Deploy of briareosai (DONE 2026-10-11 ~22:30)

New system `ykksl556…-nixos-system-briareosai`. Verified after the switch:
all Phoenix/Matrix services active (synapse, phx-synapse container, MAS,
maubot, livekit, lk-jwt, matrix-to-pi-rpc, cloudflared, nginx, postgres),
no failed units, loopback + public endpoints 200. Resistine CA removed;
Cloudflare Origin certs verify (gitlab., dashboard.:8002). Wazuh agent runs
from `/opt/phoenix-agent` (`/opt/resistine` moved) and talks to the manager
on :1517 — confirm "active" in the Wazuh dashboard. `phoenix-provisioning`
listening on 127.0.0.1:8012.

Router changes after the deploy:
- `/etc/dropbear/authorized_keys`: added the restricted provisioning key
  (`command="/usr/libexec/phoenix-peer",no-pty,no-port-forwarding,no-agent-forwarding,no-X11-forwarding … phoenix-provisioning@briareosai`).
  Backup: `/etc/dropbear/authorized_keys.bak-20261011-223108`.
- Removed the LAN DNS record `api.phoenix.exposed -> 10.42.10.252` (it pointed
  LAN/VPN clients at briareosai:443 where nothing listens). The API is public
  only through the Cloudflare tunnel, like auth./matrix. — it must be reachable
  before a device has VPN. Backup: `/etc/config/dhcp.bak-20261011-224206`.

Waiting on: Cloudflare public hostname `api.phoenix.exposed` -> HTTP
`http://127.0.0.1:8452` + Browser Integrity Check skip (optional rate limit on
`/v1/*`). Then end-to-end: `curl https://api.phoenix.exposed/healthz`, desktop
sign-in -> VPN.

## 8. After the deploy — end-to-end test and fixes (2026-10-11, 22:40–23:30)

**Provisioning works end to end.** Cloudflare hostname `api.phoenix.exposed`
is live (`/healthz` 200; no token / bogus token -> 401; BIC skip works).
Desktop sign-in got this workstation peer `PHX_NBZK6DHPKKUEAQLA` -> `10.42.20.10`
on the router (API log + `phoenix-peer add` in the router log). Router DNS cache
flushed (`killall -HUP dnsmasq`) after the record change.

**Tunnel bring-up on the workstation (AnubisAI) — blockers found and fixed:**

| Problem | Cause | Fix |
|---|---|---|
| pkexec "Not authorized", Howdy "could not find a camera" | no polkit agent running (Hyprland not started via UWSM, so graphical-session.target never activates); pkexec's text agent fails with "No session for cookie" even after Howdy approves | started `hyprpolkitagent` in the session; `~/flakes` `a4b1961` starts it from Hyprland autostart |
| still "Not authorized" with the agent | the agent retries while the previous Howdy run holds the IR camera (pam_howdy error 120), password step never reached | `~/flakes` `74578b9`: Howdy off for `polkit-1` only (sudo/login keep face unlock) |
| `cp: cannot create /etc/wireguard/resistine.conf` | /etc is read-only on NixOS | Desktop `fccecdc`: on NixOS `wg-quick up/down <~/.config/phoenix/wireguard/<name>.conf>` in place |
| config called `resistine` | default config name | Desktop `d8f5ee5`: `phoenix.conf` / interface `phoenix`, one-time migration of resistine.conf (and wg0.conf) |
| `wg-quick: command not found` | pkexec resets PATH (empty on NixOS) | Desktop `055a502`: absolute path via `shutil.which` (nixpkgs wg-quick wraps its own deps) |

Wrong turn, reverted: `674698b` (open the IR camera to the polkit helper
sandbox) — the sandbox was not the problem; removed before it went anywhere.

**Keyring:** Desktop `79d3fe0` — `utils/encryption.py` uses keyring service
`phoenix`; entries only under `resistine` are moved (copy, verify, delete).
Uninstallers (Linux/macOS) now remove these entries under both names.
(No app code imports encryption.py today.)

**Still to do for the workstation:** `cd ~/flakes && nh os switch --ask .#AnubisAI`
(applies `a4b1961` + `74578b9`), restart the app, VPN on -> check handshake on the
router and reachability of 10.42.10.250 + DNS through the tunnel.

**Other repos:** `Resistine-LLMAgent-api` has an uncommitted change by someone
else to `deploy/matrix-bridge/phoenix-matrix-bridge.service` (paths
`/root/chat` -> `/opt/phoenix-llmagent`, `After=phoenix-assistant.service`) —
left untouched.

**Remaining `resistine` identifiers** (need migration + real-machine test):
Windows service `ResistineVPN`, `C:\ProgramData\Resistine\wireguard` + IPC
token, `RESISTINE_IPC_TOKEN`; macOS bundle IDs `com.resistine.*`, app group,
system extension, `/Library/Application Support/Resistine/*`; copyright headers.

Unpushed: Resistine-Desktop 13 commits on `feat/phoenix-rebrand`; `~/flakes` 3 commits.

## Next steps

1. ~~Run the backup~~ — done.
2. ~~Verify the backup~~ — done (§6).
3. ~~Uncommitted `~/flakes` edits~~ — committed (`e9217ad`, `255ee3d`). `255ee3d` changed
   `phoenix-peer` to read the PSK on stdin; the new version is installed on the router
   and live-tested (previous version kept at `/tmp/phoenix-peer.prev` until reboot).
4. ~~Switch briareosai~~ — done (§7). Command used:
   `cd ~/flakes && nh os switch --ask --target-host francis@10.42.10.252 .#briareosai`
   Rollback if needed: `sudo nixos-rebuild switch --rollback` on briareosai (previous system recorded in `metadata.txt`).
5. After the switch: check Phoenix/Matrix services, Wazuh agent at `/opt/phoenix-agent` still connected, `journalctl -u phoenix-provisioning | grep 'router key'`.
6. Add that key to the router's `/etc/dropbear/authorized_keys` (restricted line above).
7. Cloudflare: `api.phoenix.exposed` public hostname + BIC skip rule.
8. End-to-end: `curl https://api.phoenix.exposed/healthz`, then sign in with the desktop app → VPN connects.
9. Push the 7 local Resistine-Desktop commits and the `~/flakes` commits to GitLab (when you say so).
10. Deploy the Matrix bridge fix (`354e30f`) and restart `phoenix-matrix-bridge`.

---

## Open items and warnings

- **Leaked WireGuard private key** (`6EEkoU4N…/VQ=`) is in public GitHub history (`DatOneOPGuy/resistine-desktop`). It belongs to the old AWS server `18.199.109.145:986` (`10.49.0.0/17`), **not** the router. Revoke that peer there.
- **GitLab admin token** pasted in this session — revoke it and create a new one.
- GitLab `francis/Resistine-Desktop` is **public** (LAN-reachable only, no public DNS) — anyone on the network can read it, including the leaked-key history.
- GitHub push of `feat/phoenix-rebrand` is on hold until Drake agrees (it would publish ~100 commits of private org history; secret scan was clean).
- Plugin downloads: SHA-256 verification only activates once `"sha256"` is added to each entry in `Resistine-Desktop-Plugins/plugins/optional_plugins.json`.
- `utils/windows_admin.py` still has the PowerShell quoting flaw (Defender module uses it).
- macOS Wazuh env-file staging tested on Linux only — run one real agent install on a Mac.
- Keyring robustness: if the keyring silently drops writes, the app makes a new master key each start and loses secrets.
- `validate.`, `rfr1.`, `otel.phoenix.exposed` don't exist yet; telemetry is off until `otel.phoenix.exposed` is live.
- Hosts and keys: router SSH works with `~/.ssh/francis_phoenix` (ED25519 host key `SHA256:F9F9qDTV7T0ZRXadQ0BtCuinE5/D6H1lqXBSo0ueh+Q`); briareosai likewise (`SHA256:NBdN0PjAFHfyqub0i2FnUaS3AnlHBROQ1bs9l7jZ2Uk`). Both were added to `known_hosts` this session.
- Git identity is not configured on this machine; commits used `mrFrace <mr.frace@gmail.com>` per command.
