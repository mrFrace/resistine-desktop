# Work History & Current Roadblocks

Track completed work and active blockers here.

## Template

### [Date] — Task/Issue Title
- **Status:** Done / In Progress / Blocked
- **Summary:** What was done or what's blocking?
- **Next steps:** (if applicable)

---

### 2026-11-12 — Devices → Sessions, device display name
- **Status:** Done (MR !69, !70)
- **Summary:** Sessions tab on the account's devices (`plugins/devices/sessions_api.py`, `sessions_tab.py`), removal through `DELETE /v1/devices/{id}`, this device named "Phoenix Desktop · host (OS)" in Element, stale-install prompt after sign-in.
- **Next steps:** server side (`/v1/devices`, MAS admin client, reconcile job) is not deployed yet; the desktop falls back to "Manage in browser".

### 2026-11-13 — Unknown as a state, data has an age, the week in one sentence
- **Status:** Done (MR !71–!74, !80)
- **Summary:** `Status(kind, reason, at)` with `unknown`, amber glow and captions in the rail, "As of … · next check …" lines, the week's sentence in the Recent alerts tile, weekly Matrix post, "Check now" toast with `recheck()`. Test collection pollution from `tests/platform/test_linux_distros.py` fixed.

### 2026-11-13 — GUI ideation security notes 1–5
- **Status:** Done (MR !75–!79)
- **Summary:** daily alert digest in the view only; jobs with codes + Settings → Diagnostics with redacted export; job codes the chat understands; undo declared per job; "Fix all" as a queue of the plugins' own actions, this machine only, VPN switched off by hand not offered.
- **Next steps:** see the queue below.

## Done (2026-11-13)

- Server: `/v1/devices`, the MAS admin client and the revocation sync are live on briareosai since 2026-11-12 (`~/flakes` 33723a8; verified 2026-11-13: GET /v1/devices 200, sync every 300 s, grace 86400 s). The sync's cap error now names the devices (`~/flakes` 1599318, pushed, deploy pending).
- Security review deferred items: Sysmon config bundled and pinned (LF bytes, MR !82 + !83); telemetry refuses non-https collectors; `publish-linux-repos.sh` signs the RPMs themselves (`rpmsign`, verified with `rpm --checksig`); the Windows build VM's host key is pinned after the first build (`$GOLDEN_DIR/known_hosts`).
- GUI ideation security notes 1–5 built (MR !75–!79); the week's sentence in Recent alerts and "Fix N things" in the System tile (MR !80); docs caught up (MR !81).
- macOS identity moved to Phoenix's Apple team: Drake's 5 commits from `hardening/deferred-nov13` cherry-picked (team `KTKS453599`, App Group `group.exposed.phoenix.wireguard`, plistlib entitlements, installer certificate pinned, VPN artifacts from `DatOneOPGuy/phoenix-vpn-macos`). His security commit `1db4158` was deliberately not taken (three of its fixes already exist here; the rest is listed under the security review below). GitHub `mrFrace/resistine-desktop` branch `testmacbuild` mirrors `main` for the Mac build.
- Devices against the backend as it is: the inventory list's Wazuh-native shape is normalized (`09bbc90`), the Inventory view dropdown is hidden until the detail endpoint exists (`4b01b3b`), the Responses tab filters executions per device itself and names thin AR records (`18741bf`), and a posture card with hostname "Unknown" takes its name from the inventory (`692dd22`).

## Done (2026-11-21)

- Devices → Vulnerabilities counts: the tab mixed the scan's full totals (donut) with the ≤ 50 CVEs the posture mitigations name (table), gave every CVE of a mitigation the item's severity (5 CRIT where the card had 3), and dropped unrated CVEs from the total (2,623 vs 2,757). Desktop: per-CVE severity from the item's `critical` count, `untriaged` bucket, scan total in the centre. Server: `GET /v1/me/vulnerabilities[/{agent_id}]` in LLMAgent-api (`vulnerability_cards.py`, from the stored per-agent report, now the whole scan) and forwarded by phoenix-provisioning (`~/flakes`); both deploys pending, the desktop switches from the fallback by itself once they answer.
- GitHub `mrFrace/resistine-desktop` branch `autofixes` (Drake, 2026-11-18…20) taken by `git cherry-pick -x`, 11 of 12 commits: VPN config kept out of the tests' reach (`group_containers_dir`), optional-package guard before nio, login notices and User-Agent, agent-install prompt cancel, Terms of Service and Privacy Policy in every installer and at sign-in (`utils/legal.py`, `scripts/build/render_legal.py`), Vulnerabilities tab up to 100 CVEs per package, alert detail through the Alerts text widget, in-app "Download and install" against the signed manifest (`utils/updates/installer.py`), quiet daily update check (`utils/updates/background.py`), update security plan. Skipped `1b08a13` (fix(chat): other own devices blacklisted before a send): it repairs a regression of the bot device pinning from the security commit `1db4158`, which this repo does not have; take both together when the pinning is ported. Our packaging files keep their names (`Resistine.spec`, `ResistineInstaller.iss`); git's rename detection applied the legal changes to them.

## Done (2026-11-20)

- Fixes for agent 004 (the Ubuntu host behind dashboard.phoenix.exposed, agent name "francispc"): the two "Update linux-image-7.0.0-4x-generic" items were old kernels left on disk (purged by hand), after which the running kernel 7.0.0-44 took their place with the same unfixable CVEs. Server: `posture.py` offers a package only with a known fix, or as "Remove old kernel" when it is not the running kernel (`get_os().release`); `posture_cards.py` passes `evidence.action`. Desktop: `plugins/dashboard/mitigations.py` reads `action` and gives `sudo apt purge` / `dnf remove` steps without the restart line.

## Queue (as of 2026-11-13, after the server/infra pass)

Needs the operator (one-off)
- Today ~16:53 the revocation sync's first run after the grace will find 16 devices of other users without a session, above `PROV_SYNC_MAX_RELEASE=10`, and release none. Check `journalctl -u phoenix-provisioning | grep "due for release"`; when they are real sign-outs, raise the cap for one run (`PROV_SYNC_MAX_RELEASE=20` in `/etc/secrets/phoenix-provisioning.env`, restart, then remove it).
- Deploy `~/flakes` 1599318 (nixos-rebuild from a clean checkout).
- First real `publish-linux-repos.sh` run with the release key signs the RPMs; then switch the published `.repo` file to `gpgcheck=1`.

Server / infrastructure (blocked or needs a decision)
- Swift VPN helper rebuild for the `exposed.phoenix.*` bundle IDs; macOS VPN testing waits for the Apple developer account. First distribution build on the new team: confirm `KTKS453599` is the Phoenix team (it is now hardcoded in `packaging/Resistine.entitlements`) and that the build Mac can reach `DatOneOPGuy/phoenix-vpn-macos` (the `mrFrace` gh account cannot).
- ClamAV binaries still come from the legacy `ClamAV-Mac` repo: re-home with signing certificates. (VPN artifacts are re-homed to Drake's fork.)
- LLMAgent-api: `GET /v1/me/active-response/executions` should honour `?agent_id=` (the desktop filters client-side meanwhile); `GET /v1/me/posture` sends hostname/os `"Unknown"` for an agent without a scan (036) instead of the manager's agent name.
- LLMAgent-api + phoenix-provisioning, deploy pending: `GET /v1/me/vulnerabilities[/{agent_id}]` (2026-11-21, LLMAgent-api uncommitted + `~/flakes` uncommitted). Until deployed the Vulnerabilities tab shows only the mitigations' CVEs (no medium/low) and agent 027's 2,410 CVEs stay unlisted. Open question: 027's card has no package mitigations although it has CVEs, so its Windows CVE records may lack a package version (`_package_mitigations` skips those).
- LLMAgent-api, deploy pending (dashboard.phoenix.exposed:8002, changed 2026-11-20 in `~/REPOS/Resistine-LLMAgent-api`, uncommitted): a `package_update` mitigation is emitted only when the scanner names a fixed version, and a kernel package other than the running kernel becomes "Remove old kernel …" with `evidence.action: "remove"`. Until it is deployed, Devices → Fixes keeps showing every Ubuntu agent's current kernel as "Update linux-image-…" (CVEs Canonical lists without a fix).
- phoenix-provisioning: `GET /v1/me/inventory` should carry `os` and `hardware` per device and `GET /v1/me/inventory/{id}` (processes, ports, network, packages) is still missing; the Inventory view dropdown stays hidden until then.
- VPN provisioning "Later": request signing with the device's ed25519 key (design).
- Build-image pinning by digest in `publish-linux-repos.sh` / `build-windows-vm.sh`.

Security review, still open (docs/SECURITY_REVIEW_2026-11.md, "Deferred")
- Windows IPC to a named pipe with DACL; bot device-key pinning in chat; DM membership check; appcast signing before any updater re-enable; OIDC low-priority items; remove dead `plugins/login/api.py`.

Desktop
- Devices → Inventory: the view dropdown (Devices / Processes / Ports / Network / Packages) is hidden (`plugins/devices/tabs.py`, `self.view_combo.hide()`, 2026-11-13) because only "Devices" shows data. The other four views read the per-device detail `GET /v1/me/inventory/{id}` (processes, ports, network, packages), which phoenix-provisioning does not serve yet (404); the list endpoint `GET /v1/me/inventory` (AR-B7) only returns `{id, name, status, ip}`, so OS comes from posture and CPU / RAM stays "—". Unhide once the backend serves the detail and `hardware`/`os` in the list.
- Fleet view: when fixes are shown for other machines, the `gate()` in `utils/fixes.py` is the line; the remote-device check is not designed yet.
- Ideation shortlist not built: health ribbon, manifest page.
- Settings plugin strings are hardcoded English (only the digest strings went through the i18n catalog).
- `tests/platform`: 17 long-standing failures (macOS/Windows config-dir and service tests on Linux); `plugins/vpn/main.py` has 3 pre-existing ruff findings (E402/F401/F811 on `get_text`).
- Windows: WinRT toast when the tray is unavailable (`utils/notifications/windows.py` TODO).
