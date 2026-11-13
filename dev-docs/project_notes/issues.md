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

## Queue (as of 2026-11-13)

Server / infrastructure
- Deploy `/v1/devices` + MAS admin client + reconcile job on briareosai (device-sessions.md, order of work step 1); until then the Sessions tab says "not available".
- VPN provisioning "Later": request signing with the device's ed25519 key; revocation sync for agents signed out elsewhere.
- Swift VPN helper rebuild for the `exposed.phoenix.*` bundle IDs; macOS VPN testing waits for the Apple developer account.
- Legacy artifact repos (VPN CLI, ClamAV binaries) to re-home to Phoenix infrastructure with signing certificates.

Security review deferred items (docs/SECURITY_REVIEW_2026-11.md, "Deferred")
- Windows IPC to a named pipe with DACL; bot device-key pinning in chat; DM membership check; appcast/RPM signing before any updater re-enable; build-image pinning; Sysmon config integrity; telemetry https; OIDC low-priority items; remove dead `plugins/login/api.py`.

Desktop
- Fleet view: when fixes are shown for other machines, the `gate()` in `utils/fixes.py` is the line; the remote-device check the user wants is not designed yet.
- Ideation shortlist not built: health ribbon, manifest page.
- Settings plugin strings are hardcoded English (only the digest strings went through the i18n catalog).
- `tests/platform`: 17 long-standing failures (macOS/Windows config-dir and service tests on Linux); `plugins/vpn/main.py` has 3 pre-existing ruff findings (E402/F401/F811 on `get_text`).
- Windows: WinRT toast when the tray is unavailable (`utils/notifications/windows.py` TODO).

