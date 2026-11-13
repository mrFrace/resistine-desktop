# Signed-in devices: list, verify, remove

Status (2026-11-13): done on both sides. Desktop
(`plugins/login/cross_signing.py`, `plugins/login/device_name.py`,
`plugins/devices/sessions_api.py`, `plugins/devices/sessions_tab.py`,
tests, contract and decision docs); Synapse accepts the display name under
MAS (checked live). The stale-install prompt is a toast after sign-in
pointing at a "Remove the old installation" row in the tab (toasts take
no clicks, and there are no dialogs). The server side
(`~/flakes/packages/phoenix-provisioning`, 33723a8) has been live on
briareosai since 2026-11-12 with the MAS admin client configured:
`GET /v1/devices` answers 200 and the revocation sync runs every 5 min with
a 24 h grace (verified 2026-11-13). Desktop side only below; the server is
summarised under "Server contract".

## Why

Reported 2026-11-11 by a user on phoenix.exposed: "Whenever I sign in it
makes another instance and I can't verify them, and it turns my phone
message sending off". What the server logs show:

- Every Phoenix Desktop install is its own Matrix device (`PHX_` + 16
  base32, `plugins/login/oidc.py:get_device_id`). The user had six over a
  month (rc builds on Linux and Windows). Installs that were never logged
  out keep their MAS session, VPN peer and Wazuh agent forever.
- matrix-nio has no cross-signing, so those devices can never show as
  verified in Element / Element X. That is the "can't verify them".
- Cleaning up happened in MAS `/account`, one session at a time. The user
  ended ten sessions in a minute, the last one being the phone's Element X
  session, which signed the phone out. Sessions ended there also leave the
  PHX device's VPN peer and Wazuh agent behind: nothing reconciles them
  (the "Revocation sync" in `vpn-provisioning-api.md` was never built).

Goal: the app shows every device on the account in a way that makes it
clear which is which, verifies itself, and removing a device from the app
removes its Matrix session **and** its WireGuard peer **and** its Wazuh
agent.

## Decisions (and the alternatives rejected)

1. **Removal runs on the server**, not in the app. The app calls
   `DELETE /v1/devices/{device_id}` on api.phoenix.exposed; the server ends
   the MAS session through the MAS admin API, deletes the Wazuh agent and
   the router peer. Rejected:
   - CS API `DELETE /devices/{id}`: with MAS delegation Synapse cannot do
     the UIA it requires.
   - MAS GraphQL from the app: needs the `urn:mas:graphql:*` scope on every
     desktop token, and still leaves VPN/Wazuh cleanup to a client that may
     crash halfway.
   - Opening MAS `/account?action=org.matrix.session_end`: fine for the
     session, but VPN and Wazuh would only be cleaned by the server's
     reconcile job, minutes later. Kept as the fallback link (see UI).
2. **Verification = "verify this device with your recovery key"**, done
   with our own small module on `cryptography` (already a dependency), no
   new crypto library. The app reads the self-signing key from secret
   storage (SSSS) with the recovery key the user already has from Element,
   signs its own device keys and uploads the signature. Element and
   Element X then show the PHX device as verified. Rejected:
   - nio SAS (emoji): nio only speaks the legacy to-device flow; Element
     and Element X need `m.key.verification.request`/`ready`. Not
     interoperable.
   - Switching to mautrix-python (has `verify_with_recovery_key` /
     `sign_own_device`, no SAS either) or matrix-rust-sdk bindings: the
     whole chat transport and the PyInstaller / Nix / Windows packaging
     would change for one feature. Revisit only if interactive emoji
     verification becomes a requirement.
3. **The app never verifies other devices.** Signing someone else's
   device keys from a list is trust-on-first-use and would make
   "verified" meaningless. The list shows each device's status; Element
   sessions are verified from Element (the UI says so).
4. **This device cannot be removed from the list.** Removing the current
   device is Logout (Settings), which already does local uninstall + server
   release + revoke. The server enforces this too.
5. **Placement:** a "Sessions" tab in the existing Devices plugin
   (`plugins/devices/`, tabs in `tabs.py`), not a new plugin: the name
   "Devices" is taken and users already go there for "my machines". Its
   device selector stays per Wazuh agent; the Sessions tab ignores it
   (fleet-wide, like Inventory).

## Server contract the app relies on

To be implemented in the backend (phoenix-provisioning). Same auth as
today: `Authorization: Bearer <MAS access token>`, user and calling device
from Synapse whoami, caller must be a `PHX_` device.

`GET /v1/devices` → 200

```json
{
  "devices": [
    {
      "device_id": "PHX_QS3ZBL42VSZ6YQAJ",
      "current": true,
      "kind": "phoenix",                 // "phoenix" | "matrix"
      "session": {                       // null when no active MAS session
        "client_name": "Phoenix Desktop",
        "user_agent": "Phoenix-Desktop/2026.11.06 (Linux)",
        "created_at": "2026-11-11T19:02:29Z",
        "last_active_at": "2026-11-12T14:20:00Z",
        "last_active_ip": "2603:6080:…"
      },
      "vpn":   {"hostname": "drake-laptop", "address": "10.42.20.14"} ,  // or null
      "agent": {"agent_id": "017", "agent_name": "drake-laptop-ab12…", "linked": false}  // or null
    }
  ]
}
```

Every active MAS session of the user (OAuth2 + compat) joined with the
registry rows (`devices`, `agents`) by device id. Registry rows without an
active session are included with `"session": null` ("orphaned"), so the app
can clean them up.

`DELETE /v1/devices/{device_id}` → 204 | 404 (not this user's) | 409
(`device_id` is the caller's own: use logout) | 422 (not a device id) |
503 (Wazuh / router / MAS down; nothing left half-done that a retry cannot
finish).

Server order: Wazuh agent (delete, or for a linked agent only remove the
user's group, as `release` does today) → router peer → registry rows → MAS
session finish. MAS last, so a failure leaves a still-working device that a
retry cleans up, never a dead session with live VPN/agent. Each step is
idempotent.

Not the app's concern but required for the goal: the server's reconcile job
(the "Revocation sync") that releases PHX devices whose MAS session has been
gone for longer than a grace period, so removals done in Element or MAS
`/account` also drop VPN and agent.

Until the server ships these, `GET /v1/devices` returns 404: the tab shows
the `NOT_AVAILABLE` state the way `plugins/devices/api.py` already does.

## Desktop changes

### 1. API client: `plugins/devices/sessions_api.py` (new)

- `list_devices() -> (list[DeviceRow] | None, error | None)` and
  `remove_device(device_id) -> (bool, error)` over
  `plugins.vpn.provisioning._authorized_request`, same `(data, error)` and
  `NOT_AVAILABLE` conventions as `plugins/devices/api.py:_get`.
- `DeviceRow` dataclass, parsed defensively (unknown `kind` → "matrix",
  missing blocks → None). Server strings are rendered as plain text only.
- `remove_device` validates the id locally (`^PHX_[A-Z2-7]{16}$` or MAS's
  10-char ids, `^[A-Za-z0-9_-]{1,64}$`) and URL-quotes it.

### 2. Verification status: `plugins/login/cross_signing.py` (new)

Pure functions plus two HTTP calls through the existing authorised session
(`oidc._session()`, Bearer from `oidc.refresh()`, no redirects):

- `query_own_keys() -> OwnKeys`: `POST /_matrix/client/v3/keys/query`
  `{"device_keys": {user_id: []}}` → master key, self-signing key, and
  every device's keys + signatures.
- `device_status(own_keys, device_id) -> "verified" | "unverified" |
  "no_keys" | "no_cross_signing"`: verified iff the device keys carry a
  valid ed25519 signature by the user's self-signing key, and the
  self-signing key carries a valid signature by the master key.
  Signatures are checked with `cryptography`'s `Ed25519PublicKey.verify`
  over canonical JSON (keys sorted, no whitespace, UTF-8, `signatures` and
  `unsigned` removed). Never trust a status the server reports.

### 3. Verify this device: same module

`verify_this_device(recovery_key: str) -> None`, raising
`VerificationError` with user-safe text:

1. Decode the recovery key: strip spaces, base58 (Bitcoin alphabet),
   expect prefix `0x8B 0x01`, 32 key bytes, parity byte = XOR of all
   previous bytes. Wrong format → "That is not a recovery key".
   (Optional second path: a secret-storage passphrase, PBKDF2-SHA512 with
   the salt and iterations from the key's `passphrase` field.)
2. `GET /_matrix/client/v3/user/{u}/account_data/m.secret_storage.default_key`
   → key id; `…/m.secret_storage.key.<id>` → algorithm must be
   `m.secret_storage.v1.aes-hmac-sha2`; check the key against its `iv` /
   `mac` (encrypt 32 zero bytes with name "") → wrong key → "This recovery
   key does not match your account".
3. `…/account_data/m.cross_signing.self_signing` → `encrypted[<id>]`
   {iv, ciphertext, mac}. HKDF-SHA256(key, salt = 32 zero bytes,
   info = "m.cross_signing.self_signing", 64 bytes) → AES key + HMAC key;
   check HMAC-SHA256 over the ciphertext, AES-256-CTR decrypt → base64
   32-byte ed25519 seed.
4. Derive the public key and require it to equal the self-signing key from
   `/keys/query` (otherwise SSSS and the published identity disagree: stop,
   tell the user to reset in Element).
5. Take this device's published keys from `/keys/query` (they exist:
   `matrix_transport._ensure_device_keys_published`), require the
   `ed25519:<device_id>` value to equal nio's own `olm.account` identity key
   (via `MatrixService.run_coro`), sign the canonical JSON with the seed,
   `POST /_matrix/client/v3/keys/signatures/upload`
   `{user_id: {device_id: {...device_keys, signatures: {user_id: {"ed25519:<ssk>": sig}}}}}`.
   No UIA is needed for this endpoint. Check the response's `failures`.
6. Drop the recovery key, AES/HMAC keys and seed (locals only; never
   `settings`, never logs, never `--trace` bodies: add the account-data
   and signatures paths to the trace redaction list).

No cross-signing on the account (no master key) → status
`no_cross_signing` and the UI says "Set up recovery in Element first".

### 4. UI: Sessions tab in `plugins/devices/`

- `plugins/devices/sessions_tab.py` (new), registered next to the other
  tabs in `main.py`. Fetch on a daemon thread, results back with
  `self.app.after(0, …)`, `_safe_set_text` for torn-down widgets, same as
  `_kick_fetch`.
- One card per device, grouped: **This device** first, then "Phoenix
  Desktop", then "Other apps" (Element, Element X…), then "Not signed in
  any more" (orphaned registry rows).
  Each row: name (VPN hostname for PHX devices, else client name + parsed
  user agent, e.g. "Element X · iPhone"), device id in muted small text,
  last active (relative) + IP, badges: Verified / Not verified, VPN, Wazuh
  agent `017`.
- This device, when not verified: a "Verify this device" button → sub-page
  (`SlideStack.push`) with a password-mode field for the recovery key, a
  link "Where do I find it?" (Element → Settings → Encryption), progress,
  result. Re-check the status after success. A secret-storage passphrase
  works in the same field. The field is cleared as soon as Verify is
  pressed.
- Remove (all rows except this device): no dialog (the app has none); the
  row opens a device page that names exactly what goes, with a "Remove this
  device" row at the bottom:
  - PHX device: "Sign out *drake-laptop*, delete its VPN access
    (10.42.20.14) and its Wazuh agent 017. The computer stops being
    protected until Phoenix is signed in there again."
  - Other app, extra warning when `last_active_at` is within 7 days:
    "This session was used 3 minutes ago (Element X · iPhone). If this is
    your phone, it will be signed out."
  On 503 show the server's detail and keep the row; on 404 refresh.
- "Manage in browser" link to `oidc.account_url()` as the fallback.
- i18n: new `devices.sessions_*` keys in `utils/i18n/en.json`; the other
  locales fall back to English (`get_text` only raises when English lacks
  the key too).

### 5. Fewer stale devices in the first place

- **Device display name** at login and once per app start: `PUT
  /_matrix/client/v3/devices/{device_id}` `{"display_name": "Phoenix
  Desktop · <hostname> (<OS>)"}` from `complete_login`. Best effort, log
  and continue on any error (verify early that Synapse accepts it under MAS
  delegation; if not, drop this item).
- **Stale installs of this computer**: after `_after_login`, call
  `list_devices()`; PHX rows other than this one whose VPN hostname equals
  `socket.gethostname()` → one notification "Phoenix was installed on this
  computer before. Remove the old installation?" → removes them through the
  same path. Never automatic.
- Fix the stale docstring in `plugins/wazuh/agent/enrollment.py:28-30`
  (the device id survives logout; a reinstall is what makes a new device).

### 6. Docs

- `dev-docs/plans/vpn-provisioning-api.md`: add the two endpoints and the
  reconcile job to the contract once the server plan is agreed.
- `dev-docs/project_notes/decisions.md`: decisions 1-3 above.

## Tests

Run with `source .venv/bin/activate && ./run_tests.sh unit`.

- `tests/unit/test_cross_signing.py`:
  - recovery key decode: a known-good key, bad prefix, bad parity, wrong
    length, spaces;
  - SSSS decrypt and key check against vectors generated in the test with
    `cryptography` (AES-CTR/HKDF/HMAC), wrong key → `VerificationError`;
  - canonical JSON and signature check (good, tampered, missing
    self-signing signature, SSK not signed by master);
  - `verify_this_device` end to end with the HTTP layer mocked as in
    `test_vpn_provisioning.py` (`api` fixture): asserts the uploaded
    signature verifies with the SSK public key, that nothing is written to
    settings and that the secret never appears in logged output (`caplog`).
- `tests/unit/test_sessions_api.py`: parsing (full, minimal, garbage),
  404 → `NOT_AVAILABLE`, 409 / 503 surfaced, id validation and quoting.
- `tests/unit/test_devices_sessions_tab.py` (offscreen Qt like
  `test_settings_plugin.py`): grouping, no Remove on this device, warning
  text for a recently active non-PHX session, verify button only when
  unverified.
- `tests/unit/test_security_hardening.py`: the homeserver calls never
  follow redirects with the Bearer token, and a failed verification writes
  no settings (`sessions_api` goes through `_authorized_request`, pinned in
  `test_vpn_provisioning.py`).
- The secret-storage code is checked against keys made by Element (the
  vectors in mautrix-python's `ssss/key_test.py`), not only against itself.

## Order of work

All done (2026-11-13).

1. Server endpoints + MAS admin client + reconcile job (backend repo) — live
   since 2026-11-12.
2. Desktop: `cross_signing.py` + tests (no server dependency, works against
   the live homeserver today) — MR !69.
3. Desktop: `sessions_api.py`, Sessions tab, removal, stale-install prompt,
   display name — MR !69, !70.
4. Contract and decision docs — MR !70.
