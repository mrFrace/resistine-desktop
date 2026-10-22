# Phoenix: Matrix (MAS) auth rebuild + rebrand — source map & plan

Status: research / planning (2026-10-10). Nothing implemented yet.

## 1. Where we are today

### Desktop auth (custom email + OTP, no tokens)

| What | Where |
|---|---|
| OTP REST client (`/send-otp`, `/verify-otp`) | `plugins/login/api.py:12-111` (hardcoded `host_url="rfr1.resisti.net"`, `vpn_name="testVPNapi"` :72) |
| Login screen, `LoginAPI("https://validate.resistine.work")` | `plugins/login/main.py:67`, verify `:233`, `_after_verify :258`, `_save_vpn_config :302`, signup URL `:31` |
| Setup wizard (VPN / AV / Wazuh steps) | `plugins/login/setup_wizard.py:92,461`, `plugins/login/setup_steps.py:147-990,1084` |
| Startup gate (`auth.logged_in` or Login plugin uninstalled) | `main.py:83,129`, `gui/app_window.py:109,288` |
| Logout (VPN down, Wazuh agent removed, user data wiped) | `plugins/settings/main.py:125-150,401-520` |
| Settings / secrets (Fernet `ENC:`, keyring `resistine-master-key`) | `utils/settings.py:25-51,82,221-252` |
| Deprecated OpenAPI of the OTP backend | `plugins/login/opneapi-deprecated.json` |

The only auth state is the plaintext `auth.json` with `{email, logged_in}`. There is no access or refresh token, and no session expires. A successful `/verify-otp` returns the WireGuard config, and the backend creates the Wazuh group named after the email.

### VPN

| What | Where |
|---|---|
| UI, `DNS_SERVER="10.49.11.10"`, `is_vpn_connected()` | `plugins/vpn/main.py:126,133` |
| Config registry, default name `resistine` | `plugins/vpn/config_manager.py:15,158` |
| macOS (CLI bridge, system extension, App Group dir) | `plugins/vpn/wireguard/vpn_functions_darwin.py:19-33,51-199,216` |
| Linux (`wg-quick` via pkexec, **plaintext `keys.json`**) | `plugins/vpn/wireguard/vpn_functions_linux.py:26,192,375-516` |
| Windows (service `ResistineVPN`, IPC token, `127.0.0.1:51888`) | `plugins/vpn/wireguard/vpn_functions_windows.py`, `windows_vpn_service.py:31-112`, `service_client.py`, `gui/tray.py:32-112` |
| Swift CLI + NetworkExtension (external) | private repo `Resistine/resistine-vpn-macos`, fetched by `scripts/build/download-vpn-artifacts.sh` |

Keys are generated on the client, a fresh pair on every login. The public key goes to `/verify-otp`, and the server returns `{Interface, Peer}` JSON. The VPN plugin never calls a server itself.

### Wazuh

| What | Where |
|---|---|
| Manager `dashboard.resisti.net`, ports 1514/1515, versions | `plugins/wazuh/config.py:36-39` |
| Group = email with `@`→`-`; re-enroll on email change | `agent/wazuh_functions_{darwin:85-112, linux:119-130, windows:102-120}` |
| Enrollment (`agent-auth`, **no password**) | linux `:530,586`, darwin `:520-573`, windows `:495,555-630`, `scripts/wazuh-postinstall-darwin.sh:139-190` |
| macOS install state machine | `plugins/wazuh/agent/installer_service.py:63-157,345` |
| Unused `_RESISTINE_API_BASE` | `wazuh_functions_darwin.py:115`, `wazuh_functions_windows.py:43` |

### Chat (also auth-relevant)
- The base URL is `https://dashboard.resisti.net:8002/v1` (`plugins/chat/main.py:76`, `plugins/settings/main.py:40`).
- The server authorizes requests by **VPN source IP mapped to a Wazuh agent** (`plugins/chat/streaming.py:296-303`), which is the `Resistine-LLMAgent-api` project.

### Tests to rewrite or extend
- `tests/unit/test_login_api.py`
- `tests/integration/test_auth_flow.py`
- `tests/unit/test_settings_plugin.py:216-295,503-608`
- `tests/security/test_input_validation.py:176,234-304`
- `tests/security/test_secrets_storage.py`
- the Wazuh tests that use `auth.email`

The Qt login UI and the wizard have no tests today.

## 2. Server side (what exists on phoenix.exposed)

Sources: `~/.flakes` (machine `briareosai`) and `~/orca/projects/Resistine-matrix-server`.

| Piece | Status | Source |
|---|---|---|
| Synapse `phoenix.exposed`, `public_baseurl https://matrix.phoenix.exposed/` | live, delegates auth to MAS | `~/.flakes/modules/services/matrix-synapse-phoenix.nix:89-153` |
| **MAS 1.26** at `https://auth.phoenix.exposed/` | live (M3 cutover 2026-10-10) | `~/.flakes/modules/services/phoenix-mas.nix` (public :8010, admin API :8011 loopback) |
| Grants: `authorization_code`+PKCE, `refresh_token`, **`device_code`**, `client_credentials`; dynamic client registration; `none` client auth; introspection | verified live via `/_matrix/client/v1/auth_metadata` | — |
| Legacy `m.login.password` (MAS compat layer) | live | nginx routing `matrix-synapse.nix:111-114` |
| Password registration | **off**: admin creates accounts (`mas-cli manage register-user` / MAS admin API) | `phoenix-mas.nix:94-100` |
| Example MAS admin-API client (`client_credentials`, `urn:mas:admin`) | reference implementation | `Resistine-matrix-server/bots/ai-bot/ai_bot.py:345-416`, `base-config.yaml:55-63` |
| MAS design / rollout / secrets docs | read first | `Resistine-matrix-server/docs/PHOENIX-MAS.md` (secrets L200-247, QR caveat L306-314), `docs/PHOENIX-MIGRATION.md`, `ARCHITECTURE.md:157-206` |
| **`api.phoenix.exposed`** | **does not exist** (no DNS, no code) | — |
| WireGuard server | **none on briareosai** (wg0 mesh removed 2026-10-09, `71f55e7`) | comments only, `configuration.nix:102-157` |
| Wazuh manager | not in the flake; agent on briareosai reports to `dashboard.phoenix.exposed` (francispc, 10.42.10.250), Wazuh 5.0 beta "phoenix" build, port 1517, `authd.pass` | `~/.flakes/machines/briareosai/default.nix:95-178`, `modules/services/wazuh-agent.nix` |
| Ingress | Cloudflare Tunnel, Origin CA certs, nginx SNI on 127.0.0.1:8448; hostnames are set in the CF dashboard | `cloudflared-tunnel.nix`, `configuration.nix:126-130` |
| Secrets | hand-placed `/etc/secrets/*` (no sops/agenix) | — |

**Gotcha:** Cloudflare Browser Integrity Check returns 403 for the `Python-urllib/*` user agent. The desktop app must send its own `User-Agent` (e.g. `Phoenix-Desktop/<ver>`). `auth.phoenix.exposed` and the new `api.` host also need the BIC exception.

## 3. Target architecture

```
Desktop (public OAuth client) ──OIDC (auth code+PKCE loopback, or device code)──▶ auth.phoenix.exposed (MAS)
        │  access_token (Bearer)                                                     ▲ introspect
        ▼                                                                            │
api.phoenix.exposed (NEW service) ───────────────────────────────────────────────────┘
   POST /v1/vpn/peer      {public_key, hostname} → WireGuard {Interface, Peer}
   POST /v1/wazuh/enroll  → {manager, group, one-time enrollment password}
   GET  /v1/me            → user, entitlements (VPN/AV/SIEM/chat)
   DELETE /v1/device      → revoke peer + agent (logout)
Chat (LLMAgent-api)  → accepts the Bearer token (introspection) in addition to / instead of source-IP
```

### Desktop login: recommended flow
1. Discovery: `GET https://matrix.phoenix.exposed/_matrix/client/v1/auth_metadata`. Do not hardcode the MAS endpoints.
2. Client registration (MSC2966) is either dynamic, as `application_type: native` with `client_uri`/`logo_uri` on phoenix.exposed and loopback `redirect_uris`, or a **static client pre-registered** in `/etc/secrets/phoenix-mas.yaml`. A static client is simpler and gives a stable `client_id`.
3. Primary flow: authorization code + PKCE with a loopback redirect `http://127.0.0.1:<port>/callback` (RFC 8252). The system browser opens the MAS login page. Fallback: the **device code grant** for headless use or a show-QR/code UX.
4. Scopes: `openid urn:matrix:org.matrix.msc2967.client:api:* urn:matrix:org.matrix.msc2967.client:device:<DEVICE_ID>`. Make the device ID stable per install so the Matrix device list shows the machine.
5. Store the access and refresh tokens via `settings.set_secret("auth", ...)`. Keep `auth.user_id` (`@user:phoenix.exposed`) in place of email as the identity. Refresh on 401 or before expiry. Logout calls `/oauth2/revoke`.
6. Startup gate: validate the token (refresh, or `GET /_matrix/client/v3/account/whoami`) instead of trusting the `logged_in` flag.

The token is a real Matrix token, so the Chat plugin could later talk to Matrix rooms directly.

### Device model

One account has many devices, and each install is one device. A single device ID is the key in every system:

| System | What the device ID becomes |
|---|---|
| MAS / Synapse | the Matrix device (scope `urn:matrix:client:device:<ID>`), shown in Element → Sessions and MAS `/account` |
| WireGuard | the peer's key on the server. Re-login replaces that device's peer instead of adding another one. |
| Wazuh | the agent name. The agent group comes from the account or tenant, not from the device. |
| Chat (LLMAgent-api) | which device a request came from, via the Bearer token instead of the source IP |

**Device ID.**
- Derive it from the hardware ID that the Wazuh code already reads (`/etc/machine-id`, `IOPlatformUUID`, `MachineGuid`; see `wazuh_functions_{linux:98-117, darwin:46-58, windows:68-90}`).
- Format: `PHX_` + base32 of `sha256(app_salt + hw_id)`, cut to 16 characters. Only URL-unreserved characters, at least 10 characters (MSC2967).
- Store it in `auth.device_id` and read it from there afterwards. This replaces the `hostname-<id12>` agent name, so a reinstall on the same machine keeps the same identity everywhere.
- Hash the hardware ID, never send it raw.
- Fallback when no hardware ID can be read: a random ID, persisted.

**The server reads user and device from the token, never from the request body.**
- `api.phoenix.exposed` introspects the Bearer token at MAS. `username` gives the user, and the `urn:matrix:client:device:*` entry in `scope` gives the device.
- `hostname` is a display label only.
- Otherwise any logged-in user could claim another machine's VPN peer or Wazuh agent.

**Only the desktop client may use `PHX_*` device IDs.**
- Register the desktop as a **static** MAS client (resolves open question 6). The stable `client_id` is what the policy below refers to.
- Add a MAS policy (`authorization_grant` / `device_code` entrypoints) that refuses `urn:matrix:client:device:PHX_*` for any other `client_id`.
- Restrict open dynamic client registration, which is on today, so nobody can register a lookalike "Phoenix" client and phish consent.
- Use the stable scope names (`urn:matrix:client:api:*`, `urn:matrix:client:device:*`) rather than the `org.matrix.msc2967` ones in step 4 above. MAS 1.26 accepts both.

**Revocation from anywhere.**
- Signing a device out in the app, in Element → Sessions, or in MAS `/account` must remove its WireGuard peer and Wazuh agent.
- Logout in the app keeps calling `DELETE /v1/device`.
- On top of that, a sync job in `api.phoenix.exposed` polls the MAS admin API for finished sessions of the desktop client and runs the same cleanup. MAS has no webhooks, as far as known. `ai_bot.py:345-416` is the reference MAS admin client.
- The cleanup must be idempotent.

**Account-level work runs on the first device.**
- The first successful `/v1/vpn/peer` or `/v1/wazuh/enroll` for an account runs a one-time init:
  - tenant setup (Wazuh group, Wazuh dashboard user, any tenant script)
  - recorded in the registry so later devices skip it
- It must be safe to run twice.
- Neither the dashboard user nor the tenant init exists anywhere yet.
- "Tenant" still has to be defined: one account, or an organisation with several accounts (see open question 8).

**Registry** (owned by `api.phoenix.exposed`): `user_id, device_id, mas_session_id, wg_pubkey, wazuh_agent_id, tenant, enrolled_at, last_seen, revoked_at`.

**Accepted trade-off.** With `urn:matrix:client:api:*`, the desktop token is a full Matrix account token. That is acceptable for a first-party app. Without that scope there is no Matrix device, so the device list stops being the registry. Proof-of-possession with a Matrix device key (ed25519) is left out for now, because the app is not an E2EE Matrix client. Revisit it if chat moves to Matrix.

**Verify on a throwaway MAS user before building:**
1. Requesting a device ID that already exists: does MAS reuse it or refuse it? This decides whether a reinstall resumes the same device.
2. Does the introspection response include the device scope and `username`?
3. Can the MAS 1.26 admin API list OAuth2 sessions filtered by client and status, and finish a session?
4. Is the OIDC `sub` the Matrix ID or the MAS ULID? This matters for the Wazuh dashboard OIDC login (open question 4).

## 4. Work breakdown

**A. Server (`~/.flakes`, `Resistine-matrix-server`)**
1. Register the MAS client for the desktop app (static `clients:` entry, public client, loopback redirect, device-code allowed).
2. Build `api.phoenix.exposed`:
   - FastAPI in the style of `Resistine-LLMAgent-api`.
   - Its own confidential MAS client for `/oauth2/introspect`.
   - WireGuard peer provisioning, replacing `validate.resistine.work/verify-otp`.
   - Wazuh group creation plus a per-device enrollment password through the Wazuh manager API.
3. Infra for the new host: nginx vhost on 8448, Origin cert `/etc/ssl/phoenix-api`, Cloudflare tunnel hostname with "Origin Server Name", BIC exception.
4. Decide where the WireGuard server now lives, since it has been removed from briareosai, and point peer provisioning at it.
5. Wazuh manager on `dashboard.phoenix.exposed`: turn on authd password or `-P` enrollment; group naming by Matrix localpart instead of email.
6. LLMAgent-api: accept MAS bearer tokens, not just source IP mapped to an agent.

**B. Desktop**
1. Replace `plugins/login/api.py` with an OIDC client module, e.g. `plugins/login/oidc.py` (discovery, PKCE, loopback server, device code, refresh, revoke) plus `plugins/login/phoenix_api.py` (Bearer calls to api.).
2. Rework the `plugins/login/main.py` UI: drop the email/OTP form for a "Sign in with Phoenix" button that opens the browser, plus a device-code fallback screen. Route the signup URL to Phoenix.
3. Move the auth state into secrets: `auth.access_token`, `auth.refresh_token`, `auth.user_id`, `auth.device_id`. Make `logged_in` derived.
4. `main.py:83` gate: validate the token at startup and close the "uninstall Login plugin = skip auth" bypass, or mark it as intended for offline/BYO-config use.
5. VPN: call `POST /v1/vpn/peer` after login, reusing `setup_vpn_keys` and `save_vpn_config`. Move the Linux `keys.json` into `set_secret`.
6. Wazuh: use the group, manager and enrollment password from `/v1/wazuh/enroll`. Pass `-P` to `agent-auth` and the MSI/postinstall scripts. Point `config.py` at `dashboard.phoenix.exposed`. Remove `_RESISTINE_API_BASE`.
7. Logout (`plugins/settings/main.py:401`): revoke the token, `DELETE /v1/device`, then the existing cleanup.
8. Set an HTTP `User-Agent` on every outgoing request.
9. Tests: new unit tests for the OIDC module (mock MAS); rewrite `test_login_api.py` and `test_auth_flow.py`; update the logout tests.

**C. Rebrand Resistine → Phoenix** (separate PR, after auth works)
- **Low risk** (strings, URLs):
  - UI strings (`login/main.py:95,221`), README/docs.
  - Hosts `resisti.net`/`resistine.work` → `phoenix.exposed`.
  - OTel `utils/logger.py:18,41`.
  - Appcast URL.
  - flake.nix `pname`/`mainProgram`.
  - deb `control.template`.
- **Needs migration code:**
  - Config dir (`utils/settings.py:38-51`).
  - Keyring service `resistine-master-key`. Without migration, every encrypted secret is lost.
  - WireGuard tunnel/interface name `resistine`.
  - Windows service `ResistineVPN` and `%PROGRAMDATA%\Resistine`.
  - Linux polkit actions and helpers.
  - Wazuh key backup paths and the keychain `com.resistine.wazuh.agent`, plus the existing uninstall mismatch at `utils/uninstall/darwin.py:410`.
- **Needs Apple-side changes:**
  - Bundle IDs `com.resistine.desktop*`, the system extension ID, App Group `group.Resistine.WireguardTest`, Team `C7KSRZC3Q9`.
  - Provisioning profiles, `SMPrivilegedExecutables` (`CN="Resistine"`), the URL scheme, and the Sparkle `SUPublicEDKey`/feed.
  - Coordinate with the `resistine-vpn-macos` repo.
  - Changing bundle IDs makes this a new app to macOS: the system extension is re-approved and the old one has to be uninstalled.
- Windows Inno Setup `ResistineInstaller.iss` (AppId, Run keys, registry).
- Keep `Resistine/*` GitHub repo names unless they are renamed too (plugin index URL `plugin_manager.py:25`).

## 5. Open questions
1. Where does the current `validate.resistine.work` OTP backend live, and who runs the `rfr1.resisti.net` WireGuard server? Neither is in the two trees.
2. Is the WireGuard concentrator for Phoenix a new host? It is not on briareosai anymore.
3. Account creation: admin-only stays (registration is off in MAS), or open self-signup / registration tokens?
4. Identity key for Wazuh groups and VPN peers: Matrix `user_id` or MAS user ULID? Email is optional in MAS.
5. Is the Wazuh 5.0 "phoenix" build (port 1517) the target for desktop agents too, replacing 4.11/4.14 on 1514/1515?
6. Static or dynamic MAS client registration?
7. Does the rebrand include GitHub org/repo names and the Apple team, or only user-facing names and IDs?
8. What is a tenant: one account, or an organisation with several accounts? This decides the Wazuh group, the dashboard user, and the init script (see Device model).
