# Architectural Decisions

Record significant architectural choices and their rationale here.

## Template

### [Date] — Decision Title
- **Context:** Why did this come up?
- **Decision:** What was decided?
- **Rationale:** Why this approach over alternatives?
- **Consequences:** What trade-offs were accepted?

---

### 2026-03-30 — Plugin-based architecture
- **Context:** Need modular feature set (VPN, antivirus, SIEM, etc.) across platforms
- **Decision:** Plugin system with `BasePlugin` subclasses, registered via `default_plugins.json`
- **Rationale:** Allows optional features, clean separation, independent development
- **Consequences:** Each plugin manages its own platform-specific code; shared logic must be explicitly extracted

### 2026-03-30 — macOS VPN via Swift CLI bridge + NetworkExtension
- **Context:** macOS requires NetworkExtension for system VPN tunnels
- **Decision:** Swift CLI (`resistine-vpn-cli`) communicates with NetworkExtension via XPC
- **Rationale:** Python can't directly use NetworkExtension; CLI bridge keeps Python side simple
- **Consequences:** Extra build artifact, 5s polling gap for status sync

### 2026-11-12 — Removing a device runs on the server
- **Context:** Devices → Sessions lists every device of the account and removes the old ones (dev-docs/plans/device-sessions.md).
- **Decision:** The app calls `DELETE /v1/devices/{id}` on the Phoenix API; the server finishes the MAS session and drops the VPN peer and Wazuh agent.
- **Rationale:** CS API `DELETE /devices` needs UIA that Synapse cannot do under MAS; MAS GraphQL would need an admin scope on every desktop token and leave VPN/agent cleanup to a client that may crash halfway. The MAS account page stays as the "Manage in browser" fallback.
- **Consequences:** The tab needs the server endpoints and a MAS admin client; until then it shows "not available".

### 2026-11-12 — Verify this device with the recovery key, own SSSS code
- **Context:** Element shows Phoenix devices as unverified; nio's SAS speaks only the legacy to-device flow, which Element and Element X no longer accept.
- **Decision:** `plugins/login/cross_signing.py` reads the self-signing key from secret storage with the user's Element recovery key (or passphrase), signs this device's keys and uploads the signature. Built on `cryptography`, checked against Element-made keys (mautrix-python vectors).
- **Rationale:** Switching to mautrix-python or matrix-rust-sdk would change the chat transport and all packaging for one feature.
- **Consequences:** No interactive emoji verification; revisit if that becomes a requirement. The recovery key is never stored or logged.

### 2026-11-12 — The app verifies only itself
- **Context:** The Sessions list could offer "verify" on every device.
- **Decision:** Only this device can be verified from the app; other sessions show their status and are verified from Element.
- **Rationale:** Signing another device's keys from a list is trust-on-first-use and would make "verified" meaningless.
- **Consequences:** Users with several Phoenix installs verify each one on that computer.

### 2026-11-13 — Unknown is a state of its own; data has an age
- **Context:** The shell showed every unreadable or stale check as a warning or as green, and nothing said how old the numbers were (GUI ideation, idea 3).
- **Decision:** `BasePlugin.status_info()` returns ok / warning / error / off / unknown with a reason; unknown glows amber in the rail with the reason as a caption. Headers and tiles carry "As of 7 min ago · next check 22:39". The Dashboard opens with one sentence ("3 alerts this week, all false positives. Nothing needs you.") that withholds the verdict while any tile is unknown; once a week the sentence is posted into the user's SIEM alerts DM; a plugin unknown past 3× its freshness window gets one toast per episode.
- **Rationale:** Not knowing must never look calmer than a minor problem, and never redder than a real one. Posting into the bot's DM reuses the running Matrix session and the room the user already watches on the phone; siemgent reads reactions only, and the listener keeps the bot's messages only, so the post never comes back as an alert.
- **Consequences:** Legacy `get_status()` strings stay for Store and Dashboard consumers. Only counts and tile names leave the machine in the post; alert text never does. One post per machine per week, labelled with the hostname.
