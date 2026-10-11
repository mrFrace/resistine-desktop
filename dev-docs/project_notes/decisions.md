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
