# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Phoenix Desktop is a cross-platform (macOS/Linux/Windows) security desktop app built with Python and PyQt6. It was renamed from Resistine; bundle IDs, service names and system paths still carry the old name. It provides VPN (WireGuard), antivirus (ClamAV), SIEM (Wazuh), endpoint management, and AI chat through a modular plugin system.

## Commands

### Environment

Before running python, pytest, or any Python tool, activate the venv: `source .venv/bin/activate`

### Running the App

```bash
./scripts/install.sh           # First-time: install deps + launch
./run.sh                       # Launch from existing venv
python main.py                 # Direct launch (requires venv active)
python main.py -d              # Debug mode with runtime inspector
```

### Tests

```bash
./run_tests.sh              # All tests
./run_tests.sh unit         # Unit tests only
./run_tests.sh fast         # Unit + security (skip slow)
./run_tests.sh coverage     # All tests + HTML coverage report
python -m pytest tests/unit/test_settings.py           # Single file
python -m pytest tests/unit/test_settings.py::TestFoo  # Single class
python -m pytest -m platform_darwin                     # By marker
```

Test markers: `unit`, `integration`, `security`, `platform_darwin`, `platform_windows`, `platform_linux`, `slow`, `network`.

`tests/unit/test_security_hardening.py` pins security rejection paths (unsigned updates refused, IPC input validation, shell-metacharacter sanitization). Never weaken these to make a feature pass — change the feature.

### Linting (Trunk)

```bash
trunk check                    # Run all linters on changed files
trunk check --all              # Lint entire repo
trunk check path/to/file.py   # Lint specific file
trunk fmt                      # Auto-format changed files
```

Configured linters: ruff, black, isort, bandit, shellcheck, shfmt, markdownlint, prettier, trufflehog, checkov. Pre-commit hook runs `trunk fmt`, pre-push runs `trunk check`.

### Build (macOS)

```bash
./scripts/build/build-distribution.sh   # Full build: PyInstaller + sign + notarize + DMG
./scripts/build/build-installer.sh      # PyInstaller .app bundle only
```

### Build (Windows, from Linux)

```bash
./scripts/build/build-windows-vm.sh     # Phoenix-Setup-<version>.exe into dist/installers/
```

Runs `scripts/build/build-windows-installer.ps1` (PyInstaller + Inno Setup) over SSH in a throwaway copy of the golden Windows image from `Resistine-Server-install/scripts/windows/make_golden.sh` (dockur/windows, needs docker and /dev/kvm). Set `GOLDEN_DIR` if the image is not in `/var/lib/phoenix-win/golden`, and `BUILD_DIR` off tmpfs (the VM disk copy is sparse, up to 64 GB). The installer must stay silent-safe: WinSparkle upgrades run it with `/VERYSILENT /SUPPRESSMSGBOXES`, so use `SuppressibleMsgBox`, never `MsgBox`.

### NixOS

`flake.nix` builds the app (`packages.phoenix`) and exports `nixosModules.default` (`nix/module.nix`: `programs.phoenix.*`, plus the SIEM agent service in `nix/wazuh-agent.nix`). On NixOS the app can't install packages or write `/etc`, so ClamAV units, the agent and the VPN prerequisites come from this module. VM test: `nix build .#checks.x86_64-linux.nixos-module -L` (needs the phoenix-agent `.deb` in the store).

## Architecture

### Plugin System

All features are plugins in `plugins/`. Each plugin subclasses `plugins/base_plugin.py:BasePlugin` and overrides `create_main_screen()` (returns a QWidget). Plugins are discovered by scanning the `plugins/` directory (and a user plugins directory) at runtime. `plugins/plugin_manager.py` handles dynamic loading, ordering, and Store downloads.

Core (non-uninstallable) plugins: Dashboard, Store, Help, Settings. Optional: Login, Chat, VPN, Wazuh (Endpoint), Devices, Antivirus. `plugins/devices/` is the successor of the removed Wazuh Overview: it is built on the posture cards from `GET /v1/me/posture` (`plugins/dashboard/posture.py`), the SIEM alerts from Matrix and the local agent state, because the Phoenix API has no vulnerability/inventory/SCA endpoints; its charts are QPainter (no matplotlib).

### GUI (PyQt6)

`main.py` is the entry point (QApplication). `gui/app_window.py` hosts the icon-rail sidebar (SVG nav icons with status glow), a QStackedWidget of plugin screens, and slide-in sub-views. `gui/page_kit.py` is the flat page kit (Page, PageHeader, SettingRow, MenuRow) plugin screens are built from; `gui/qt_widgets.py` has shared widgets (Card, CardGrid, StatusBadge, set_pill). Theming is palette-driven in `gui/theme.py` (Phoenix brand tokens, light/dark pairs) — use `theme.color(name)`, never hardcoded hex in screens.

### i18n

`utils/i18n/` holds the catalog (13 locale JSONs) and `get_text(key, **fmt)`. User-visible strings go through the catalog; `utils/i18n/extractor/` finds unwired strings. Language switching is instant (Settings rebuilds the shell). Plugin sidebar names localize via `BasePlugin.get_display_name()` — `get_name()` stays the stable English identifier used for navigation keys.

### Chat & SIEM alerts

`plugins/chat/` has a pluggable transport: OpenAI-compatible HTTPS (`utils/chat_endpoint.py`, internal root CA in `resources/certs/`) or end-to-end-encrypted Matrix (`matrix_transport.py`). SIEM alerts from siemgent arrive over Matrix into a read-only alerts view (`siem_alerts.py`) and the Dashboard. **Alert text is untrusted** (it quotes monitored-host data): render it with `markdown_to_html(..., allow_html=False)` and links disabled — both the Dashboard's `_AlertText` and chat's `untrusted=True` bubbles do this; follow that pattern for any new alert surface.

### Platform-Specific Code

Platform-specific implementations live in `*_functions_{darwin,linux,windows}.py` files within each plugin. macOS VPN uses a Swift CLI bridge (`resistine-vpn-cli`) talking to a NetworkExtension via XPC. Windows VPN uses a SYSTEM service (`plugins/vpn/wireguard/windows_vpn_service.py`) reached over token-authenticated localhost IPC — every value received over that IPC is attacker-controllable and must be validated (`config_validation.is_valid_config_name`, path confinement).

### Security conventions (do not regress)

- Anything interpolated into a privileged command (root `sh -c`, `osascript ... with administrator privileges`, elevated PowerShell) must be quoted with the module's helpers (`shlex.quote`, `_applescript_string`/`_sh`, `_ps_quote`) AND allowlist-sanitized if it originates from settings, the network, or the user.
- Never write predictable fixed paths in shared temp dirs for privileged reads/writes — use `tempfile.mkdtemp()`/uuid-suffixed names.
- Updates and plugins are executable content: signatures are mandatory (a missing signature is a hard failure, same as a bad one), downloads are HTTPS-only.
- Secrets go through `utils/settings.py` `set_secret`/`get_secret` (Fernet, `ENC:` prefix, master key in system keyring). `get_secret` fails closed on un-prefixed values.
- Server-supplied WireGuard configs go through `plugins/vpn/wireguard/config_validation.py` (rejects `PostUp`/`PreUp`/... script hooks). Files holding private keys are 0600/SYSTEM-only.

### Settings & Secrets

`utils/settings.py` provides namespaced JSON config with Fernet encryption for secrets (prefixed `ENC:`). Master key stored in system keyring. Config dirs: `~/Library/Application Support/Phoenix` (macOS), `%APPDATA%/Phoenix` (Windows), `~/.config/phoenix` (Linux); a pre-rebrand `Resistine`/`resistine` dir and the `resistine-master-key` keyring entry are migrated on first start.

### Auth

`main.py` is the app entry point (builds a `QApplication` and the `gui/app_window.py` main window). UI components are in `gui/`. The plugin manager injects plugin screens into the main window. Theme switching (light/dark) via `gui/theme_manager.py`.

### Logging

`utils/logger.py` configures Loguru with OpenTelemetry integration. Logs rotate at 10 MB, compress after 1 week. Intercepts stdlib logging. Never log secret values, tokens, or private keys.

### CI/CD

- `.github/workflows/ci.yml`: compileall + pip-audit on push/PR (Python 3.13)
- `.github/workflows/release.yml`: macOS build + sign + notarize + DMG on version tags (appcast publishing retired with the old update channel)

### Updates

**Auto-updates are hard-disabled** (`utils/updates/manager.py: UPDATES_ENABLED = False`): the legacy feed and its signing keys belong to the old company, so Phoenix builds carry no feed URL and no update public key. Re-enabling requires Phoenix-owned feed infrastructure plus a FRESH signing keypair generated in CI — never re-point at the old endpoint. The platform backends (`utils/updates/{darwin,windows,linux}.py`) keep their verification logic: signatures are mandatory, unsigned entries are refused.

### External Artifacts

VPN CLI binary and ClamAV binaries are fetched during the build via `gh` CLI (currently from legacy artifact repos — being re-homed to Phoenix infrastructure along with signing certificates).

## Key Conventions

- Platform requirements split: `scripts/requirements/requirements-{mac,windows,linux}.txt`
- Test deps: `scripts/requirements/requirements-test.txt`
- Python 3.13 target
- Ruff for linting (rules: B, D3, E, F; E501 ignored), Black for formatting, isort with Black profile
