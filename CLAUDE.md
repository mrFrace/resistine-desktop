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

All features are plugins in `plugins/`. Each plugin subclasses `plugins/base_plugin.py:BasePlugin` and overrides `create_main_screen()`. Plugins are discovered by scanning the `plugins/` directory (and a user plugins directory) at runtime. `plugins/plugin_manager.py` handles dynamic loading and ordering.

Core (non-uninstallable) plugins: Dashboard, Store, Help, Settings. Optional: Login, Chat, VPN, Wazuh, Antivirus.

### Platform-Specific Code

Platform-specific implementations live in `*_functions_{darwin,linux,windows}.py` files within each plugin. The VPN plugin (`plugins/vpn/`) has three separate platform modules. macOS VPN uses a Swift CLI bridge (`resistine-vpn-cli`) that communicates with a NetworkExtension via XPC.

### Settings & Secrets

`utils/settings.py` provides namespaced JSON config with Fernet encryption for secrets (prefixed `ENC:`). Master key stored in system keyring. Config dirs: `~/Library/Application Support/Phoenix` (macOS), `%APPDATA%/Phoenix` (Windows), `~/.config/phoenix` (Linux); a pre-rebrand `Resistine`/`resistine` dir and the `resistine-master-key` keyring entry are migrated on first start.

### GUI

`main.py` is the app entry point (builds a `QApplication` and the `gui/app_window.py` main window). UI components are in `gui/`. The plugin manager injects plugin screens into the main window. Theme switching (light/dark) via `gui/theme_manager.py`.

### Logging

`utils/logger.py` configures Loguru with OpenTelemetry integration. Logs rotate at 10 MB, compress after 1 week. Intercepts stdlib logging.

### CI/CD

- `.github/workflows/ci.yml`: syntax check via `python -m compileall` on push/PR (Python 3.13)
- `.github/workflows/release.yml`: macOS build + sign + notarize + DMG + Sparkle appcast on version tags

### External Artifacts

VPN CLI binary downloaded from `Resistine/resistine-vpn-macos` CI. ClamAV binaries from `Resistine/ClamAV-Mac` CI. Both are fetched during the build process via `gh` CLI.

## Key Conventions

- Platform requirements split: `scripts/requirements/requirements-{mac,windows,linux}.txt`
- Test deps: `scripts/requirements/requirements-test.txt`
- Python 3.13 target
- Ruff for linting (rules: B, D3, E, F; E501 ignored), Black for formatting, isort with Black profile
