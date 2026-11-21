# Release History

> The history below predates the Phoenix update channel. The Sparkle and
> WinSparkle updaters it mentions are removed; see "Update Instructions"
> for how updates work now.


Complete release history for Phoenix Desktop across all platforms.

## Version 2026.03.19

**Release Date:** March 19, 2026

### What's New
- Fixed Sparkle auto-update crash on macOS
- Switched to date-based versioning
- Improved markdown rendering: tables, box diagrams, admonitions, and ASCII art
- Cairo rendering backend for Linux with antialiasing support
- Wazuh endpoint agent support on Linux and Windows with Sysmon integration
- Smoother cross-platform scrolling for chat, settings, and help plugins
- Updated app icon for all platforms and reorganized file structure
- Fixed VPN DNS serialization and Linux connection issues
- Windows: suppress console windows during installs, elevate config writes
- Linux: Ctrl+A support, scrollbar fixes, and VPN page padding

### Platform Downloads
- **macOS**: phoenix-desktop-Mac-2026.03.19.dmg (41.2 MB)
- **Windows**: Phoenix-Setup-2026.03.19.exe
- **Linux**: Available via package managers

---

## Version 1.0.5

**Release Date:** March 11, 2026

### What's New
- Wazuh endpoint protection agent integration with full lifecycle management
- Wazuh keys stored securely in macOS Keychain
- VPN-gated agent connectivity — agent activates only when VPN is connected
- Agent group registration through the API
- Agent auto-reconnects after install without requiring a restart
- Refreshed UI — replaced orange buttons with blue theme
- Improved uninstall and reinstall logic across macOS and Windows
- Multi-device login support via hostname in OTP verification
- Fixed Wazuh agent signup bug on macOS

### Platform Downloads
- **macOS**: Phoenix-Installer-1.0.5.dmg (42.5 MB)
- **Windows**: Available from previous releases
- **Linux**: Available via package managers

---

## Version 1.0.4

**Release Date:** March 3, 2026

### What's New
- Extended Wazuh support
- Performance improvements

### Platform Downloads
- **macOS**: Phoenix-Installer-1.0.4.dmg (36.9 MB)

---

## Version 1.0.3

**Release Date:** March 2, 2026

### What's New
- New macOS release with stability improvements

### Platform Downloads
- **macOS**: Phoenix-Installer-1.0.3.dmg (36.8 MB)

---

## Version 1.0.2

**Release Date:** February 16, 2026

### What's New
- Polished UI themes for chat and help plugins (dark + light)
- Reworked chat welcome screen with suggestion prompts
- Multi-config VPN support with import, delete, and switch
- Refined login OTP flow and settings card layout
- Replaced icons with Phosphor icon set

### Platform Downloads
- **macOS**: Phoenix-Installer-1.0.2.dmg (42.3 MB)

---

## Version 1.0.1

**Release Date:** February 10, 2026

### What's New
- Reorganized update system architecture
- Added in-app uninstall option

### Platform Downloads
- **macOS**: Phoenix-Installer-1.0.1.dmg (36.9 MB)

---

## Version 1.0.0

**Release Date:** February 9, 2026

### What's New
- VPN management with WireGuard
- AI-powered endpoint protection
- Auto-update support via Sparkle

### Platform Downloads
- **macOS**: Phoenix-Installer.dmg (36.8 MB)

---

## Platform Support

### Current Versions by Platform

| Platform | Current Version | Auto-Update | Status |
|----------|-----------------|-------------|--------|
| macOS (13.0+) | 2026.03.19 | ✓ In-app | Stable |
| Windows (10+) | 2026.03.19 | ✓ In-app | Stable |
| Linux | 2026.03.19 | ✓ Package Manager | Stable |
| Android | TBD | ✓ Google Play | Coming Soon |

### System Requirements

- **macOS**: 13.0 or later (Intel/Apple Silicon)
- **Windows**: Windows 10 or later (64-bit)
- **Linux**: Ubuntu 20.04+, Fedora 35+, other modern distributions
- **Android**: Android 8.0+

---

## Update Instructions

### macOS
Phoenix checks its signed update channel once a day and tells you when a newer build exists. Settings → Updates → "Download and install" fetches it, checks it against the signed release and starts it.

**Manual Update:**
1. Download the latest DMG from the releases page
2. Open the DMG and drag Phoenix to Applications
3. Restart the application

### Windows
Phoenix checks its signed update channel once a day and tells you when a newer build exists. Settings → Updates → "Download and install" fetches it, checks it against the signed release and starts it.

**Manual Update:**
1. Download the latest .exe installer
2. Run the installer
3. Follow the installation wizard

### Linux
Updates are delivered through your package manager:

```bash
# Ubuntu/Debian
sudo apt update && sudo apt upgrade phoenix

# Fedora
sudo dnf upgrade phoenix

# Arch
sudo pacman -Su phoenix
```

---

## Reporting Issues

Found a bug? Have a feature request?

- **GitHub Issues**: [Report on GitHub](https://github.com/DatOneOPGuy/phoenix-desktop/issues)
- **Email**: support@phoenix.dev
- **Community**: Join our community forum

---

## Version Numbering

Starting with version 2026.03.19, we use **date-based versioning**:
- Format: `YYYY.MM.DD`
- Example: `2026.03.19` = March 19, 2026

Earlier versions (1.0.x) used semantic versioning.
