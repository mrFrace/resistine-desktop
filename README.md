# Phoenix AI EndPoint Detection and Response (AI EDR)

For Windows, Mac, and Linux desktops.

## Prerequisites

- Python 3.12+ (unless using a precompiled distribution)
- macOS 13+ (Ventura), Windows 11, or Linux
- [GitHub CLI](https://cli.github.com/) (`gh`) authenticated — used to download build artifacts
- Apple Developer ID certificate (macOS distribution builds only)

## Running from Source

```bash
./install.sh   # first time — installs dependencies
./run.sh       # run the app
./run.sh -d    # run in debug mode (runtime inspector)
```

Debug mode is also enabled automatically when running inside VSCode or JetBrains IDEs.

## Command Line Arguments

```
usage: main.py [-h] [-d] [-l {DEBUG,INFO,WARNING,ERROR,CRITICAL}]

  -h, --help       Show help
  -d, --debug      Enable debug mode
  -l, --log-level  Set logging level (default: INFO)
```

## Building for macOS

### Pre-Setup (one-time)

1. **Xcode Command Line Tools** (required for codesign, notarytool, etc.):
   ```bash
   xcode-select --install
   ```

2. **Python 3.12+** from [python.org](https://www.python.org/downloads/) (universal2 build):
   ```bash
   # Do NOT use Homebrew Python — it only targets the current macOS version.
   # Verify python.org install:
   /Library/Frameworks/Python.framework/Versions/3.*/bin/python3 --version
   ```

3. **Homebrew** (if not already installed):
   ```bash
   /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
   ```

4. **GitHub CLI** (used to download VPN and ClamAV artifacts from CI):
   ```bash
   brew install gh
   gh auth login
   ```
   Your account needs read access to `Resistine/resistine-vpn-macos` and `Resistine/ClamAV-Mac`.

5. **Apple Developer ID certificate** — must be installed in your Keychain. Verify:
   ```bash
   security find-identity -v -p codesigning | grep "Developer ID Application"
   ```
   If nothing shows up, import the certificate from your Apple Developer account or ask the team lead.

6. **Notarization credentials** (optional — the build will prompt if missing):
   ```bash
   xcrun notarytool store-credentials "resistine-notarize" \
     --apple-id "your@email.com" --team-id "YOURTEAMID" \
     --password "<app-specific-password>"
   ```

7. **Clone the repo and switch to the build branch**:
   ```bash
   git clone git@github.com:Resistine/Resistine-Desktop.git
   cd Resistine-Desktop
   git checkout build/vpn-artifacts
   ```

### Prerequisites Summary

| Tool | Install | Verify |
|------|---------|--------|
| Xcode CLI Tools | `xcode-select --install` | `xcode-select -p` |
| Python 3.12+ (python.org) | [python.org/downloads](https://www.python.org/downloads/) | `python3 --version` |
| Homebrew | [brew.sh](https://brew.sh) | `brew --version` |
| GitHub CLI | `brew install gh` | `gh auth status` |
| Developer ID cert | Apple Developer portal | `security find-identity -v -p codesigning` |

### Distribution Build (signed + notarized DMG)

```bash
scripts/build/build-distribution.sh
```

This script:
1. Downloads VPN artifacts from `Resistine/resistine-vpn-macos` CI (or builds locally from `vpn-apple/`)
2. Downloads ClamAV artifacts from `Resistine/ClamAV-Mac` CI
3. Builds the Python app with PyInstaller
4. Places VPN and ClamAV components in the app bundle
5. Signs everything with Developer ID
6. Creates a DMG, notarizes, and staples it
7. Installs to `/Applications/`

Output: `dist/Phoenix-Installer.dmg` (contains `Resistine.app`; the bundle keeps its pre-rebrand file name for now)

### Local Dev Build (signed, not notarized)

```bash
scripts/build/build-installer.sh
```

Uses Apple Development certificate instead of Developer ID. Good for local testing.

### Artifact Scripts

VPN and ClamAV components are built by separate repos and downloaded as CI artifacts:

```bash
scripts/build/download-vpn-artifacts.sh      # from Resistine/resistine-vpn-macos
scripts/build/download-clamav-artifacts.sh    # from Resistine/ClamAV-Mac
```

These run automatically during the build. To manually refresh:

```bash
scripts/build/download-vpn-artifacts.sh          # download latest
scripts/build/download-clamav-artifacts.sh        # download latest
scripts/build/download-vpn-artifacts.sh --check   # check if up-to-date
```

## Building for Windows

```powershell
scripts\build\build-windows-installer.ps1
```

Requirements:
- `python` on PATH
- Inno Setup 6 (`ISCC.exe`) installed

The installer bundles Python dependencies via PyInstaller and attempts to install WireGuard and GTK3 runtime via `winget`.

## Testing the Build

After building, verify:

1. **App launches**: Open `Resistine.app` (or run from `/Applications/`)
2. **VPN**: Connect to a WireGuard server — confirm tunnel activates
3. **Antivirus**: Trigger a scan — confirm ClamAV binaries run
4. **Signatures**: `codesign --verify --verbose /Applications/Resistine.app`

## WireGuard Configuration

```bash
cp plugins/vpn/wireguard/wg0-example.conf plugins/vpn/wireguard/wg0.conf
```

Edit `wg0.conf` with your VPN server details (PrivateKey, Address, Endpoint, PublicKey).

## License

Copyright (C) 2025 Resistine

This program is free software under the terms of the GNU General Public License v2 or later.

Phoenix comes with ABSOLUTELY NO WARRANTY.

See the [LICENSE](LICENSE.md) file for more details.
