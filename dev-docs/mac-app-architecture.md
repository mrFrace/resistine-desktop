# Resistine macOS App Architecture

This document describes the architecture of the Resistine macOS application, with a focus on how privileged components (like the VPN Network Extension) integrate with the main Python UI.

## Overview

Resistine is a cross-platform security application with a **Python/CustomTkinter UI** that embeds native **Swift components** for privileged macOS operations.

┌─────────────────────────────────────────────────────────────────┐
│                    Resistine.app (PyInstaller)                  │
├─────────────────────────────────────────────────────────────────┤
│  Contents/                                                      │
│  ├── MacOS/                                                     │
│  │   ├── Resistine             ← Python executable              │
│  │   └── resistine-vpn-cli     ← Swift VPN Controller           │
│  ├── Frameworks/               ← Python framework + deps        │
│  ├── Resources/                                                 │
│  │   └── plugins/              ← Python plugin modules          │
│  ├── PlugIns/                                                   │
│  │   └── network-extension.appex  ← Network Extension           │
│  └── _CodeSignature/                                            │
└─────────────────────────────────────────────────────────────────┘

## Communication Pattern

The Python UI communicates with privileged Swift components via **subprocess calls** to a CLI tool:

```
Python Plugin (UI)
       │
       │ subprocess.run(["resistine-vpn-cli", "start|stop|status"])
       ▼
Swift CLI Tool (Resistine.app/Contents/MacOS/)
       │
       │ NetworkExtension / SystemConfiguration APIs
       ▼
App Extension (PlugIns/network-extension.appex)
       │
       │ System Frameworks
       ▼
macOS Kernel / System Services
```

### Why CLI, Not Direct XPC?

| Approach | Pros | Cons |
|----------|------|------|
| **CLI (chosen)** | Simple, no PyObjC, easy to test | Extra process overhead |
| **XPC from Python** | Direct, efficient | Requires PyObjC, complex |
| **Embedded Swift** | Tight integration | Bundling complexity |

---

## Code Signing Architecture

macOS requires strict code signing for privileged components. Here's the signing hierarchy:

```
Resistine.app (signed with Developer ID Application)
├── resistine-vpn-cli (signed with Developer ID + provisioning profile)
└── network-extension.appex (signed with Developer ID + provisioning profile)
```

### Key Signing Requirements

| Component | Certificate Type | Provisioning Profile | Entitlements |
|-----------|-----------------|---------------------|--------------|
| Main App | Developer ID Application | Not required | App Sandbox, Hardened Runtime |
| CLI Tool | Developer ID Application | **Required** (VPNXPC) | App Sandbox, App Groups, Network Extension |
| Network Extension | Developer ID Application | **Required** | Network Extension, App Groups |

> [!IMPORTANT]
> Network Extensions require **Developer ID provisioning profiles** from Apple Developer Portal. Apple Development profiles work for local testing but fail notarization.

---

## Adding a New Privileged Plugin

Follow this guide when adding a new macOS-specific privileged component (e.g., System Extension, Endpoint Security, etc.).

### Step 1: Create the Swift Project

1. **Create a new Xcode project** or add targets to the existing `wireguard-apple.xcodeproj`:
   ```
   parent-directory/
   ├── Resistine-Desktop/        ← Python UI
   └── wireguard-apple/          ← Swift components (or new project)
   ```

2. **Add required targets**:
   - **CLI Tool** — Command-line interface for Python to call
   - **App Extension/XPC Service** — The privileged component
   - **Container App** — Hosts the extension during build

### Step 2: Configure Bundle IDs

Choose a bundle ID hierarchy that matches your team:

```
com.resistine.desktop                              ← Main Python app
com.resistine.desktop.network-extension            ← Network Extension
com.resistine.desktop.vpnxpc                       ← CLI Tool (reusing ID)
```

### Step 3: Register App IDs in Apple Developer Portal

1. Go to [Certificates, Identifiers & Profiles](https://developer.apple.com/account/resources/identifiers/list)

2. **Create App ID** for your new component:
   - Click "+" → "App IDs" → "App"
   - Enter Bundle ID: `com.resistine.wireguard-apple.your-new-extension`
   - Enable required capabilities (e.g., "System Extension", "Network Extension", etc.)

3. **Enable specific capability types** if required:
   - Network Extension: Select `packet-tunnel-provider`, `app-proxy-provider`, etc.
   - System Extension: Select `endpoint-security`, `network-extension`, etc.

### Step 4: Create Provisioning Profiles

> [!CAUTION]
> This step is **critical** for notarization. Without Developer ID profiles, notarization will fail.

1. Go to [Profiles](https://developer.apple.com/account/resources/profiles/list)

2. **Create Developer ID profile** for each privileged component:
   - Click "+" → "Developer ID" (under Distribution)
   - Select your App ID
   - Select your **Developer ID Application** certificate
   - Download the `.provisionprofile` file

3. **Install profiles**:
   ```bash
   # Double-click to install, or:
   cp ~/Downloads/*.provisionprofile ~/Library/MobileDevice/Provisioning\ Profiles/
   ```

### Step 5: Configure Entitlements

Create an entitlements file for your new component:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "...">
<plist version="1.0">
<dict>
    <!-- Required for all sandboxed apps -->
    <key>com.apple.security.app-sandbox</key>
    <true/>
    
    <!-- App Groups for IPC between components -->
    <key>com.apple.security.application-groups</key>
    <array>
        <string>$(TeamIdentifierPrefix)com.resistine.shared</string>
    </array>
    
    <!-- Your specific capability -->
    <key>com.apple.developer.networking.networkextension</key>
    <array>
        <string>packet-tunnel-provider</string>
    </array>
</dict>
</plist>
```

### Step 6: Create CLI Interface

Create a Swift CLI tool that Python can call:

```swift
// main.swift
import Foundation
import NetworkExtension // or your framework

@main
struct YourCLI {
    static func main() async {
        let args = CommandLine.arguments
        guard args.count >= 2 else {
            print("Usage: your-cli <command>")
            exit(1)
        }
        
        switch args[1] {
        case "start":
            // Start your service
            print("Started")
        case "stop":
            // Stop your service
            print("Stopped")
        case "status":
            // Check status
            print("Running") // or "Stopped"
        default:
            print("Unknown command")
            exit(1)
        }
    }
}
```

### Step 7: Create Python Wrapper

Add a Python module to interface with your CLI:

```python
# plugins/your_plugin/your_functions_darwin.py
import subprocess
import sys
import os

class YourHelper:
    def __init__(self):
        self.cli_path = self._find_cli_path()
    
    def _find_cli_path(self):
        if getattr(sys, "frozen", False):
            macos_dir = os.path.dirname(sys.executable)
            contents_dir = os.path.dirname(macos_dir)
            return os.path.join(
                contents_dir, "Resources", "wireguard-apple.app",
                "Contents", "MacOS", "your-cli"
            )
        return None
    
    def start(self) -> tuple[bool, str]:
        result = subprocess.run(
            [self.cli_path, "start"],
            capture_output=True, text=True, timeout=30
        )
        return (result.returncode == 0, result.stdout.strip())
    
    def status(self) -> tuple[bool, str]:
        result = subprocess.run(
            [self.cli_path, "status"],
            capture_output=True, text=True, timeout=30
        )
        is_running = "Running" in result.stdout
        return (is_running, result.stdout.strip())
```

### Step 8: Update Build Script

Add your new component to `build-installer.sh`:

```bash
# After embedding wireguard-apple.app, verify your new component:
if [ ! -f "$EMBEDDED_APP/Contents/MacOS/your-cli" ]; then
    echo "❌ Error: your-cli not found"
    exit 1
fi

# If it's an app extension:
if [ ! -d "$EMBEDDED_APP/Contents/PlugIns/your-extension.appex" ]; then
    echo "❌ Error: your-extension.appex not found"  
    exit 1
fi

# Re-sign CLI with entitlements (extensions keep Xcode signatures):
YOUR_CLI_ENTITLEMENTS="$VPN_PROJECT_PATH/your-cli/entitlements.plist"
codesign --force --sign "$SIGN_IDENTITY" \
    --options runtime \
    --timestamp \
    --entitlements "$YOUR_CLI_ENTITLEMENTS" \
    "$EMBEDDED_APP/Contents/MacOS/your-cli"
```

---

## Notarization Checklist

Before submitting for notarization, verify:

- [ ] All binaries signed with **Developer ID Application** certificate
- [ ] All signatures include **secure timestamps** (`--timestamp` flag)
- [ ] All app extensions have **Developer ID provisioning profiles**
- [ ] All components have **Hardened Runtime** enabled (`--options runtime`)
- [ ] No Apple Development certificates used in any component

### Verifying Signatures

```bash
# Check signing identity
codesign -dvv /path/to/component 2>&1 | grep "Authority"

# Should show: "Developer ID Application: Your Name (TEAM_ID)"
# NOT: "Apple Development: ..."

# Verify provisioning profile type
security cms -D -i /path/to/embedded.provisionprofile | grep -A1 "Name"

# Should NOT contain "Mac Team Provisioning Profile" for distribution
```

### Common Notarization Errors

| Error | Cause | Fix |
|-------|-------|-----|
| "not signed with Developer ID" | Using Apple Development cert | Create Developer ID provisioning profiles |
| "no secure timestamp" | Missing `--timestamp` | Add `--timestamp` to codesign |
| "hardened runtime not enabled" | Missing `--options runtime` | Add `--options runtime` to codesign |

---

## File Locations Reference

| Component | Source Location | Installed Location |
|-----------|----------------|-------------------|
| Python UI | `Resistine-Desktop/` | `Resistine.app/Contents/MacOS/` |
| Python plugins | `plugins/` | `Resistine.app/Contents/Resources/plugins/` |
| Swift project | `vpn-apple/` | — |
| CLI tool | `resistine-vpn-cli/` | `Resistine.app/Contents/MacOS/` |
| Network Extension | `network-extension/` | `Resistine.app/Contents/PlugIns/` |

---

## Troubleshooting

### VPN shows "Disconnected" on app restart
The Python UI must query actual status on startup. See `initialize_vpn_status()` in `plugins/vpn/main.py`.

### "Internal Error: nesessionmanager"
- Check CLI entitlements include App Groups and Network Extension
- Verify Bundle IDs match provisioning profiles exactly
- Ensure Extension is in `PlugIns/` and CLI is in `MacOS/` of the SAME bundle

### Notarization fails with "Invalid"
```bash
# Get detailed error log
xcrun notarytool log <submission-id> --keychain-profile "your-profile"
```

### Extension won't load
Check System Preferences → Privacy & Security → Extensions for approval prompts.
