# Phoenix VPN Architecture

## Overview

The Phoenix VPN uses a clean **CLI-only architecture** for communication between the Python UI and the native VPN implementation:

```
┌──────────────────────┐
│  Python UI (PyTK)    │
│   plugins/vpn/       │
└──────────┬───────────┘
           │
           │ subprocess.run()
           │ ["resistine-vpn-cli", "start|stop|status", ...]
           ▼
┌──────────────────────┐
│ resistine-vpn-cli    │
│    (Swift CLI)       │
└──────────┬───────────┘
           │
           │ NetworkExtension APIs
           ▼
┌──────────────────────┐
│ network-extension    │
│   (App Extension)    │
│   NEPacketTunnel     │
│   Provider           │
└──────────┬───────────┘
           │
           │ WireGuardKit
           ▼
┌──────────────────────┐
│   WireGuard Tunnel   │
│   (System Level)     │
└──────────────────────┘
```

## Components

### 1. Python VPN Plugin
- **Location**: `plugins/vpn/`
- **Files**: `main.py`, `wireguard/vpn_functions_darwin.py`
- **Purpose**: User interface and VPN management logic
- **Communication**: Subprocess calls to resistine-vpn-cli using `subprocess.run()`
- **Commands Used**:
  - `resistine-vpn-cli start <config_path>` - Start VPN with given config
  - `resistine-vpn-cli stop` - Stop active VPN connection
  - `resistine-vpn-cli status` - Check VPN connection status

### 2. resistine-vpn-cli (Swift CLI Tool)
- **Location**: `wireguard-apple/resistine-vpn-cli/`
- **Source File**: `main.swift`
- **Entitlements**: `entitlements.plist`
- **Purpose**: Thin wrapper interface to NetworkExtension framework
- **Responsibilities**:
  - Parse command-line arguments (start, stop, status)
  - Configure NetworkExtension VPN tunnel settings
  - Report tunnel status to caller
- **Key Functions**:
  - `start(configPath:)` - Load config and activate tunnel
  - `stop()` - Deactivate active tunnel
  - `status()` - Report tunnel connection status
- **Exit Codes**:
  - `0` - Success
  - Non-zero - Failure with error details on stderr

### 3. network-extension.appex (App Extension)
- **Location**: `wireguard-apple/network-extension/`
- **Type**: `NEPacketTunnelProvider` (macOS NetworkExtension)
- **Purpose**: Actual VPN tunnel implementation
- **Responsibilities**:
  - Handle VPN packets (encrypt/decrypt)
  - Manage tunnel lifecycle
  - Apply DNS configuration
  - Implement WireGuard protocol
- **Libraries**: WireGuardKit framework
- **Sandbox**: Runs in sandboxed extension context

## Why CLI-Only?

### Benefits
1. **Clean Separation**: Python doesn't need to know about macOS-specific APIs
2. **No PyObjC**: Eliminates dependency on PyObjC (which can be fragile)
3. **Testability**: CLI can be tested independently from Python UI
4. **Simplicity**: Subprocess calls are straightforward and well-understood
5. **No XPC Bridge**: Removing the XPC bridge eliminates the "internal error" caused by bundle detection failures.
6. **Security**: CLI handles privileged operations, Python never directly accesses APIs

## Build Process

### Swift Compilation
1. Xcode project (`wireguard-apple.xcodeproj`) builds two main targets:
   - `resistine-vpn-cli` - Swift CLI tool
   - `network-extension` - App extension (.appex bundle)

2. CLI is built with embedded entitlements for NetworkExtension access

### App Bundling
1. Build script (`build-installer.sh`) embeds compiled outputs in Phoenix.app:
   ```
   Phoenix.app/Contents/
   ├── MacOS/
   │   └── resistine-vpn-cli          ← CLI tool
   └── PlugIns/
       └── network-extension.appex    ← App extension
   ```

2. Python discovers CLI at runtime:
   - Frozen app (PyInstaller): `sys.executable` → find Contents/MacOS/resistine-vpn-cli
   - Development: Not available (run `build-installer.sh` first)

### Code Signing
- CLI signed with `-i com.resistine.resistine-vpn-cli` identifier
- Network Extension has bundle ID: `com.resistine.wireguard-apple.network-extension`
- Both have NetworkExtension and App Sandbox entitlements

## Communication Flow Examples

### Starting VPN
```
Python UI (toggle ON)
  ↓
plugins/vpn/main.py:toggle_vpn_connection()
  ↓
plugins/vpn/main.py:activate_tunnel(config_name)
  ↓
vpn_functions_darwin.py:start_vpn(config_path)
  ↓
VPNHelper.start_vpn(config_path)
  ↓
subprocess.run([cli_path, "start", "/path/to/config.conf"])
  ↓
resistine-vpn-cli start /path/to/config.conf
  ↓
Initialize NetworkExtension tunnel with config
  ↓
NetworkExtension activates tunnel via PacketTunnelProvider
  ↓
Return status: "Connected" / "Running"
```

### Checking Status
```
Python VPN Plugin:get_system_info()
  ↓
check_service_status(interface_name)
  ↓
VPNHelper.check_status()
  ↓
subprocess.run([cli_path, "status"])
  ↓
resistine-vpn-cli status
  ↓
Query NetworkExtension for tunnel status
  ↓
Return status: "Connected" / "Disconnected"
```

## Testing VPN Independently

### Test CLI directly
```bash
cd /Applications/Phoenix.app/Contents/MacOS

# Check if CLI is available
./resistine-vpn-cli --help

# Check VPN status
./resistine-vpn-cli status

# Start VPN (requires valid config file)
./resistine-vpn-cli start /path/to/wireguard.conf

# Stop VPN
./resistine-vpn-cli stop
```

### Test from Python
```python
from plugins.vpn.wireguard.vpn_functions_darwin import VPNHelper

# Start VPN
success, output = VPNHelper.start_vpn("/path/to/config.conf")
print(f"Start: {success}, {output}")

# Check status
is_running, status = VPNHelper.check_status()
print(f"Status: {is_running}, {status}")

# Stop VPN
success, output = VPNHelper.stop_vpn()
print(f"Stop: {success}, {output}")
```

### Monitor VPN Activity
```bash
# Watch VPN logs in real-time
log stream --predicate 'process == "Phoenix"' --level debug

# Look for CLI command execution
# Expected: "[CLI] Executing: /path/to/resistine-vpn-cli start|stop|status"
# Expected: "[CLI] Result: returncode=0, output='...'"

# Should NOT see:
# - XPC communication logs
# - Direct NetworkExtension API calls from Python
# - objc/PyObjC references
```

## Key Files

### Python Code
- `plugins/vpn/main.py` - VPN UI plugin
- `plugins/vpn/wireguard/vpn_functions_darwin.py` - CLI interface wrapper

### Swift Code
- `wireguard-apple/resistine-vpn-cli/main.swift` - CLI implementation
- `wireguard-apple/network-extension/PacketTunnelProvider.swift` - Extension provider

### Configuration
- `Phoenix.entitlements` - App sandbox and NetworkExtension permissions
- `resistine-vpn-cli/entitlements.plist` - CLI-specific permissions
- `network-extension/Info.plist` - Extension configuration
- `build-installer.sh` - Bundle assembly script

## Architecture Decisions

### ✅ Selected: Python → CLI → NetworkExtension
**Why**:
- Avoids complex XPC protocol management
- Python stays lightweight and portable
- Clear separation of concerns
- Easy to debug and test
- Minimal dependencies

### ❌ Rejected: Python → XPC Directly
**Why**:
- Python would need PyObjC for XPC communication
- Adds complexity to Python layer
- CLI provides cleaner abstraction

### ❌ Rejected: Python → NetworkExtension APIs
**Why**:
- Would require PyObjC (fragile dependency)
- Python running as main executable can't directly access some NetworkExtension APIs
- Privileged operations require helper mechanism anyway

## Future Improvements

1. **Direct Swift UI**: If building native Swift UI components, they could call CLI directly
2. **XPC Service**: If Swift background daemon needed, XPC service could replace CLI
3. **Config Validation**: Add pre-flight validation of configs before passing to CLI
4. **Logging**: Enhanced logging in CLI for troubleshooting
5. **Error Handling**: More granular error codes from CLI

## Troubleshooting

### VPN not starting
1. Check if `resistine-vpn-cli` exists: `ls -la /Applications/Phoenix.app/Contents/MacOS/resistine-vpn-cli`
2. Check WireGuard installation: `which wg wg-quick`
3. Check logs: `log stream --predicate 'process == "Phoenix"'`
4. Test CLI directly: `/Applications/Phoenix.app/Contents/MacOS/resistine-vpn-cli status`

### CLI not found at runtime
- Build app with: `./build-installer.sh`
- Test from: `dist/Phoenix.app/Contents/MacOS/`

### Tunnel won't activate
1. Check config file syntax
2. Check NetworkExtension entitlements
3. Review system Console logs for extension errors
4. Verify provisioning profiles are valid

## References

- [macOS NetworkExtension Documentation](https://developer.apple.com/documentation/networkextension)
- [WireGuardKit GitHub](https://github.com/wireguard/wireguard-apple)
- [macOS App Sandbox](https://developer.apple.com/documentation/security/app_sandbox)
