#!/bin/bash
set -e

# Phoenix Complete Build & Installer Script
# This script builds both the Swift components and Python UI, then packages everything
# Works on any computer as long as the directory structure is maintained

echo "=== Phoenix Build System ==="
echo "Building unified installer with modular architecture"
echo ""

# Project paths
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PYTHON_UI_PATH="$(cd "$SCRIPT_DIR/../.." && pwd)"
VPN_PROJECT_PATH="$PYTHON_UI_PATH/vpn-apple"

# Validate paths exist
echo "Checking project structure..."
if [ ! -d "$PYTHON_UI_PATH" ]; then
    echo "❌ Error: Python UI directory not found at: $PYTHON_UI_PATH"
    echo ""
    echo "Expected structure:"
    echo "  parent-directory/"
    echo "  ├── Resistine-Desktop/"
    echo "  └── wireguard-apple/"
    echo ""
    echo "Please ensure both directories exist in the same parent directory."
    exit 1
fi

if [ ! -d "$VPN_PROJECT_PATH" ]; then
    echo "❌ Error: VPN project directory not found at: $VPN_PROJECT_PATH"
    exit 1
fi

echo "✅ Found Python UI: $PYTHON_UI_PATH"
echo "✅ Found VPN project: $VPN_PROJECT_PATH"
echo ""

# Build configuration
BUILD_DIR="$VPN_PROJECT_PATH/build"
DIST_DIR="$PYTHON_UI_PATH/dist"
APP_NAME="Phoenix"   # bundle file name (Phoenix.app); see packaging/Resistine.spec
DISPLAY_NAME="Phoenix" # what users see: installer title, DMG/pkg names
BUNDLE_ID="com.resistine.desktop"

# Step 1: Build Swift Components (VPN)
echo "Step 1: Building Swift components..."
cd "$VPN_PROJECT_PATH"

# Clean previous builds
rm -rf build/

# Detect signing identity
echo "  - Detecting code signing certificate..."
DEV_ID_CERT=$(security find-identity -v -p codesigning 2>/dev/null | grep "Developer ID Application" | head -1 | awk '{print $2}')

if [ -z "$DEV_ID_CERT" ]; then
    echo "  ⚠️  Warning: No Developer ID Application certificate found"
    echo "     Falling back to Apple Development certificate..."
    DEV_CERT=$(security find-identity -v -p codesigning 2>/dev/null | grep "Apple Development" | head -1 | awk '{print $2}')
    if [ -z "$DEV_CERT" ]; then
        echo "  ❌ Error: No valid signing certificate found."
        echo "     The networkextension entitlement requires a valid Apple certificate and provisioning profile."
        echo "     Ad-hoc signing will NOT work for VPN functionality."
        exit 1
    fi
    echo "  ✅ Found Apple Development certificate: $DEV_CERT"
    SIGN_IDENTITY="$DEV_CERT"
else
    echo "  ✅ Found Developer ID certificate: $DEV_ID_CERT"
    SIGN_IDENTITY="$DEV_ID_CERT"
fi

# Detect Development Team ID from certificate
# The output format is: 1) HASH "Developer ID Application: Name (TEAMID)"
# Extract just the alphanumeric team ID from within the parentheses
TEAM_ID=$(security find-identity -v -p codesigning 2>/dev/null | grep "$SIGN_IDENTITY" | grep -o '([A-Z0-9]*)' | tr -d '()' | head -1)
echo "  - Team ID: $TEAM_ID"

if [ -z "$TEAM_ID" ]; then
    echo "  ❌ Error: Could not detect Team ID from certificate."
    echo "     Please set TEAM_ID manually in this script."
    exit 1
fi

# Build the Xcode project for Release with proper code signing
# IMPORTANT: Code signing must happen during the Xcode build, not after.
# The networkextension entitlement is a restricted entitlement that requires
# a valid provisioning profile embedded by Xcode during the archive step.
# Re-signing with codesign alone is NOT sufficient.
xcodebuild \
  -project wireguard-apple.xcodeproj \
  -scheme wireguard-apple \
  -configuration Release \
  -archivePath "$BUILD_DIR/wireguard-apple.xcarchive" \
  archive \
  -allowProvisioningUpdates

echo "✅ Swift components built"

# Step 2: Build Python UI with PyInstaller
echo ""
echo "Step 2: Building Python UI..."
cd "$PYTHON_UI_PATH"

# Ensure virtual environment exists
if [ ! -d ".venv" ]; then
    echo "  - Creating virtual environment..."
    # Use python.org universal2 build for broad macOS compatibility (target 13.0 Ventura)
    # Do NOT use Homebrew Python which targets only the current macOS version
    # Auto-detect the latest python.org install instead of hardcoding a version
    PYTHONORG=$(ls -d /Library/Frameworks/Python.framework/Versions/3.*/bin/python3.* 2>/dev/null | grep -v config | sort -t/ -k7 -V | tail -1)
    if [ -n "$PYTHONORG" ] && [ -f "$PYTHONORG" ]; then
        echo "  Using python.org Python: $PYTHONORG"
        "$PYTHONORG" -m venv .venv
    else
        echo "  Warning: python.org Python not found"
        echo "  Falling back to system python3 (may have limited macOS compatibility)"
        python3 -m venv .venv
    fi
fi

# Activate venv and install dependencies
echo "  - Installing dependencies..."
source .venv/bin/activate
export MACOSX_DEPLOYMENT_TARGET=13.0  # Ensure compiled extensions target macOS 13+ (Ventura)
pip install -q -r scripts/requirements/requirements-mac.txt

# Check if Resistine.spec exists
if [ ! -f "packaging/Resistine.spec" ]; then
    echo "❌ Error: packaging/Resistine.spec not found in $PYTHON_UI_PATH"
    echo "Please ensure Resistine.spec is in the packaging/ directory."
    exit 1
fi

# Clean dist directory to avoid conflicts
rm -rf dist/Resistine dist/Resistine.app dist/Phoenix dist/Phoenix.app

# Build with PyInstaller using the spec file
echo "  - Building with PyInstaller..."
pyinstaller packaging/Resistine.spec --noconfirm

echo "✅ Python UI built"

# Step 3: Place VPN components directly in Phoenix.app bundle
# Apple bundle structure requirements (from Apple documentation):
#   - App Extensions (.appex): Contents/PlugIns/
#   - Helper Tools / CLI: Contents/MacOS/
#   - Frameworks: Contents/Frameworks/
#
# CRITICAL: Do NOT nest bundles inside Contents/Resources/. macOS extension
# discovery looks for components relative to the parent bundle.
echo ""
echo "Step 3: Placing VPN components in main app bundle..."

PYTHON_APP="$DIST_DIR/$APP_NAME.app"
VPN_ARCHIVE="$BUILD_DIR/wireguard-apple.xcarchive/Products/Applications/wireguard-apple.app"

# Verify Python app was built
if [ ! -d "$PYTHON_APP" ]; then
    echo "❌ Error: Python app bundle not found at $PYTHON_APP"
    exit 1
fi

# Verify VPN archive exists
if [ ! -d "$VPN_ARCHIVE" ]; then
    echo "❌ Error: VPN archive not found at $VPN_ARCHIVE"
    exit 1
fi

# Create Apple-standard directories
mkdir -p "$PYTHON_APP/Contents/PlugIns"
mkdir -p "$PYTHON_APP/Contents/Library/SystemExtensions"

# --- Copy CLI to Contents/MacOS/ ---
# IMPORTANT: The CLI must be in Contents/MacOS/ (not Contents/Helpers/) because
# NSXPCConnection(serviceName:) relies on launchd to discover XPC services.
# launchd associates a process with its parent app bundle by checking if the
# binary is in Contents/MacOS/. Binaries in Contents/Helpers/ are NOT associated
# with the app bundle, so launchd can't find the XPC service for them.
echo "  - Copying resistine-vpn-cli to Contents/MacOS/..."
if [ ! -f "$VPN_ARCHIVE/Contents/MacOS/resistine-vpn-cli" ]; then
    echo "❌ Error: resistine-vpn-cli not found in archive"
    exit 1
fi
cp "$VPN_ARCHIVE/Contents/MacOS/resistine-vpn-cli" "$PYTHON_APP/Contents/MacOS/"

# --- Copy Network Extension as System Extension ---
echo "  - Copying network-extension to Contents/Library/SystemExtensions/..."
SYSEX_PATH="$PYTHON_APP/Contents/Library/SystemExtensions/com.resistine.desktop.network-extension.systemextension"

if [ -d "$VPN_ARCHIVE/Contents/PlugIns/network-extension.appex" ]; then
    cp -R "$VPN_ARCHIVE/Contents/PlugIns/network-extension.appex" "$SYSEX_PATH"
elif [ -d "$VPN_ARCHIVE/Contents/Library/SystemExtensions/com.resistine.desktop.network-extension.systemextension" ]; then
    cp -R "$VPN_ARCHIVE/Contents/Library/SystemExtensions/com.resistine.desktop.network-extension.systemextension" "$SYSEX_PATH"
else
    echo "❌ Error: Network Extension not found in archive"
    exit 1
fi

# Verify placement
echo "  - Verifying bundle structure..."
if [ ! -f "$PYTHON_APP/Contents/MacOS/resistine-vpn-cli" ]; then
    echo "❌ Error: CLI not in Contents/MacOS/"
    exit 1
fi
if [ ! -d "$PYTHON_APP/Contents/Library/SystemExtensions/com.resistine.desktop.network-extension.systemextension" ]; then
    echo "❌ Error: System Extension not in Contents/Library/SystemExtensions/"
    exit 1
fi

echo "✅ VPN components placed in Apple-standard locations"
echo "   - CLI: Contents/MacOS/resistine-vpn-cli"
echo "   - System Extension: Contents/Library/SystemExtensions/com.resistine.desktop.network-extension.systemextension"

# Step 4: Verify permissions
echo ""
echo "Step 4: Verifying permissions..."

# The binaries were already built and signed by Xcode with correct permissions.
# Do NOT chmod after signing — it invalidates the code signature.

if [ ! -x "$PYTHON_APP/Contents/MacOS/resistine-vpn-cli" ]; then
    echo "  ⚠️  resistine-vpn-cli is not executable — this may indicate a build issue"
fi

if [ ! -x "$SYSEX_PATH/Contents/MacOS/network-extension" ]; then
    echo "  ⚠️  network-extension is not executable — this may indicate a build issue"
fi

echo "✅ Permissions verified"

# Step 5: Code signing
echo ""
echo "Step 5: Code signing..."

# SIGN_IDENTITY was already determined in Step 1
echo "  - Signing with identity: $SIGN_IDENTITY"

# Check if entitlements file exists for the main app
ENTITLEMENTS_FILE="$PYTHON_UI_PATH/packaging/Resistine.entitlements"
if [ ! -f "$ENTITLEMENTS_FILE" ]; then
    echo "  ⚠️  Warning: Resistine.entitlements not found, signing without entitlements"
    ENTITLEMENTS_FLAG=""
else
    ENTITLEMENTS_FLAG="--entitlements $ENTITLEMENTS_FILE"
fi

# The network-extension.appex was signed by Xcode
# during archive with provisioning profiles and restricted entitlements.
# DO NOT re-sign it — re-signing strips provisioning profiles.
#
# The CLI (resistine-vpn-cli) must be re-signed with Developer ID for distribution,
# but we MUST preserve its entitlements (sandbox + application-groups).
# Without these entitlements, the CLI cannot connect to the Network Extension.
CLI_ENTITLEMENTS="$VPN_PROJECT_PATH/resistine-vpn-cli/entitlements.plist"
if [ ! -f "$CLI_ENTITLEMENTS" ]; then
    echo "  ⚠️  Warning: CLI entitlements file not found at $CLI_ENTITLEMENTS"
    echo "     CLI will be signed without entitlements (XPC communication may fail)"
    CLI_ENTITLEMENTS_FLAG=""
else
    CLI_ENTITLEMENTS_FLAG="--entitlements $CLI_ENTITLEMENTS"
fi

echo "  - Re-signing resistine-vpn-cli (with entitlements for XPC access)..."
codesign --force --sign "$SIGN_IDENTITY" \
    --options runtime \
    --timestamp \
    $CLI_ENTITLEMENTS_FLAG \
    "$PYTHON_APP/Contents/MacOS/resistine-vpn-cli" || {
    echo "  ❌ resistine-vpn-cli signing failed"
    exit 1
}
echo "  ✅ resistine-vpn-cli signed (with entitlements)"

echo "  - Verifying VPN component signatures..."
codesign --verify --verbose "$PYTHON_APP/Contents/MacOS/resistine-vpn-cli" 2>&1 && \
    echo "  ✅ resistine-vpn-cli signature valid" || \
    echo "  ❌ resistine-vpn-cli signature INVALID"

codesign --verify --verbose "$PYTHON_APP/Contents/Library/SystemExtensions/com.resistine.desktop.network-extension.systemextension" 2>&1 && \
    echo "  ✅ system-extension signature valid" || \
    echo "  ❌ system-extension signature INVALID — Xcode signing may have failed"

# Sign all PyInstaller-produced frameworks, dylibs, and shared objects.
# PyInstaller ad-hoc signs these, but macOS AMFI rejects ad-hoc signed
# binaries in an app bundle signed with a Developer ID certificate.
# We must sign them individually BEFORE signing the outer app bundle.
echo "  - Signing PyInstaller frameworks and shared libraries..."
SIGN_COUNT=0
SIGN_FAIL=0

# Find all Mach-O binaries inside Contents/Frameworks/ and Contents/MacOS/
# NOTE: python.org Python bundles bare Tcl/Tk binaries (no file extension)
find "$PYTHON_APP/Contents/Frameworks" "$PYTHON_APP/Contents/MacOS" \
    -type f \( -name "*.so" -o -name "*.dylib" -o -name "Python" -o -name "Tcl" -o -name "Tk" -o -name "tkhtml" \) | while read -r binary; do
    codesign --force --sign "$SIGN_IDENTITY" \
        --options runtime \
        --timestamp \
        "$binary" 2>/dev/null && {
        SIGN_COUNT=$((SIGN_COUNT + 1))
    } || {
        echo "  ⚠️  Failed to sign: $(basename "$binary")"
        SIGN_FAIL=$((SIGN_FAIL + 1))
    }
done
echo "  ✅ Framework/library signing complete"

# Sign the main Phoenix.app bundle (the outer PyInstaller app)
# Use --force but NOT --deep: --deep would re-sign nested components
# and strip their provisioning profiles
echo "  - Signing main Phoenix.app bundle..."
codesign --force --sign "$SIGN_IDENTITY" \
    --options runtime \
    $ENTITLEMENTS_FLAG \
    --timestamp \
    "$PYTHON_APP" || {
    echo "  ❌ Main app signing failed"
    exit 1
}

echo "✅ App signed"

# Verify signatures
echo "  - Verifying final signatures..."
codesign --verify --verbose=2 "$PYTHON_APP" 2>&1 || echo "  ⚠️  Outer app signature verification had warnings"

# Step 6: Create DMG installer
echo ""
echo "Step 6: Creating DMG installer..."

# Install create-dmg if not available
if ! command -v create-dmg &> /dev/null; then
    echo "  - create-dmg not found. Installing via Homebrew..."
    if command -v brew &> /dev/null; then
        brew install create-dmg
    else
        echo "  ⚠️  Homebrew not found. Skipping DMG creation."
        echo "     Install Homebrew from https://brew.sh then run: brew install create-dmg"
        echo ""
        echo "  You can still use the app bundle directly: $PYTHON_APP"
        exit 0
    fi
fi

# Remove old DMG if exists
rm -f "$DIST_DIR/$DISPLAY_NAME-Installer.dmg"

# Check for optional background images
BACKGROUND_FLAG=""
if [ -f "$PYTHON_UI_PATH/resources/installer-background.png" ]; then
    BACKGROUND_FLAG="--background $PYTHON_UI_PATH/resources/installer-background.png"
fi

# Check for app icon
ICON_FLAG=""
if [ -f "$PYTHON_UI_PATH/resources/icons/PhoenixMark.png" ]; then
    ICON_FLAG="--volicon $PYTHON_UI_PATH/resources/icons/PhoenixMark.png"
fi

# Create DMG
create-dmg \
  --volname "$DISPLAY_NAME Installer" \
  $ICON_FLAG \
  --window-pos 200 120 \
  --window-size 800 400 \
  --icon-size 100 \
  --icon "$APP_NAME.app" 200 190 \
  --hide-extension "$APP_NAME.app" \
  --app-drop-link 600 185 \
  $BACKGROUND_FLAG \
  "$DIST_DIR/$DISPLAY_NAME-Installer.dmg" \
  "$PYTHON_APP" 2>&1 || {
    echo "  ⚠️  DMG creation had warnings but may have succeeded"
  }

if [ -f "$DIST_DIR/$DISPLAY_NAME-Installer.dmg" ]; then
    echo "✅ DMG created: $DIST_DIR/$DISPLAY_NAME-Installer.dmg"

    # Calculate DMG size
    DMG_SIZE=$(du -h "$DIST_DIR/$DISPLAY_NAME-Installer.dmg" | cut -f1)
    echo "   DMG size: $DMG_SIZE"

    # Sign the DMG if we have a certificate
    if [ -n "$SIGN_IDENTITY" ]; then
        echo ""
        echo "  - Signing DMG..."
        codesign --force --sign "$SIGN_IDENTITY" "$DIST_DIR/$DISPLAY_NAME-Installer.dmg" && {
            echo "  ✅ DMG signed successfully"
            codesign --verify --verbose "$DIST_DIR/$DISPLAY_NAME-Installer.dmg" 2>&1 | grep -q "valid on disk" && \
                echo "  ✅ DMG signature verified"
        } || echo "  ⚠️  DMG signing failed (non-critical)"
    else
        echo ""
        echo "  ⚠️  DMG not signed (no certificate available)"
    fi
else
    echo "⚠️  DMG creation failed, but app bundle is available: $PYTHON_APP"
fi

# Step 7: Auto-install to /Applications
echo ""
echo "Step 7: Installing to /Applications..."

# Remove old installation if it exists (and the pre-rebrand Resistine.app)
rm -rf "/Applications/Resistine.app" 2>/dev/null || true
if [ -d "/Applications/$APP_NAME.app" ]; then
    echo "  - Removing old /Applications/$APP_NAME.app..."
    rm -rf "/Applications/$APP_NAME.app" || {
        echo "  ❌ Failed to remove old app (may need sudo)"
        echo "     Try: sudo rm -rf '/Applications/$APP_NAME.app'"
        echo "     Then re-run this script or manually copy from: $PYTHON_APP"
    }
fi

# Copy new build to /Applications
echo "  - Copying new build to /Applications..."
cp -R "$PYTHON_APP" "/Applications/$APP_NAME.app" && {
    echo "  ✅ Installed to /Applications/$APP_NAME.app"
} || {
    echo "  ❌ Failed to install (may need sudo)"
    echo "     Try: sudo cp -R '$PYTHON_APP' '/Applications/$APP_NAME.app'"
}

# Step 8: Notarization instructions (optional)
echo ""
echo "Step 8: Notarization (optional for public distribution)..."
echo "To notarize for public distribution (requires Apple Developer account):"
echo ""
echo "  xcrun notarytool submit $DIST_DIR/$DISPLAY_NAME-Installer.dmg \\"
echo "    --apple-id YOUR_APPLE_ID \\"
echo "    --team-id YOUR_TEAM_ID \\"
echo "    --password YOUR_APP_SPECIFIC_PASSWORD \\"
echo "    --wait"
echo ""
echo "  # Then staple the ticket:"
echo "  xcrun stapler staple $DIST_DIR/$DISPLAY_NAME-Installer.dmg"
echo ""

# Summary
echo "==================================="
echo "✅ Build Complete!"
echo "==================================="
echo ""
echo "📦 Installer: $DIST_DIR/$DISPLAY_NAME-Installer.dmg"
echo "📱 App Bundle: $PYTHON_APP"
echo ""
echo "Next steps:"
echo "  1. Test the installed app: open '/Applications/$APP_NAME.app'"
echo "  2. Notarize for public distribution (optional)"
echo ""
echo "Distribution checklist:"
    echo "  ☐ Test installation on clean macOS system"
    echo "  ☐ Test VPN connection functionality"
    echo "  ☐ Check Console.app for errors"
    echo "  ☐ Verify CLI subprocess communication"
    echo "  ☐ Notarize DMG (for public distribution)"
echo "  ☐ Upload to distribution server"
echo ""
