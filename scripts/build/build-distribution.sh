#!/bin/bash
set -e

# Phoenix Distribution Build Script
# Builds, signs with Developer ID, creates DMG, notarizes, and staples.
# Use build-installer.sh for local development/testing (Apple Development signing).
# Use this script for public distribution (Developer ID + notarization).

echo "=== Phoenix Distribution Build ==="
echo "Building for public distribution (Developer ID + Notarization)"
echo ""

# Project paths
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PYTHON_UI_PATH="$(cd "$SCRIPT_DIR/../.." && pwd)"
VPN_PROJECT_PATH="$PYTHON_UI_PATH/vpn-apple"

# Validate paths exist
echo "Checking project structure..."
if [ ! -d "$PYTHON_UI_PATH" ]; then
    echo "  Error: Python UI directory not found at: $PYTHON_UI_PATH"
    exit 1
fi

echo "  Found Python UI: $PYTHON_UI_PATH"
echo ""

# Build configuration
BUILD_DIR="$VPN_PROJECT_PATH/build"
DIST_DIR="$PYTHON_UI_PATH/dist"
APP_NAME="Resistine"   # bundle file name (Resistine.app); see packaging/Resistine.spec
DISPLAY_NAME="Phoenix" # what users see: installer title, DMG/pkg names
BUNDLE_ID="com.resistine.desktop"

# ============================================================
# Step 1: Verify Developer ID certificate (REQUIRED for distribution)
# ============================================================
echo "Step 1: Verifying Developer ID certificate..."

SIGN_IDENTITY=$(security find-identity -v -p codesigning 2>/dev/null | grep "Developer ID Application" | head -1 | awk '{print $2}')

if [ -z "$SIGN_IDENTITY" ]; then
    echo "  Error: No Developer ID Application certificate found."
    echo "  Distribution builds REQUIRE a Developer ID certificate."
    echo "  Use build-installer.sh for local development instead."
    exit 1
fi

SIGN_NAME=$(security find-identity -v -p codesigning 2>/dev/null | grep "$SIGN_IDENTITY" | sed 's/.*"\(.*\)".*/\1/')
echo "  Signing with: $SIGN_NAME"

TEAM_ID=$(security find-identity -v -p codesigning 2>/dev/null | grep "$SIGN_IDENTITY" | grep -o '([A-Z0-9]*)' | tr -d '()' | head -1)
echo "  Team ID: $TEAM_ID"

if [ -z "$TEAM_ID" ]; then
    echo "  Error: Could not detect Team ID from certificate."
    exit 1
fi

# Notarization toggle — set to true to skip for faster builds
SKIP_NOTARIZE=${SKIP_NOTARIZE:-false}

if [ "$SKIP_NOTARIZE" = true ]; then
    echo "  Skipping notarization (SKIP_NOTARIZE=true)"
else
    # Probe notarytool. Capture both streams so we can distinguish:
    #   (a) credentials genuinely missing       → tell user to store them
    #   (b) Apple agreement expired (HTTP 403)  → tell user to accept it
    #   (c) auth failure (bad password/Team ID) → tell user to re-store
    #   (d) network down                        → suggest retry
    # The previous version swallowed all four into "credentials not
    # found", which was wrong for 3 of the 4 cases.
    echo "  Checking notarization credentials..."
    # `set -e` is active and command substitution propagates non-zero
    # exits from the inner command — meaning a plain
    #   notarize_probe="$(xcrun notarytool history ...)"
    # would kill the entire build script on Apple's 403 / 401 / network
    # errors before we ever get to print a diagnostic. Wrapping the
    # assignment in an `if` block catches the failure so `set -e`
    # doesn't trip, AND lets us record the exit code AND the output.
    if notarize_probe="$(xcrun notarytool history --keychain-profile "resistine-notarize" 2>&1)"; then
        notarize_rc=0
    else
        notarize_rc=$?
    fi
    if [ $notarize_rc -eq 0 ]; then
        echo "  Notarization credentials found"
    else
        echo ""
        echo "  ! Notarization pre-check failed:"
        echo "$notarize_probe" | sed 's/^/      /'
        echo ""
        if echo "$notarize_probe" | grep -qiE "agreement is missing or has expired|required agreement"; then
            echo "  Apple Developer team agreement needs to be (re-)accepted."
            echo "  An Account Holder / Admin on Team ID $TEAM_ID must:"
            echo "    1. Sign in to https://developer.apple.com/account"
            echo "    2. Accept the pending agreement(s) banner at the top"
            echo "    3. Re-run this script — no credential re-storage needed"
        elif echo "$notarize_probe" | grep -qiE "could not find|no such keychain|profile not found"; then
            echo "  Notarization keychain profile is missing. Store it with:"
            echo "    xcrun notarytool store-credentials \"resistine-notarize\" \\"
            echo "      --apple-id \"jackie@resistine.com\" \\"
            echo "      --team-id \"$TEAM_ID\" \\"
            echo "      --password \"<app-specific-password from appleid.apple.com>\""
        elif echo "$notarize_probe" | grep -qiE "401|unauthorized|invalid credentials"; then
            echo "  Stored credentials were rejected by Apple. Re-store with"
            echo "  a fresh app-specific password from appleid.apple.com."
        elif echo "$notarize_probe" | grep -qiE "could not connect|network|timeout"; then
            echo "  Could not reach Apple's notarization service. Check VPN /"
            echo "  network connectivity and retry."
        fi
        echo ""
        echo "  Press Enter to continue WITHOUT notarization (the resulting"
        echo "  app will need notarization done manually before distribution),"
        echo "  or Ctrl+C to cancel and fix the problem first..."
        read -r
        SKIP_NOTARIZE=true
    fi
fi

echo ""

# ============================================================
# Step 2: Obtain Swift Components (VPN)
# ============================================================
# Artifacts are auto-downloaded from Resistine/resistine-vpn-macos CI.
# The script detects stale artifacts and re-downloads when a newer
# build is available. Set VPN_ARTIFACTS_DIR to override the path.
# Fallback: build locally from vpn-apple/ if present.
# ============================================================

VPN_ARTIFACTS_DIR="${VPN_ARTIFACTS_DIR:-$SCRIPT_DIR/vpn-artifacts}"

echo "Step 2: Checking VPN artifacts..."

# Auto-download if missing or stale
if [ -f "$SCRIPT_DIR/download-vpn-artifacts.sh" ] && command -v gh &> /dev/null; then
    if ! "$SCRIPT_DIR/download-vpn-artifacts.sh" --check 2>/dev/null; then
        echo "  VPN artifacts missing or stale — downloading from CI..."
        "$SCRIPT_DIR/download-vpn-artifacts.sh" || {
            echo "  Warning: Auto-download failed"
        }
    else
        echo "  VPN artifacts up-to-date"
    fi
fi

if [ -f "$VPN_ARTIFACTS_DIR/resistine-vpn-cli" ] && \
   [ -d "$VPN_ARTIFACTS_DIR/com.resistine.desktop.network-extension.systemextension" ]; then
    echo "  Using pre-built VPN artifacts from $VPN_ARTIFACTS_DIR"
    USE_PREBUILT_VPN=true
elif [ -d "$VPN_PROJECT_PATH" ]; then
    echo "  No pre-built artifacts — building Swift components locally..."
    cd "$VPN_PROJECT_PATH"

    rm -rf build/

    xcodebuild \
      -project wireguard-apple.xcodeproj \
      -scheme wireguard-apple \
      -configuration Release \
      -archivePath "$BUILD_DIR/wireguard-apple.xcarchive" \
      archive \
      -allowProvisioningUpdates

    echo "  Swift components built"
    USE_PREBUILT_VPN=false
else
    echo "  Error: No VPN artifacts and no vpn-apple project to build from."
    echo "  Install gh CLI (brew install gh) and authenticate (gh auth login)."
    exit 1
fi

# ============================================================
# Step 2b: Obtain ClamAV Components
# ============================================================
# Artifacts are auto-downloaded from Resistine/ClamAV-Mac CI.
# The script detects stale artifacts and re-downloads when a newer
# build is available. Set CLAMAV_ARTIFACTS_DIR to override the path.
# ============================================================

CLAMAV_ARTIFACTS_DIR="${CLAMAV_ARTIFACTS_DIR:-$SCRIPT_DIR/clamav-artifacts}"

echo "Step 2b: Checking ClamAV artifacts..."

# Auto-download if missing or stale
if [ -f "$SCRIPT_DIR/download-clamav-artifacts.sh" ] && command -v gh &> /dev/null; then
    if ! "$SCRIPT_DIR/download-clamav-artifacts.sh" --check 2>/dev/null; then
        echo "  ClamAV artifacts missing or stale — downloading from CI..."
        "$SCRIPT_DIR/download-clamav-artifacts.sh" || {
            echo "  Warning: Auto-download failed"
        }
    else
        echo "  ClamAV artifacts up-to-date"
    fi
fi

CLAMAV_AVAILABLE=false
if [ -d "$CLAMAV_ARTIFACTS_DIR/binaries" ]; then
    CLAMAV_AVAILABLE=true
fi

# ============================================================
# Step 3: Build Python UI with PyInstaller
# ============================================================
echo ""
echo "Step 3: Building Python UI..."
cd "$PYTHON_UI_PATH"

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

echo "  - Installing dependencies..."
source .venv/bin/activate
export MACOSX_DEPLOYMENT_TARGET=13.0  # Ensure compiled extensions target macOS 13+ (Ventura)
pip install -q -r scripts/requirements/requirements-mac.txt

if [ ! -f "packaging/Resistine.spec" ]; then
    echo "  Error: packaging/Resistine.spec not found in $PYTHON_UI_PATH"
    exit 1
fi

rm -rf dist/Resistine dist/Resistine.app

echo "  - Building with PyInstaller..."
pyinstaller packaging/Resistine.spec --noconfirm

echo "  Python UI built"

# ============================================================
# Step 4: Place VPN components directly in Resistine.app bundle
# ============================================================
# Apple bundle structure requirements (from Apple documentation):
#   - App Extensions (.appex): Contents/PlugIns/
#   - Helper Tools / CLI: Contents/MacOS/
#   - Frameworks: Contents/Frameworks/
#
# CRITICAL: Do NOT nest bundles inside Contents/Resources/. macOS extension
# discovery looks for components relative to the parent bundle. If the XPC
# service is nested inside wireguard-apple.app, it will look for the network
# extension inside wireguard-apple.app/Contents/PlugIns/ instead of the main
# Resistine.app/Contents/PlugIns/.
echo ""
echo "Step 4: Placing VPN components in main app bundle..."

PYTHON_APP="$DIST_DIR/$APP_NAME.app"

if [ ! -d "$PYTHON_APP" ]; then
    echo "  Error: Python app bundle not found at $PYTHON_APP"
    exit 1
fi

# ------------------------------------------------------------
# Bundle consistency gate — fail fast on a broken Python framework.
#
# The PyInstaller bootloader loads Frameworks/Python at launch. If that symlink
# resolves to a missing or mismatched runtime, the app crashes with exit 255
# ("Failed to load Python shared library"). This check verifies the freshly
# built bundle is internally consistent BEFORE we sign, notarize, and ship it,
# so a structurally broken DMG/PKG can never reach users again.
# ------------------------------------------------------------
echo "  - Verifying Python framework consistency..."
_PYLINK="$PYTHON_APP/Contents/Frameworks/Python"
if [ ! -e "$_PYLINK" ]; then
    echo "  Error: $_PYLINK is missing — bundle has no Python runtime."
    exit 1
fi
# Resolve the symlink target and confirm the file actually exists.
if ! _PYREAL=$(cd "$(dirname "$_PYLINK")" && readlink -f "$(readlink "$_PYLINK" 2>/dev/null || echo Python)" 2>/dev/null); then
    _PYREAL=""
fi
if [ ! -f "$_PYLINK" ]; then
    echo "  Error: Frameworks/Python does not resolve to a real file (dangling symlink)."
    echo "         Target: $(readlink "$_PYLINK" 2>/dev/null)"
    ls -la "$PYTHON_APP/Contents/Frameworks/Python.framework/Versions/" 2>/dev/null
    exit 1
fi
# Confirm exactly one Python version directory is present (no stale extras).
_PYVERS=$(ls -1 "$PYTHON_APP/Contents/Frameworks/Python.framework/Versions/" 2>/dev/null | grep -E '^[0-9]+\.[0-9]+$' | sort -u)
_PYVCOUNT=$(echo "$_PYVERS" | grep -c . || true)
if [ "$_PYVCOUNT" -ne 1 ]; then
    echo "  Error: expected exactly one Python version in the bundle, found:"
    echo "$_PYVERS" | sed 's/^/         /'
    exit 1
fi
echo "    Python framework OK (version $_PYVERS)"

# Resolve VPN component sources (pre-built artifacts or local archive)
if [ "$USE_PREBUILT_VPN" = true ]; then
    CLI_SOURCE="$VPN_ARTIFACTS_DIR/resistine-vpn-cli"
    NE_SOURCE="$VPN_ARTIFACTS_DIR/com.resistine.desktop.network-extension.systemextension"
else
    VPN_ARCHIVE="$BUILD_DIR/wireguard-apple.xcarchive/Products/Applications/wireguard-apple.app"

    if [ ! -d "$VPN_ARCHIVE" ]; then
        echo "  Error: VPN archive not found at $VPN_ARCHIVE"
        exit 1
    fi

    CLI_SOURCE=$(find "$VPN_ARCHIVE" -name "resistine-vpn-cli" -type f | grep -v "dSYM" | grep "/MacOS/" | head -1)
    if [ -z "$CLI_SOURCE" ] || [ ! -f "$CLI_SOURCE" ]; then
        echo "  Error: resistine-vpn-cli not found in archive"
        exit 1
    fi

    NE_SOURCE=$(find "$VPN_ARCHIVE" -name "*network-extension*" \( -name "*.appex" -o -name "*.systemextension" \) -type d | grep -v "dSYM" | head -1)
    if [ -z "$NE_SOURCE" ]; then
        echo "  Error: Network Extension not found in archive"
        exit 1
    fi
fi

# Create Apple-standard directories
mkdir -p "$PYTHON_APP/Contents/PlugIns"
mkdir -p "$PYTHON_APP/Contents/Library/SystemExtensions"

# --- Copy CLI to Contents/MacOS/ as a Bundle ---
# To support restricted entitlements (App Groups) in the CLI, it must have a
# provisioning profile embedded. Standalone binaries cannot easily have embedded
# profiles, so we wrap it in a nested bundle: ResistineCLI.app

echo "  - Packaging resistine-vpn-cli into nested bundle..."
CLI_APP="$PYTHON_APP/Contents/MacOS/ResistineCLI.app"
mkdir -p "$CLI_APP/Contents/MacOS"

echo "    Found CLI at: $CLI_SOURCE"
cp "$CLI_SOURCE" "$CLI_APP/Contents/MacOS/resistine-vpn-cli"

# --- Copy Network Extension to Contents/Library/SystemExtensions/ ---
# CRITICAL: System Extensions MUST use .systemextension extension, not .appex!
echo "  - Copying network-extension to Contents/Library/SystemExtensions/..."

# Use the full bundle name: com.resistine.desktop.network-extension.systemextension
DEST_EXTENSION="$PYTHON_APP/Contents/Library/SystemExtensions/com.resistine.desktop.network-extension.systemextension"
mkdir -p "$PYTHON_APP/Contents/Library/SystemExtensions"
rm -rf "$DEST_EXTENSION"
cp -R "$NE_SOURCE" "$DEST_EXTENSION"

# Verify placement
if [ ! -d "$PYTHON_APP/Contents/Library/SystemExtensions/com.resistine.desktop.network-extension.systemextension" ]; then
    echo "  Error: System Extension not in Contents/Library/SystemExtensions/"
    exit 1
fi

# Create minimal Info.plist for the CLI bundle
cat > "$CLI_APP/Contents/Info.plist" << PLISTEOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleIdentifier</key>
    <string>com.resistine.desktop.vpnxpc</string>
    <key>CFBundleName</key>
    <string>ResistineCLI</string>
    <key>CFBundleExecutable</key>
    <string>resistine-vpn-cli</string>
    <key>CFBundleVersion</key>
    <string>1.0</string>
    <key>CFBundleShortVersionString</key>
    <string>1.0</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
</dict>
</plist>
PLISTEOF

# ============================================================
# Step 4b: Place ClamAV components in app bundle
# ============================================================
echo ""
if [ -d "$CLAMAV_ARTIFACTS_DIR/binaries" ]; then
    echo "Step 4b: Placing ClamAV components in app bundle..."

    CLAMAV_BINARIES_DIR="$CLAMAV_ARTIFACTS_DIR/binaries"
    CLAMAV_LIB_DIR="$CLAMAV_ARTIFACTS_DIR/lib"

    # clamonacc → nested app bundle (ESF entitlements need a bundle)
    CLAMAV_APP="$PYTHON_APP/Contents/Helpers/ResistineClamAV.app"
    mkdir -p "$CLAMAV_APP/Contents/MacOS"

    cp "$CLAMAV_BINARIES_DIR/clamonacc" "$CLAMAV_APP/Contents/MacOS/clamonacc"
    echo "  - Placed clamonacc in ResistineClamAV.app"

    cat > "$CLAMAV_APP/Contents/Info.plist" << 'PLISTEOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleIdentifier</key>
    <string>com.resistine.desktop.clamonacc</string>
    <key>CFBundleName</key>
    <string>ResistineClamAV</string>
    <key>CFBundleExecutable</key>
    <string>clamonacc</string>
    <key>CFBundleVersion</key>
    <string>1.0</string>
    <key>CFBundleShortVersionString</key>
    <string>1.0</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
</dict>
</plist>
PLISTEOF

    # Standalone binaries → Contents/Helpers/
    mkdir -p "$PYTHON_APP/Contents/Helpers"
    for bin in clamd clamscan clamdscan freshclam; do
        if [ -f "$CLAMAV_BINARIES_DIR/$bin" ]; then
            cp "$CLAMAV_BINARIES_DIR/$bin" "$PYTHON_APP/Contents/Helpers/$bin"
            echo "  - Placed $bin in Contents/Helpers/"
        fi
    done

    # First-party freshclam auto-update wrapper → Contents/Helpers/
    # Run by the root LaunchDaemon com.resistine.desktop.freshclam.
    if [ -f "$PYTHON_UI_PATH/scripts/clamav/freshclam-update.sh" ]; then
        cp "$PYTHON_UI_PATH/scripts/clamav/freshclam-update.sh" \
            "$PYTHON_APP/Contents/Helpers/freshclam-update.sh"
        chmod 755 "$PYTHON_APP/Contents/Helpers/freshclam-update.sh"
        echo "  - Placed freshclam-update.sh in Contents/Helpers/"
    fi

    # CVD signature-verification certs → Contents/certs/
    if [ -d "$CLAMAV_ARTIFACTS_DIR/certs" ]; then
        mkdir -p "$PYTHON_APP/Contents/certs"
        cp "$CLAMAV_ARTIFACTS_DIR/certs/"* "$PYTHON_APP/Contents/certs/"
        echo "  - Placed CVD verification certs in Contents/certs/"
    fi

    # Shared libraries → Contents/Frameworks/ (skip static archives, deduplicate symlinks)
    mkdir -p "$PYTHON_APP/Contents/Frameworks"
    for f in "$CLAMAV_LIB_DIR"/*; do
        [ -e "$f" ] || continue
        # Skip static archives — only needed at compile time, not runtime
        case "$f" in *.a) continue ;; esac
        # Only copy the real file for each library; recreate version symlinks
        if [ -L "$f" ]; then
            cp -a "$f" "$PYTHON_APP/Contents/Frameworks/"
        else
            cp "$f" "$PYTHON_APP/Contents/Frameworks/"
        fi
    done
    echo "  - Placed ClamAV libraries in Contents/Frameworks/"

    # ── Fix dylib rpaths ──
    # CI-built binaries have hardcoded rpaths from the build machine.
    # Rewrite them so binaries find dylibs in Contents/Frameworks/ at runtime.
    echo "  - Fixing ClamAV dylib rpaths..."

    FRAMEWORKS_RELATIVE="@executable_path/../Frameworks"

    # Fix binaries in Contents/Helpers/
    for bin in clamd clamscan clamdscan freshclam; do
        BIN_PATH="$PYTHON_APP/Contents/Helpers/$bin"
        [ -f "$BIN_PATH" ] || continue

        # Remove all existing LC_RPATH entries
        for old_rpath in $(otool -l "$BIN_PATH" 2>/dev/null | awk '/cmd LC_RPATH/{found=1} found && /path /{print $2; found=0}'); do
            install_name_tool -delete_rpath "$old_rpath" "$BIN_PATH" 2>/dev/null || true
        done

        # Add the correct rpath
        install_name_tool -add_rpath "$FRAMEWORKS_RELATIVE" "$BIN_PATH" 2>/dev/null || true

        # Rewrite hardcoded Homebrew load commands to @rpath
        for homebrew_ref in $(otool -L "$BIN_PATH" 2>/dev/null | awk '/\/opt\/homebrew/{print $1}'); do
            install_name_tool -change "$homebrew_ref" "@rpath/$(basename "$homebrew_ref")" "$BIN_PATH" 2>/dev/null || true
        done
        echo "    Fixed rpath: $bin → $FRAMEWORKS_RELATIVE"
    done

    # Fix clamonacc in nested bundle (different relative path)
    CLAMONACC_PATH="$CLAMAV_APP/Contents/MacOS/clamonacc"
    if [ -f "$CLAMONACC_PATH" ]; then
        CLAMONACC_FRAMEWORKS="@executable_path/../../../../Frameworks"
        for old_rpath in $(otool -l "$CLAMONACC_PATH" 2>/dev/null | awk '/cmd LC_RPATH/{found=1} found && /path /{print $2; found=0}'); do
            install_name_tool -delete_rpath "$old_rpath" "$CLAMONACC_PATH" 2>/dev/null || true
        done
        install_name_tool -add_rpath "$CLAMONACC_FRAMEWORKS" "$CLAMONACC_PATH" 2>/dev/null || true
        # Rewrite hardcoded Homebrew load commands to @rpath
        for homebrew_ref in $(otool -L "$CLAMONACC_PATH" 2>/dev/null | awk '/\/opt\/homebrew/{print $1}'); do
            install_name_tool -change "$homebrew_ref" "@rpath/$(basename "$homebrew_ref")" "$CLAMONACC_PATH" 2>/dev/null || true
        done
        echo "    Fixed rpath: clamonacc → $CLAMONACC_FRAMEWORKS"
    fi

    # Fix dylibs that reference other dylibs via @rpath
    for dylib in "$PYTHON_APP/Contents/Frameworks"/lib*.dylib; do
        [ -f "$dylib" ] || continue
        [ -L "$dylib" ] && continue  # Skip symlinks

        # Remove hardcoded rpaths
        for old_rpath in $(otool -l "$dylib" 2>/dev/null | awk '/cmd LC_RPATH/{found=1} found && /path /{print $2; found=0}'); do
            install_name_tool -delete_rpath "$old_rpath" "$dylib" 2>/dev/null || true
        done

        # Set the dylib's own install name to @rpath/name
        DYLIB_NAME=$(basename "$dylib")
        install_name_tool -id "@rpath/$DYLIB_NAME" "$dylib" 2>/dev/null || true

        # Add rpath for peer dylib resolution
        install_name_tool -add_rpath "@loader_path" "$dylib" 2>/dev/null || true

        # Rewrite hardcoded Homebrew load commands to @rpath
        for homebrew_ref in $(otool -L "$dylib" 2>/dev/null | awk '/\/opt\/homebrew/{print $1}'); do
            install_name_tool -change "$homebrew_ref" "@rpath/$(basename "$homebrew_ref")" "$dylib" 2>/dev/null || true
        done
    done
    echo "    Fixed dylib install names and rpaths"

    # LaunchDaemon plists → Contents/Library/LaunchDaemons/
    # Registered at runtime via SMAppService (no manual launchctl needed).
    # clamd/clamonacc plists ship from the ClamAV-Mac CI artifact (downloaded
    # into the gitignored clamav-artifacts/ dir, which download-clamav-artifacts.sh
    # wipes+repopulates each build).
    LAUNCHD_SRC="$CLAMAV_ARTIFACTS_DIR/launchd"
    DAEMONS_DIR="$PYTHON_APP/Contents/Library/LaunchDaemons"
    mkdir -p "$DAEMONS_DIR"
    if [ -d "$LAUNCHD_SRC" ]; then
        cp "$LAUNCHD_SRC/"*.plist "$DAEMONS_DIR/"
        echo "  - Placed launchd plists in Contents/Library/LaunchDaemons/"

        # Normalize legacy plist names to the com.resistine.desktop.* convention
        # that clamav-postinstall-darwin.sh (load_daemons step) and the runtime
        # SMAppService registration both expect. The ClamAV-Mac CI artifact still
        # ships the pre-migration names (com.resistine.clamd / com.resistine.clamonacc);
        # only freshclam was migrated. Without this rename the postinstall fails
        # with "plist not found: com.resistine.desktop.clamd.plist" and antivirus
        # setup never completes. Renames the file AND rewrites the internal Label
        # so SMAppService registers under the matching identifier. Idempotent: a
        # no-op once the upstream artifact ships the .desktop. names.
        for base in clamd clamonacc; do
            old="$DAEMONS_DIR/com.resistine.$base.plist"
            new="$DAEMONS_DIR/com.resistine.desktop.$base.plist"
            if [ -f "$old" ]; then
                /usr/bin/sed -i '' \
                    "s/com\.resistine\.$base/com.resistine.desktop.$base/g" "$old"
                mv "$old" "$new"
                echo "  - Normalized com.resistine.$base.plist -> com.resistine.desktop.$base.plist"
            fi
        done
    else
        echo "  - Warning: No launchd plists found in artifacts"
    fi

    # First-party freshclam auto-update daemon plist (tracked in git, NOT a
    # downloaded artifact — so it survives the artifacts-dir wipe and needs no
    # ClamAV-Mac changes). Pairs with Contents/Helpers/freshclam-update.sh.
    FRESHCLAM_PLIST_SRC="$PYTHON_UI_PATH/scripts/clamav/com.resistine.desktop.freshclam.plist"
    if [ -f "$FRESHCLAM_PLIST_SRC" ]; then
        cp "$FRESHCLAM_PLIST_SRC" \
            "$PYTHON_APP/Contents/Library/LaunchDaemons/com.resistine.desktop.freshclam.plist"
        echo "  - Placed freshclam auto-update daemon plist"
    fi

    echo "  ClamAV components placed in bundle"
else
    echo "Step 4b: Skipping ClamAV — no artifacts found"
    echo "  Run: scripts/build/download-clamav-artifacts.sh"
    CLAMAV_AVAILABLE=false
fi

# ============================================================
# Step 5: Embed Developer ID provisioning profiles & sign
# ============================================================
echo ""
echo "Step 5: Embedding Developer ID provisioning profiles & signing..."

PROFILES_DIR="$PYTHON_UI_PATH/provisioning-profiles"
NE_PROFILE="$PROFILES_DIR/Mac_Network_Ext.provisionprofile"
XPC_PROFILE="$PROFILES_DIR/Mac_VPNXPC.provisionprofile"
MAIN_PROFILE="$PROFILES_DIR/Mac_Desktop.provisionprofile"
CLAMONACC_PROFILE="$PROFILES_DIR/Mac_ClamOnAcc.provisionprofile"

# Validate Profiles
if [ ! -f "$NE_PROFILE" ]; then
    echo "  Error: Network Extension Developer ID profile not found at: $NE_PROFILE"
    exit 1
fi

if [ ! -f "$XPC_PROFILE" ]; then
    echo "  Error: VPNXPC Service Developer ID profile not found at: $XPC_PROFILE"
    exit 1
fi

if [ ! -f "$MAIN_PROFILE" ]; then
    echo "  Error: Main App Developer ID profile not found at: $MAIN_PROFILE"
    exit 1
fi

# Embedding Developer ID profiles into components
echo "  - Embedding Developer ID profile into system extension..."
cp "$NE_PROFILE" "$PYTHON_APP/Contents/Library/SystemExtensions/com.resistine.desktop.network-extension.systemextension/Contents/embedded.provisionprofile"

echo "  - Embedding Developer ID profile into main app..."
cp "$MAIN_PROFILE" "$PYTHON_APP/Contents/embedded.provisionprofile"

echo "  - Embedding XPC profile into CLI bundle..."
cp "$XPC_PROFILE" "$CLI_APP/Contents/embedded.provisionprofile"

# Embed ESF provisioning profile into ResistineClamAV.app (clamonacc)
if [ "$CLAMAV_AVAILABLE" = true ] && [ -d "$PYTHON_APP/Contents/Helpers/ResistineClamAV.app" ]; then
    if [ -f "$CLAMONACC_PROFILE" ]; then
        echo "  - Embedding ESF profile into ResistineClamAV.app..."
        cp "$CLAMONACC_PROFILE" "$PYTHON_APP/Contents/Helpers/ResistineClamAV.app/Contents/embedded.provisionprofile"
    else
        echo "  - Warning: ClamOnAcc provisioning profile not found at $CLAMONACC_PROFILE"
        echo "    clamonacc will not be able to register as an ESF client"
    fi
fi

# Create symlink for compatibility
# Python code expects resistine-vpn-cli at ../MacOS/resistine-vpn-cli
echo "  - Creating symlink for CLI..."
ln -sf "ResistineCLI.app/Contents/MacOS/resistine-vpn-cli" "$PYTHON_APP/Contents/MacOS/resistine-vpn-cli"

# --- Copy Sparkle.framework for auto-updates ---
echo "  - Copying Sparkle.framework..."
SPARKLE_SOURCE="$PYTHON_UI_PATH/frameworks/Sparkle.framework"
if [ -d "$SPARKLE_SOURCE" ]; then
    mkdir -p "$PYTHON_APP/Contents/Frameworks"
    cp -R "$SPARKLE_SOURCE" "$PYTHON_APP/Contents/Frameworks/Sparkle.framework"
    echo "    Sparkle.framework copied"
else
    echo "    Warning: Sparkle.framework not found at $SPARKLE_SOURCE — skipping auto-update"
fi

# --- Copy LICENSE files into bundle Resources/ ---
# Ship the GPL text and the auto-generated third-party license file inside
# Contents/Resources/ so end users can find them via "Show Package Contents"
# in Finder, and so compliance/auditor questions have a single canonical
# answer that lives next to the app rather than only on GitHub.
echo "  - Copying LICENSE files into bundle Resources/..."
mkdir -p "$PYTHON_APP/Contents/Resources"
if [ -f "$PYTHON_UI_PATH/LICENSE.md" ]; then
    cp "$PYTHON_UI_PATH/LICENSE.md" "$PYTHON_APP/Contents/Resources/LICENSE.md"
    echo "    LICENSE.md copied"
else
    echo "    Warning: LICENSE.md not found at $PYTHON_UI_PATH/LICENSE.md"
fi
if [ -f "$PYTHON_UI_PATH/LICENSE-3rd-Party.md" ]; then
    cp "$PYTHON_UI_PATH/LICENSE-3rd-Party.md" "$PYTHON_APP/Contents/Resources/LICENSE-3rd-Party.md"
    echo "    LICENSE-3rd-Party.md copied"
else
    # Don't fail the build — release.yml regenerates this before this step
    # runs, but local dev builds may skip generation. Warn loudly so it's
    # obvious in the build log.
    echo "    Warning: LICENSE-3rd-Party.md not found at repo root."
    echo "    Run ./scripts/sbom/run.sh to create it."
fi
if [ -f "$PYTHON_UI_PATH/sbom.cdx.json" ]; then
    cp "$PYTHON_UI_PATH/sbom.cdx.json" "$PYTHON_APP/Contents/Resources/sbom.cdx.json"
    echo "    sbom.cdx.json copied"
else
    echo "    Warning: sbom.cdx.json not found at repo root."
    echo "    Run ./scripts/sbom/run.sh to create it."
fi


# Locate entitlements files
ENTITLEMENTS_FILE="$PYTHON_UI_PATH/packaging/Resistine.entitlements"

NE_DIST_ENTITLEMENTS="/tmp/ne-distribution.entitlements.plist"
CLI_DIST_ENTITLEMENTS="/tmp/cli-distribution.entitlements.plist"

echo "  - Generating distribution entitlements..."

# NE Entitlements
cat > "$NE_DIST_ENTITLEMENTS" << ENTEOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>com.apple.application-identifier</key>
	<string>${TEAM_ID}.com.resistine.desktop.network-extension</string>
	<key>com.apple.developer.team-identifier</key>
	<string>${TEAM_ID}</string>
	<key>com.apple.developer.networking.networkextension</key>
	<array>
		<string>packet-tunnel-provider-systemextension</string>
	</array>
	<key>com.apple.security.app-sandbox</key>
	<true/>
	<key>com.apple.security.application-groups</key>
	<array>
		<string>group.Resistine.WireguardTest</string>
		<string>${TEAM_ID}.*</string>
	</array>
	<key>com.apple.security.network.client</key>
	<true/>
	<key>com.apple.security.network.server</key>
	<true/>
	<key>keychain-access-groups</key>
	<array>
		<string>${TEAM_ID}.*</string>
	</array>
</dict>
</plist>
ENTEOF

# CLI Entitlements (referencing the bundle ID)
cat > "$CLI_DIST_ENTITLEMENTS" << ENTEOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>com.apple.application-identifier</key>
	<string>${TEAM_ID}.com.resistine.desktop.vpnxpc</string>
	<key>com.apple.developer.team-identifier</key>
	<string>${TEAM_ID}</string>
	<key>com.apple.developer.networking.networkextension</key>
	<array>
		<string>packet-tunnel-provider-systemextension</string>
	</array>
	<key>com.apple.security.app-sandbox</key>
	<true/>
	<key>com.apple.security.application-groups</key>
	<array>
		<string>group.Resistine.WireguardTest</string>
		<string>${TEAM_ID}.*</string>
	</array>
	<key>com.apple.security.network.client</key>
	<true/>
	<key>keychain-access-groups</key>
	<array>
		<string>${TEAM_ID}.*</string>
	</array>
</dict>
</plist>
ENTEOF


ENTITLEMENTS_FLAG=""
if [ -f "$ENTITLEMENTS_FILE" ]; then
    ENTITLEMENTS_FLAG="--entitlements $ENTITLEMENTS_FILE"
fi

# --- Sign innermost components first, then work outward ---
# Order matters: sign binaries inside bundles before signing the bundle itself.

# 5-clamav: Sign ClamAV components (innermost first)
if [ "$CLAMAV_AVAILABLE" = true ]; then
    echo "  - Signing ClamAV components with Developer ID..."

    CLAMAV_ENTITLEMENTS="$CLAMAV_ARTIFACTS_DIR/entitlements.plist"

    # Sign clamonacc with ESF entitlements
    if [ -f "$CLAMAV_ENTITLEMENTS" ]; then
        codesign --force --sign "$SIGN_IDENTITY" \
            --options runtime --timestamp \
            --entitlements "$CLAMAV_ENTITLEMENTS" \
            "$PYTHON_APP/Contents/Helpers/ResistineClamAV.app/Contents/MacOS/clamonacc" || {
            echo "    clamonacc signing failed"
            exit 1
        }
    fi

    # Sign ResistineClamAV.app bundle (preserve ESF entitlements for clamonacc)
    codesign --force --sign "$SIGN_IDENTITY" \
        --options runtime --timestamp \
        ${CLAMAV_ENTITLEMENTS:+--entitlements "$CLAMAV_ENTITLEMENTS"} \
        "$PYTHON_APP/Contents/Helpers/ResistineClamAV.app" || {
        echo "    ResistineClamAV.app signing failed"
        exit 1
    }

    # Sign other ClamAV binaries (hardened runtime for notarization).
    # freshclam-update.sh is the first-party auto-update wrapper — a signed
    # shell script inside the notarized bundle.
    for binary in clamd clamscan clamdscan freshclam freshclam-update.sh; do
        if [ -f "$PYTHON_APP/Contents/Helpers/$binary" ]; then
            codesign --force --sign "$SIGN_IDENTITY" \
                --options runtime --timestamp \
                "$PYTHON_APP/Contents/Helpers/$binary" || {
                echo "    $binary signing failed"
                exit 1
            }
        fi
    done

    # Sign ClamAV shared libraries (all ClamAV-related dylibs including unrar, ssl, crypto)
    find "$PYTHON_APP/Contents/Frameworks" \( -name "libclamav*" -o -name "libfreshclam*" -o -name "libclammspack*" -o -name "libclamunrar*" -o -name "libcrypto*" -o -name "libssl*" -o -name "libjson-c*" \) -type f | while read -r lib; do
        codesign --force --sign "$SIGN_IDENTITY" \
            --options runtime --timestamp \
            "$lib" 2>/dev/null || true
    done

    echo "    ClamAV components signed"
fi

# 5a: Sign the system extension with distribution entitlements
echo "  - Signing system extension with Developer ID..."
codesign --force --sign "$SIGN_IDENTITY" \
    --options runtime \
    --timestamp \
    --entitlements "$NE_DIST_ENTITLEMENTS" \
    "$PYTHON_APP/Contents/Library/SystemExtensions/com.resistine.desktop.network-extension.systemextension" || {
    echo "  System Extension signing failed"
    exit 1
}
echo "    System Extension signed"

# 5b: Sign the CLI with distribution entitlements (reusing VPNXPC profile)
echo "  - Signing resistine-vpn-cli with Developer ID..."
codesign --force --sign "$SIGN_IDENTITY" \
    --options runtime \
    --timestamp \
    --entitlements "$CLI_DIST_ENTITLEMENTS" \
    "$PYTHON_APP/Contents/MacOS/resistine-vpn-cli" || {
    echo "  resistine-vpn-cli signing failed"
    exit 1
}
echo "    resistine-vpn-cli signed"

# 5d: Sign all PyInstaller frameworks/libraries
# NOTE: python.org Python bundles bare Tcl/Tk binaries (no file extension).
# We must sign ALL Mach-O binaries, not just *.so/*.dylib.
echo "  - Signing PyInstaller frameworks and shared libraries..."
find "$PYTHON_APP/Contents/Frameworks" "$PYTHON_APP/Contents/MacOS" \
    -type f \( -name "*.so" -o -name "*.dylib" -o -name "Python" -o -name "Tcl" -o -name "Tk" -o -name "tkhtml" \) | while read -r binary; do
    codesign --force --sign "$SIGN_IDENTITY" \
        --options runtime \
        --timestamp \
        "$binary" 2>/dev/null || {
        echo "    Warning: Failed to sign: $(basename "$binary")"
    }
done
echo "    Framework/library signing complete"

# 5d-2: Sign Qt framework binaries (PyQt6)
# PyInstaller bundles Qt as Contents/Frameworks/PyQt6/Qt6/lib/<Name>.framework
# whose main binaries are EXTENSIONLESS Mach-O files (Versions/A/QtCore etc.)
# — the pattern-find above never matches them, which fails notarization
# ("binary is not signed with a valid Developer ID certificate"). PyQt6 wheels
# ship slimmed frameworks without Resources/Info.plist, so codesign on the
# .framework bundle can error with "bundle format unrecognized"; sign each
# Mach-O binary file directly instead — exactly the paths the notary log
# reports.
echo "  - Signing Qt framework binaries (PyQt6)..."
_QT_SIGNED=0
while IFS= read -r binary; do
    file "$binary" 2>/dev/null | grep -q "Mach-O" || continue
    codesign --force --sign "$SIGN_IDENTITY" \
        --options runtime \
        --timestamp \
        "$binary" 2>/dev/null || {
        echo "    Warning: Failed to sign: $binary"
        continue
    }
    _QT_SIGNED=$((_QT_SIGNED + 1))
done < <(find "$PYTHON_APP/Contents/Frameworks" \
    -path "*.framework/Versions/*" -type f \
    ! -name "*.plist" ! -name "*.prl" ! -name "*.h" \
    ! -path "*Sparkle.framework*" ! -path "*Python.framework*")
echo "    Qt framework binaries signed ($_QT_SIGNED)"

# 5e: Sign Sparkle.framework (inner-to-outer: deepest bundles first)
if [ -d "$PYTHON_APP/Contents/Frameworks/Sparkle.framework" ]; then
    SPARKLE_FW="$PYTHON_APP/Contents/Frameworks/Sparkle.framework"
    echo "  - Signing Sparkle.framework internals (inner-to-outer)..."

    # Sign XPC services (Downloader.xpc, Installer.xpc)
    # --preserve-metadata=entitlements: keeps Sparkle's original entitlements intact
    find "$SPARKLE_FW" -name "*.xpc" -type d | while read -r xpc_bundle; do
        codesign --force --sign "$SIGN_IDENTITY" \
            --options runtime --timestamp \
            --preserve-metadata=entitlements \
            "$xpc_bundle" 2>/dev/null || {
            echo "    Warning: Failed to sign: $(basename "$xpc_bundle")"
        }
    done

    # Sign Updater.app (Sparkle 2.9+ ships its own updater app)
    find "$SPARKLE_FW" -name "Updater.app" -type d | while read -r updater_app; do
        codesign --force --sign "$SIGN_IDENTITY" \
            --options runtime --timestamp \
            --preserve-metadata=entitlements \
            "$updater_app" 2>/dev/null || {
            echo "    Warning: Failed to sign Updater.app"
        }
    done

    # Sign the Autoupdate executable
    # CRITICAL: Autoupdate has com.apple.application-identifier which it needs
    # to register mach services for the installer agent connection.
    find "$SPARKLE_FW" -name "Autoupdate" -type f | while read -r autoupdate; do
        codesign --force --sign "$SIGN_IDENTITY" \
            --options runtime --timestamp \
            --preserve-metadata=entitlements \
            "$autoupdate" 2>/dev/null || {
            echo "    Warning: Failed to sign Autoupdate"
        }
    done

    # Sign the Sparkle.framework bundle itself (outermost)
    echo "  - Signing Sparkle.framework..."
    codesign --force --sign "$SIGN_IDENTITY" \
        --options runtime --timestamp \
        "$SPARKLE_FW" || {
        echo "  Sparkle.framework signing failed"
        exit 1
    }
    echo "    Sparkle.framework signed"
fi

# 5f: Sign the outer Resistine.app bundle
echo "  - Signing main Resistine.app bundle..."
codesign --force --sign "$SIGN_IDENTITY" \
    --options runtime \
    $ENTITLEMENTS_FLAG \
    --timestamp \
    "$PYTHON_APP" || {
    echo "  Main app signing failed"
    exit 1
}
echo "    Resistine.app signed"

# Verify all signatures
echo ""
echo "  Verifying signatures..."
VERIFY_FAILED=false

codesign --verify --verbose "$PYTHON_APP/Contents/Library/SystemExtensions/com.resistine.desktop.network-extension.systemextension" 2>&1 && \
    echo "    network-extension.systemextension: valid" || { echo "    network-extension.systemextension: INVALID"; VERIFY_FAILED=true; }

codesign --verify --verbose "$PYTHON_APP/Contents/MacOS/resistine-vpn-cli" 2>&1 && \
    echo "    resistine-vpn-cli: valid" || { echo "    resistine-vpn-cli: INVALID"; VERIFY_FAILED=true; }

if [ -d "$PYTHON_APP/Contents/Frameworks/Sparkle.framework" ]; then
    codesign --verify --verbose "$PYTHON_APP/Contents/Frameworks/Sparkle.framework" 2>&1 && \
        echo "    Sparkle.framework: valid" || { echo "    Sparkle.framework: INVALID"; VERIFY_FAILED=true; }
fi

if [ "$CLAMAV_AVAILABLE" = true ] && [ -d "$PYTHON_APP/Contents/Helpers/ResistineClamAV.app" ]; then
    codesign --verify --verbose "$PYTHON_APP/Contents/Helpers/ResistineClamAV.app" 2>&1 && \
        echo "    ResistineClamAV.app: valid" || { echo "    ResistineClamAV.app: INVALID"; VERIFY_FAILED=true; }
fi

codesign --verify --verbose=2 "$PYTHON_APP" 2>&1 && \
    echo "    Resistine.app: valid" || { echo "    Resistine.app: INVALID"; VERIFY_FAILED=true; }

if [ "$VERIFY_FAILED" = true ]; then
    echo ""
    echo "  Error: One or more signatures are invalid. Aborting."
    exit 1
fi

echo ""
echo "  All signatures verified"

# ============================================================
# Step 6: Create PKG installer (primary distribution format)
# ============================================================
echo ""
echo "Step 6: Creating PKG installer..."

# Detect version from spec file
APP_VERSION=$(python3 -c "
import re, pathlib
spec = pathlib.Path('$PYTHON_UI_PATH/packaging/Resistine.spec').read_text()
m = re.search(r\"VERSION\s*=\s*'([^']+)'\", spec)
print(m.group(1) if m else '1.0.0')
")
echo "  App version: $APP_VERSION"

# Detect Developer ID Installer certificate
INSTALLER_IDENTITY=$(security find-identity -v -p basic 2>/dev/null | grep "Developer ID Installer" | head -1 | awk '{print $2}')
INSTALLER_NAME=""
if [ -n "$INSTALLER_IDENTITY" ]; then
    INSTALLER_NAME=$(security find-identity -v -p basic 2>/dev/null | grep "$INSTALLER_IDENTITY" | sed 's/.*"\(.*\)".*/\1/')
    echo "  Installer signing with: $INSTALLER_NAME"
else
    echo "  Warning: No Developer ID Installer certificate found"
    echo "  PKG will not be signed (install one for distribution)"
fi

# Create install scripts for the pkg.
PKG_SCRIPTS_DIR="$DIST_DIR/pkg-scripts"
mkdir -p "$PKG_SCRIPTS_DIR"

# Preinstall: remove any existing app bundle BEFORE the payload is laid down.
#
# CRITICAL: pkgbuild --install-location installs by MERGING the payload onto the
# destination — it does NOT replace the existing bundle. Files the new payload
# lacks are left behind. With a versioned framework like Python.framework, an
# update from a bundle that shipped (e.g.) Python 3.14 to one shipping 3.13
# leaves the old Versions/3.14 stranded while the Versions/3.13 overwrite can be
# incomplete, producing a bundle whose Frameworks/Python symlink points at a
# half-written runtime. The PyInstaller bootloader then fails with
# "Failed to load Python shared library .../Frameworks/Python" and the app
# crashes on launch (exit 255).
#
# DMG (drag-to-Applications) replaces the bundle atomically, which is why every
# pre-pkg release updated cleanly. Deleting first restores that guarantee.
cat > "$PKG_SCRIPTS_DIR/preinstall" << 'PREEOF'
#!/bin/bash
# Quit the running app, then remove the previously installed bundle so the new
# payload fully REPLACES it instead of MERGING onto stale files.
#
# Why this exists: pkgbuild --install-location merges the payload file-by-file
# onto whatever is already at the destination; it never deletes old files the
# new payload lacks. A versioned framework (Python.framework/Versions/3.X) at a
# different version than the previous install therefore strands the old version
# directory, leaving Frameworks/Python pointing at an incomplete runtime and the
# app crashing on launch. A DMG (Finder drag) replaces the whole .app folder
# atomically, which is why pre-pkg releases updated cleanly. Deleting first makes
# the pkg behave the same way.
#
# We do NOT relaunch here: Sparkle relaunches the app (as the correct user)
# after an auto-update, and a manual pkg install shows Installer's own success
# screen. Launching from this script would run the app as root.

# Quit the app gracefully, then force-kill any stragglers, before removing it.
osascript -e 'quit app "Resistine"' 2>/dev/null || true
pkill -x Resistine 2>/dev/null || true
sleep 1

if [ -d "/Applications/Resistine.app" ]; then
    rm -rf "/Applications/Resistine.app" 2>/dev/null || true
fi
exit 0
PREEOF
chmod +x "$PKG_SCRIPTS_DIR/preinstall"

cat > "$PKG_SCRIPTS_DIR/postinstall" << 'POSTEOF'
#!/bin/bash
# Register with LaunchServices so Spotlight / Finder recognise the app
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -f "/Applications/Resistine.app" 2>/dev/null || true

# NOTE: System Extensions (.systemextension) are NOT managed by pluginkit.
# They are activated via OSSystemExtensionRequest from the running app.
# The app triggers extension activation/replacement on launch automatically.

# Clean up stale log files from previous versions (the network extension
# used to write to ~/Library/Logs/resistine.log but this can contain
# outdated error messages that confuse diagnostics).
CONSOLE_USER=$( /usr/bin/stat -f "%Su" /dev/console 2>/dev/null || echo "" )
if [ -n "$CONSOLE_USER" ]; then
    STALE_LOG=$( eval echo "~$CONSOLE_USER/Library/Logs/resistine.log" )
    if [ -f "$STALE_LOG" ]; then
        rm -f "$STALE_LOG" 2>/dev/null || true
    fi
    STALE_ERR=$( eval echo "~$CONSOLE_USER/Library/Logs/resistine-error.log" )
    if [ -f "$STALE_ERR" ]; then
        rm -f "$STALE_ERR" 2>/dev/null || true
    fi
fi

# Clean up legacy ClamAV daemon labels from versions <= 4.12
# Old versions registered these directly; new versions use SMAppService.
for label in com.resistine.clamd com.resistine.freshclam; do
    plist="/Library/LaunchDaemons/${label}.plist"
    if [ -f "$plist" ]; then
        launchctl bootout system "$plist" 2>/dev/null || true
        rm -f "$plist" 2>/dev/null || true
    fi
done

exit 0
POSTEOF
chmod +x "$PKG_SCRIPTS_DIR/postinstall"

# Build the component package
echo "  - Building component package..."
pkgbuild \
    --root "$PYTHON_APP" \
    --install-location "/Applications/$APP_NAME.app" \
    --identifier "$BUNDLE_ID" \
    --version "$APP_VERSION" \
    --scripts "$PKG_SCRIPTS_DIR" \
    "$DIST_DIR/$APP_NAME-component.pkg"

# Create distribution XML for customized installer UI
cat > "$DIST_DIR/distribution.xml" << DISTEOF
<?xml version="1.0" encoding="utf-8"?>
<installer-gui-script minSpecVersion="2">
    <title>$DISPLAY_NAME</title>
    <organization>com.resistine</organization>
    <domains enable_localSystem="true"/>
    <options customize="never" require-scripts="false" hostArchitectures="arm64,x86_64"/>
    <welcome file="welcome.html" mime-type="text/html"/>
    <license file="license.html" mime-type="text/html"/>
    <conclusion file="conclusion.html" mime-type="text/html"/>
    <volume-check>
        <allowed-os-versions>
            <os-version min="13.0"/>
        </allowed-os-versions>
    </volume-check>
    <choices-outline>
        <line choice="default">
            <line choice="$BUNDLE_ID"/>
        </line>
    </choices-outline>
    <choice id="default"/>
    <choice id="$BUNDLE_ID" visible="false">
        <pkg-ref id="$BUNDLE_ID"/>
    </choice>
    <pkg-ref id="$BUNDLE_ID" version="$APP_VERSION" onConclusion="none">$APP_NAME-component.pkg</pkg-ref>
</installer-gui-script>
DISTEOF

# Resources directory containing welcome/license/conclusion HTML
PKG_RESOURCES_DIR="$PYTHON_UI_PATH/packaging/pkg-resources"
if [ ! -d "$PKG_RESOURCES_DIR" ]; then
    echo "  Error: pkg resources directory not found at: $PKG_RESOURCES_DIR"
    exit 1
fi

# Build the final product archive
echo "  - Building product archive..."
PKG_PATH="$DIST_DIR/$DISPLAY_NAME-Installer.pkg"

if [ -n "$INSTALLER_NAME" ]; then
    productbuild \
        --distribution "$DIST_DIR/distribution.xml" \
        --package-path "$DIST_DIR" \
        --resources "$PKG_RESOURCES_DIR" \
        --sign "$INSTALLER_NAME" \
        --timestamp \
        "$PKG_PATH"
    echo "  PKG signed with: $INSTALLER_NAME"
else
    productbuild \
        --distribution "$DIST_DIR/distribution.xml" \
        --package-path "$DIST_DIR" \
        --resources "$PKG_RESOURCES_DIR" \
        "$PKG_PATH"
    echo "  PKG created (unsigned)"
fi

# Clean up intermediate files
rm -f "$DIST_DIR/$APP_NAME-component.pkg"
rm -f "$DIST_DIR/distribution.xml"
rm -rf "$PKG_SCRIPTS_DIR"

PKG_SIZE=$(du -h "$PKG_PATH" | cut -f1)
echo "  PKG created: $PKG_PATH ($PKG_SIZE)"

# ============================================================
# Step 6b: Create DMG (secondary — for users who prefer drag-and-drop)
# ============================================================
echo ""
echo "Step 6b: Creating DMG installer..."

if ! command -v create-dmg &> /dev/null; then
    echo "  - create-dmg not found. Installing via Homebrew..."
    if command -v brew &> /dev/null; then
        brew install create-dmg
    else
        echo "  Homebrew not found. Cannot create DMG."
        exit 1
    fi
fi

rm -f "$DIST_DIR/$DISPLAY_NAME-Installer.dmg"

BACKGROUND_FLAG=""
if [ -f "$PYTHON_UI_PATH/resources/installer-background.png" ]; then
    BACKGROUND_FLAG="--background $PYTHON_UI_PATH/resources/installer-background.png"
fi

ICON_FLAG=""
if [ -f "$PYTHON_UI_PATH/resources/icons/PhoenixMark.png" ]; then
    ICON_FLAG="--volicon $PYTHON_UI_PATH/resources/icons/PhoenixMark.png"
fi

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
    echo "  DMG creation had warnings but may have succeeded"
  }

if [ ! -f "$DIST_DIR/$DISPLAY_NAME-Installer.dmg" ]; then
    echo "  Error: DMG creation failed"
    exit 1
fi

DMG_SIZE=$(du -h "$DIST_DIR/$DISPLAY_NAME-Installer.dmg" | cut -f1)
echo "  DMG created: $DIST_DIR/$DISPLAY_NAME-Installer.dmg ($DMG_SIZE)"

# Sign the DMG
echo "  - Signing DMG..."
codesign --force --sign "$SIGN_IDENTITY" --timestamp "$DIST_DIR/$DISPLAY_NAME-Installer.dmg" || {
    echo "  DMG signing failed"
    exit 1
}
echo "  DMG signed"

# ============================================================
# Step 7: Notarization (both PKG and DMG)
# ============================================================
echo ""
echo "Step 7: Notarization..."

notarize_and_staple() {
    local artifact="$1"
    local label="$2"
    local log_file="/tmp/resistine-notarize-${label}.txt"

    echo "  Submitting $label for notarization..."
    xcrun notarytool submit "$artifact" \
        --keychain-profile "resistine-notarize" \
        --wait 2>&1 | tee "$log_file"

    if grep -q "status: Accepted" "$log_file"; then
        echo "  $label notarization accepted"
        echo "  Stapling notarization ticket to $label..."
        xcrun stapler staple "$artifact" && {
            echo "  $label stapled successfully"
        } || {
            echo "  Warning: $label stapling failed (still notarized, just not stapled)"
        }
        rm -f "$log_file"
        return 0
    else
        echo ""
        echo "  $label notarization failed. Fetching detailed log..."
        SUBMISSION_ID=$(grep "id:" "$log_file" | head -1 | awk '{print $2}')
        if [ -n "$SUBMISSION_ID" ]; then
            echo ""
            xcrun notarytool log "$SUBMISSION_ID" \
                --keychain-profile "resistine-notarize" 2>&1
        fi
        rm -f "$log_file"
        return 1
    fi
}

if [ "$SKIP_NOTARIZE" = true ]; then
    echo "  Skipping notarization (no credentials configured)"
    echo ""
    echo "  To notarize manually later:"
    echo "    xcrun notarytool submit $DIST_DIR/$DISPLAY_NAME-Installer.pkg \\"
    echo "      --keychain-profile \"resistine-notarize\" --wait"
    echo "    xcrun stapler staple $DIST_DIR/$DISPLAY_NAME-Installer.pkg"
else
    # Notarize PKG (primary)
    notarize_and_staple "$DIST_DIR/$DISPLAY_NAME-Installer.pkg" "PKG" || {
        echo "  Fix the issues above and re-run this script."
        exit 1
    }

    # Notarize DMG (secondary)
    notarize_and_staple "$DIST_DIR/$DISPLAY_NAME-Installer.dmg" "DMG" || {
        echo "  Warning: DMG notarization failed (PKG is still valid)"
    }
fi

# Clean up temporary entitlements files
rm -f /tmp/ne-distribution.entitlements.plist /tmp/cli-distribution.entitlements.plist

# ============================================================
# Step 8: Install to /Applications
# ============================================================
echo ""
echo "Step 8: Installing to /Applications..."

if [ -d "/Applications/$APP_NAME.app" ]; then
    echo "  - Removing old /Applications/$APP_NAME.app..."
    rm -rf "/Applications/$APP_NAME.app" || {
        echo "  Failed to remove old app (may need sudo)"
    }
fi

cp -R "$PYTHON_APP" "/Applications/$APP_NAME.app" && {
    echo "  Installed to /Applications/$APP_NAME.app"
} || {
    echo "  Failed to install (may need sudo)"
}

# Register with LaunchServices so Spotlight / Finder recognise the new build
echo "  - Registering app with LaunchServices..."
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -f "/Applications/$APP_NAME.app" 2>/dev/null || true

# NOTE: System Extensions are activated via OSSystemExtensionRequest at app
# launch, not via pluginkit (which is for PlugIn Kit extensions only).
# The app will detect the version mismatch and request replacement on first run.

# ── ClamAV system setup ──
# System directories, configs, and DB seeding are handled at runtime by
# activate_system_daemons() in clamav_platform_darwin.py (with a native
# macOS admin dialog), matching the VPN helper pattern. No sudo needed
# at build time — daemons are registered via SMAppService at app launch.

# ============================================================
# Summary
# ============================================================
echo ""
echo "==================================="
echo "  Distribution Build Complete!"
echo "==================================="
echo ""
echo "  PKG Installer: $DIST_DIR/$DISPLAY_NAME-Installer.pkg  (recommended)"
echo "  DMG Installer: $DIST_DIR/$DISPLAY_NAME-Installer.dmg  (drag-and-drop alternative)"
echo "  App Bundle:    $PYTHON_APP"
echo ""
if [ "$SKIP_NOTARIZE" = true ]; then
    echo "  Status: Signed with Developer ID (NOT notarized)"
    echo "  Run notarization manually before distributing."
else
    echo "  Status: Signed, Notarized, and Stapled"
    echo "  Ready for public distribution."
fi
echo ""
