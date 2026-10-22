#!/bin/bash
set -e

# Download pre-built VPN artifacts from GitHub Actions
# Requires: GitHub CLI (gh) authenticated with access to Resistine/resistine-vpn-macos
#
# Usage:
#   ./download-vpn-artifacts.sh                  # download latest from main
#   ./download-vpn-artifacts.sh <run-id>         # download from specific run
#   ./download-vpn-artifacts.sh --check          # exit 0 if up-to-date, 1 if stale
#
# Called automatically by build-distribution.sh when artifacts are missing or stale.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ARTIFACTS_DIR="$SCRIPT_DIR/vpn-artifacts"
REPO="Resistine/resistine-vpn-macos"
VERSION_FILE="$ARTIFACTS_DIR/.vpn-version"

# Check for gh CLI
if ! command -v gh &> /dev/null; then
    echo "Error: GitHub CLI (gh) is required but not installed."
    echo "  Install: brew install gh"
    echo "  Then:    gh auth login"
    exit 1
fi

# Query the latest artifact's commit SHA from CI
get_remote_sha() {
    gh api "repos/$REPO/actions/artifacts?name=vpn-macos-latest&per_page=1" \
        --jq '.artifacts[0].workflow_run.head_sha' 2>/dev/null || echo ""
}

# Read local version
get_local_sha() {
    if [ -f "$VERSION_FILE" ]; then
        cat "$VERSION_FILE"
    else
        echo ""
    fi
}

# --check mode: just report if up-to-date
if [ "$1" = "--check" ]; then
    LOCAL_SHA=$(get_local_sha)
    if [ -z "$LOCAL_SHA" ]; then
        echo "No local VPN artifacts"
        exit 1
    fi
    REMOTE_SHA=$(get_remote_sha)
    if [ -z "$REMOTE_SHA" ]; then
        echo "Could not query remote version (offline or no access)"
        exit 0  # don't block builds when offline
    fi
    if [ "$LOCAL_SHA" = "$REMOTE_SHA" ]; then
        echo "VPN artifacts up-to-date ($LOCAL_SHA)"
        exit 0
    else
        echo "VPN artifacts stale (local: ${LOCAL_SHA:0:12}, remote: ${REMOTE_SHA:0:12})"
        exit 1
    fi
fi

# Determine what to download
if [ -n "$1" ]; then
    echo "Downloading VPN artifacts from run $1..."
    DOWNLOAD_SHA=""
else
    # Check if we even need to download
    REMOTE_SHA=$(get_remote_sha)
    LOCAL_SHA=$(get_local_sha)

    if [ -n "$REMOTE_SHA" ] && [ "$LOCAL_SHA" = "$REMOTE_SHA" ] \
       && [ -f "$ARTIFACTS_DIR/resistine-vpn-cli" ] \
       && [ -d "$ARTIFACTS_DIR/com.resistine.desktop.network-extension.systemextension" ]; then
        echo "VPN artifacts already up-to-date (${REMOTE_SHA:0:12})"
        exit 0
    fi

    if [ -n "$REMOTE_SHA" ]; then
        echo "Downloading VPN artifacts (${REMOTE_SHA:0:12})..."
    else
        echo "Downloading latest VPN artifacts from main..."
    fi
    DOWNLOAD_SHA="$REMOTE_SHA"
fi

# Clean previous artifacts
rm -rf "$ARTIFACTS_DIR"
mkdir -p "$ARTIFACTS_DIR"

if [ -n "$1" ]; then
    gh run download "$1" --repo "$REPO" --dir "$ARTIFACTS_DIR"
else
    gh run download --repo "$REPO" --name vpn-macos-latest --dir "$ARTIFACTS_DIR"
fi

# gh run download nests files inside a subdirectory named after the artifact.
# Flatten so files are directly in ARTIFACTS_DIR.
NESTED=$(find "$ARTIFACTS_DIR" -mindepth 1 -maxdepth 1 -type d | head -1)
if [ -n "$NESTED" ] && [ ! -f "$ARTIFACTS_DIR/resistine-vpn-cli" ]; then
    echo "  Flattening nested directory: $(basename "$NESTED")"
    mv "$NESTED"/* "$ARTIFACTS_DIR/" 2>/dev/null || true
    find "$NESTED" -mindepth 1 -maxdepth 1 -type d -exec mv {} "$ARTIFACTS_DIR/" \; 2>/dev/null || true
    rmdir "$NESTED" 2>/dev/null || true
fi

# Verify expected files
if [ ! -f "$ARTIFACTS_DIR/resistine-vpn-cli" ]; then
    echo "Error: resistine-vpn-cli not found in downloaded artifacts"
    exit 1
fi

if [ ! -d "$ARTIFACTS_DIR/com.resistine.desktop.network-extension.systemextension" ]; then
    echo "Error: network extension not found in downloaded artifacts"
    exit 1
fi

# Verify artifact checksums (if present)
if [ -f "$ARTIFACTS_DIR/checksums.txt" ]; then
    echo "  Verifying artifact checksums..."
    if (cd "$ARTIFACTS_DIR" && shasum -a 256 -c checksums.txt); then
        echo "  Checksums verified"
    else
        echo "Error: Checksum verification failed — artifacts may be corrupted"
        exit 1
    fi
fi

# Save version for staleness checks
if [ -n "$DOWNLOAD_SHA" ]; then
    echo "$DOWNLOAD_SHA" > "$VERSION_FILE"
elif [ -n "$1" ]; then
    # For specific run IDs, query the run's head SHA
    RUN_SHA=$(gh api "repos/$REPO/actions/runs/$1" --jq '.head_sha' 2>/dev/null || echo "")
    if [ -n "$RUN_SHA" ]; then
        echo "$RUN_SHA" > "$VERSION_FILE"
    fi
fi

echo ""
echo "VPN artifacts downloaded to: $ARTIFACTS_DIR"
ls -lh "$ARTIFACTS_DIR/"
