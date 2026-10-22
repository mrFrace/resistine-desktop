#!/bin/bash
set -e

# Download pre-built ClamAV artifacts from GitHub Actions
# Requires: GitHub CLI (gh) authenticated with access to Resistine/ClamAV-Mac
#
# Usage:
#   ./download-clamav-artifacts.sh                  # download latest from main
#   ./download-clamav-artifacts.sh <run-id>         # download from specific run
#   ./download-clamav-artifacts.sh --check          # exit 0 if up-to-date, 1 if stale
#
# Called automatically by build-distribution.sh when artifacts are missing or stale.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ARTIFACTS_DIR="$SCRIPT_DIR/clamav-artifacts"
REPO="Resistine/ClamAV-Mac"
VERSION_FILE="$ARTIFACTS_DIR/.clamav-version"

# Check for gh CLI
if ! command -v gh &> /dev/null; then
    echo "Error: GitHub CLI (gh) is required but not installed."
    echo "  Install: brew install gh"
    echo "  Then:    gh auth login"
    exit 1
fi

# Query the latest artifact's commit SHA and name from CI (single API call)
# Sets LATEST_SHA and LATEST_ARTIFACT_NAME globals
fetch_latest_artifact_info() {
    local info
    info=$(gh api "repos/$REPO/actions/artifacts?per_page=1" \
        --jq '.artifacts[0] | "\(.workflow_run.head_sha) \(.name)"' 2>/dev/null || echo "")
    LATEST_SHA="${info%% *}"
    LATEST_ARTIFACT_NAME="${info#* }"
}

get_remote_sha() {
    if [ -z "${LATEST_SHA+x}" ]; then
        fetch_latest_artifact_info
    fi
    echo "$LATEST_SHA"
}

get_artifact_name() {
    if [ -z "${LATEST_ARTIFACT_NAME+x}" ]; then
        fetch_latest_artifact_info
    fi
    echo "$LATEST_ARTIFACT_NAME"
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
        echo "No local ClamAV artifacts"
        exit 1
    fi
    REMOTE_SHA=$(get_remote_sha)
    if [ -z "$REMOTE_SHA" ]; then
        echo "Could not query remote version (offline or no access)"
        exit 0  # don't block builds when offline
    fi
    if [ "$LOCAL_SHA" = "$REMOTE_SHA" ]; then
        echo "ClamAV artifacts up-to-date ($LOCAL_SHA)"
        exit 0
    else
        echo "ClamAV artifacts stale (local: ${LOCAL_SHA:0:12}, remote: ${REMOTE_SHA:0:12})"
        exit 1
    fi
fi

# Determine what to download
if [ -n "$1" ]; then
    echo "Downloading ClamAV artifacts from run $1..."
    DOWNLOAD_SHA=""
else
    # Check if we even need to download
    REMOTE_SHA=$(get_remote_sha)
    LOCAL_SHA=$(get_local_sha)

    if [ -n "$REMOTE_SHA" ] && [ "$LOCAL_SHA" = "$REMOTE_SHA" ] \
       && [ -f "$ARTIFACTS_DIR/binaries/clamonacc" ] \
       && [ -f "$ARTIFACTS_DIR/binaries/clamd" ]; then
        echo "ClamAV artifacts already up-to-date (${REMOTE_SHA:0:12})"
        exit 0
    fi

    ARTIFACT_NAME=$(get_artifact_name)

    if [ -n "$REMOTE_SHA" ]; then
        echo "Downloading ClamAV artifacts (${REMOTE_SHA:0:12})..."
    else
        echo "Downloading latest ClamAV artifacts from main..."
    fi
    DOWNLOAD_SHA="$REMOTE_SHA"
fi

# Clean previous artifacts
rm -rf "$ARTIFACTS_DIR"
mkdir -p "$ARTIFACTS_DIR"

if [ -n "$1" ]; then
    gh run download "$1" --repo "$REPO" --dir "$ARTIFACTS_DIR"
else
    if [ -z "$ARTIFACT_NAME" ]; then
        echo "Error: Could not determine artifact name from CI"
        exit 1
    fi
    gh run download --repo "$REPO" --name "$ARTIFACT_NAME" --dir "$ARTIFACTS_DIR"
fi

# gh run download nests files inside a subdirectory named after the artifact.
# Flatten so files are directly in ARTIFACTS_DIR.
NESTED=$(find "$ARTIFACTS_DIR" -mindepth 1 -maxdepth 1 -type d | head -1)
if [ -n "$NESTED" ] && [ ! -d "$ARTIFACTS_DIR/binaries" ]; then
    echo "  Flattening nested directory: $(basename "$NESTED")"
    mv "$NESTED"/* "$ARTIFACTS_DIR/" 2>/dev/null || true
    find "$NESTED" -mindepth 1 -maxdepth 1 -type d -exec mv {} "$ARTIFACTS_DIR/" \; 2>/dev/null || true
    rmdir "$NESTED" 2>/dev/null || true
fi

# Verify expected files
if [ ! -f "$ARTIFACTS_DIR/binaries/clamonacc" ]; then
    echo "Error: binaries/clamonacc not found in downloaded artifacts"
    exit 1
fi

if [ ! -f "$ARTIFACTS_DIR/binaries/clamd" ]; then
    echo "Error: binaries/clamd not found in downloaded artifacts"
    exit 1
fi

LIBCLAMAV_COUNT=$(find "$ARTIFACTS_DIR/lib" -name "libclamav*" 2>/dev/null | wc -l)
if [ "$LIBCLAMAV_COUNT" -eq 0 ]; then
    echo "Error: lib/libclamav* not found in downloaded artifacts"
    exit 1
fi

if [ ! -d "$ARTIFACTS_DIR/launchd" ]; then
    echo "Warning: launchd/ directory not found in artifacts (daemon auto-start won't work)"
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

# ── Bundle CVD signature-verification certs ──
# freshclam needs clamav.crt to verify downloaded CVD signatures. The CI build
# bakes a hardcoded certs path that won't exist on end-user machines.
# Search order: CI artifact → local ClamAV-Mac source tree → GitHub repo.
if [ ! -f "$ARTIFACTS_DIR/certs/clamav.crt" ]; then
    CLAMAV_SRC="${CLAMAV_SRC_DIR:-$(cd "$SCRIPT_DIR/../.." && pwd)/../ClamAV-Mac}"
    CERT_CANDIDATES=(
        "$CLAMAV_SRC/install/etc/certs/clamav.crt"
        "$CLAMAV_SRC/certs/clamav.crt"
    )
    FOUND_CERT=""
    for cert in "${CERT_CANDIDATES[@]}"; do
        if [ -f "$cert" ]; then
            FOUND_CERT="$cert"
            break
        fi
    done
    if [ -n "$FOUND_CERT" ]; then
        mkdir -p "$ARTIFACTS_DIR/certs"
        cp "$FOUND_CERT" "$ARTIFACTS_DIR/certs/clamav.crt"
        echo "  Bundled CVD verification cert from ClamAV-Mac source"
    else
        # Fetch from the ClamAV-Mac repo via gh (already authenticated).
        echo "  Fetching clamav.crt from $REPO..."
        mkdir -p "$ARTIFACTS_DIR/certs"
        for remote_path in certs/clamav.crt etc/certs/clamav.crt install/etc/certs/clamav.crt; do
            if gh api "repos/$REPO/contents/$remote_path" --jq '.content' 2>/dev/null \
               | base64 -d > "$ARTIFACTS_DIR/certs/clamav.crt" 2>/dev/null \
               && [ -s "$ARTIFACTS_DIR/certs/clamav.crt" ]; then
                FOUND_CERT="$ARTIFACTS_DIR/certs/clamav.crt"
                echo "  Downloaded clamav.crt from $REPO ($remote_path)"
                break
            fi
        done
        if [ -z "$FOUND_CERT" ]; then
            rm -f "$ARTIFACTS_DIR/certs/clamav.crt"
            echo "  WARNING: clamav.crt not found — freshclam CVD verification will fail"
            echo "  Set CLAMAV_SRC_DIR to point to a ClamAV source tree containing certs/"
        fi
    fi
fi

# Remove static archives (only needed at compile time, not runtime)
rm -f "$ARTIFACTS_DIR/lib/"*.a 2>/dev/null && \
    echo "  Removed static archives (.a) — not needed at runtime"

# Recreate library symlinks from manifest (CI records them in symlinks.txt)
if [ -f "$ARTIFACTS_DIR/lib/symlinks.txt" ]; then
    echo "  Recreating library symlinks from manifest..."
    while IFS=' ' read -r link_name _ link_target; do
        [ -n "$link_name" ] && [ -n "$link_target" ] || continue
        (cd "$ARTIFACTS_DIR/lib" && ln -sf "$link_target" "$link_name")
    done < "$ARTIFACTS_DIR/lib/symlinks.txt"
    rm "$ARTIFACTS_DIR/lib/symlinks.txt"
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

# ── Bundle missing Homebrew dependencies ──
# CI-built binaries may link against Homebrew libraries that aren't in the
# artifact. Detect and copy them so the app is self-contained.
echo "  Checking for missing Homebrew dependencies..."

collect_homebrew_deps() {
    for f in "$ARTIFACTS_DIR/binaries"/* "$ARTIFACTS_DIR/lib"/lib*.dylib; do
        [ -f "$f" ] || continue
        [ -L "$f" ] && continue
        otool -L "$f" 2>/dev/null | awk '/\/opt\/homebrew/{print $1}'
    done | sort -u
}

for homebrew_lib in $(collect_homebrew_deps); do
    LIB_BASENAME=$(basename "$homebrew_lib")
    if [ ! -f "$ARTIFACTS_DIR/lib/$LIB_BASENAME" ]; then
        if [ -f "$homebrew_lib" ]; then
            echo "  - Bundling missing dependency: $LIB_BASENAME"
            cp "$homebrew_lib" "$ARTIFACTS_DIR/lib/$LIB_BASENAME"
        else
            echo "  WARNING: $LIB_BASENAME referenced but not found at $homebrew_lib"
        fi
    fi
done

# ── Fix dylib rpaths ──
# CI-built binaries have hardcoded rpaths from the build machine (e.g.
# /Users/runner/work/...). Rewrite them so binaries find dylibs in lib/.
echo "  Fixing ClamAV dylib rpaths..."

LIB_RPATH="@executable_path/../lib"
for bin in "$ARTIFACTS_DIR/binaries"/*; do
    [ -f "$bin" ] || continue
    # Remove all existing LC_RPATH entries
    for old_rpath in $(otool -l "$bin" 2>/dev/null | awk '/cmd LC_RPATH/{found=1} found && /path /{print $2; found=0}'); do
        install_name_tool -delete_rpath "$old_rpath" "$bin" 2>/dev/null || true
    done
    # Add rpath relative to the binary → ../lib/
    install_name_tool -add_rpath "$LIB_RPATH" "$bin" 2>/dev/null || true
    # Rewrite hardcoded Homebrew load commands to @rpath
    for homebrew_ref in $(otool -L "$bin" 2>/dev/null | awk '/\/opt\/homebrew/{print $1}'); do
        install_name_tool -change "$homebrew_ref" "@rpath/$(basename "$homebrew_ref")" "$bin" 2>/dev/null || true
    done
done

# Fix dylib install names and inter-dylib references
for dylib in "$ARTIFACTS_DIR/lib"/lib*.dylib; do
    [ -f "$dylib" ] || continue
    [ -L "$dylib" ] && continue  # Skip symlinks
    DYLIB_NAME=$(basename "$dylib")
    install_name_tool -id "@rpath/$DYLIB_NAME" "$dylib" 2>/dev/null || true
    for old_rpath in $(otool -l "$dylib" 2>/dev/null | awk '/cmd LC_RPATH/{found=1} found && /path /{print $2; found=0}'); do
        install_name_tool -delete_rpath "$old_rpath" "$dylib" 2>/dev/null || true
    done
    install_name_tool -add_rpath "@loader_path" "$dylib" 2>/dev/null || true
    # Rewrite hardcoded Homebrew load commands to @rpath
    for homebrew_ref in $(otool -L "$dylib" 2>/dev/null | awk '/\/opt\/homebrew/{print $1}'); do
        install_name_tool -change "$homebrew_ref" "@rpath/$(basename "$homebrew_ref")" "$dylib" 2>/dev/null || true
    done
done
echo "  Dylib rpaths fixed"

echo ""
echo "ClamAV artifacts downloaded to: $ARTIFACTS_DIR"
ls -lhR "$ARTIFACTS_DIR/"
