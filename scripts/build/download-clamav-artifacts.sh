#!/bin/bash
set -e

# Download pre-built ClamAV artifacts for macOS.
#
# Source of truth is a GitHub *release* on Phoenix's own ClamAV repo, not an
# Actions artifact: Actions artifacts expire after 90 days, and the ones this
# project used to consume already have. A release asset does not expire.
#
# Requires: GitHub CLI (gh) authenticated with access to the repo below.
#
# Usage:
#   ./download-clamav-artifacts.sh              # latest release
#   ./download-clamav-artifacts.sh <tag>        # a specific release tag
#   ./download-clamav-artifacts.sh --check      # exit 0 if up-to-date, 1 if stale
#
# Called automatically by build-distribution.sh when artifacts are missing.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ARTIFACTS_DIR="$SCRIPT_DIR/clamav-artifacts"
REPO="${CLAMAV_ARTIFACTS_REPO:-DatOneOPGuy/phoenix-clamav-mac}"
ASSET="${CLAMAV_ARTIFACTS_ASSET:-clamav-macos-artifacts.tar.gz}"
VERSION_FILE="$ARTIFACTS_DIR/.clamav-version"

if ! command -v gh &> /dev/null; then
    echo "Error: GitHub CLI (gh) is required but not installed."
    echo "  Install: brew install gh"
    echo "  Then:    gh auth login"
    exit 1
fi

# Latest release tag, or "" when the repo/network is unreachable. Only a
# plausible tag is returned -- on an HTTP error gh can print JSON onto stdout,
# which must never be mistaken for a version.
get_remote_tag() {
    local tag
    tag=$(gh release view --repo "$REPO" --json tagName -q .tagName 2>/dev/null || echo "")
    case "$tag" in
        ""|*[!A-Za-z0-9._-]*) echo "" ;;
        *) echo "$tag" ;;
    esac
}

get_local_tag() {
    [ -f "$VERSION_FILE" ] && cat "$VERSION_FILE" || echo ""
}

have_usable_artifacts() {
    [ -f "$ARTIFACTS_DIR/binaries/clamonacc" ] && [ -f "$ARTIFACTS_DIR/binaries/clamd" ]
}

if [ "$1" = "--check" ]; then
    LOCAL_TAG=$(get_local_tag)
    if [ -z "$LOCAL_TAG" ] || ! have_usable_artifacts; then
        echo "No local ClamAV artifacts"
        exit 1
    fi
    REMOTE_TAG=$(get_remote_tag)
    if [ -z "$REMOTE_TAG" ]; then
        echo "Could not query $REPO (offline or no access)"
        exit 0  # never block a build just because we cannot check
    fi
    if [ "$LOCAL_TAG" = "$REMOTE_TAG" ]; then
        echo "ClamAV artifacts up-to-date ($LOCAL_TAG)"
        exit 0
    fi
    echo "ClamAV artifacts stale (local: $LOCAL_TAG, remote: $REMOTE_TAG)"
    exit 1
fi

# Decide which release to fetch
if [ -n "$1" ]; then
    TAG="$1"
    echo "Downloading ClamAV artifacts from release $TAG..."
else
    TAG=$(get_remote_tag)
    LOCAL_TAG=$(get_local_tag)

    if [ -n "$TAG" ] && [ "$LOCAL_TAG" = "$TAG" ] && have_usable_artifacts; then
        echo "ClamAV artifacts already up-to-date ($TAG)"
        exit 0
    fi

    if [ -z "$TAG" ]; then
        # Never wipe a working local copy just because the release cannot be
        # queried -- that would leave the build with no ClamAV at all.
        if have_usable_artifacts; then
            echo "$REPO unreachable -- using existing local ClamAV artifacts ($(get_local_tag))."
            exit 0
        fi
        echo "Error: cannot reach $REPO and no local ClamAV artifacts are present."
        echo "  Check 'gh auth status', or set CLAMAV_ARTIFACTS_REPO."
        exit 1
    fi
    echo "Downloading ClamAV artifacts ($TAG)..."
fi

# Download into a staging dir first: the existing artifacts are the fallback
# if anything here fails, so they are only replaced once the new set is known
# to be complete.
STAGE="$(mktemp -d)"
cleanup_stage() { rm -rf "$STAGE"; }
trap cleanup_stage EXIT

if ! gh release download "$TAG" --repo "$REPO" --pattern "$ASSET" --dir "$STAGE" 2>&1; then
    echo "Error: could not download $ASSET from $REPO release $TAG"
    exit 1
fi

if [ ! -s "$STAGE/$ASSET" ]; then
    echo "Error: downloaded asset is empty: $ASSET"
    exit 1
fi

# The tarball carries a top-level clamav-artifacts/ directory, so it unpacks
# straight over ARTIFACTS_DIR's parent.
if ! tar -xzf "$STAGE/$ASSET" -C "$STAGE"; then
    echo "Error: could not extract $ASSET"
    exit 1
fi

if [ ! -d "$STAGE/clamav-artifacts/binaries" ]; then
    echo "Error: $ASSET does not contain clamav-artifacts/binaries/"
    exit 1
fi

rm -rf "$ARTIFACTS_DIR"
mv "$STAGE/clamav-artifacts" "$ARTIFACTS_DIR"
echo "$TAG" > "$VERSION_FILE"

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
# Search order: release artifact → local ClamAV source tree → the repo.
if [ ! -f "$ARTIFACTS_DIR/certs/clamav.crt" ]; then
    CLAMAV_SRC="${CLAMAV_SRC_DIR:-$(cd "$SCRIPT_DIR/../.." && pwd)/../phoenix-clamav-mac}"
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
        echo "  Bundled CVD verification cert from local ClamAV source"
    else
        # Fetch from the Phoenix ClamAV repo via gh (already authenticated).
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
