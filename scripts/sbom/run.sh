#!/usr/bin/env bash
# Generate Phoenix's SBOM (sbom.cdx.json) + license attribution doc
# (LICENSE-3rd-Party.md) from a clean production virtual environment.
#
# Why a wrapper? cyclonedx-py walks the active Python env. Running
# generate_sbom.py from your dev venv would include pytest, pytest-mock,
# black, etc. in the SBOM — those don't ship to users, and the freshness
# gate in CI would reject the resulting artifacts. This wrapper sidesteps
# the footgun by building (and caching) a clean prod venv at .sbom-venv/.
#
# Usage:
#   ./scripts/sbom/run.sh                      # regenerate, write to repo root
#   ./scripts/sbom/run.sh --check              # CI mode: fail if stale
#   ./scripts/sbom/run.sh --rebuild-venv       # nuke .sbom-venv/ first
#
# Author: Phoenix Team
# Copyright (c) Phoenix 2026
# Licensed under the GNU General Public License v2 or later

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# Separate flags consumed by the wrapper from flags forwarded to the
# Python generator (currently just `--check`).
REBUILD_VENV=0
PASSTHROUGH=()
for arg in "$@"; do
    case "$arg" in
        --rebuild-venv) REBUILD_VENV=1 ;;
        *)              PASSTHROUGH+=("$arg") ;;
    esac
done

case "$(uname -s)" in
    Darwin)              REQS="$REPO_ROOT/scripts/requirements/requirements-mac.txt" ;;
    Linux)               REQS="$REPO_ROOT/scripts/requirements/requirements-linux.txt" ;;
    MINGW*|CYGWIN*|MSYS*) REQS="$REPO_ROOT/scripts/requirements/requirements-windows.txt" ;;
    *) echo "ERROR: unsupported platform: $(uname -s)" >&2; exit 1 ;;
esac

if [ ! -f "$REQS" ]; then
    echo "ERROR: requirements file not found: $REQS" >&2
    exit 1
fi

VENV="$REPO_ROOT/.sbom-venv"

if [ "$REBUILD_VENV" -eq 1 ] && [ -d "$VENV" ]; then
    echo "→ Removing existing $VENV (rebuild requested)…"
    rm -rf "$VENV"
fi

if [ ! -d "$VENV" ]; then
    echo "→ Creating clean prod venv at $(realpath --relative-to="$REPO_ROOT" "$VENV" 2>/dev/null || basename "$VENV")…"
    python3 -m venv "$VENV"
fi

echo "→ Installing $(basename "$REQS") + cyclonedx-bom…"
"$VENV/bin/pip" install --quiet --upgrade pip
"$VENV/bin/pip" install --quiet -r "$REQS"
"$VENV/bin/pip" install --quiet "cyclonedx-bom>=7.0.0"

echo "→ Generating SBOM…"
exec "$VENV/bin/python" "$SCRIPT_DIR/generate_sbom.py" "${PASSTHROUGH[@]+"${PASSTHROUGH[@]}"}"
