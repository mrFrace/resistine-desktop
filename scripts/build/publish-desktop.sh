#!/usr/bin/env bash

# Description: Publish one Phoenix Desktop build to the signed update channel.
#   Writes ONE manifest listing every OS's package of the build, signs it with
#   the desktop minisign key (one password prompt), and uploads the directory
#   to the upload-only drop on briareosai. There phoenix-packages-promote
#   checks the signature and each sha512 and makes it the current release at
#   https://auth.phoenix.exposed/packages/desktop/current/manifest.json, which
#   the app reads (utils/updates/channel.py). Server side: ~/flakes
#   modules/services/phoenix-packages.nix.
# Usage: ./scripts/build/publish-desktop.sh [--stage DIR] <package>...
#   e.g. dist/installers/Phoenix-Setup-*-<build>.exe dist/linux/*<build>*.{deb,rpm,pkg.tar.xz}
#   --stage DIR  only write the signed release directory into DIR (no upload)
# Every package must carry the same build ID (scripts/build/build-*.sh name
# them by it). The server refuses a build at or below the current one, and the
# app refuses one below the highest it has seen: to roll back, rebuild the
# older code under a new build ID.
#
#   PHOENIX_DESKTOP_KEY    minisign secret key (password-protected)
#                          default ~/.config/phoenix-release/desktop-minisign.key
#   PHOENIX_PKG_DROP_KEY   SSH key for the drop, default ~/.ssh/phoenix-pkg-desktop
#   PHOENIX_PKG_DROP       default phoenix-pkg@10.42.10.252
#   PHOENIX_EXPIRES_DAYS   days until the app calls this release stale (default 90)

set -euo pipefail

die() {
	echo "[publish-desktop.sh] ERROR: $1" >&2
	exit 1
}
log() { echo "[publish-desktop.sh] $1" >&2; }

STAGE_OUT=""
if [ "${1:-}" = "--stage" ]; then
	STAGE_OUT="$(realpath -m "${2:?--stage needs a directory}")"
	shift 2
fi
[ $# -gt 0 ] || die "usage: publish-desktop.sh [--stage DIR] <package>..."
# Absolute paths: the version is read from the repo root below.
PKGS=()
for pkg in "$@"; do PKGS+=("$(realpath -m "$pkg")"); done
cd "$(dirname "$0")/../.."

KEY="${PHOENIX_DESKTOP_KEY:-$HOME/.config/phoenix-release/desktop-minisign.key}"
DROP_KEY="${PHOENIX_PKG_DROP_KEY:-$HOME/.ssh/phoenix-pkg-desktop}"
DROP="${PHOENIX_PKG_DROP:-phoenix-pkg@10.42.10.252}"
DAYS="${PHOENIX_EXPIRES_DAYS:-90}"
[ -s "$KEY" ] || die "no signing key at $KEY"
if command -v minisign >/dev/null; then
	MINISIGN=(minisign)
else
	MINISIGN=(nix shell nixpkgs#minisign -c minisign)
fi

VERSION=$(sed -nE "s/^VERSION\s*=\s*['\"]([^'\"]+)['\"].*/\1/p" packaging/Resistine.spec)
[[ "$VERSION" =~ ^[0-9A-Za-z.+~-]+$ ]] || die "bad VERSION '$VERSION' in packaging/Resistine.spec"
[[ "$DAYS" =~ ^[0-9]+$ ]] || die "bad PHOENIX_EXPIRES_DAYS '$DAYS'"

# Which OS each package is for, and the one build ID they share.
BUILD=""
declare -A FILES=()
for pkg in "${PKGS[@]}"; do
	[ -s "$pkg" ] || die "$pkg missing or empty"
	name="$(basename "$pkg")"
	[[ "$name" =~ ^[0-9A-Za-z._+~-]+$ ]] || die "bad file name '$name'"
	case "$name" in
	Phoenix-Setup-*.exe) os=windows ;;
	phoenix_*_amd64.deb) os=linux-deb ;;
	phoenix-*.x86_64.rpm) os=linux-rpm ;;
	phoenix-*-x86_64.pkg.tar.*) os=linux-arch ;;
	*.dmg) os=macos-arm64 ;;
	*) die "don't know which OS $name is for" ;;
	esac
	[ -z "${FILES[$os]:-}" ] || die "two packages for $os: ${FILES[$os]} and $pkg"
	FILES[$os]="$pkg"
	b="$(grep -oE '[0-9]{12}' <<<"$name" | head -1)" || die "no build ID in $name"
	[ -z "$BUILD" ] || [ "$b" = "$BUILD" ] || die "$name is build $b, others are $BUILD"
	BUILD="$b"
done
DIR="${VERSION}-${BUILD}"
EXPIRES="$(date -u -d "+${DAYS} days" +%F)"

stage="$(mktemp -d)"
trap 'rm -rf "$stage"' EXIT
mkdir "$stage/$DIR"
entries=()
for os in $(printf '%s\n' "${!FILES[@]}" | sort); do
	name="$(basename "${FILES[$os]}")"
	cp "${FILES[$os]}" "$stage/$DIR/$name"
	sha="$(sha512sum "$stage/$DIR/$name" | cut -d' ' -f1)"
	size="$(stat -c %s "$stage/$DIR/$name")"
	entries+=("    \"$os\": {\"file\": \"$name\", \"sha512\": \"$sha\", \"size\": $size}")
	log "$os: $name ($size bytes)"
done

# Every value is checked above to need no JSON escaping.
{
	printf '{\n  "product": "phoenix-desktop",\n  "version": "%s",\n  "build": %s,\n' "$VERSION" "$BUILD"
	printf '  "dir": "%s",\n  "expires": "%s",\n  "published": "%s",\n  "files": {\n' "$DIR" "$EXPIRES" "$(date -u +%FT%TZ)"
	(
		IFS=$'\n'
		sed '$!s/$/,/' <<<"${entries[*]}"
	)
	printf '  }\n}\n'
} >"$stage/$DIR/manifest.json"
python3 -c 'import json,sys; json.load(open(sys.argv[1]))' "$stage/$DIR/manifest.json" ||
	die "wrote an invalid manifest"

# The trusted comment is signed too: the server and the app check it against
# the manifest, pinning the directory (so the build) and the expiry.
log "Signing $DIR (expires $EXPIRES) with $KEY"
"${MINISIGN[@]}" -S -s "$KEY" -m "$stage/$DIR/manifest.json" -t "phoenix-desktop $DIR $EXPIRES" >/dev/null
chmod 0770 "$stage/$DIR"
chmod 0640 "$stage/$DIR"/*

if [ -n "$STAGE_OUT" ]; then
	mkdir -p "$STAGE_OUT"
	cp -a "$stage/$DIR" "$STAGE_OUT/"
	touch "$STAGE_OUT/$DIR/.done"
	log "Staged $STAGE_OUT/$DIR"
	exit 0
fi

[ -s "$DROP_KEY" ] || die "no SSH key for the drop at $DROP_KEY"
SSH_OPTS=(-i "$DROP_KEY" -o BatchMode=yes -o ConnectTimeout=20)
touch "$stage/.done"
# The account is chrooted to the drop: /incoming/desktop/ exists, the rest is ours.
scp -q -r "${SSH_OPTS[@]}" "$stage/$DIR" "$DROP:/incoming/desktop/"
scp -q "${SSH_OPTS[@]}" "$stage/.done" "$DROP:/incoming/desktop/$DIR/.done"
log "Uploaded $DIR; briareosai verifies and publishes it within a minute:"
log "  https://auth.phoenix.exposed/packages/desktop/current/manifest.json"
