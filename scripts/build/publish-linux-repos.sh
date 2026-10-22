#!/usr/bin/env bash

# Description: Add one Linux build to the Phoenix package repositories and
#   publish them at https://phoenix.exposed/linux/{apt,rpm,arch}. The .deb,
#   .rpm and Arch packages set the repository up (packaging/linux/repo), so
#   apt, dnf/zypper and pacman install later builds as ordinary upgrades.
#   Metadata is generated in throwaway Debian, Alma and Arch containers and
#   signed here with the repository's OpenPGP key (password-protected; gpg asks
#   once per run). Only metadata is signed; packages stay byte-identical to
#   the signed update channel (publish-desktop.sh). Run this from a terminal.
# Usage: ./scripts/build/publish-linux-repos.sh [--no-upload] <package>...
#   e.g. dist/linux/*<build>*.{deb,rpm,pkg.tar.xz}
# The last $KEEP builds stay in each repository, so users can downgrade.
#
#   PHOENIX_REPO_DIR    local repository tree, default
#                       ~/REPOS/Phoenix-cybersec-web/web/linux (the website's
#                       deploy.sh serves the same tree)
#   PHOENIX_GNUPGHOME   default ~/.config/phoenix-release/gnupg
#   PHOENIX_WEB_HOST    default 10.42.10.252 (webroot /var/www/phoenix.exposed)
#   PHOENIX_REPO_KEEP   builds kept per repository (default 3)

set -euo pipefail

die() {
	echo "[publish-linux-repos.sh] ERROR: $1" >&2
	exit 1
}
log() { echo "[publish-linux-repos.sh] $1" >&2; }

UPLOAD=1
if [ "${1:-}" = "--no-upload" ]; then
	UPLOAD=0
	shift
fi
[ $# -gt 0 ] || die "usage: publish-linux-repos.sh [--no-upload] <package>..."
PKGS=()
for pkg in "$@"; do PKGS+=("$(realpath -m "$pkg")"); done
cd "$(dirname "$0")/../.."

REPO="${PHOENIX_REPO_DIR:-$HOME/REPOS/Phoenix-cybersec-web/web/linux}"
export GNUPGHOME="${PHOENIX_GNUPGHOME:-$HOME/.config/phoenix-release/gnupg}"
HOST="${PHOENIX_WEB_HOST:-10.42.10.252}"
KEEP="${PHOENIX_REPO_KEEP:-3}"
KEY=packaging/linux/phoenix-archive-keyring.asc
[[ "$KEEP" =~ ^[1-9][0-9]*$ ]] || die "bad PHOENIX_REPO_KEEP '$KEEP'"
if command -v gpg >/dev/null; then
	GPG=(gpg)
else
	GPG=(nix shell nixpkgs#gnupg -c gpg)
fi
# Sign with exactly the key the packages trust.
FPR=$("${GPG[@]}" --show-keys --with-colons "$KEY" | awk -F: '/^fpr/ {print $10; exit}')
[ -n "$FPR" ] || die "no public key in $KEY"
"${GPG[@]}" --list-secret-keys "$FPR" >/dev/null 2>&1 || die "no secret key $FPR in $GNUPGHOME"
sign() { "${GPG[@]}" --quiet --yes --pinentry-mode loopback --local-user "$FPR" "$@"; }

mkdir -p "$REPO/apt/pool/main/p/phoenix" "$REPO/apt/dists/stable/main/binary-amd64" "$REPO/rpm" "$REPO/arch"
for pkg in "${PKGS[@]}"; do
	[ -s "$pkg" ] || die "$pkg missing or empty"
	case "$(basename "$pkg")" in
	phoenix_*_amd64.deb) cp "$pkg" "$REPO/apt/pool/main/p/phoenix/" ;;
	phoenix-*.x86_64.rpm) cp "$pkg" "$REPO/rpm/" ;;
	phoenix-*-x86_64.pkg.tar.*) cp "$pkg" "$REPO/arch/" ;;
	*) die "not a Phoenix Linux package: $pkg" ;;
	esac
	log "added $(basename "$pkg")"
done
cp "$KEY" "$REPO/phoenix-archive-keyring.asc"

# Keep the newest $KEEP builds (by the build ID in the file name).
prune() { # <dir> <glob>
	local f
	find "$1" -maxdepth 1 -name "$2" -printf '%f\n' |
		sed -nE 's/^(.*([0-9]{12}).*)$/\2 \1/p' | sort -rn | tail -n +$((KEEP + 1)) |
		while read -r _ f; do
			rm -f "$1/$f" "$1/$f.sig"
			log "pruned $f"
		done
}
prune "$REPO/apt/pool/main/p/phoenix" 'phoenix_*.deb'
prune "$REPO/rpm" 'phoenix-*.rpm'
prune "$REPO/arch" 'phoenix-*.pkg.tar.*[!g]'

# Arch: detached package signatures first; repo-add records them in the db.
for p in "$REPO"/arch/phoenix-*.pkg.tar.xz "$REPO"/arch/phoenix-*.pkg.tar.zst; do
	[ -f "$p" ] && [ ! -f "$p.sig" ] || continue
	sign --detach-sign --no-armor -o "$p.sig" "$p"
done

# Unsigned metadata, in containers (each writes as root; hand it back).
OWNER="$(id -u):$(id -g)"
log "apt metadata (debian:12)"
docker run --rm -v "$REPO/apt:/r" -e OWNER="$OWNER" debian:12 bash -euo pipefail -c '
apt-get update -qq >/dev/null && apt-get install -y -qq apt-utils xz-utils >/dev/null
cd /r
apt-ftparchive packages pool >dists/stable/main/binary-amd64/Packages
xz -kf dists/stable/main/binary-amd64/Packages
rm -f dists/stable/Release dists/stable/InRelease dists/stable/Release.gpg
apt-ftparchive -o APT::FTPArchive::Release::Origin=Phoenix -o APT::FTPArchive::Release::Label=Phoenix \
	-o APT::FTPArchive::Release::Suite=stable -o APT::FTPArchive::Release::Codename=stable \
	-o APT::FTPArchive::Release::Architectures=amd64 -o APT::FTPArchive::Release::Components=main \
	release dists/stable >/tmp/Release
mv /tmp/Release dists/stable/Release
chown -R "$OWNER" /r'
log "rpm metadata (almalinux:9)"
docker run --rm -v "$REPO/rpm:/r" -e OWNER="$OWNER" almalinux:9 bash -euo pipefail -c '
dnf -q -y install createrepo_c >/dev/null
createrepo_c -q /r
chown -R "$OWNER" /r'
log "pacman metadata (archlinux)"
docker run --rm -v "$REPO/arch:/r" -e OWNER="$OWNER" archlinux:base bash -euo pipefail -c '
cd /r
rm -f phoenix.db* phoenix.files*
repo-add -q phoenix.db.tar.gz phoenix-*.pkg.tar.xz
chown -R "$OWNER" /r'

# Sign the metadata (gpg asks for the passphrase once; the agent keeps it).
log "signing with $FPR"
a="$REPO/apt/dists/stable"
sign --clearsign -o "$a/InRelease" "$a/Release"
sign --detach-sign --armor -o "$a/Release.gpg" "$a/Release"
sign --detach-sign --armor -o "$REPO/rpm/repodata/repomd.xml.asc" "$REPO/rpm/repodata/repomd.xml"
# repo-add makes phoenix.db/.files symlinks; serve plain files instead.
for db in phoenix.db phoenix.files; do
	rm -f "$REPO/arch/$db" "$REPO/arch/$db.sig"
	sign --detach-sign --no-armor -o "$REPO/arch/$db.tar.gz.sig" "$REPO/arch/$db.tar.gz"
	cp "$REPO/arch/$db.tar.gz" "$REPO/arch/$db"
	cp "$REPO/arch/$db.tar.gz.sig" "$REPO/arch/$db.sig"
done
for s in "$a/InRelease" "$REPO/rpm/repodata/repomd.xml.asc" "$REPO/arch/phoenix.db.sig"; do
	case "$s" in
	*InRelease) "${GPG[@]}" --quiet --verify "$s" 2>/dev/null ;;
	*.asc) "${GPG[@]}" --quiet --verify "$s" "${s%.asc}" 2>/dev/null ;;
	*) "${GPG[@]}" --quiet --verify "$s" "${s%.sig}" 2>/dev/null ;;
	esac || die "signature check failed: $s"
done
chmod -R a+rX "$REPO"
log "repositories ready in $REPO"

[ "$UPLOAD" = 1 ] || exit 0
# Packages first, then the signed indexes: a client never sees an index
# pointing at a file that isn't there yet.
DEST="$HOST:/var/www/phoenix.exposed/linux/"
rsync -rlt --chmod=D755,F644 --exclude 'dists/' --exclude 'repodata/' \
	--exclude 'phoenix.db*' --exclude 'phoenix.files*' "$REPO/" "$DEST"
rsync -rlt --chmod=D755,F644 --delete-after "$REPO/" "$DEST"
log "published https://phoenix.exposed/linux/{apt,rpm,arch}"
