#!/usr/bin/env bash

# Description: Build the Linux app once in an AlmaLinux 9 container and
#   package it as .deb, .rpm and an Arch Linux .pkg.tar.xz (x86_64). glibc 2.34 there is the oldest PyQt6's
#   wheels support, so the PyInstaller bundle runs on RHEL/Alma/Rocky 9+,
#   Ubuntu 22.04+, Debian 12+ and Fedora. A build made on the host (NixOS)
#   would only run on NixOS.
# Usage: ./scripts/build/build-linux-packages.sh
# Output (<build> = UTC YYYYMMDDHHMM, or $PHOENIX_BUILD): dist/linux/
#   phoenix_<version~rc>-<build>_amd64.deb, phoenix-<version~rc>-<build>.x86_64.rpm,
#   phoenix-<pkgver>-<build>-x86_64.pkg.tar.xz with its PKGBUILD, and the
#   staged root phoenix-<version>-<build>-x86_64.tar.xz the PKGBUILD repackages.
# Needs: docker. Builds from the committed tree (git archive HEAD).

set -euo pipefail

cd "$(dirname "$0")/../.."

IMAGE="almalinux:9"
OUT="dist/linux"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/phoenix-linux.XXXXXX")"
# The container writes the build tree as root; delete it from inside one.
trap 'docker run --rm -v "$WORK:/w" "$IMAGE" find /w -mindepth 1 -delete >/dev/null 2>&1; rm -rf "$WORK"' EXIT

VERSION=$(sed -nE "s/^VERSION\s*=\s*['\"]([^'\"]+)['\"].*/\1/p" packaging/Resistine.spec)
[ -n "$VERSION" ] || {
	echo "No VERSION in packaging/Resistine.spec" >&2
	exit 1
}
# RPM versions can't contain '-': 2026.07.20-rc -> 2026.07.20~rc (sorts before 2026.07.20).
RPM_VERSION="${VERSION//-/\~}"
# pacman versions can't contain '-' either: 2026.07.20-rc -> 2026.07.20rc (also sorts first).
ARCH_VERSION="${VERSION//-/}"
# Build ID (UTC minutes, see packaging/Resistine.spec): every build of one
# VERSION gets a package version above the last, so apt/dnf/pacman upgrade
# instead of calling a new build "already installed".
BUILD="${PHOENIX_BUILD:-$(date -u +%Y%m%d%H%M)}"
# Debian: '~' sorts the rc before the release, the build is the revision. The
# epoch is needed once: earlier .debs were "2026.07.20-rc", which dpkg reads
# as 2026.07.20 revision rc, above any 2026.07.20~rc-*.
DEB_VERSION="1:${VERSION//-/\~}-${BUILD}"
echo "Building Phoenix ${VERSION} build ${BUILD} (deb ${DEB_VERSION}, rpm ${RPM_VERSION}-${BUILD}, arch ${ARCH_VERSION}-${BUILD}) in ${IMAGE}"

git archive HEAD | tar -x -C "$WORK"
mkdir -p "$OUT"

docker run --rm \
	-v "$WORK:/src" \
	-v "$PWD/$OUT:/out" \
	-e VERSION="$VERSION" -e RPM_VERSION="$RPM_VERSION" -e DEB_VERSION="$DEB_VERSION" \
	-e BUILD="$BUILD" -e PHOENIX_BUILD="$BUILD" \
	-e HOST_UID="$(id -u)" -e HOST_GID="$(id -g)" \
	-w /src "$IMAGE" bash -euo pipefail -c '
dnf -q -y install epel-release >/dev/null
dnf -q -y install dpkg rpm-build binutils python3-pip \
	mesa-libGL mesa-libEGL libxkbcommon libxkbcommon-x11 fontconfig dbus-libs \
	xcb-util-cursor xcb-util-wm xcb-util-image xcb-util-keysyms xcb-util-renderutil >/dev/null

# Python 3.13 from uv (a shared-library build, which PyInstaller needs).
pip3 install -q uv
uv venv -q --python 3.13 /venv
VIRTUAL_ENV=/venv uv pip install -q -r scripts/requirements/requirements-linux.txt
/venv/bin/pyinstaller --clean -y packaging/Resistine.spec
[ -x dist/Phoenix/Phoenix ]
/venv/bin/python scripts/build/check_bundle.py dist/Phoenix
# The collected libgcc_s needs glibc 2.35 (RHEL 9 has 2.34); every system has its own.
find dist/Phoenix/_internal -maxdepth 1 -name "libgcc_s.so.1" -delete

# One staged root for both formats.
root=/stage/root
mkdir -p $root/opt/phoenix $root/usr/bin $root/usr/share/applications $root/usr/share/pixmaps
cp -a dist/Phoenix/. $root/opt/phoenix/
printf "#!/bin/sh\nexec /opt/phoenix/Phoenix \"\$@\"\n" >$root/usr/bin/phoenix
chmod 755 $root/usr/bin/phoenix
cp packaging/linux/phoenix.desktop $root/usr/share/applications/
cp resources/icons/app_icon.png $root/usr/share/pixmaps/phoenix.png

# Each package also sets up the Phoenix repository for its package manager
# (packaging/linux/repo; served by scripts/build/publish-linux-repos.sh), so
# the system updater installs later builds.
key=packaging/linux/phoenix-archive-keyring.asc
fpr=$(gpg --show-keys --with-colons $key | awk -F: "/^fpr/ {print \$10; exit}")
[ -n "$fpr" ] || { echo "no public key in $key" >&2; exit 1; }

# .deb
deb=/stage/deb
cp -a $root $deb
install -Dm644 packaging/linux/repo/phoenix.sources $deb/etc/apt/sources.list.d/phoenix.sources
mkdir -p $deb/usr/share/keyrings
gpg --dearmor <$key >$deb/usr/share/keyrings/phoenix-archive-keyring.gpg
chmod 644 $deb/usr/share/keyrings/phoenix-archive-keyring.gpg
mkdir -p $deb/DEBIAN
echo /etc/apt/sources.list.d/phoenix.sources >$deb/DEBIAN/conffiles
sed "s/\${VERSION}/$DEB_VERSION/g" packaging/linux/control.template >$deb/DEBIAN/control
install -m 755 packaging/linux/postinst packaging/linux/postrm $deb/DEBIAN/
dpkg-deb --root-owner-group --build $deb /out/phoenix_${DEB_VERSION#*:}_amd64.deb

# .rpm
rpmroot=/stage/rpmroot
cp -a $root $rpmroot
install -Dm644 packaging/linux/repo/phoenix.repo $rpmroot/etc/yum.repos.d/phoenix.repo
install -Dm644 $key $rpmroot/etc/pki/rpm-gpg/RPM-GPG-KEY-phoenix
install -Dm644 packaging/linux/repo/phoenix-zypp.repo $rpmroot/usr/share/phoenix/phoenix-zypp.repo
sed -e "s/@VERSION@/$RPM_VERSION/" -e "s/@RELEASE@/$BUILD/" packaging/linux/phoenix.spec.in >/stage/phoenix.spec
rpmbuild -bb --quiet --define "_topdir /stage/rpm" --define "_phoenix_root $rpmroot" /stage/phoenix.spec
cp /stage/rpm/RPMS/x86_64/*.rpm /out/

# Staged root for the Arch PKGBUILD (packaged below in an Arch container),
# with the repository config and the key for pacman-key --populate phoenix.
install -Dm644 packaging/linux/repo/phoenix-pacman.conf $root/etc/pacman.d/phoenix.conf
install -Dm644 $key $root/usr/share/pacman/keyrings/phoenix.gpg
echo "$fpr:4:" >$root/usr/share/pacman/keyrings/phoenix-trusted
chmod 644 $root/usr/share/pacman/keyrings/phoenix-trusted
mkdir -p /stage/arch
cp LICENSE.md /stage/arch/
mv $root /stage/arch/root
tar -C /stage/arch --owner=0 --group=0 -cJf /out/phoenix-${VERSION}-${BUILD}-x86_64.tar.xz root LICENSE.md

chown "$HOST_UID:$HOST_GID" /out/*
'

# Arch Linux .pkg.tar.xz from the staged root.
TARBALL="phoenix-${VERSION}-${BUILD}-x86_64.tar.xz"
SHA=$(sha256sum "$OUT/$TARBALL" | cut -d" " -f1)
sed -e "s/@PKGVER@/$ARCH_VERSION/" -e "s/@PKGREL@/$BUILD/" -e "s/@VERSION@/$VERSION-$BUILD/" -e "s/@SHA256@/$SHA/" \
	packaging/linux/arch/PKGBUILD >"$OUT/PKGBUILD"
cp packaging/linux/repo/phoenix.install "$OUT/phoenix.install"
docker run --rm \
	-v "$PWD/$OUT:/out" \
	-e HOST_UID="$(id -u)" -e HOST_GID="$(id -g)" -e TARBALL="$TARBALL" \
	archlinux:base-devel bash -euo pipefail -c '
useradd -m build
install -d -o build /build
cp /out/PKGBUILD /out/phoenix.install "/out/$TARBALL" /build/
chown build /build/*
cd /build
su build -c "PKGEXT=.pkg.tar.xz makepkg -f --nodeps --noconfirm" >/dev/null
pkg=$(ls /build/*.pkg.tar.xz)
pacman -Qip "$pkg" | grep -E "^(Name|Version|Architecture|Depends On|Installed Size)"
cp "$pkg" /out/
chown "$HOST_UID:$HOST_GID" /out/*
'

ls -lh "$OUT"
