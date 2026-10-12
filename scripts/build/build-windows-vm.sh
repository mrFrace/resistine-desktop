#!/bin/bash
#==============================================================================
# Phoenix Desktop Windows installer, built from Linux in a throwaway VM
#==============================================================================
#
# Usage: scripts/build/build-windows-vm.sh
#
# Same method as Resistine-Server-install/build_agent_windows.sh, and the same
# golden image (Resistine-Server-install/scripts/windows/make_golden.sh: Windows
# Server 2025 evaluation with OpenSSH, booted with dockur/windows):
#
#   1. Archive this checkout (HEAD plus uncommitted changes to tracked files).
#   2. Copy the golden image, boot it, wait for SSH.
#   3. Run scripts/build/windows-vm-build.ps1 in it: installs Python 3.13 and
#      Inno Setup 6, then scripts/build/build-windows-installer.ps1
#      (PyInstaller + Inno Setup).
#   4. Fetch the setup .exe, delete the VM.
#
#   BUILD_DIR        staging                  (default /tmp/phoenix-build)
#   GOLDEN_DIR       golden image             (default /var/lib/phoenix-win/golden)
#   WIN_BUILDER_KEY  SSH key baked into it    (default ~/.ssh/phoenix-win-builder)
#   PACKAGE_OUTPUT   where the installer goes (default ./dist/installers)
#   WIN_RAM, WIN_CPUS                          (default 6G, 6)
#
# Host needs docker, /dev/kvm, git, ssh/scp and ~70 GB free next to BUILD_DIR
# for the VM's copy of the golden disk (sparse, mostly unused).
#==============================================================================

set -euo pipefail

die() { echo "[$(date '+%F %T')] [build-windows-vm.sh] ERROR: $1" >&2; exit 1; }
log() { echo "[$(date '+%F %T')] [build-windows-vm.sh] $1" >&2; }

ROOT="$(cd "$(dirname "$0")/../.." && pwd -P)"
STAGE_DIR="${BUILD_DIR:-/tmp/phoenix-build}/desktop-windows"
GOLDEN_DIR="${GOLDEN_DIR:-/var/lib/phoenix-win/golden}"
KEY="${WIN_BUILDER_KEY:-$HOME/.ssh/phoenix-win-builder}"
OUTPUT_DIR="${PACKAGE_OUTPUT:-$ROOT/dist/installers}"
DOCKUR_IMAGE="${DOCKUR_IMAGE:-dockurr/windows:6.05}"
VM_NAME="phoenix-desktop-win-build-${CI_JOB_ID:-$$}"
VM_DIR="${VM_DIR:-$STAGE_DIR/vm}"

[ -c /dev/kvm ] || die "/dev/kvm missing: this host cannot run the Windows VM"
[ -f "$GOLDEN_DIR/data.img" ] || die "no golden image in $GOLDEN_DIR (run Resistine-Server-install/scripts/windows/make_golden.sh)"
[ -f "$KEY" ] || die "builder key $KEY not found"
mkdir -p "$STAGE_DIR" "$OUTPUT_DIR"

# ---------------------------------------------------------------------------
# 1. Source archive
# ---------------------------------------------------------------------------
SRC_ZIP="$STAGE_DIR/phoenix-desktop-src.zip"
# stash create: a commit of the uncommitted tracked changes, without touching
# the work tree or the index. Empty when the tree is clean.
ref="$(git -C "$ROOT" stash create)"
untracked="$(git -C "$ROOT" ls-files --others --exclude-standard -- plugins gui utils resources packaging scripts main.py)"
[ -z "$untracked" ] || log "not in the build (untracked): $(echo "$untracked" | tr '\n' ' ')"
rm -f "$SRC_ZIP"
git -C "$ROOT" archive --format=zip -o "$SRC_ZIP" "${ref:-HEAD}"
log "Source: $(git -C "$ROOT" rev-parse --short HEAD)${ref:+ + uncommitted changes}"

# ---------------------------------------------------------------------------
# 2. Throwaway copy of the golden Windows image
# ---------------------------------------------------------------------------
cleanup() {
    docker rm -f "$VM_NAME" >/dev/null 2>&1 || true
    rm -rf "$VM_DIR"
}
trap cleanup EXIT
cleanup
mkdir -p "$VM_DIR"
log "Copying the golden image to $VM_DIR"
cp -a --sparse=always "$GOLDEN_DIR"/. "$VM_DIR"/

# dockur boots an existing install only under the VERSION it was installed with;
# any other (unset means 11) makes it download and install that one instead.
win_version="$(sed -n 's/^version //p' "$GOLDEN_DIR/phoenix-golden.txt" 2>/dev/null)"
[ -n "$win_version" ] || die "no version in $GOLDEN_DIR/phoenix-golden.txt"
log "Booting Windows $win_version ($VM_NAME)"
docker run -d --name "$VM_NAME" \
    --device /dev/kvm --device /dev/net/tun --cap-add NET_ADMIN \
    -e VERSION="$win_version" -e RAM_SIZE="${WIN_RAM:-6G}" -e CPU_CORES="${WIN_CPUS:-6}" \
    -v "$VM_DIR":/storage --stop-timeout 120 "$DOCKUR_IMAGE" >/dev/null
ip="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$VM_NAME")"
[ -n "$ip" ] || die "no IP for $VM_NAME"
SSH_OPTS=(-i "$KEY" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 -o LogLevel=ERROR)
ssh_vm() { ssh "${SSH_OPTS[@]}" "phoenix@$ip" "$@"; }

for i in $(seq 1 60); do
    ssh_vm 'echo up' 2>/dev/null | grep -q up && break
    docker inspect -f '{{.State.Running}}' "$VM_NAME" | grep -q true \
        || { docker logs --tail 30 "$VM_NAME"; die "the VM container stopped"; }
    [ "$i" = 60 ] && { docker logs --tail 30 "$VM_NAME"; die "no SSH from Windows after 10 min"; }
    sleep 10
done
log "Windows is up at $ip; building"

# ---------------------------------------------------------------------------
# 3. Python + Inno Setup + PyInstaller in the VM
# ---------------------------------------------------------------------------
scp "${SSH_OPTS[@]}" "$SRC_ZIP" "$ROOT/scripts/build/windows-vm-build.ps1" "phoenix@$ip:C:/Users/phoenix/"
ssh_vm "powershell -NoProfile -ExecutionPolicy Bypass -File C:\\Users\\phoenix\\windows-vm-build.ps1 -Zip C:\\Users\\phoenix\\phoenix-desktop-src.zip"

# ---------------------------------------------------------------------------
# 4. Fetch the installer
# ---------------------------------------------------------------------------
setup="$(ssh_vm '(Get-ChildItem C:\b\src\dist\installers\*.exe | Select-Object -First 1).Name' | tr -d '\r')"
[ -n "$setup" ] || die "the build produced no installer"
scp "${SSH_OPTS[@]}" "phoenix@$ip:C:/b/src/dist/installers/$setup" "$OUTPUT_DIR/$setup"
[ -s "$OUTPUT_DIR/$setup" ] || die "could not fetch $setup"
sha512sum "$OUTPUT_DIR/$setup" > "$OUTPUT_DIR/$setup.sha512"
log "Done: $OUTPUT_DIR/$setup"
