#!/usr/bin/env bash
# ============================================================
# Phoenix (formerly Resistine) — Full Uninstaller (Linux)
# Removes the SIEM agent, VPN tunnels/configs, antivirus daemons,
# privileged helpers, stored secrets, and all user data.
#
# Usage:
#   scripts/uninstall/uninstall.sh [-y] [--keep-venv] [--keep-clamav-pkgs]
#
#   -y, --yes            Don't prompt for confirmation.
#   --keep-venv          Don't remove the project's .venv.
#   --keep-clamav-pkgs   Only deactivate ClamAV services; leave the distro
#                        packages installed (default already keeps packages).
#   -h, --help           Show this help.
#
# The script re-executes itself with sudo for the privileged steps (one
# password prompt), then drops back to the real user for ~/.config + keyring.
#
# Author: Resistine Team
# Copyright (c) Resistine 2025
# Licensed under the GNU General Public License v2 or later
# ============================================================
set -u

ASSUME_YES=0
KEEP_VENV=0

usage() { sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'; exit 0; }

for arg in "$@"; do
    case "$arg" in
        -y|--yes)          ASSUME_YES=1 ;;
        --keep-venv)       KEEP_VENV=1 ;;
        --keep-clamav-pkgs) : ;;  # accepted for symmetry; packages are kept by default
        -h|--help)         usage ;;
        *) echo "Unknown option: $arg" >&2; exit 2 ;;
    esac
done

# --- Resolve the real (non-root) user and their paths -----------------------
# Works whether invoked directly or via sudo.
REAL_USER="${SUDO_USER:-$USER}"
if [ "$REAL_USER" = "root" ] && [ -n "${SUDO_USER:-}" ]; then
    REAL_USER="$SUDO_USER"
fi
USER_HOME="$(getent passwd "$REAL_USER" | cut -d: -f6)"
[ -n "$USER_HOME" ] || USER_HOME="$HOME"

# Honor XDG_CONFIG_HOME as the app does (utils/settings.get_config_dir). It is
# preserved across the sudo re-exec via `sudo -E`; otherwise fall back to the
# resolved home's .config (correct for the vast majority of setups).
# Both the Phoenix dir and the pre-rebrand resistine one.
CONFIG_BASE="${XDG_CONFIG_HOME:-$USER_HOME/.config}"
CONFIG_DIRS="$CONFIG_BASE/phoenix $CONFIG_BASE/resistine"

# Project root: two levels up from scripts/uninstall/.
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

WAZUH_DIR="/var/ossec"
HELPER_DIR="/usr/local/lib/resistine"

info()  { printf '  \033[0;36m%s\033[0m\n' "$*"; }
ok()    { printf '  \033[0;32m%s\033[0m\n' "$*"; }
warn()  { printf '  \033[0;33m%s\033[0m\n' "$*"; }
step()  { printf '\n\033[1m%s\033[0m\n' "$*"; }

# --- Confirmation (before any escalation) -----------------------------------
if [ "$ASSUME_YES" -ne 1 ]; then
    printf '\033[1mPhoenix Full Uninstaller\033[0m\n'
    printf 'This removes the SIEM agent, VPN tunnels/configs, antivirus daemons,\n'
    printf 'privileged helpers, and all user data at:\n'
    for d in $CONFIG_DIRS; do printf '  %s\n' "$d"; done
    printf '\n'
    printf 'Continue? [y/N] '
    read -r reply
    case "$reply" in
        y|Y|yes|YES) ;;
        *) echo "Aborted."; exit 1 ;;
    esac
fi

# --- Re-exec with sudo for the privileged phase -----------------------------
if [ "$(id -u)" -ne 0 ]; then
    info "Requesting administrator privileges..."
    # "$@" already carries the original flags (e.g. --keep-venv); add -y so the
    # re-executed root run doesn't prompt for confirmation again.
    exec sudo -E "$0" -y "$@"
fi

# ============================================================
# PRIVILEGED PHASE (running as root)
# ============================================================

# ---- 1. Stop the running app ----
step "[1/7] Stopping Phoenix app processes..."
pkill -TERM -u "$REAL_USER" -f "[m]ain.py" 2>/dev/null && ok "Signalled app to stop" || info "No running app found"
sleep 1

# ---- 2. VPN / WireGuard teardown ----
step "[2/7] Removing VPN tunnels and configs..."
for CONFIG_DIR in $CONFIG_DIRS; do
    WG_DIR="$CONFIG_DIR/wireguard"
    [ -d "$WG_DIR" ] || continue
    for conf in "$WG_DIR"/*.conf; do
        [ -e "$conf" ] || continue
        iface="$(basename "$conf" .conf)"
        wg-quick down "$iface" 2>/dev/null && ok "Brought down tunnel: $iface" || true
        rm -f "/etc/wireguard/${iface}.conf"
    done
done
# Bring down a stray 'resistine' interface in case no config remained.
wg-quick down resistine 2>/dev/null || true
rm -f /etc/wireguard/resistine.conf
ok "VPN teardown done"

# ---- 3. Wazuh SIEM agent removal ----
step "[3/7] Removing SIEM (Wazuh) agent..."
if [ -d "$WAZUH_DIR" ] || systemctl list-unit-files 2>/dev/null | grep -q '^wazuh-agent'; then
    ( "$WAZUH_DIR/bin/wazuh-control" stop 2>/dev/null ) || true
    systemctl stop wazuh-agent 2>/dev/null || true
    systemctl disable wazuh-agent 2>/dev/null || true
    rm -f /usr/lib/systemd/system/wazuh-agent.service \
          /etc/systemd/system/wazuh-agent.service
    systemctl daemon-reload 2>/dev/null || true

    # Package-managed installs: let the package manager run its postrm
    # (drops the wazuh user/group). Arch/extraction installs aren't tracked,
    # so remove the user/group by hand.
    if command -v apt-get >/dev/null 2>&1 && apt-get remove -y wazuh-agent >/dev/null 2>&1; then
        ok "Removed wazuh-agent via apt"
    elif command -v dnf >/dev/null 2>&1 && dnf remove -y wazuh-agent >/dev/null 2>&1; then
        ok "Removed wazuh-agent via dnf"
    elif command -v yum >/dev/null 2>&1 && yum remove -y wazuh-agent >/dev/null 2>&1; then
        ok "Removed wazuh-agent via yum"
    elif command -v zypper >/dev/null 2>&1 && zypper --non-interactive remove wazuh-agent >/dev/null 2>&1; then
        ok "Removed wazuh-agent via zypper"
    else
        userdel wazuh 2>/dev/null || true
        groupdel wazuh 2>/dev/null || true
        ok "Removed wazuh user/group (untracked install)"
    fi
    rm -rf "$WAZUH_DIR"
    ok "Removed $WAZUH_DIR"
else
    info "Wazuh agent not installed"
fi

# ---- 4. ClamAV antivirus daemons ----
step "[4/7] Deactivating antivirus (ClamAV) daemons..."
for svc in clamd@scan clamav-daemon clamav-freshclam clamav-clamonacc; do
    systemctl disable --now "$svc" 2>/dev/null || true
done
ok "ClamAV services deactivated (packages left installed)"

# ---- 5. Privileged helpers + polkit policies ----
step "[5/7] Removing privileged helpers..."
rm -f "$HELPER_DIR/resistine-vpn-helper" \
      "$HELPER_DIR/resistine-wazuh-helper" \
      /usr/share/polkit-1/actions/com.resistine.vpn.control.policy \
      /usr/share/polkit-1/actions/com.resistine.wazuh.control.policy
rmdir "$HELPER_DIR" 2>/dev/null || true
ok "Helpers and polkit policies removed"

# ---- 6. Desktop integration ----
step "[6/7] Removing desktop entries..."
for id in phoenix resistine; do
    rm -f "$USER_HOME/.local/share/applications/$id.desktop" \
          "$USER_HOME/.config/autostart/$id.desktop" \
          "/usr/share/applications/$id.desktop"
done
ok "Desktop entries removed (if any)"

# ---- 7. User data (secrets + config) — run as the real user ----
step "[7/7] Removing user data and secrets..."
run_as_user() { sudo -u "$REAL_USER" env HOME="$USER_HOME" "$@"; }

# Keyring master key (best-effort; secret-tool from libsecret).
if command -v secret-tool >/dev/null 2>&1; then
    for svc in phoenix-master-key resistine-master-key; do
        run_as_user secret-tool clear service "$svc" username master-key 2>/dev/null \
            && ok "Removed keyring master key $svc" || info "No keyring entry $svc (or no active keyring)"
    done
else
    info "secret-tool not available — skipping keyring (delete 'phoenix-master-key' / 'resistine-master-key' manually if needed)"
fi

# App config dir (settings, secrets, VPN keys, Wazuh key backup).
for CONFIG_DIR in $CONFIG_DIRS; do
    if [ -d "$CONFIG_DIR" ]; then
        rm -rf "$CONFIG_DIR"
        ok "Removed $CONFIG_DIR"
    else
        info "Config dir not found: $CONFIG_DIR"
    fi
done

# Project virtual environment.
if [ "$KEEP_VENV" -ne 1 ] && [ -d "$PROJECT_ROOT/.venv" ]; then
    rm -rf "$PROJECT_ROOT/.venv"
    ok "Removed $PROJECT_ROOT/.venv"
fi

printf '\n\033[0;32mPhoenix has been uninstalled.\033[0m\n'
printf 'Note: the application source at %s was left in place.\n' "$PROJECT_ROOT"
