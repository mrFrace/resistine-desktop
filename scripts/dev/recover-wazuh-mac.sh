#!/bin/bash
# scripts/dev/recover-wazuh-mac.sh
#
# Recovers a half-broken Wazuh agent install on macOS — the state you end up
# in after the manager rejects enrollment with "Duplicate agent name" and
# launchd subsequently throttles the daemon with "Bootstrap failed: 5".
#
# What this does (idempotent):
#   1. Bootout + disable the launchd service (clears the throttle).
#   2. Stop any straggler wazuh-* daemons (graceful — NO SIGKILL on agentd).
#   3. Wipe /Library/Phoenix, the client.keys file backup, and the System
#      Keychain entry, so the next install enrolls fresh.
#   4. Clear the Phoenix app's stored install state so the UI no longer
#      thinks the agent is installed.
#
# AFTER running this script you ALSO need to delete the manager-side
# registration of this device's agent name. Without that, the next install
# will hit "Duplicate agent name" again and the new postinstall script will
# enroll under a suffixed name (which works but clutters the dashboard).
#
# Usage:
#   sudo bash scripts/dev/recover-wazuh-mac.sh
#
# Author: Resistine Team
# Copyright (c) Resistine 2025

set -euo pipefail

if [ "$EUID" -ne 0 ]; then
    echo "Re-running with sudo…" >&2
    exec sudo bash "$0" "$@"
fi

WAZUH_DIR="/Library/Phoenix"
PLIST="/Library/LaunchDaemons/com.wazuh.agent.plist"
KEY_BACKUP="/Library/Application Support/Resistine/wazuh_client.keys"
KEYCHAIN="/Library/Keychains/System.keychain"
KC_SERVICE="com.resistine.wazuh.agent"
KC_ACCOUNT="client_key"
RESISTINE_SETTINGS="$HOME/Library/Application Support/Phoenix/settings.json"

echo "[1/5] Booting out launchd service…"
launchctl bootout system "$PLIST" 2>/dev/null || true
# We intentionally do NOT call `launchctl disable` here. Disable persists
# across reboots and will block every future `launchctl bootstrap` with
# "Bootstrap failed: 5: Input/output error" until something re-enables it.
launchctl enable system/com.wazuh.agent 2>/dev/null || true

echo "[2/5] Stopping wazuh-control (graceful)…"
if [ -x "$WAZUH_DIR/bin/wazuh-control" ]; then
    "$WAZUH_DIR/bin/wazuh-control" stop 2>/dev/null || true
fi
sleep 1

echo "[3/5] Removing /Library/Phoenix and launchd plist…"
rm -rf "$WAZUH_DIR"
rm -f  "$PLIST"
rm -rf "/Library/StartupItems/WAZUH"

echo "[4/5] Wiping client.keys backup + System Keychain entry…"
rm -f "$KEY_BACKUP"
security delete-generic-password \
    -s "$KC_SERVICE" -a "$KC_ACCOUNT" "$KEYCHAIN" >/dev/null 2>&1 || true

echo "[5/5] Resetting Phoenix install-state…"
# Drop just the wazuh.* fields so other settings survive. python3 always
# ships on macOS, so use it for the JSON edit.
if [ -f "$RESISTINE_SETTINGS" ]; then
    REAL_USER="${SUDO_USER:-$USER}"
    sudo -u "$REAL_USER" python3 - "$RESISTINE_SETTINGS" <<'PY'
import json, sys
path = sys.argv[1]
with open(path) as f:
    data = json.load(f)
wazuh = data.get("wazuh", {})
for k in (
    "install_state", "install_status_file", "failure_reason",
    "retry_count", "last_attempt_ts",
    "pkg_cached_path", "pkg_cached_version",
    "enrolled_email",
):
    wazuh.pop(k, None)
data["wazuh"] = wazuh
with open(path, "w") as f:
    json.dump(data, f, indent=2)
print(f"  cleared wazuh.* install fields in {path}")
PY
fi

echo
echo "Done. Next steps:"
echo "  1. Ask the Wazuh manager admin to delete the agent named"
echo "     '$(scutil --get LocalHostName 2>/dev/null || hostname)-…'"
echo "     (or enable <force><enabled>yes</enabled></force> in authd config)."
echo "  2. Quit Phoenix fully, then relaunch and click Install Security again."
echo "     The new postinstall script will retry under a suffixed name if the"
echo "     server-side cleanup hasn't happened yet."
