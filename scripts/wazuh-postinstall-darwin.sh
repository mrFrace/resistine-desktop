#!/bin/bash
# Wazuh Agent Post-Install Script for macOS
# Runs as root (via osascript with administrator privileges), detached from
# the Resistine UI process.  Survives app quit.
#
# Author: Resistine Team
# Copyright (c) Resistine 2025
# Licensed under the GNU General Public License v2 or later

set -euo pipefail

# --- Argument Parsing ---
PKG_PATH=""
AGENT_NAME=""
AGENT_GROUP=""
MANAGER=""
STATUS_FILE=""
LOG_FILE=""
RESTORE_KEYS="false"

while [ $# -gt 0 ]; do
    case "$1" in
        --pkg-path)
            PKG_PATH="$2"
            shift 2
            ;;
        --agent-name)
            AGENT_NAME="$2"
            shift 2
            ;;
        --agent-group)
            AGENT_GROUP="$2"
            shift 2
            ;;
        --manager)
            MANAGER="$2"
            shift 2
            ;;
        --status-file)
            STATUS_FILE="$2"
            shift 2
            ;;
        --log-file)
            LOG_FILE="$2"
            shift 2
            ;;
        --restore-keys)
            RESTORE_KEYS="true"
            shift
            ;;
        *)
            echo "Unknown argument: $1" >&2
            exit 1
            ;;
    esac
done

# --- Validation ---
if [ -z "$PKG_PATH" ] || [ -z "$AGENT_NAME" ] || [ -z "$AGENT_GROUP" ] \
    || [ -z "$MANAGER" ] || [ -z "$STATUS_FILE" ] || [ -z "$LOG_FILE" ]; then
    echo "Missing required arguments" >&2
    exit 1
fi

if ! [[ "$AGENT_NAME" =~ ^[A-Za-z0-9._-]+$ ]]; then
    echo "Invalid agent name: $AGENT_NAME" >&2
    exit 1
fi

if ! [[ "$AGENT_GROUP" =~ ^[A-Za-z0-9._-]+$ ]]; then
    echo "Invalid agent group: $AGENT_GROUP" >&2
    exit 1
fi

if [ ! -f "$PKG_PATH" ]; then
    echo "Package not found: $PKG_PATH" >&2
    exit 1
fi

# --- Helpers ---
write_status() {
    local tmp="${STATUS_FILE}.tmp"
    printf '%s' "$1" > "$tmp"
    mv "$tmp" "$STATUS_FILE"
}

# Binary overrides — let the test harness substitute fakes without us having to
# search PATH (real installs always use the absolute paths below).
INSTALLER_BIN="${INSTALLER_BIN:-installer}"
SED_BIN="${SED_BIN:-sed}"
SECURITY_BIN="${SECURITY_BIN:-security}"
LAUNCHCTL_BIN="${LAUNCHCTL_BIN:-launchctl}"
AGENT_AUTH_BIN="${AGENT_AUTH_BIN:-/Library/Ossec/bin/agent-auth}"
WAZUH_CONTROL_BIN="${WAZUH_CONTROL_BIN:-/Library/Ossec/bin/wazuh-control}"
OSSEC_CONF_OVERRIDE="${OSSEC_CONF_OVERRIDE:-/Library/Ossec/etc/ossec.conf}"
CLIENT_KEYS_OVERRIDE="${CLIENT_KEYS_OVERRIDE:-/Library/Ossec/etc/client.keys}"
KEY_BACKUP_OVERRIDE="${KEY_BACKUP_OVERRIDE:-/Library/Application Support/Resistine/wazuh_client.keys}"
PLIST_OVERRIDE="${PLIST_OVERRIDE:-/Library/LaunchDaemons/com.wazuh.agent.plist}"

CURRENT_STEP="init"

# --- Logging ---
exec 2>>"$LOG_FILE"
set -x

# --- Error Trap ---
trap 'write_status "{\"status\":\"failed\",\"step\":\"$CURRENT_STEP\",\"error\":\"unexpected error on line $LINENO\"}"' ERR

# --- Step 1: Install Package ---
CURRENT_STEP="install_pkg"
write_status '{"status":"running","step":"install_pkg","pid":'"$$"'}'
"$INSTALLER_BIN" -pkg "$PKG_PATH" -target /

# --- Step 2: Patch ossec.conf ---
CURRENT_STEP="patch_config"
write_status '{"status":"running","step":"patch_config","pid":'"$$"'}'
OSSEC_CONF="$OSSEC_CONF_OVERRIDE"
"$SED_BIN" -i '' "s|<agent_name>.*</agent_name>|<agent_name>${AGENT_NAME}</agent_name>|" "$OSSEC_CONF"

# --- Step 3: Key Restore or Enrollment ---
CURRENT_STEP="enrollment"
write_status '{"status":"running","step":"enrollment","pid":'"$$"'}'

CLIENT_KEYS="$CLIENT_KEYS_OVERRIDE"
KEY_BACKUP="$KEY_BACKUP_OVERRIDE"
KEYCHAIN="/Library/Keychains/System.keychain"
KC_SERVICE="com.resistine.wazuh.agent"
KC_ACCOUNT="client_key"
AGENT_AUTH_LOG="${LOG_FILE%.log}-agent-auth.log"

# Always run agent-auth so the manager receives the group in the registration
# request.  Server-side groups are auto-created on enroll; restoring a stale
# client.keys would skip that and the agent would land in "default".
rm -f "$CLIENT_KEYS"

# agent-auth writes its diagnostic lines to stderr on success and to stdout on
# some failure modes — capture both so we can detect "Duplicate agent name".
EFFECTIVE_AGENT_NAME="$AGENT_NAME"
ENROLLMENT_RESULT="enroll_failed"
ENROLLMENT_ERROR=""
MAX_ENROLL_ATTEMPTS=3

for attempt in $(seq 1 "$MAX_ENROLL_ATTEMPTS"); do
    set +e
    "$AGENT_AUTH_BIN" \
        -m "$MANAGER" \
        -A "$EFFECTIVE_AGENT_NAME" \
        -G "$AGENT_GROUP" \
        > "$AGENT_AUTH_LOG" 2>&1
    AUTH_RC=$?
    set -e

    # Mirror agent-auth output into the main install log for diagnostics.
    cat "$AGENT_AUTH_LOG" >&2 || true

    if [ "$AUTH_RC" -eq 0 ] && [ -s "$CLIENT_KEYS" ]; then
        ENROLLMENT_RESULT="enrolled"
        AGENT_NAME="$EFFECTIVE_AGENT_NAME"
        break
    fi

    # Detect specific failure modes for retry + reporting.
    if grep -q "Duplicate agent name" "$AGENT_AUTH_LOG"; then
        ENROLLMENT_ERROR="duplicate_name"
        # Append a short, sortable, install-attempt suffix.  We deliberately
        # keep the base name intact so the dashboard still groups records by
        # device; the suffix only changes on retry.
        SUFFIX="$(date +%s | tail -c 7)-$attempt"
        EFFECTIVE_AGENT_NAME="${AGENT_NAME}-${SUFFIX}"
        continue
    fi

    if grep -q "Unable to connect" "$AGENT_AUTH_LOG" \
        || grep -q "Connection refused" "$AGENT_AUTH_LOG" \
        || grep -q "Network is unreachable" "$AGENT_AUTH_LOG"; then
        ENROLLMENT_ERROR="manager_unreachable"
    else
        ENROLLMENT_ERROR="enroll_rc_${AUTH_RC}"
    fi

    # Transient failures (TLS handshake / routing not settled right after the
    # VPN comes up) reliably succeed on a second attempt — previously only
    # duplicate_name retried and every other error bailed on attempt 1, which
    # made users see "enrollment failed (code 1)" and then succeed manually.
    if [ "$attempt" -lt "$MAX_ENROLL_ATTEMPTS" ]; then
        echo "agent-auth attempt ${attempt} failed (${ENROLLMENT_ERROR}); retrying in 3s" >&2
        sleep 3
        continue
    fi
    break
done

# Hard stop: if we never wrote a client.keys, starting the daemon is pointless
# (it will crash-loop and launchd will throttle it, producing the spurious
# "Bootstrap failed: 5: Input/output error" we used to see).
if [ "$ENROLLMENT_RESULT" != "enrolled" ]; then
    # Persist the manager-side name we tried, plus the precise reason, so the
    # UI can surface something better than "launchctl bootstrap failed".
    write_status "{\"status\":\"failed\",\"step\":\"enrollment\",\"error\":\"${ENROLLMENT_ERROR:-enroll_failed}\",\"attempted_name\":\"${EFFECTIVE_AGENT_NAME}\"}"
    exit 1
fi

# Update ossec.conf if we ended up enrolling under a suffixed name.
if [ "$AGENT_NAME" != "$EFFECTIVE_AGENT_NAME" ]; then
    "$SED_BIN" -i '' "s|<agent_name>.*</agent_name>|<agent_name>${EFFECTIVE_AGENT_NAME}</agent_name>|" "$OSSEC_CONF" || true
    AGENT_NAME="$EFFECTIVE_AGENT_NAME"
fi

# --- Step 4: Back Up Key ---
CURRENT_STEP="key_backup"
write_status '{"status":"running","step":"key_backup","pid":'"$$"'}'
if [ -s "$CLIENT_KEYS" ]; then
    mkdir -p "$(dirname "$KEY_BACKUP")"
    cp "$CLIENT_KEYS" "$KEY_BACKUP"
    "$SECURITY_BIN" add-generic-password -U \
        -k "$KEYCHAIN" -s "$KC_SERVICE" -a "$KC_ACCOUNT" \
        -w "$(cat "$CLIENT_KEYS")" 2>/dev/null || true
fi

# --- Step 5: Bootstrap Launchd ---
CURRENT_STEP="launchd"
write_status '{"status":"running","step":"launchd","pid":'"$$"'}'
PLIST="$PLIST_OVERRIDE"

# Tear down any prior daemon state and wait briefly for launchd to release the
# label.  Without the sleep, a fast re-bootstrap collides with launchd's
# throttling on a service that just exited and returns "5: Input/output error".
"$LAUNCHCTL_BIN" bootout system "$PLIST" 2>/dev/null || true
"$WAZUH_CONTROL_BIN" stop 2>/dev/null || true
# Re-enable the service in case a prior uninstall left it disabled (the
# uninstall path issues `launchctl disable system/com.wazuh.agent` to dodge
# Wazuh's anti-tampering retaliation, and that flag persists across reboots).
# bootstrap returns "5: Input/output error" on a disabled label.
"$LAUNCHCTL_BIN" enable system/com.wazuh.agent 2>/dev/null || true
sleep "${BOOTSTRAP_SETTLE_SECONDS:-2}"

BOOTSTRAP_RC=1
BOOTSTRAP_ERROR=""
for attempt in 1 2 3; do
    set +e
    BOOTSTRAP_OUT="$("$LAUNCHCTL_BIN" bootstrap system "$PLIST" 2>&1)"
    BOOTSTRAP_RC=$?
    set -e
    echo "$BOOTSTRAP_OUT" >&2
    if [ "$BOOTSTRAP_RC" -eq 0 ]; then
        break
    fi
    BOOTSTRAP_ERROR="$BOOTSTRAP_OUT"
    "$LAUNCHCTL_BIN" bootout system "$PLIST" 2>/dev/null || true
    sleep $((attempt * ${BOOTSTRAP_RETRY_BACKOFF_SECONDS:-3}))
done

if [ "$BOOTSTRAP_RC" -ne 0 ]; then
    SAFE_BOOTSTRAP_ERROR="$(printf '%s' "$BOOTSTRAP_ERROR" | tr -d '\n\r"' | cut -c1-160)"
    write_status "{\"status\":\"failed\",\"step\":\"launchd\",\"error\":\"launchctl bootstrap failed\",\"detail\":\"${SAFE_BOOTSTRAP_ERROR}\"}"
    exit 1
fi

# --- Make live agent state readable for the UI's connection status ---
# wazuh-agentd.state + ossec.log are root-owned and /Library/Ossec/var/run isn't
# traversable by the (non-root) app, so get_agent_connection() reads "unknown".
# Loosen the dirs + files so the UI can show connected/pending/disconnected.
# wazuh-agentd truncate-writes the state file, so the mode persists.
sleep 2
chmod o+rx /Library/Ossec/var /Library/Ossec/var/run /Library/Ossec/logs 2>/dev/null || true
chmod o+r /Library/Ossec/var/run/wazuh-agentd.state 2>/dev/null || true
chmod o+r /Library/Ossec/logs/ossec.log 2>/dev/null || true

# --- Done ---
write_status "{\"status\":\"success\",\"step\":\"done\",\"enrollment\":\"${ENROLLMENT_RESULT}\",\"agent_name\":\"${AGENT_NAME}\"}"

# --- Self-cleanup: remove our one-shot LaunchDaemon plist ---
INSTALLER_PLIST="${INSTALLER_PLIST_OVERRIDE:-/Library/LaunchDaemons/com.resistine.wazuh-installer.plist}"
if [ -f "$INSTALLER_PLIST" ]; then
    "$LAUNCHCTL_BIN" bootout system "$INSTALLER_PLIST" 2>/dev/null || true
    rm -f "$INSTALLER_PLIST"
fi
