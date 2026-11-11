#!/bin/bash
# ClamAV Post-Install Script for macOS
# Runs as root (via osascript with administrator privileges), detached from
# the Resistine UI process.  Survives app quit.
#
# Sets up system-level ClamAV directories, configs, seeds DB from user-level
# pre-downloaded signatures, and loads daemons via launchctl.
#
# Author: Resistine Team
# Copyright (c) Resistine 2025
# Licensed under the GNU General Public License v2 or later

set -euo pipefail

# Root-write hardening: everything this script creates starts root-only.
# Paths that must be readable by the unprivileged app (status file, log,
# configs, DB) are chmod'd to 644/755 explicitly below.
umask 077

# --- Argument Parsing ---
APP_CONTENTS=""
DB_SOURCE=""
STATUS_FILE=""
LOG_FILE=""

while [ $# -gt 0 ]; do
    case "$1" in
        --app-contents)
            APP_CONTENTS="$2"
            shift 2
            ;;
        --db-source)
            DB_SOURCE="$2"
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
        *)
            echo "Unknown argument: $1" >&2
            exit 1
            ;;
    esac
done

# --- Validation ---
if [ -z "$APP_CONTENTS" ] || [ -z "$DB_SOURCE" ] \
    || [ -z "$STATUS_FILE" ] || [ -z "$LOG_FILE" ]; then
    echo "Missing required arguments" >&2
    echo "Usage: $0 --app-contents PATH --db-source PATH --status-file PATH --log-file PATH" >&2
    exit 1
fi

if [ ! -d "$APP_CONTENTS" ]; then
    echo "App contents not found: $APP_CONTENTS" >&2
    exit 1
fi

if [ ! -d "$DB_SOURCE" ]; then
    echo "DB source directory not found: $DB_SOURCE" >&2
    exit 1
fi

# Caller-supplied paths this root script writes to live in /tmp. Refuse
# pre-planted symlinks (and non-regular files) — writing through one would
# be an arbitrary root file write.
for p in "$STATUS_FILE" "$LOG_FILE"; do
    if [ -L "$p" ] || { [ -e "$p" ] && [ ! -f "$p" ]; }; then
        echo "Refusing to write to non-regular file or symlink: $p" >&2
        exit 1
    fi
done

# --- Constants ---
SYSTEM_DIR="/Library/Application Support/Resistine/clamav"
SYSTEM_DB_DIR="$SYSTEM_DIR/db"
SYSTEM_LOG_DIR="$SYSTEM_DIR/log"
SYSTEM_RUN_DIR="$SYSTEM_DIR/run"
CLAMD_CONF="$SYSTEM_DIR/clamd.conf"
FRESHCLAM_CONF="$SYSTEM_DIR/freshclam.conf"
CLAMD_SOCKET="$SYSTEM_RUN_DIR/clamd.sock"
LAUNCHD_DIR="$APP_CONTENTS/Library/LaunchDaemons"

# --- Helpers ---
write_status() {
    # Re-check on every write: never follow a symlink planted after start
    # (arbitrary root file write).
    if [ -L "$STATUS_FILE" ]; then
        echo "Refusing to write status through symlink: $STATUS_FILE" >&2
        exit 1
    fi
    local tmp
    tmp=$(mktemp "${STATUS_FILE}.XXXXXX") || exit 1
    printf '%s' "$1" > "$tmp"
    # The unprivileged app polls this file — must be world-readable.
    chmod 644 "$tmp"
    mv -f "$tmp" "$STATUS_FILE"
}

CURRENT_STEP="init"

# The freshclam LaunchDaemon plist is shipped static and code-signed, so its
# ProgramArguments and CVD_CERTS_DIR hardcode /Applications/Phoenix.app. We
# cannot rewrite a signed plist at install time, so refuse to set up the
# daemons from any other location rather than register a daemon pointing at a
# path that does not exist (every scheduled run would fail to exec). Most
# signed macOS security apps require /Applications for the same reason. This
# runs after write_status() is defined so the UI sees the failure reason.
if [ "$APP_CONTENTS" != "/Applications/Phoenix.app/Contents" ]; then
    write_status "{\"status\":\"failed\",\"step\":\"validate\",\"error\":\"Phoenix must be installed in /Applications (found: $APP_CONTENTS)\",\"error_code\":\"WRONG_INSTALL_LOCATION\",\"exit_code\":1,\"pid\":$$,\"ts\":$(date +%s)}"
    echo "Phoenix must be installed in /Applications. Move Phoenix.app to /Applications and reopen it." >&2
    exit 1
fi

# --- Logging ---
# Drop any pre-existing entry at the log path (removes an attacker's link,
# never the target), then verify nothing reappeared before root opens it.
rm -f "$LOG_FILE" 2>/dev/null || true
if [ -L "$LOG_FILE" ] || [ -e "$LOG_FILE" ]; then
    echo "Refusing to open log file: $LOG_FILE" >&2
    exit 1
fi
exec 2>>"$LOG_FILE"
# Log is for user-facing diagnostics — make it readable (umask made it 600).
chmod 644 "$LOG_FILE" 2>/dev/null || true
set -x

# --- Cleanup on Failure ---
cleanup_failed_install() {
    # Bootout any daemons we may have loaded
    launchctl bootout system/com.resistine.desktop.freshclam 2>/dev/null || true
    launchctl bootout system/com.resistine.desktop.clamonacc 2>/dev/null || true
    launchctl bootout system/com.resistine.desktop.clamd 2>/dev/null || true
    # Remove config files (safe to retry)
    rm -f "$CLAMD_CONF" "$FRESHCLAM_CONF" 2>/dev/null || true
    # Do NOT remove dirs or DB — safe to leave for retry
}

# --- Error Trap ---
# write_status is best-effort; cleanup_failed_install must always run
trap 'write_status "{\"status\":\"failed\",\"step\":\"$CURRENT_STEP\",\"error\":\"unexpected error on line $LINENO\",\"error_code\":\"SCRIPT_ERROR\",\"exit_code\":$?,\"pid\":'"$$"',\"ts\":'"$(date +%s)"'}" 2>/dev/null || true; cleanup_failed_install' ERR

# --- Step 1: Create Directories ---
CURRENT_STEP="create_dirs"
write_status '{"status":"running","step":"create_dirs","pid":'"$$"',"ts":'"$(date +%s)"'}'
mkdir -p "$SYSTEM_DB_DIR" "$SYSTEM_LOG_DIR" "$SYSTEM_RUN_DIR"
# umask 077 makes freshly created dirs 700 — open them up so the
# unprivileged app can read configs/DB and reach the clamd socket.
# All stay root-owned (mkdir as root); none are user-writable.
chmod 755 "/Library/Application Support/Resistine" "$SYSTEM_DIR" \
    "$SYSTEM_DB_DIR" "$SYSTEM_LOG_DIR" "$SYSTEM_RUN_DIR"

# --- Step 2: Write Configs ---
CURRENT_STEP="write_configs"
write_status '{"status":"running","step":"write_configs","pid":'"$$"',"ts":'"$(date +%s)"'}'

cat > "$CLAMD_CONF" << 'CLAMD_EOF'
# Auto-generated by Resistine — do not edit manually
LocalSocket /Library/Application Support/Resistine/clamav/run/clamd.sock
PidFile /Library/Application Support/Resistine/clamav/run/clamd.pid
DatabaseDirectory /Library/Application Support/Resistine/clamav/db
LogFile /Library/Application Support/Resistine/clamav/log/clamd.log
LogFileMaxSize 5M
LogTime yes
LogVerbose yes
LogClean yes
MaxThreads 8
MaxDirectoryRecursion 20
FollowDirectorySymlinks yes
SelfCheck 60
ExcludePath ^/proc
ExcludePath ^/sys
ExcludePath ^/dev

# On-access real-time monitoring (clamonacc via ESF)
OnAccessIncludePath /Users
OnAccessIncludePath /Applications
OnAccessIncludePath /private/tmp
OnAccessExcludePath /Library/Application Support/Resistine/clamav
OnAccessPrevention no
OnAccessExtraScanning yes
OnAccessMaxFileSize 50M
CLAMD_EOF

cat > "$FRESHCLAM_CONF" << FRESHCLAM_EOF
# Auto-generated by Resistine — do not edit manually
DatabaseDirectory /Library/Application Support/Resistine/clamav/db
UpdateLogFile /Library/Application Support/Resistine/clamav/log/freshclam.log
LogFileMaxSize 2M
LogTime yes
DatabaseMirror database.clamav.net
NotifyClamd $CLAMD_CONF
# Run by the root LaunchDaemon. Without this, freshclam drops privileges to
# the default "clamav" user (which does not exist on macOS) and fails to open
# the root-owned UpdateLogFile — "Problem with internal logger / libfreshclam
# init failed" — so signatures silently never update. Pin to root.
DatabaseOwner root
FRESHCLAM_EOF

# Append CVDCertsDirectory if certs exist in app bundle
if [ -d "$APP_CONTENTS/certs" ] && [ -f "$APP_CONTENTS/certs/clamav.crt" ]; then
    echo "CVDCertsDirectory $APP_CONTENTS/certs" >> "$FRESHCLAM_CONF"
fi

# --- Step 3: Set Permissions ---
CURRENT_STEP="set_permissions"
write_status '{"status":"running","step":"set_permissions","pid":'"$$"',"ts":'"$(date +%s)"'}'
# SECURITY: these configs are consumed by ROOT daemons (clamd, clamonacc,
# freshclam). They must never be writable by a non-root user — a writable
# clamd.conf (VirusEvent) or freshclam.conf (OnUpdateExecute) is direct
# root code execution, and a group/world-writable DB dir lets any local
# user replace the signature databases. Root-owned, world-readable only.
chown root:wheel "$CLAMD_CONF" "$FRESHCLAM_CONF" "$SYSTEM_DB_DIR"
chmod 644 "$CLAMD_CONF" "$FRESHCLAM_CONF"
chmod 755 "$SYSTEM_DB_DIR"
chmod 755 "$SYSTEM_LOG_DIR"

# --- Step 4: Seed DB (local copy, no network) ---
CURRENT_STEP="seed_db"
write_status '{"status":"running","step":"seed_db","pid":'"$$"',"ts":'"$(date +%s)"'}'
if ls "$DB_SOURCE"/*.cvd 1>/dev/null 2>&1; then
    cp "$DB_SOURCE"/*.cvd "$SYSTEM_DB_DIR/" 2>/dev/null || true
    cp "$DB_SOURCE"/*.cld "$SYSTEM_DB_DIR/" 2>/dev/null || true
    # Root-owned signatures; world-readable so user-level clamscan can
    # still read the system DB. umask 077 would otherwise leave them 600.
    chown root:wheel "$SYSTEM_DB_DIR"/*.cvd 2>/dev/null || true
    chown root:wheel "$SYSTEM_DB_DIR"/*.cld 2>/dev/null || true
    chmod 644 "$SYSTEM_DB_DIR"/*.cvd 2>/dev/null || true
    chmod 644 "$SYSTEM_DB_DIR"/*.cld 2>/dev/null || true
else
    write_status '{"status":"failed","step":"seed_db","error":"No CVD files in source directory","error_code":"NO_DB_FILES","exit_code":1,"pid":'"$$"',"ts":'"$(date +%s)"'}'
    cleanup_failed_install
    exit 1
fi

# --- Step 5: Cleanup Legacy Daemons ---
CURRENT_STEP="cleanup_legacy"
write_status '{"status":"running","step":"cleanup_legacy","pid":'"$$"',"ts":'"$(date +%s)"'}'
launchctl bootout system/com.resistine.clamd 2>/dev/null || true
launchctl bootout system/com.resistine.clamonacc 2>/dev/null || true
rm -f /Library/LaunchDaemons/com.resistine.clamd.plist 2>/dev/null || true
rm -f /Library/LaunchDaemons/com.resistine.clamonacc.plist 2>/dev/null || true

# --- Step 6: Load Daemons ---
CURRENT_STEP="load_daemons"
write_status '{"status":"running","step":"load_daemons","pid":'"$$"',"ts":'"$(date +%s)"'}'

for PLIST_NAME in com.resistine.desktop.clamd.plist com.resistine.desktop.clamonacc.plist com.resistine.desktop.freshclam.plist; do
    LABEL="${PLIST_NAME%.plist}"
    PLIST_PATH="$LAUNCHD_DIR/$PLIST_NAME"
    if [ ! -f "$PLIST_PATH" ]; then
        write_status "{\"status\":\"failed\",\"step\":\"load_daemons\",\"error\":\"plist not found: $PLIST_NAME\",\"error_code\":\"LAUNCHCTL_LOAD_FAILED\",\"exit_code\":113,\"pid\":$$,\"ts\":$(date +%s)}"
        cleanup_failed_install
        exit 113
    fi
    launchctl kickstart -k "system/$LABEL" 2>/dev/null || \
        launchctl load -w "$PLIST_PATH" 2>/dev/null || true
done

# --- Done ---
write_status "{\"status\":\"success\",\"step\":\"done\",\"pid\":$$,\"ts\":$(date +%s)}"
