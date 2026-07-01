#!/bin/bash
#
# freshclam-update.sh — Resistine ClamAV signature auto-updater (macOS)
#
# Run by the root LaunchDaemon com.resistine.desktop.freshclam via /bin/bash.
# Runs freshclam exactly ONCE and exits. The cadence (every 4h) is owned by
# launchd via the plist's StartCalendarInterval, NOT by a sleep-loop here.
# StartCalendarInterval runs the most recent missed occurrence once on wake,
# so signatures stay fresh across overnight sleep — which neither a self-
# managed sleep-loop (pauses during sleep) nor StartInterval (silently dropped
# when its whole interval elapses while asleep) could do.
#
# This script is bundled (SIP-protected, code-signed) at
# Contents/Helpers/freshclam-update.sh and invoked by absolute path — it must
# NEVER call a bare `freshclam` (a Homebrew ClamAV may sit in PATH with a
# different binary and DB dir).
#
# Author: Resistine Team
# Copyright (c) Resistine 2025
# Licensed under the GNU General Public License v2 or later

set -u

FRESHCLAM="/Applications/Resistine.app/Contents/Helpers/freshclam"
CONF="/Library/Application Support/Resistine/clamav/freshclam.conf"
# Records the epoch of the last attempt. Used to enforce ClamAV's CDN rule of
# "no more than once per hour" — exceeding it earns an HTTP 429/403 block and
# a multi-hour cool-down, regardless of our own cadence.
STAMP="/Library/Application Support/Resistine/clamav/run/freshclam-last-run"
MIN_SPACING=3600  # seconds; ClamAV CDN hard limit is once per hour

log() {
    # Timestamped line to stdout (captured by the daemon's StandardOutPath).
    printf '%s %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$1"
}

# Not yet seeded by postinstall — exit non-zero so launchd retries on its next
# scheduled mark rather than us holding the process open.
if [ ! -x "$FRESHCLAM" ] || [ ! -f "$CONF" ]; then
    log "freshclam binary or conf missing — will retry next interval ($FRESHCLAM / $CONF)"
    exit 1
fi

# Rate-limit guard: refuse to hit the CDN more than once an hour. The cadence
# is 4h, but a catch-up fire on wake, app-launch kickstarts, daemon relaunches,
# or manual runs can stack up and trip ClamAV's 429 rate limit (observed: a
# multi-hour CDN cool-down). launchd treats our early exit 0 as a normal
# completion and simply waits for the next scheduled mark. Skipped in test mode
# (RESISTINE_FRESHCLAM_INTERVAL set).
if [ -z "${RESISTINE_FRESHCLAM_INTERVAL:-}" ] && [ -f "$STAMP" ]; then
    last=$(cat "$STAMP" 2>/dev/null || echo 0)
    now=$(date +%s)
    if [ "$((now - last))" -lt "$MIN_SPACING" ]; then
        log "skipping: last run $((now - last))s ago (< ${MIN_SPACING}s CDN limit)"
        exit 0
    fi
fi

# Pre-update jitter (0-60s) so a fleet of machines whose intervals align don't
# hit the mirrors at the same instant. Small because launchd now spawns us per
# interval — we are not the long-lived process anymore. Skipped when
# RESISTINE_FRESHCLAM_INTERVAL is set, which only happens during testing where
# "run now" is the point.
if [ -z "${RESISTINE_FRESHCLAM_INTERVAL:-}" ]; then
    sleep $((RANDOM % 60))
fi

# Stamp the attempt BEFORE running: the CDN rate limit counts every request,
# success or not, so a failed run must still hold off the next one for an hour.
mkdir -p "$(dirname "$STAMP")" 2>/dev/null || true
date +%s > "$STAMP" 2>/dev/null || true

if "$FRESHCLAM" --config-file="$CONF"; then
    log "freshclam update OK"
else
    # Exit 0 anyway: a network/cert hiccup is not a crash. launchd retries on
    # the next scheduled mark; a non-zero exit would invite throttling/backoff.
    log "freshclam update FAILED (will retry next interval)"
fi

exit 0
