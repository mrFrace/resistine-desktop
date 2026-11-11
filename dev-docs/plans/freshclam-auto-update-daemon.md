# Plan: macOS freshclam auto-update LaunchDaemon

Branch: `feat/mac-antivirus-freshclam-updater`

## Revision (post-implementation): scheduling redesign

The sections below describe the ORIGINAL design — a wrapper that loops forever,
sleeping a jittered interval, kept alive by launchd `KeepAlive`. That shipped,
then was revised after real-world testing revealed two problems:

1. **Missed overnight updates.** A `sleep`-loop pauses during system sleep and
   launchd never re-fires an always-running job, so a laptop closed overnight
   did not update until something restarted the daemon. Fixed by letting
   **launchd own the cadence** via `StartInterval` (14400s = 4h): the wrapper
   now runs freshclam **once and exits**, and launchd coalesces intervals
   missed during sleep into a single run on wake. `KeepAlive` is removed.

2. **CDN rate-limit (HTTP 429).** App-launch kickstarts, daemon relaunches, and
   manual runs each fired freshclam immediately, stacking many requests within
   an hour and tripping ClamAV's "no more than once per hour" CDN limit (a
   multi-hour cool-down). Fixed with a **once-per-hour floor** in the wrapper:
   it stamps `…/clamav/run/freshclam-last-run` on every attempt and exits early
   if the last attempt was < 3600s ago, regardless of what triggered it.

Net cadence: **~4h** (StartInterval) with a **hard 1h floor** enforced
independently of the trigger. Jitter shrank from 0–60min (loop spacing) to
0–60s (pre-run fleet de-sync), since launchd now owns spacing.
`RESISTINE_FRESHCLAM_INTERVAL` still bypasses jitter AND the rate-limit floor
for testing ("run now"). See `scripts/clamav/freshclam-update.sh` and
`com.resistine.desktop.freshclam.plist` for the shipped behavior.

## Revision 2 (2026-06-15): StartInterval → StartCalendarInterval

Revision 1's claim that "launchd coalesces intervals missed during sleep into a
single run on wake" turned out to be **false for `StartInterval`**. Field
evidence: a laptop closed for ~2 days (confirmed via `pmset -g log`: only
DarkWakes, no full wakes, between the runs) had freshclam run exactly **once**
(`RunAtLoad`) and never again across multiple lid-open wakes — `launchctl print`
showed `runs = 1`, leaving `daily` ~3 versions / ~2 days stale. An
`StartInterval` whose entire interval elapses while the Mac is asleep is simply
dropped; launchd does **not** re-fire it on wake.

Fix: switch the plist to **`StartCalendarInterval`** at fixed 4h wall-clock
marks (00/04/08/12/16/20). `StartCalendarInterval` *does* run the most recent
missed occurrence once on wake, which is the behavior Revision 1 wanted. The
once-per-hour CDN floor (Revision 1, item 2) still guards the catch-up fire from
tripping the 429 limit. The wrapper is unchanged behaviorally — only its
comments were updated to say "scheduled mark" instead of "StartInterval."

## Scope guarantees (per user)

- **macOS only.** Every new/changed file is a macOS-only path EXCEPT the shared `plugins/antivirus/main.py`.
  In that one shared file the change is gated `platform.system() == "Darwin"`, and the **else (Linux/Windows)
  branch must preserve today's exact behavior** — the in-process scheduler keeps starting unconditionally on
  those platforms as it does now ([main.py:240-241](plugins/antivirus/main.py#L240-L241),
  [:888-889](plugins/antivirus/main.py#L888-L889)). Net effect on Linux/Windows: **zero behavior change.**
- **One repo only — phoenix-desktop.** No work in the ClamAV-Mac sibling repo: the `freshclam` binary
  already ships (`scripts/build/clamav-artifacts/binaries/freshclam` → copied to `Contents/Helpers/freshclam`
  and signed at build-distribution.sh:348 & :635). We only *schedule* the existing binary; we do not rebuild
  it, change its behavior, or touch CVD certs. ClamAV-Mac's role (compiling the binaries + certs) is unaffected.
- **Watch-out during impl:** build-distribution.sh:845 has a legacy `com.resistine.freshclam` cleanup label —
  confirm it does not clash with the new `com.resistine.desktop.freshclam` label.

## Context

ClamAV's signature DBs (`daily.cvd`, `main.cvd`, `bytecode.cvd`) are published by Cisco/Talos
continuously (event-driven, several times/day for `daily`); clients are expected to poll
periodically. Today Phoenix updates signatures two ways on macOS:

1. **In-process scheduler** in `plugins/antivirus/main.py` (`_auto_update_loop`, lines 950–1019):
   a daemon thread that runs `freshclam` daily at 4 AM ±2h jitter — **only while the app is open**.
2. **Manual "Update Now"** button → `_start_sig_update` → `clamav.run_freshclam`.

The gap: if the app isn't running, signatures go stale. We want **OS-level** updates that run
even when the app is closed, on a rolling **4h + random(0–60min)** cadence ("since last check",
minimum spacing always ≥4h).

Verified on this machine: there is **no existing Phoenix freshclam daemon** and **no
clamd/clamonacc daemon currently loaded** (`launchctl print system/com.resistine.desktop.*`
returns nothing; `/Library/LaunchDaemons/` has no Phoenix plists). The system dir
`/Library/Application Support/Resistine/clamav/` *does* exist (postinstall ran here), and its
`freshclam.conf` is the app's own. A separate **Homebrew** ClamAV exists in PATH
(`/opt/homebrew/bin/freshclam`) — irrelevant to the app, different binary + DB dir, no service —
but it means the daemon **must invoke freshclam by absolute bundle path**, never bare `freshclam`.

So this LaunchDaemon is genuinely new and won't collide with anything.

## Design decisions (chosen with the user)

- **True OS LaunchDaemon** (runs when app is closed), not in-process. On Darwin the in-process
  scheduler is demoted; Linux/Windows keep it.
- **Rolling "since last check"** interval, not fixed wall-clock slots.
- **+0 to +60min jitter** on top of 4h: each cycle waits `14400 + rand(0,3600)` seconds. Mean ~4.5h,
  never more often than every 4h.
- **Wrapper-script loop** (not `StartInterval`, which has no jitter): a small bash script runs
  freshclam once, then `sleep`s the jittered interval, and loops forever; launchd `KeepAlive` keeps it alive.
- **Wrapper bundled under `Contents/Helpers/`** (SIP-protected, code-signed, versions with the app) —
  NOT generated into the user-writable system DB dir (a root daemon running a user-writable script
  is a privilege-escalation vector).

## Files to CREATE

### `scripts/build/clamav-artifacts/launchd/com.resistine.desktop.freshclam.plist`
Modeled on `com.resistine.desktop.clamd.plist`. Auto-bundles into `Contents/Library/LaunchDaemons/`
via the existing `*.plist` glob in `build-distribution.sh:446-448` — no build-script change for the plist.
- `Label`: `com.resistine.desktop.freshclam`
- `ProgramArguments`: `["/bin/bash", "/Applications/Phoenix.app/Contents/Helpers/freshclam-update.sh"]`
  (explicit `/bin/bash` because the script uses `$RANDOM`, which POSIX `/bin/sh` lacks)
- `RunAtLoad`: `true`; `KeepAlive`: `true` (bare bool — any exit of the infinite-loop script is
  unexpected → relaunch); `ThrottleInterval`: `30`
- `UserName`: `root`, `GroupName`: `wheel`
- `EnvironmentVariables`: `CVD_CERTS_DIR=/Applications/Phoenix.app/Contents/certs`,
  `SSL_CERT_FILE=/etc/ssl/cert.pem` (matches `clamav_env()` / the clamd plist)
- `StandardOutPath` / `StandardErrorPath`: `/Library/Application Support/Resistine/clamav/log/freshclam-daemon.{stdout,stderr}.log`

### `scripts/clamav/freshclam-update.sh`
First-party wrapper (NOT a downloaded artifact, so no `checksums.txt` entry needed). Behavior:
- `#!/bin/bash`, `set -u`. Constants: `FRESHCLAM=/Applications/Phoenix.app/Contents/Helpers/freshclam`,
  `CONF=/Library/Application Support/Resistine/clamav/freshclam.conf`.
- If `$FRESHCLAM` or `$CONF` missing: log + `sleep 3600; exit 0` (avoids KeepAlive hot-loop;
  retries ~hourly until postinstall has set things up).
- Initial jitter on first iteration: `sleep $((RANDOM % 900))` (0–15min) — smooths the
  update-on-every-boot/login spike.
- Loop forever: run `"$FRESHCLAM" --config-file="$CONF"` (the conf's `NotifyClamd` reloads clamd),
  log a timestamped result line, then `sleep $((14400 + RANDOM % 3600))`. **Never exit on freshclam
  failure** (network/cert hiccups self-heal next cycle).
- Honor optional env override `RESISTINE_FRESHCLAM_INTERVAL` for the 14400 base (testability only;
  production stays 14400).

## Files to MODIFY

### `plugins/antivirus/clamav_platform_darwin.py`
- Append `"com.resistine.desktop.freshclam.plist"` to `_DAEMON_PLISTS` (lines 39–42). This alone makes
  `ensure_daemons_registered()` (401–485) register/approve/reload it and `deactivate_system_daemons()`
  (697–727, loops `reversed(_DAEMON_PLISTS)`) bootout it — no other change to those functions.
- Add `set_freshclam_daemon_enabled(enabled: bool)`: on enable → `ensure_daemons_registered()`
  (idempotent; re-registering loaded daemons is a cheap no-op). On disable → bootout **only**
  `com.resistine.desktop.freshclam` via the existing osascript-admin pattern (mirror
  `deactivate_system_daemons` but a single label — do NOT use `deactivate_system_daemons`, which
  would also kill clamd/clamonacc real-time protection).

### `plugins/antivirus/main.py` (ONLY shared file — Linux/Windows behavior must stay identical)
- `__init__` (lines 240–241): replace `if self._auto_update_on: self._start_auto_update_scheduler()` with a
  Darwin branch. On **Darwin**: do NOT start the thread (the OS daemon owns updates; registration already
  happens via `ensure_daemons_registered()` in the existing `_darwin_daemon_init` at line 209+). On
  **non-Darwin**: call `self._start_auto_update_scheduler()` exactly as today — unchanged.
- `_toggle_auto_update` (881–891): keep `settings.set("antivirus","auto_update_enabled",…)` for all platforms.
  On **Darwin** call `clamav.set_freshclam_daemon_enabled(self._auto_update_on)` (register/bootout the daemon).
  On **non-Darwin** start/stop the in-process thread exactly as today (the existing
  `_start_auto_update_scheduler`/`_stop_auto_update_scheduler` calls). On macOS the setting now means
  "freshclam daemon active".
- Verify no other call site starts the scheduler on Darwin (grep `_start_auto_update_scheduler`).
- Keep `_auto_update_loop`/`_seconds_until_next_run` (still used Linux/Windows); add a comment that
  Darwin uses the OS daemon. Keep "Update Now" (`_start_sig_update`) untouched — works on all platforms.
- DB-freshness UI (`get_db_info`/`_refresh_db_info`) needs **no change**: it reads mtimes from the
  system DB dir the root daemon writes, so daemon updates surface on the next view refresh.

### `scripts/clamav-postinstall-darwin.sh`
- Step 6 load loop (lines 189–199): add `com.resistine.desktop.freshclam.plist` to the
  `for PLIST_NAME in …` list so it is kickstarted on install. (Log dir already created in Step 1 +
  chmod 755 in Step 3, so the daemon can write its logs. freshclam.conf heredoc already correct.)

### `scripts/build/build-distribution.sh`
- Step 4b Helpers copy (~lines 346–352): add `cp scripts/clamav/freshclam-update.sh
  "$PYTHON_APP/Contents/Helpers/freshclam-update.sh"` + `chmod 755`.
- Include `freshclam-update.sh` in the Helpers codesign loop (~384–639) so it's signed with the app
  identity (signed shell script is fine; it's inside the notarized bundle).

### `utils/uninstall/darwin.py` — `_remove_clamav_daemons` (157–225)
- Add `"com.resistine.desktop.freshclam.plist"` to the SMAppService unregister list, the
  legacy/`/Library/LaunchDaemons` bootout+rm list (defensive), and the bootout-by-label list (205–214).
- Add `pkill -f freshclam-update.sh` and `pkill -x freshclam` to the process-kill commands (217–218)
  so an in-flight update stops. Existing `rm -rf` of the system dir already clears logs/conf.

### `scripts/build/clamav-artifacts/checksums.txt` — NO change
Current `com.resistine.desktop.*` plists are already not checksum-gated (file still lists old
`com.resistine.clamd.plist` names); they're verified by git, not download. The wrapper under
`scripts/clamav/` is first-party, also not gated. `download-clamav-artifacts.sh` unaffected.

## Sequencing
1. Create wrapper + plist. 2. Wire build packaging (so they land + sign). 3. Wire registration/load
(`_DAEMON_PLISTS` + postinstall Step 6). 4. Wire uninstaller teardown. 5. Demote in-process scheduler +
rewire toggle + add `set_freshclam_daemon_enabled`. 6. Tests. (Do 5 after 1–4 so the toggle controls a
daemon that exists.)

## Edge cases (handled)
- **Not approved** (SMAppService status 2): existing approval flow surfaces it; manual update still works.
- **Cert/network failure**: freshclam exits non-zero, script logs + continues; no crash-loop (we don't exit on failure).
- **clamd down for NotifyClamd**: DB files still written; clamd `SelfCheck 60` reloads within ~60s; KeepAlive restarts clamd.
- **Sleep/wake**: no `StartInterval` to miss; the running `sleep` suspends and resumes late on wake → desired rolling behavior, no accumulation.
- **Conf/DB not yet seeded**: script long-sleeps + retries, no hot-loop.
- **Concurrent manual + daemon run**: freshclam's DB-dir lock makes the second invocation exit cleanly.

## Verification
- `plutil -lint` the new plist; `bash -n` (+ `shellcheck`) the wrapper.
- Run wrapper with `RESISTINE_FRESHCLAM_INTERVAL=60` to watch two runs ~60–63s apart (jitter range OK)
  without waiting 4h.
- Hand-run `…/Helpers/freshclam --config-file=/Library/.../freshclam.conf` to confirm env+conf → real
  update + NotifyClamd. (Use the **bundle** freshclam, not Homebrew's.)
- Daemon load (launchctl works in dev): copy plist to scratch, `sudo launchctl bootstrap system <plist>`,
  `sudo launchctl print system/com.resistine.desktop.freshclam` (loaded, env, program path),
  `kickstart -k` (forces run → check `freshclam-daemon.stdout.log` + `freshclam.log`),
  `bootout` (clean teardown).
- Toggle: call `set_freshclam_daemon_enabled(False/True)` in dev, verify via `launchctl print`.
- Uninstall: run `_remove_clamav_daemons` path, confirm `launchctl print system/com.resistine.desktop.freshclam`
  → "Could not find service".

## Tests (`tests/`)
- `tests/unit/test_clamav.py`: assert `_DAEMON_PLISTS` includes the freshclam plist; test
  `set_freshclam_daemon_enabled` (monkeypatch subprocess/osascript — disable builds
  `launchctl bootout system/com.resistine.desktop.freshclam`; enable routes through `ensure_daemons_registered`).
- `tests/unit/test_antivirus_plugin.py`: on Darwin, `_start_auto_update_scheduler` NOT started in
  `__init__`/toggle (thread stays None) and toggle calls the daemon helper; on non-Darwin the scheduler
  still starts. Mock `platform.system` + the helper.
- Optional static guard (gate on `darwin`/`plutil` present): `plutil -lint` all three plists + `bash -n`
  the wrapper, at CI time.
