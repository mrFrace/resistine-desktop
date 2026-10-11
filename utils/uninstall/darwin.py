"""
macOS Uninstaller Backend.

Performs full cleanup in three phases:

Phase 1 — Non-privileged work (no admin prompt):
  - Unregister ClamAV daemons via SMAppService
  - Stop VPN tunnel
  - Deactivate system extension (waits up to 15s)
  - Remove keychain items
  - Remove WireGuard config files
  - Remove user-level app config

Phase 2 — Privileged work (single admin prompt):
  - Stop/remove Wazuh agent (fallback path)
  - Kill and clean up ClamAV daemons/plists/data
  - Remove system-level app config
  - Remove Wazuh key backup

Phase 3 — App bundle removal (privileged if needed):
  - Remove the .app bundle from /Applications (admin rm -rf)

Author: Resistine Team
Copyright (c) Resistine 2025
Licensed under the GNU General Public License v2 or later
"""

import os
import shutil
import subprocess
import sys

from utils.logger import logger

_EXTENSION_BUNDLE_ID = "com.resistine.desktop.network-extension"


def is_available():
    """Uninstall is always available on macOS."""
    return True


def run_uninstall(app, progress_callback=None):
    """Execute the full macOS uninstall sequence.

    SINGLE password prompt: every command that requires admin privileges
    (Wazuh agent removal, ClamAV cleanup, system-level config, app-bundle
    removal) is collected into one shell script and run via ONE
    ``osascript with administrator privileges`` call. Previous versions
    asked for the password 2-3 times because Wazuh removal and app-bundle
    removal each had their own prompt — those are now batched in.
    """

    def _progress(msg):
        logger.info(f"[UNINSTALL] {msg}")
        if progress_callback:
            try:
                progress_callback(msg)
            except Exception as e:
                logger.debug(f"[UNINSTALL] Progress callback failed: {e}")

    errors = []
    admin_cmds = []  # Shell commands that require admin privileges

    # -- Phase 1: Non-privileged work + collect admin commands ---------------

    # Wazuh — emits commands into admin_cmds (no separate prompt anymore).
    _progress("Preparing SIEM agent removal...")
    try:
        _collect_wazuh_admin_cmds(admin_cmds)
    except Exception as e:
        logger.error(f"[UNINSTALL] Failed — SIEM agent prep: {e}")
        errors.append(f"SIEM agent prep: {e}")

    # ClamAV — SMAppService (no admin), then collect admin commands
    _progress("Stopping ClamAV daemons...")
    try:
        _remove_clamav_daemons(admin_cmds)
    except Exception as e:
        logger.error(f"[UNINSTALL] Failed — ClamAV daemons: {e}")
        errors.append(f"ClamAV daemons: {e}")

    # Non-privileged steps
    non_privileged_steps = [
        ("Stopping VPN tunnel...",             "VPN stop",
         _stop_vpn_tunnel),
        ("Deactivating system extension...",   "Extension deactivation",
         _deactivate_system_extension),
        ("Removing keychain items...",         "Keychain",
         _remove_keychain_items),
        ("Removing VPN configurations...",     "WG configs",
         _remove_wireguard_configs),
    ]
    for message, label, func in non_privileged_steps:
        _progress(message)
        try:
            func()
        except Exception as e:
            logger.error(f"[UNINSTALL] Failed — {label}: {e}")
            errors.append(f"{label}: {e}")

    # App config — user-level (no admin), system-level (admin)
    _progress("Removing application data...")
    try:
        _remove_app_config(admin_cmds)
    except Exception as e:
        logger.error(f"[UNINSTALL] Failed — App config: {e}")
        errors.append(f"App config: {e}")

    # App bundle removal — append to admin_cmds so it runs in the same
    # prompt instead of asking for the password again.
    try:
        _collect_app_bundle_admin_cmd(admin_cmds)
    except Exception as e:
        logger.error(f"[UNINSTALL] Failed — App bundle prep: {e}")
        errors.append(f"App bundle prep: {e}")

    # -- Phase 2: Run all privileged commands in ONE admin prompt -----------

    if admin_cmds:
        _progress("Authenticating for system cleanup...")
        try:
            _run_privileged(admin_cmds)
        except _UserCancelled:
            # User clicked Cancel on the password dialog. Distinguish
            # from an actual failure — the rest of the uninstall ran
            # but the privileged steps were skipped at the user's
            # request, so don't blast a red error label at them.
            return (False, "Uninstall cancelled at password prompt.")
        except Exception as e:
            logger.error(f"[UNINSTALL] Failed — Privileged cleanup: {e}")
            errors.append(f"Privileged cleanup: {e}")

    if errors:
        return (False, f"Completed with errors: {'; '.join(errors)}")
    return (True, "Phoenix has been uninstalled successfully.")


class _UserCancelled(Exception):
    """User clicked Cancel on the admin password prompt."""
    pass


# ---------------------------------------------------------------------------
# Privileged command runner
# ---------------------------------------------------------------------------


_STEP_LOG = "/tmp/resistine-uninstall.log"


def _instrument_cmds(cmds):
    """Wrap each command with a step-log line so a post-mortem reveals
    exactly which command died when the shell exits with a signal.

    The log file at ``/tmp/resistine-uninstall.log`` is overwritten at the
    start of every uninstall and gets a `STEP N/TOTAL: <command>` line
    BEFORE each command, plus a final `DONE` sentinel. When the shell is
    SIGKILL'd mid-run the file contains every step that started — the
    last `STEP` entry is the one that was running when the kernel
    pulled the rug. ``_run_privileged`` reads the log on nonzero return
    and surfaces "died after step N: <description>" in the error so we
    can stop guessing which operation triggers the kill.
    """
    instrumented = [f"true > {_STEP_LOG} 2>/dev/null"]
    n_total = len(cmds)
    for i, c in enumerate(cmds, 1):
        # First 80 chars of the command so the log stays grep-able. Escape
        # any double-quotes in the description so the echo doesn't break.
        desc = c[:80].replace('"', "'")
        instrumented.append(
            f'echo "STEP {i}/{n_total}: {desc}" >> {_STEP_LOG} 2>/dev/null'
        )
        instrumented.append(c)
    instrumented.append(f'echo DONE >> {_STEP_LOG} 2>/dev/null')
    return instrumented


def _read_last_step():
    """Return the last `STEP N/TOTAL: ...` line written to the log, or
    None if the log doesn't exist or is empty. Used by _run_privileged
    to attribute a SIGKILL to a specific command.
    """
    try:
        with open(_STEP_LOG, "r", encoding="utf-8", errors="replace") as f:
            lines = [ln.strip() for ln in f.readlines() if ln.strip()]
    except OSError:
        return None
    if not lines:
        return None
    if lines[-1] == "DONE":
        return "DONE (all steps completed)"
    for ln in reversed(lines):
        if ln.startswith("STEP "):
            return ln
    return None


def _run_privileged(cmds):
    """Run a list of shell commands in a single admin osascript prompt.

    Each command is joined with `;` so a failure in one doesn't abort the
    rest — every command also has its own `|| true` fallback inside
    sub-helpers so transient state (e.g. plist already gone) doesn't
    short-circuit the cleanup. Every command is preceded by a STEP marker
    that gets appended to ``/tmp/resistine-uninstall.log`` so when the
    privileged shell is SIGKILL'd by some external actor (corporate EDR
    hooking the AuthorizationExecuteWithPrivileges trampoline; macOS
    EndpointSecurity teardown of Wazuh's ES subscription during bootout;
    etc.) we can attribute the kill to a specific step.

    On failure, the prior version raised "Privileged cleanup failed: "
    with an empty message because osascript surfaces error text via
    stdout, not stderr. Capture both streams, the exit code, AND the
    last-completed step from the log so the UI shows something actionable.
    """
    script = "; ".join(_instrument_cmds(cmds))
    escaped = script.replace("\\", "\\\\").replace('"', '\\"')
    cmd = [
        "osascript", "-e",
        f'do shell script "{escaped}" with administrator privileges',
    ]
    # 5-minute timeout: a slow Wazuh shutdown + system extension dance
    # can take 30-60 s; the 60 s ceiling was tight.
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    if result.returncode == 0:
        logger.info("[UNINSTALL] Privileged cleanup completed")
        return
    # Capture BOTH streams so a future error has actionable detail.
    err = (result.stderr or "").strip()
    out = (result.stdout or "").strip()
    combined = "\n".join(s for s in (err, out) if s).strip()
    # Distinguish user-cancelled from a real failure. osascript surfaces
    # the cancel as exit code 1 (or -128 on some macOS versions) with
    # the phrase "User canceled" / "User cancelled" / "-128".
    if (result.returncode == -128
            or "User canceled" in combined
            or "User cancelled" in combined
            or "-128" in combined):
        logger.info("[UNINSTALL] User cancelled the admin prompt")
        raise _UserCancelled()
    # Always include the exit code, even when stderr/stdout is non-empty.
    # The previous version dropped the code when stderr had any content,
    # which made signal kills (exit 9 = SIGKILL, exit 137 = OOM-kill) and
    # other non-textual failures indistinguishable from script errors.
    last_step = _read_last_step()
    if last_step:
        logger.error(f"[UNINSTALL] Last privileged step: {last_step}")
    if combined:
        detail = f"{combined} (exit code {result.returncode})"
    else:
        # Most useful generic hint when the script returned no output —
        # tends to be the OS killing osascript, not osascript itself
        # erroring out. Surface the signal name when we recognize it.
        sig_names = {
            1: "SIGHUP", 2: "SIGINT", 9: "SIGKILL", 11: "SIGSEGV",
            13: "SIGPIPE", 15: "SIGTERM", 137: "SIGKILL (OOM-killed)",
        }
        sig = sig_names.get(result.returncode, "")
        detail = f"exit code {result.returncode}"
        if sig:
            detail += f" ({sig})"
        if last_step:
            detail += f" — died after {last_step}"
        else:
            detail += (
                " — privileged shell died with no output; "
                "log file missing too. See /tmp/resistine-uninstall.log "
                "if it exists."
            )
    raise OSError(detail)


# ---------------------------------------------------------------------------
# Cleanup helpers
# ---------------------------------------------------------------------------


def _remove_clamav_daemons(admin_cmds):
    """Unregister ClamAV daemons and collect admin commands for cleanup."""
    _SYSTEM_CLAMAV_DIR = "/Library/Application Support/Resistine/clamav"

    # 1. SMAppService unregistration (no admin needed)
    _smappservice_plist_names = [
        "com.resistine.desktop.freshclam.plist",
        "com.resistine.desktop.clamonacc.plist",
        "com.resistine.desktop.clamd.plist",
        "com.resistine.clamonacc.plist",
        "com.resistine.clamd.plist",
    ]
    try:
        from ServiceManagement import SMAppService

        for plist_name in _smappservice_plist_names:
            try:
                service = SMAppService.daemonServiceWithPlistName_(plist_name)
                status = int(service.status())
                if status in (1, 2):  # enabled or requiresApproval
                    success, err = service.unregisterAndReturnError_(None)
                    if not success:
                        logger.warning(
                            f"[UNINSTALL] SMAppService unregister error "
                            f"({plist_name}): {err}",
                        )
                    else:
                        logger.info(
                            f"[UNINSTALL] Unregistered {plist_name} via SMAppService",
                        )
            except Exception as e:
                logger.warning(
                    f"[UNINSTALL] SMAppService unregister failed ({plist_name}): {e}",
                )
    except ImportError:
        logger.debug("[UNINSTALL] ServiceManagement not available")

    # ORDER MATTERS (same reason as _collect_wazuh_admin_cmds): kill the
    # ClamAV daemon processes FIRST, then bootout the launchd plists.
    # `clamonacc` is a macOS EndpointSecurity client (subscribes to
    # file-creation/write events to drive on-access scanning). When
    # launchctl boots out an ES-subscribed daemon the ES framework's
    # teardown path has been observed to SIGKILL processes that have
    # active subscriptions or events in-flight, which has cascaded onto
    # the privileged shell osascript spawned (`exit code -9` with no
    # output). Killing first means the ES subscription is gone before
    # launchd's bootout-time cleanup runs.
    #
    # `[f]` regex trick — `pkill -f` matches against the full command
    # line, and our own admin shell script (passed verbatim to
    # `osascript -e`) contains the literal text we'd otherwise be
    # searching for. Without the bracket trick, pkill matches its own
    # parent shell/osascript and SIGKILLs them, surfacing to the user
    # as `exit code -9` with no output. `[f]reshclam-update.sh`
    # matches `freshclam-update.sh` in REAL process command lines via
    # the one-char character class, but the literal string
    # `[f]reshclam-update.sh` doesn't appear anywhere else.
    admin_cmds.append("pkill -f '[f]reshclam-update.sh' 2>/dev/null || true")
    admin_cmds.append("pkill -x freshclam 2>/dev/null || true")
    admin_cmds.append("pkill -x clamonacc 2>/dev/null || true")
    admin_cmds.append("pkill -x clamd 2>/dev/null || true")
    # Brief sleep to let the ES framework process daemon-death notifications
    # before we tear down the launchd plists they're bound to.
    admin_cmds.append("sleep 0.2")

    # Collect admin commands for legacy plist cleanup
    legacy_plists = [
        "/Library/LaunchDaemons/com.resistine.clamonacc.plist",
        "/Library/LaunchDaemons/com.resistine.clamd.plist",
        "/Library/LaunchDaemons/com.resistine.desktop.clamonacc.plist",
        "/Library/LaunchDaemons/com.resistine.desktop.clamd.plist",
        "/Library/LaunchDaemons/com.resistine.desktop.freshclam.plist",
    ]
    for plist in legacy_plists:
        if os.path.exists(plist):
            admin_cmds.append(f"launchctl bootout system '{plist}' 2>/dev/null || true")
            admin_cmds.append(f"rm -f '{plist}'")

    # Bootout by label in case plists are gone but daemons still loaded
    for label in (
        "com.resistine.desktop.freshclam",
        "com.resistine.desktop.clamd",
        "com.resistine.desktop.clamonacc",
        "com.resistine.clamd",
        "com.resistine.clamonacc",
    ):
        admin_cmds.append(
            f"launchctl bootout system/{label} 2>/dev/null || true",
        )

    # Remove system-level ClamAV data (signatures, configs, logs)
    if os.path.exists(_SYSTEM_CLAMAV_DIR):
        admin_cmds.append(f"rm -rf '{_SYSTEM_CLAMAV_DIR}'")


def _collect_wazuh_admin_cmds(admin_cmds):
    """Append every Wazuh-agent teardown command into ``admin_cmds``.

    Previously delegated to ``plugins.wazuh.agent.wazuh_functions_darwin.
    remove_agent()`` which ran its OWN ``osascript with administrator
    privileges`` — that's the second of the user's three password
    prompts. Now we emit the same commands inline so they batch with
    the rest of the privileged cleanup. wipe_keys=True semantics
    (logout-style full identity wipe) is embedded directly: delete
    /Library/Ossec, the launchd plist, the key backup file, and the
    System Keychain entry.
    """
    # Wazuh constants — keep in sync with plugins.wazuh.config /
    # wazuh_functions_darwin. Imported lazily so an environment without
    # the Wazuh plugin (e.g. dev/test) still uninstalls cleanly.
    try:
        from plugins.wazuh.agent.wazuh_functions_darwin import (
            _KEY_BACKUP, _KC_ACCOUNT, _KC_SERVICE, _KEYCHAIN,
            _WAZUH_CONTROL, is_agent_installed, _is_service_loaded,
            _has_keychain_entry,
        )
        from plugins.wazuh.config import (
            WAZUH_INSTALL_DIR, WAZUH_LAUNCHD_PLIST,
        )
        agent_present = (
            is_agent_installed()
            or _is_service_loaded()
            or os.path.exists(_KEY_BACKUP)
            or _has_keychain_entry()
        )
    except ImportError:
        # Fallback paths matching the plugin's defaults.
        _WAZUH_CONTROL = "/Library/Ossec/bin/wazuh-control"
        WAZUH_LAUNCHD_PLIST = "/Library/LaunchDaemons/com.wazuh.agent.plist"
        WAZUH_INSTALL_DIR = "/Library/Ossec"
        _KEY_BACKUP = "/Library/Application Support/Resistine/wazuh_client.keys"
        _KC_SERVICE = "com.resistine.wazuh.client.keys"
        _KC_ACCOUNT = "wazuh-agent"
        _KEYCHAIN = "/Library/Keychains/System.keychain"
        agent_present = (
            os.path.exists(WAZUH_INSTALL_DIR)
            or os.path.exists(WAZUH_LAUNCHD_PLIST)
            or os.path.exists(_KEY_BACKUP)
        )

    if not agent_present:
        logger.info("[UNINSTALL] Wazuh agent not installed, skipping")
        return

    # Shell-quote keychain account/service to defend against any future
    # rename containing a quote.
    def _sq(s: str) -> str:
        return s.replace("'", "'\\''")

    # DO NOT pkill -9 the wazuh-* processes. Empirically that triggered
    # a SIGKILL cascade onto the privileged shell — most likely Wazuh's
    # anti-tampering or a sibling daemon (wazuh-execd / wazuh-modulesd
    # / wazuh-syscheckd) reacting to wazuh-agentd's forced death by
    # killing the killer's parent process. Symptom: `exit code -9`
    # surfacing at the first command AFTER the pkill (a no-op `sleep`),
    # which is when the retaliatory SIGKILL lands on our osascript-
    # spawned shell.
    #
    # Graceful shutdown sequence instead:
    #   1. `wazuh-control stop` — Wazuh's own teardown, which disables
    #      its protection hooks BEFORE the daemons exit.
    #   2. `launchctl disable system/<plist>` — tell launchd not to
    #      respawn the daemon and not to monitor it (KeepAlive=true
    #      otherwise re-launches agentd while we're trying to remove
    #      its files).
    #   3. 1s sleep — give the graceful shutdown time to actually
    #      flush ES subscriptions, close sockets, deregister with
    #      launchd. 200 ms was empirically too short.
    #   4. `launchctl bootout` — now the daemon is already supposed
    #      to be gone; bootout is a no-op for any live ES subscription
    #      and the kernel ES framework has nothing to cascade.
    #
    # If wazuh-control stop fails (binary missing, ossec dir corrupted,
    # etc.) we still proceed to bootout + rm — the worst case is leftover
    # files we'll clean on the next launchctl call. We do NOT attempt a
    # forceful kill anymore; the anti-tamper response is worse than
    # leaving a defunct process around for 30 s while launchd reaps it.
    admin_cmds.append(
        f"'{_sq(_WAZUH_CONTROL)}' stop 2>/dev/null || true")
    # Extract the bare label from the plist path so launchctl disable
    # accepts the system/<label> form. WAZUH_LAUNCHD_PLIST is the
    # /Library/LaunchDaemons/<label>.plist path; the label is the
    # basename minus .plist. Hardcode the fallback to match the
    # `com.wazuh.agent` ImportError default earlier in this function.
    _wazuh_label = (
        os.path.basename(WAZUH_LAUNCHD_PLIST).removesuffix(".plist")
        or "com.wazuh.agent"
    )
    admin_cmds.append(
        f"launchctl disable system/{_sq(_wazuh_label)} 2>/dev/null || true")
    # Give wazuh-control stop time to actually complete its teardown +
    # let launchd process the disable. 1 s is the empirical minimum
    # observed to consistently avoid retaliation.
    admin_cmds.append("sleep 1")
    admin_cmds.append(
        f"launchctl bootout system '{_sq(WAZUH_LAUNCHD_PLIST)}' 2>/dev/null || true")
    # Identity wipe — same semantics as remove_agent(wipe_keys=True).
    admin_cmds.append(f"rm -f '{_sq(_KEY_BACKUP)}'")
    admin_cmds.append(
        f"security delete-generic-password -s '{_sq(_KC_SERVICE)}' "
        f"-a '{_sq(_KC_ACCOUNT)}' '{_sq(_KEYCHAIN)}' 2>/dev/null || true")
    admin_cmds.append(f"rm -rf '{_sq(WAZUH_INSTALL_DIR)}'")
    admin_cmds.append(f"rm -f '{_sq(WAZUH_LAUNCHD_PLIST)}'")


def _stop_vpn_tunnel():
    """Stop the VPN tunnel via the CLI tool."""
    cli_path = _find_cli_path()
    if not cli_path:
        logger.info("[UNINSTALL] CLI not found, skipping VPN stop")
        return

    result = subprocess.run(
        [cli_path, "stop"],
        capture_output=True,
        text=True,
        timeout=10,
    )
    if result.returncode == 0:
        logger.info("[UNINSTALL] VPN tunnel stopped")
    else:
        logger.warning(
            f"[UNINSTALL] VPN stop returned non-zero "
            f"(may already be stopped): {result.stderr.strip()}"
        )


_DEACTIVATOR_CLASS = None
_DEACTIVATION_STATE = {"done_event": None, "error": None}


def _get_deactivator_class():
    """Cache the ``_Deactivator`` NSObject subclass at module level.

    PyObjC registers a Python class as an Objective-C class the first
    time it's defined. Re-running the class definition (e.g. on a
    second uninstall click) logs the warning the user saw —
    "_Deactivator is overriding existing Objective-C class". That
    message was being treated as an error by the uninstall flow, so
    a click that otherwise succeeded showed up red. Define the class
    ONCE, lazily, and reuse the cached reference forever after.
    """
    global _DEACTIVATOR_CLASS
    if _DEACTIVATOR_CLASS is not None:
        return _DEACTIVATOR_CLASS
    from Foundation import NSObject

    class _Deactivator(NSObject):
        # Talks to module-level _DEACTIVATION_STATE rather than capturing
        # closures over per-call locals — locals from the first call
        # would otherwise persist for every subsequent invocation.
        def request_didFinishWithResult_(self, request, result):
            logger.info(
                f"[UNINSTALL] Extension deactivation finished: {result}")
            ev = _DEACTIVATION_STATE.get("done_event")
            if ev is not None:
                ev.set()

        def request_didFailWithError_(self, request, error):
            msg = error.localizedDescription()
            logger.error(f"[UNINSTALL] Extension deactivation failed: {msg}")
            _DEACTIVATION_STATE["error"] = msg
            ev = _DEACTIVATION_STATE.get("done_event")
            if ev is not None:
                ev.set()

        def requestNeedsUserApproval_(self, request):
            logger.info(
                "[UNINSTALL] Extension deactivation needs user approval")

        def request_actionForReplacingExtension_withExtension_(
            self, request, existing, extension
        ):
            return 1  # Replace

    _DEACTIVATOR_CLASS = _Deactivator
    return _Deactivator


def _deactivate_system_extension():
    """Deactivate the network extension via SystemExtensions framework.

    Blocks up to 15 seconds for the delegate callback, so the uninstall
    doesn't remove the app bundle while deactivation is still in flight.

    If the extension isn't installed (because the app was never run, or
    a prior uninstall already removed it), the OSSystemExtensionManager
    returns a "no such extension" error which we treat as success — the
    end state matches the goal.
    """
    try:
        from Foundation import NSOperationQueue
        from SystemExtensions import (
            OSSystemExtensionManager,
            OSSystemExtensionRequest,
        )
    except ImportError:
        logger.info("[UNINSTALL] SystemExtensions not available (dev mode)")
        return

    import threading
    done_event = threading.Event()
    _DEACTIVATION_STATE["done_event"] = done_event
    _DEACTIVATION_STATE["error"] = None
    _Deactivator = _get_deactivator_class()

    try:
        deactivator = _Deactivator.alloc().init()
        queue = NSOperationQueue.mainQueue().underlyingQueue()
        request = (
            OSSystemExtensionRequest.deactivationRequestForExtension_queue_(
                _EXTENSION_BUNDLE_ID, queue
            )
        )
        request.setDelegate_(deactivator)
        OSSystemExtensionManager.sharedManager().submitRequest_(request)

        # Store reference to prevent GC
        _deactivate_system_extension._ref = deactivator
        logger.info("[UNINSTALL] Extension deactivation request submitted")

        if not done_event.wait(timeout=15):
            logger.warning(
                "[UNINSTALL] Extension deactivation timed out after 15s "
                "— continuing anyway"
            )
            return
        err = _DEACTIVATION_STATE.get("error")
        if err:
            # "no extension installed" is the desired end state, not
            # an error — happens when the user clicks Uninstall a
            # second time after the first one already deactivated.
            low = err.lower()
            if any(s in low for s in (
                "no such extension",
                "not found",
                "no installed",
                "is not installed",
            )):
                logger.info(
                    "[UNINSTALL] Extension already deactivated, treating as success")
                return
            raise OSError(f"Extension deactivation failed: {err}")
    except OSError:
        raise
    except Exception as e:
        raise OSError(f"Extension deactivation error: {e}") from e


def _remove_wireguard_configs():
    """Remove WireGuard configuration files.

    macOS SIP protects the Group Container directory itself — even admin
    ``rm -rf`` cannot delete it.  We remove the *contents* instead and
    tolerate the empty directory remaining (the OS cleans it up when the
    app is fully removed).
    """
    wg_dir = os.path.expanduser(
        "~/Library/Group Containers/group.Resistine.WireguardTest"
    )
    if not os.path.exists(wg_dir):
        logger.info("[UNINSTALL] WireGuard config dir not found, skipping")
        return

    # Remove contents, not the container directory itself
    try:
        entries = os.listdir(wg_dir)
    except PermissionError:
        logger.info(
            f"[UNINSTALL] Cannot access {wg_dir} (SIP-protected) — "
            f"macOS will clean it up when the app is removed"
        )
        return
    if not entries:
        logger.info("[UNINSTALL] WireGuard config dir already empty")
        return

    removed = 0
    failed = []
    for entry in entries:
        entry_path = os.path.join(wg_dir, entry)
        try:
            if os.path.isdir(entry_path):
                shutil.rmtree(entry_path)
            else:
                os.remove(entry_path)
            removed += 1
        except OSError as e:
            logger.warning(f"[UNINSTALL] Could not remove {entry_path}: {e}")
            failed.append(entry_path)

    # Try to remove the now-empty directory (may fail due to SIP — that's OK)
    try:
        os.rmdir(wg_dir)
        logger.info(f"[UNINSTALL] Removed {wg_dir} ({removed} item(s))")
    except OSError:
        logger.info(
            f"[UNINSTALL] Cleared {removed} item(s) from {wg_dir} "
            f"(directory kept by macOS)"
        )

    if failed and removed == 0:
        raise OSError(
            f"Failed to remove any WireGuard config files "
            f"({len(failed)} failures)"
        )


def _remove_app_config(admin_cmds):
    """Remove application configuration directories (user + system level)."""
    home = os.path.expanduser("~")

    # User-level config (no admin needed)
    config_dir = os.path.join(home, "Library", "Application Support", "Resistine")
    if os.path.exists(config_dir):
        shutil.rmtree(config_dir)
        logger.info(f"[UNINSTALL] Removed {config_dir}")
    else:
        logger.info("[UNINSTALL] User config dir not found, skipping")

    # Stale log files — the network extension wrote these as root; old entries
    # persist across builds and cause diagnostic confusion.  Must use admin
    # because the files are root-owned.
    for log_name in ("resistine.log", "resistine-error.log"):
        log_path = os.path.join(home, "Library", "Logs", log_name)
        if os.path.exists(log_path):
            escaped = log_path.replace("'", "'\\''")
            admin_cmds.append(f"rm -f '{escaped}'")

    # Sandbox containers — macOS creates these for sandboxed app bundles.
    # The OS may recreate them, but clearing stale data prevents confusion.
    containers_dir = os.path.join(home, "Library", "Containers")
    if os.path.isdir(containers_dir):
        for entry in os.listdir(containers_dir):
            if entry.startswith("com.resistine"):
                container_path = os.path.join(containers_dir, entry)
                try:
                    shutil.rmtree(container_path)
                    logger.info(f"[UNINSTALL] Removed container {container_path}")
                except OSError as e:
                    logger.warning(
                        f"[UNINSTALL] Could not remove {container_path}: {e}"
                    )

    # System-level directory — batch with other admin commands
    sys_dir = "/Library/Application Support/Resistine"
    if os.path.exists(sys_dir):
        admin_cmds.append(f"rm -rf '{sys_dir}'")


def _remove_keychain_items():
    """Remove keychain entries created by Resistine."""
    try:
        import keyring
    except ImportError:
        logger.info("[UNINSTALL] keyring not available, skipping")
        return

    entries = [
        ("resistine-master-key", "master-key"),
    ]

    failed = []
    for service, username in entries:
        try:
            keyring.delete_password(service, username)
            logger.info(f"[UNINSTALL] Removed keychain: {service}/{username}")
        except keyring.errors.PasswordDeleteError:
            logger.info(f"[UNINSTALL] Keychain entry not found: {service}/{username}")
        except Exception as e:
            logger.error(f"[UNINSTALL] Keychain removal failed: {service}: {e}")
            failed.append(f"{service}: {e}")

    if failed:
        raise OSError(
            f"Keychain removal failed: {'; '.join(failed)}"
        )


def _collect_app_bundle_admin_cmd(admin_cmds):
    """Append the ``rm -rf /Applications/Resistine.app`` command into
    ``admin_cmds`` so it runs in the SAME osascript prompt as everything
    else. Previously the bundle removal had its own prompt — the third
    of the user's three password requests.

    macOS allows deleting files that are in use — the kernel keeps the
    data until the last file descriptor closes — so the running process
    can issue its own deletion and remain alive long enough to display
    the success message and exit cleanly.

    Returns silently when there's nothing to remove (dev mode / source
    run / already gone).
    """
    if not getattr(sys, "frozen", False):
        logger.info("[UNINSTALL] Not a frozen app, skipping bundle removal")
        return

    # sys.executable → .../Resistine.app/Contents/MacOS/Resistine
    from pathlib import Path
    app_bundle = str(Path(sys.executable).parents[2])

    if not app_bundle.endswith(".app"):
        logger.warning(f"[UNINSTALL] Unexpected bundle path: {app_bundle}")
        return

    if not os.path.exists(app_bundle):
        logger.info("[UNINSTALL] App bundle not found, skipping")
        return

    escaped = app_bundle.replace("'", "'\\''")
    admin_cmds.append(f"rm -rf '{escaped}'")


def _find_cli_path():
    """Find the resistine-vpn-cli binary."""
    if not getattr(sys, "frozen", False):
        return None

    macos_dir = os.path.dirname(sys.executable)
    cli_path = os.path.join(macos_dir, "resistine-vpn-cli")
    if os.path.exists(cli_path):
        return cli_path
    return None
