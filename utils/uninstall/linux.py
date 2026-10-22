"""
Linux Uninstaller Backend.

Removes Phoenix's runtime footprint on Linux.  Every privileged operation
(VPN teardown, Wazuh agent removal, ClamAV deactivation) is collected into a
SINGLE shell script and run through ONE privilege-escalation prompt, mirroring
the macOS uninstaller.  Earlier revisions escalated once per component, which
prompted the user for their password up to four times.

Phases:
  1. Collect privileged commands from each plugin's tested script builders
     (guarded so an un-configured component contributes nothing).
  2. Run them all in one pkexec/sudo prompt.
  3. Non-privileged cleanup (no prompt): keyring master key + config dir
     (~/.config/phoenix, and the pre-rebrand ~/.config/resistine — settings, secrets, VPN keys, Wazuh key backup).

Running from source (run.sh) there is no installed binary or .desktop entry to
remove.  A packaged build should extend phase 1/3 with artifact removal.

Author: Resistine Team
Copyright (c) Resistine 2025
Licensed under the GNU General Public License v2 or later
"""

import os
import shutil

from utils.logger import logger


def is_available():
    """Uninstall is supported on Linux."""
    return True


def run_uninstall(app, progress_callback=None):
    """Execute the full Linux uninstall sequence in a single password prompt.

    Returns (success, message).  Individual step failures are collected and
    reported rather than aborting the whole teardown.
    """

    def _progress(msg):
        logger.info(f"[UNINSTALL-LINUX] {msg}")
        if progress_callback:
            try:
                progress_callback(msg)
            except Exception as e:
                logger.debug(f"[UNINSTALL-LINUX] Progress callback failed: {e}")

    errors = []
    admin_cmds = []  # privileged shell commands, run in ONE prompt

    # -- Phase 1: collect privileged commands (no execution yet) -------------
    for message, label, collector in (
        ("Preparing VPN teardown...",        "VPN",        _collect_vpn_cmds),
        ("Preparing SIEM agent removal...",  "SIEM agent", _collect_wazuh_cmds),
        ("Preparing antivirus teardown...",  "Antivirus",  _collect_clamav_cmds),
    ):
        _progress(message)
        try:
            collector(admin_cmds)
        except Exception as e:
            logger.error(f"[UNINSTALL-LINUX] Failed — {label} prep: {e}")
            errors.append(f"{label} prep: {e}")

    # -- Phase 2: run every privileged command in ONE prompt -----------------
    if admin_cmds:
        _progress("Authenticating for system cleanup...")
        try:
            _run_privileged_batch(admin_cmds)
        except _UserCancelled:
            return (False, "Uninstall cancelled at password prompt.")
        except Exception as e:
            logger.error(f"[UNINSTALL-LINUX] Failed — Privileged cleanup: {e}")
            errors.append(f"Privileged cleanup: {e}")

    # -- Phase 3: non-privileged cleanup (no prompt) -------------------------
    for message, label, func in (
        ("Removing stored secrets...",   "Secrets",  _remove_keyring_master_key),
        ("Removing application data...", "App data", _remove_app_config),
    ):
        _progress(message)
        try:
            func()
        except Exception as e:
            logger.error(f"[UNINSTALL-LINUX] Failed — {label}: {e}")
            errors.append(f"{label}: {e}")

    if errors:
        return (False, f"Completed with errors: {'; '.join(errors)}")
    return (True, "Phoenix has been uninstalled successfully.")


class _UserCancelled(Exception):
    """User clicked Cancel on the privilege-escalation prompt."""
    pass


# ---------------------------------------------------------------------------
# Privileged command runner
# ---------------------------------------------------------------------------


def _run_privileged_batch(admin_cmds):
    """Run all collected privileged commands in a single escalation.

    Reuses the shared Linux privilege helper (pkexec, then a themed sudo
    dialog).  Every command already carries its own ``|| true`` guard so one
    failing step can't abort the rest.
    """
    from plugins.wazuh.agent.wazuh_functions_linux import run_privileged_command

    script = "\n".join(admin_cmds)
    success, output = run_privileged_command(["sh", "-c", script], timeout=600)
    if success:
        logger.info("[UNINSTALL-LINUX] Privileged cleanup completed")
        return
    if output and "User cancelled" in output:
        raise _UserCancelled()
    raise OSError(output or "Privileged cleanup failed")


# ---------------------------------------------------------------------------
# Phase 1 collectors — append privileged shell commands, no execution
# ---------------------------------------------------------------------------


def _collect_vpn_cmds(admin_cmds):
    """Append WireGuard teardown commands for each stored config."""
    try:
        from utils.settings import get_config_dir
    except ImportError:
        return

    wg_dir = os.path.join(get_config_dir(), "wireguard")
    if not os.path.isdir(wg_dir):
        logger.info("[UNINSTALL-LINUX] No WireGuard config dir, skipping VPN")
        return

    confs = [fn for fn in os.listdir(wg_dir) if fn.endswith(".conf")]
    if not confs:
        logger.info("[UNINSTALL-LINUX] No WireGuard configs, skipping VPN")
        return

    for fn in confs:
        iface = os.path.splitext(fn)[0].replace("'", "")
        # Match stop_vpn: bring the interface down by name (AppArmor-friendly)
        # then remove the /etc/wireguard copy wg-quick reads.
        admin_cmds.append(f"wg-quick down '{iface}' 2>/dev/null || true")
        admin_cmds.append(f"rm -f '/etc/wireguard/{iface}.conf'")


def _collect_wazuh_cmds(admin_cmds):
    """Append the Wazuh agent teardown script (full identity wipe)."""
    try:
        from plugins.wazuh.agent import wazuh_functions_linux as wazuh
    except ImportError:
        logger.info("[UNINSTALL-LINUX] Wazuh plugin not present, skipping")
        return

    if not wazuh.agent_present(wipe_keys=True):
        logger.info("[UNINSTALL-LINUX] Wazuh agent not present, skipping")
        return

    admin_cmds.append(wazuh.build_remove_script(wipe_keys=True))


def _collect_clamav_cmds(admin_cmds):
    """Append ClamAV daemon deactivation, guarded on an active service."""
    try:
        from plugins.antivirus import clamav_platform_linux as clamav
    except ImportError:
        logger.info("[UNINSTALL-LINUX] Antivirus plugin not present, skipping")
        return

    if not clamav.is_any_service_active():
        logger.info("[UNINSTALL-LINUX] No active ClamAV services, skipping")
        return

    script = clamav.build_deactivate_script()
    if script:
        admin_cmds.append(script)


# ---------------------------------------------------------------------------
# Phase 3 helpers — non-privileged cleanup
# ---------------------------------------------------------------------------


def _remove_keyring_master_key():
    """Delete the encryption master key from the system keyring."""
    try:
        import keyring
    except ImportError:
        logger.info("[UNINSTALL-LINUX] keyring not available, skipping")
        return

    from utils.settings import (LEGACY_MASTER_KEY_SERVICE, MASTER_KEY_SERVICE,
                                MASTER_KEY_USERNAME)

    from utils.encryption import KEYRING_SERVICE, LEGACY_KEYRING_SERVICE

    entries = [(service, MASTER_KEY_USERNAME)
               for service in (MASTER_KEY_SERVICE, LEGACY_MASTER_KEY_SERVICE)]
    entries += [(service, name)
                for service in (KEYRING_SERVICE, LEGACY_KEYRING_SERVICE)
                for name in ("encryption_key", "encrypted_data")]
    for service, username in entries:
        try:
            keyring.delete_password(service, username)
            logger.info(f"[UNINSTALL-LINUX] Removed keyring entry {service}/{username}")
        except keyring.errors.PasswordDeleteError:
            logger.info(f"[UNINSTALL-LINUX] Keyring entry {service}/{username} not found")


def _remove_app_config():
    """Remove the user config directory (settings, secrets, VPN/Wazuh keys)."""
    from utils.settings import get_config_dir, get_legacy_config_dir

    for config_dir in (get_config_dir(), get_legacy_config_dir()):
        if os.path.exists(config_dir):
            shutil.rmtree(config_dir, ignore_errors=True)
            logger.info(f"[UNINSTALL-LINUX] Removed {config_dir}")
        else:
            logger.info(f"[UNINSTALL-LINUX] Config dir {config_dir} not found, skipping")
