# -*- coding: utf-8 -*-
# @file plugins/login/setup_steps.py
# Description: Platform glue for the post-login customer setup wizard.
#
# Each SetupStep wraps one capability (VPN, Antivirus, Full Disk Access,
# Endpoint agent) behind a uniform interface the wizard drives without knowing
# any plugin internals:
#
#   is_applicable()  -> should this step appear on this system at all?
#   is_complete()    -> is the capability already set up / permissioned?
#   begin(on_status) -> kick off the work (activation, install, open Settings);
#                       long/blocking work runs on a background thread and
#                       reports progress through on_status(text).
#   check_failed()   -> a user-facing error string if the last attempt failed,
#                       else None (lets the wizard offer "Try Again").
#
# The wizard calls begin() once (when the user clicks the step's primary
# button), then polls is_complete()/check_failed() every couple seconds and
# auto-advances when the capability reports ready. All UI-thread marshalling is
# done by the wizard — steps just call on_status() from wherever they run.
#
# Author: Resistine Team
# Copyright: Resistine (c) 2025
# Licensed under the GNU General Public License v2 or later

import platform
import threading
import webbrowser

from utils.logger import logger

_PLATFORM = platform.system()


class SetupStep:
    """Base class — a single guided setup step. Subclasses override the hooks."""

    key = ""
    icon = "🛡️"
    title = ""
    subtitle = ""          # one-line summary for the welcome checklist
    detail = ""            # longer explanation shown while on the step
    instructions = []      # optional numbered guidance (list[str])
    primary_label = "Enable"
    working_label = "Working…"

    def __init__(self, app):
        self.app = app
        self._failed = None  # user-facing error string, or None
        self._logged_failure = False  # dedupe one-time failure logging
        self._activated = False  # set once the step's service is running
        self._cancel = threading.Event()  # set when the wizard leaves this step

    def cancelled(self) -> bool:
        return self._cancel.is_set()

    # ── Hooks ───────────────────────────────────────────────────────
    def is_applicable(self) -> bool:
        return True

    def is_complete(self) -> bool:
        return False

    def begin(self, on_status):
        """Start the step. on_status(text) reports progress (thread-safe)."""

    def check_failed(self):
        """Return a user-facing failure message, or None if not failed."""
        return self._failed

    # ── Helpers ─────────────────────────────────────────────────────
    def _run_bg(self, fn):
        """Run fn() on a daemon thread, capturing exceptions to _failed."""
        def _worker():
            try:
                fn()
            except Exception as e:  # noqa: BLE001 — surface, never crash the UI
                logger.error(f"[SETUP] Step '{self.key}' failed: {e}")
                self._failed = "Something went wrong. You can try again or skip."
        threading.Thread(target=_worker, daemon=True).start()


# ════════════════════════════════════════════════════════════════════
# VPN — module helpers (import lazily; keep the slow status check off the
# UI thread by only calling it inside worker threads).
# ════════════════════════════════════════════════════════════════════

def _vpn_config():
    """Return (config_name, config_path) for the active tunnel, or (None, None)."""
    try:
        from plugins.vpn.main import _config_manager
        return (_config_manager.get_active_config_name(),
                _config_manager.get_active_config_path())
    except Exception as e:  # noqa: BLE001
        logger.warning(f"[VPN-SETUP] config lookup failed: {e}")
        return None, None


def _vpn_status(name):
    """Return "Running"/"Stopped" for the tunnel. Blocking — worker thread only."""
    try:
        if _PLATFORM == "Windows":
            from plugins.vpn.wireguard.vpn_windows_client import get_status
            return get_status(name).get("state", "Stopped")
        if _PLATFORM == "Linux":
            from plugins.vpn.wireguard.vpn_functions_linux import check_service_status
            return check_service_status(name, None)
        from plugins.vpn.wireguard.vpn_functions_darwin import check_service_status
        return check_service_status(name)
    except Exception as e:  # noqa: BLE001
        logger.warning(f"[VPN-SETUP] status check failed: {e}")
        return "Stopped"


def _vpn_connect(name, path):
    """Start/connect the tunnel. Blocking — worker thread only."""
    if _PLATFORM == "Windows":
        from plugins.vpn.wireguard.vpn_windows_client import connect
        return connect(name, config_path=path)
    if _PLATFORM == "Linux":
        from plugins.vpn.wireguard.vpn_functions_linux import start_vpn
        return start_vpn(path)
    from plugins.vpn.wireguard.vpn_functions_darwin import start_vpn
    return start_vpn(path)


def _vpn_mark_connected(name):
    """Sync the VPN plugin's in-memory state so the app's toggle/dashboard
    show the tunnel as ON. The wizard connects the tunnel directly (not through
    the plugin's toggle), so the plugin's module globals — read when the VPN
    screen builds — would otherwise still say "Stopped" until a later poll.
    """
    try:
        import plugins.vpn.main as vpnmain
        vpnmain.my_vpn_status = "Running"
        if name:
            vpnmain.active_client_name = name
        logger.info("[VPN-SETUP] synced plugin toggle state -> Running")
    except Exception as e:  # noqa: BLE001
        logger.warning(f"[VPN-SETUP] could not sync plugin toggle state: {e}")


# ════════════════════════════════════════════════════════════════════
# VPN — steps
# ════════════════════════════════════════════════════════════════════

class _VPNStepBase(SetupStep):
    """Shared VPN step: ensure permission/install, then connect the tunnel.

    Completion means the tunnel is actually up (self._activated), not merely
    that the extension/WireGuard is present — the flow must leave the VPN
    running, not just set up.
    """

    key = "vpn"
    icon = "🔒"

    def is_complete(self) -> bool:
        # Fast checks only (called on the UI thread). _perm_ready() is a quick,
        # cached probe; _activated is a bool set by the worker once the tunnel
        # is confirmed up. The slow status check stays in the worker.
        try:
            return self._perm_ready() and self._activated
        except Exception:  # noqa: BLE001
            return False

    # Subclasses implement these.
    def _perm_ready(self) -> bool:
        raise NotImplementedError

    def _ensure_permission(self, on_status) -> bool:
        """Bring the platform prerequisite (extension/WireGuard) online.
        Return True when ready; set self._failed and return False otherwise."""
        raise NotImplementedError

    def begin(self, on_status):
        self._failed = None

        def _work():
            if not self._ensure_permission(on_status):
                return  # _failed already set
            name, path = _vpn_config()
            if not path:
                # Phoenix sign-in: get this device's config from the API.
                from plugins.vpn import provisioning
                try:
                    name, path = provisioning.ensure_vpn_config(on_status)
                except provisioning.ProvisioningError as e:
                    self._failed = str(e)
                    logger.error(f"[VPN-SETUP] provisioning failed: {e}")
                    return
            if _vpn_status(name) == "Running":
                logger.info("[VPN-SETUP] tunnel already up")
                self._activated = True
                _vpn_mark_connected(name)
                return
            logger.info(f"[VPN-SETUP] connecting tunnel '{name}'")
            on_status("Connecting to VPN…")
            _vpn_connect(name, path)
            import time
            deadline = time.time() + 40
            while time.time() < deadline:
                if self.cancelled():
                    return
                st = _vpn_status(name)
                if st == "Running":
                    logger.info("[VPN-SETUP] connected")
                    self._activated = True
                    _vpn_mark_connected(name)
                    return
                time.sleep(2)
            logger.error(f"[VPN-SETUP] connect timed out (status={_vpn_status(name)})")
            self._failed = "VPN didn't connect. You can try again or skip."

        self._run_bg(_work)


class _VPNStepMac(_VPNStepBase):
    title = "Enable & Connect VPN"
    subtitle = "Secure your connection with a private tunnel"
    detail = (
        "Phoenix installs a system network extension, then connects you to a "
        "secure VPN. Approving the extension is a one-time step in System "
        "Settings."
    )
    primary_label = "Enable VPN"
    working_label = "Setting up VPN…"

    def __init__(self, app):
        super().__init__(app)
        self.instructions = self._mac_instructions()

    def _perm_ready(self) -> bool:
        from plugins.vpn.wireguard.vpn_functions_darwin import is_extension_enabled
        return bool(is_extension_enabled())

    def _ensure_permission(self, on_status) -> bool:
        import time

        from plugins.vpn.wireguard.vpn_functions_darwin import (
            VPNHelper,
            is_extension_enabled,
            vpn_unavailable_reason,
        )
        reason = vpn_unavailable_reason()
        if reason:
            logger.warning(f"[VPN-SETUP] {reason}")
            self._failed = reason
            return False
        if is_extension_enabled():
            return True
        logger.info("[VPN-SETUP] requesting extension activation")
        try:
            sent = VPNHelper.activate_extension()
        except Exception as e:  # noqa: BLE001
            logger.warning(f"[VPN-SETUP] activate_extension failed: {e}")
            sent = False
        if not sent:
            self._failed = "Couldn't ask macOS to enable the VPN extension. You can try again or skip."
            return False

        def refused() -> bool:
            err = VPNHelper.activation_error()
            if err:
                logger.error(f"[VPN-SETUP] macOS refused the extension: {err}")
                self._failed = f"macOS refused the Phoenix VPN extension: {err}"
            return bool(err)

        # A refusal (unsigned build, missing entitlement) comes back within
        # moments; don't send the user to System Settings for nothing.
        for _ in range(8):
            if refused():
                return False
            if is_extension_enabled():
                return True
            time.sleep(0.5)
        self._open_settings()
        on_status("Approve the Phoenix extension in System Settings — this "
                  "continues automatically once enabled.")
        deadline = time.time() + 300
        while time.time() < deadline:
            if self.cancelled() or refused():
                return False
            if is_extension_enabled():
                logger.info("[VPN-SETUP] extension approved")
                return True
            time.sleep(2)
        logger.error("[VPN-SETUP] extension approval timed out")
        self._failed = ("VPN extension wasn't approved. You can try again or skip.")
        return False

    def _open_settings(self):
        import subprocess
        try:
            subprocess.Popen([
                "open",
                "x-apple.systempreferences:com.apple.LoginItems-Settings.extension",
            ])
        except Exception as e:  # noqa: BLE001
            logger.error(f"[VPN-SETUP] Failed to open System Settings: {e}")

    @staticmethod
    def _mac_instructions():
        try:
            major = int(platform.mac_ver()[0].split(".")[0] or "0")
        except ValueError:
            major = 0
        if major >= 15:
            where = "Open General ▸ Login Items & Extensions ▸ Network Extensions"
        else:
            where = "Open Privacy & Security and scroll to Security"
        return [
            "A macOS dialog appears — click “Open System Settings”.",
            where,
            "Enable the Phoenix extension and click Allow.",
        ]


class _VPNStepWindows(_VPNStepBase):
    title = "Set Up & Connect VPN"
    subtitle = "Install WireGuard to secure your connection"
    detail = (
        "Phoenix's VPN is powered by WireGuard. Install it once and Phoenix "
        "connects and manages the secure tunnel for you."
    )
    instructions = [
        "Click “Download WireGuard” to open the installer page.",
        "Run the WireGuard installer and accept the prompts.",
        "This step continues and connects automatically once installed.",
    ]
    primary_label = "Download WireGuard"
    working_label = "Setting up VPN…"

    def _perm_ready(self) -> bool:
        from plugins.vpn.wireguard.vpn_functions_windows import check_wireguard_installed
        return bool(check_wireguard_installed())

    def _ensure_permission(self, on_status) -> bool:
        from plugins.vpn.wireguard.vpn_functions_windows import check_wireguard_installed
        if check_wireguard_installed():
            return True
        webbrowser.open("https://www.wireguard.com/install/")
        on_status("Install WireGuard — this continues automatically once done.")
        import time
        deadline = time.time() + 300
        while time.time() < deadline:
            if self.cancelled():
                return False
            if check_wireguard_installed():
                return True
            time.sleep(3)
        self._failed = "WireGuard wasn't installed. You can try again or skip."
        return False


class _VPNStepLinux(_VPNStepBase):
    title = "Set Up & Connect VPN"
    subtitle = "Install WireGuard to secure your connection"
    detail = (
        "Phoenix's VPN is powered by WireGuard. We'll install the tools and "
        "connect you — you may be asked for your password."
    )
    primary_label = "Set Up VPN"
    working_label = "Setting up VPN…"

    def _perm_ready(self) -> bool:
        from plugins.vpn.wireguard.vpn_functions_linux import check_wireguard_installed
        return bool(check_wireguard_installed())

    def _ensure_permission(self, on_status) -> bool:
        from plugins.vpn.wireguard.vpn_functions_linux import (
            check_wireguard_installed,
            run_installer_as_admin,
        )
        if check_wireguard_installed():
            return True
        on_status("Installing WireGuard — you may be prompted for your password…")
        run_installer_as_admin("")
        if check_wireguard_installed():
            return True
        self._failed = "WireGuard didn't install. You can try again or skip."
        return False


# ════════════════════════════════════════════════════════════════════
# Antivirus
# ════════════════════════════════════════════════════════════════════

class _AntivirusStepMac(SetupStep):
    key = "antivirus"
    icon = "🛡️"
    title = "Turn On Antivirus"
    subtitle = "Real-time malware scanning with ClamAV"
    detail = (
        "Phoenix downloads virus definitions and installs the ClamAV scanning "
        "service. You'll be asked once for your administrator password, then to "
        "approve it in System Settings — first in Login Items & Extensions, then "
        "Full Disk Access."
    )
    instructions = [
        "Click “Enable Antivirus” and enter your administrator password.",
        "Enable all the ClamAV items under Login Items & Extensions.",
        "Then grant Phoenix Full Disk Access when prompted — protection turns "
        "on automatically.",
    ]
    primary_label = "Enable Antivirus"
    working_label = "Setting up antivirus…"

    def is_complete(self) -> bool:
        # STATE_COMPLETED means the admin install ran — but on macOS 13+ the
        # daemons still sit in "Approval Required" until enabled in Login Items,
        # and real-time monitoring (clamonacc) needs Full Disk Access. This step
        # now walks BOTH approvals, so it's only done once neither is
        # outstanding: runtime is past approval_required AND fda_required
        # (healthy = full real-time; degraded = clamd up, FDA already granted).
        from plugins.antivirus.installer_service import (
            STATE_COMPLETED,
            get_runtime_state,
            get_setup_state,
        )
        if get_setup_state() != STATE_COMPLETED:
            return False
        return get_runtime_state() in ("healthy", "degraded")

    def check_failed(self):
        if self._failed:
            return self._failed
        from plugins.antivirus.installer_service import (
            STATE_INSTALL_FAILED,
            STATE_SEED_FAILED,
            get_setup_state,
        )
        if get_setup_state() in (STATE_SEED_FAILED, STATE_INSTALL_FAILED):
            return self._fail_msg("Antivirus setup didn't finish.")
        return None

    def _fail_msg(self, prefix):
        """Build a user-facing failure message that includes the installer's
        recorded reason, and log the full reason+detail once for diagnosis."""
        from plugins.antivirus.installer_service import (
            get_failure_detail,
            get_failure_reason,
            get_setup_state,
        )
        reason = get_failure_reason() or "unknown"
        detail = get_failure_detail() or ""
        if not self._logged_failure:
            self._logged_failure = True
            logger.error(
                f"[AV-SETUP] FAILED state={get_setup_state()} "
                f"reason={reason} detail={detail!r}"
            )
        return f"{prefix} ({reason}) You can try again or skip."

    def begin(self, on_status):
        import time
        from plugins.antivirus import installer_service as av

        self._logged_failure = False
        state0 = av.get_setup_state()
        logger.info(
            f"[AV-SETUP] begin: setup_state={state0} "
            f"runtime_state={self._safe_runtime()} "
            f"prior_reason={av.get_failure_reason()!r} "
            f"prior_detail={av.get_failure_detail()!r}"
        )

        # A prior failed attempt leaves the state machine parked — reset it so
        # this run starts cleanly.
        if state0 in (av.STATE_SEED_FAILED, av.STATE_INSTALL_FAILED):
            logger.info(f"[AV-SETUP] resetting parked state {state0} via retry()")
            av.retry()
        self._failed = None

        def _work():
            # Self-heal stale state from a previous install. Settings live in
            # ~/Library/Application Support/Phoenix and SURVIVE an app
            # uninstall, so a dev uninstall/reinstall can leave
            # setup_state="completed" while the system files and — critically —
            # the SMAppService "Login Items & Extensions" registration are gone.
            # check_and_advance() resets to not_started when the system install
            # is missing; a genuine "completed" falls through to phase 4, which
            # re-registers the daemons and refreshes the Login Items entry.
            try:
                av.check_and_advance()
            except Exception as e:  # noqa: BLE001
                logger.warning(f"[AV-SETUP] check_and_advance: {e}")
            state = av.get_setup_state()
            logger.info(f"[AV-SETUP] post-heal state={state} "
                        f"runtime={self._safe_runtime()}")

            if state != av.STATE_COMPLETED:
                # Phase 1: virus definitions (seeded at login; wait for it).
                logger.info("[AV-SETUP] phase 1: ensure_db_seed_started()")
                av.ensure_db_seed_started()
                on_status("Downloading virus definitions…")
                deadline = time.time() + 180
                last = None
                while time.time() < deadline:
                    if self.cancelled():
                        return
                    state = av.get_setup_state()
                    if state != last:
                        logger.info(f"[AV-SETUP] phase 1 state -> {state}")
                        last = state
                    if state in (av.STATE_DB_READY, av.STATE_COMPLETED):
                        break
                    if state == av.STATE_SEED_FAILED:
                        self._failed = self._fail_msg("Couldn't download virus definitions.")
                        return
                    time.sleep(2)
                else:
                    logger.error("[AV-SETUP] phase 1 TIMED OUT waiting for DB_READY "
                                 f"(last state={last})")
                    self._failed = "Downloading definitions timed out. You can try again or skip."
                    return

                # Phase 2 + 3: system install (admin prompt), unless a
                # concurrent path already completed it.
                if av.get_setup_state() != av.STATE_COMPLETED:
                    logger.info("[AV-SETUP] phase 2: trigger_system_setup() (admin prompt)")
                    on_status("Approve the administrator prompt to enable protection…")
                    launched = av.trigger_system_setup()
                    logger.info(f"[AV-SETUP] trigger_system_setup() -> {launched}")
                    if not launched:
                        self._failed = self._fail_msg("Antivirus setup couldn't start.")
                        return

                    _STEPS = {
                        "install_files": "Installing ClamAV…",
                        "seed_db": "Preparing definitions…",
                        "register_daemons": "Registering protection service…",
                        "start_daemons": "Starting real-time protection…",
                    }
                    logger.info("[AV-SETUP] phase 3: polling install progress")
                    last_step = None
                    while True:
                        if self.cancelled():
                            return
                        result = av.poll_setup_progress()
                        step = result.get("step", "")
                        if step and step != last_step:
                            logger.info(f"[AV-SETUP] install step -> {step}")
                            last_step = step
                            on_status(_STEPS.get(step, "Setting up antivirus…"))
                        if result.get("finished"):
                            logger.info(f"[AV-SETUP] install finished: {result}")
                            if result.get("success"):
                                logger.info("[AV-SETUP] admin install OK")
                            else:
                                # The postinstall can report failure while the
                                # daemons merely await Login Items approval —
                                # don't hard-fail if that's the real blocker.
                                rt = self._safe_runtime()
                                logger.warning(
                                    f"[AV-SETUP] install poll not success; runtime={rt}")
                                if rt != av.RUNTIME_APPROVAL_REQUIRED:
                                    self._failed = self._fail_msg("Antivirus setup didn't finish.")
                                    return
                            break
                        time.sleep(2)
            else:
                logger.info("[AV-SETUP] system already set up — refreshing "
                            "daemon registration")

            # Phase 4: guide BOTH System Settings approvals in sequence —
            # Login Items & Extensions first (daemon approval), then Full Disk
            # Access (real-time monitoring). A single loop reacts to the runtime
            # state, which naturally advances approval_required → fda_required →
            # healthy as the user grants each one. First (re)register so the
            # Login Items entry exists — this is what a reinstall loses, and a
            # missing registration also reports as approval_required.
            logger.info("[AV-SETUP] phase 4: Login Items + Full Disk Access")
            self._register_daemons()
            opened_login = False
            opened_fda = False
            start = time.time()
            deadline = start + 420  # room for two manual approvals
            while time.time() < deadline:
                if self.cancelled():
                    logger.info("[AV-SETUP] phase 4 cancelled (step left)")
                    return
                rt = self._safe_runtime()
                elapsed = int(time.time() - start)
                if rt in ("healthy", "degraded"):
                    logger.info(f"[AV-SETUP] SUCCESS — protection active (runtime={rt})")
                    return
                if rt == av.RUNTIME_APPROVAL_REQUIRED:
                    if not opened_login:
                        # Re-assert registration right before opening Settings so
                        # the entry is definitely present for the user to enable.
                        self._register_daemons()
                        logger.info("[AV-SETUP] opening Login Items & Extensions")
                        self._open_pane("open_login_items_settings")
                        opened_login = True
                    on_status("Step 1 of 2 — enable all the ClamAV items under "
                              "System Settings ▸ Login Items & Extensions… "
                              f"({elapsed}s)")
                elif rt == av.RUNTIME_FDA_REQUIRED:
                    # Login Items done; now walk Full Disk Access.
                    if not opened_fda:
                        logger.info("[AV-SETUP] opening Full Disk Access")
                        self._open_pane("open_fda_settings")
                        opened_fda = True
                    on_status("Step 2 of 2 — turn on Full Disk Access for Phoenix "
                              "under System Settings ▸ Privacy & Security… "
                              f"({elapsed}s)")
                else:  # offline — actively (re)start the daemons
                    logger.info(f"[AV-SETUP] runtime={rt}; activate_system_daemons()")
                    try:
                        from plugins.antivirus import clamav
                        ok, msg = clamav.activate_system_daemons()
                        logger.info(f"[AV-SETUP] activate_system_daemons -> {ok} ({msg})")
                    except Exception as e:  # noqa: BLE001
                        logger.error(f"[AV-SETUP] activate_system_daemons failed: {e}")
                    on_status(f"Starting real-time protection… ({elapsed}s)")
                time.sleep(2)

            logger.error("[AV-SETUP] phase 4 TIMED OUT (runtime="
                         f"{self._safe_runtime()})")
            self._failed = ("Protection is installed but still waiting on approval "
                            "in System Settings (Login Items & Extensions and Full "
                            "Disk Access). You can finish this from the Antivirus "
                            "page, or skip.")

        self._run_bg(_work)

    @staticmethod
    def _open_pane(func_name):
        """Open a System Settings pane via a clamav facade function by name
        (open_login_items_settings / open_fda_settings)."""
        try:
            from plugins.antivirus import clamav
            getattr(clamav, func_name)()
        except Exception as e:  # noqa: BLE001
            logger.error(f"[AV-SETUP] {func_name} failed: {e}")

    @staticmethod
    def _register_daemons():
        """(Re)register the ClamAV daemons via SMAppService so their Login Items
        entry exists. Idempotent — a no-op when already registered/approved,
        re-creates the entry after an uninstall/reinstall."""
        try:
            from plugins.antivirus import clamav
            clamav.ensure_daemons_registered()
            logger.info("[AV-SETUP] ensure_daemons_registered() done")
        except Exception as e:  # noqa: BLE001
            logger.error(f"[AV-SETUP] ensure_daemons_registered failed: {e}")

    @staticmethod
    def _safe_runtime():
        try:
            from plugins.antivirus.installer_service import get_runtime_state
            return get_runtime_state()
        except Exception as e:  # noqa: BLE001
            return f"<err:{e}>"


class _AntivirusStepDefender(SetupStep):
    """Windows/Linux antivirus via the clamav facade (Defender / ClamAV)."""

    key = "antivirus"
    icon = "🛡️"
    title = "Turn On Antivirus"
    subtitle = "Enable real-time malware protection"
    detail = (
        "Phoenix turns on real-time antivirus protection. You may be asked to "
        "approve an administrator prompt."
    )
    primary_label = "Enable Antivirus"
    working_label = "Turning on protection…"

    def __init__(self, app):
        super().__init__(app)
        if _PLATFORM == "Windows":
            self.detail = (
                "Phoenix enables Microsoft Defender real-time protection. "
                "Approve the Windows prompt to continue."
            )
        else:
            self.detail = (
                "Phoenix installs and starts the ClamAV scanning service. "
                "You may be asked for your password."
            )

    def is_complete(self) -> bool:
        from plugins.antivirus import clamav
        try:
            state = clamav.get_realtime_status().get("runtime_state", "")
        except Exception:  # noqa: BLE001
            return False
        return state in ("healthy", "degraded")

    def begin(self, on_status):
        on_status(self.working_label)

        def _work():
            from plugins.antivirus import clamav
            ok, msg = clamav.activate_system_daemons()
            logger.info(f"[AV-SETUP] activate_system_daemons -> {ok} ({msg})")
            if not ok:
                # Surface the platform's own message so the failure is specific
                # (e.g. "package install failed", "UAC declined") rather than a
                # blank "couldn't turn on antivirus".
                detail = (msg or "").strip()
                if _PLATFORM == "Windows":
                    base = ("Couldn't turn on Microsoft Defender real-time "
                            "protection.")
                else:
                    base = "Couldn't install or start ClamAV."
                self._failed = (f"{base} {detail}".strip()
                                + " You can try again or skip.")
        self._run_bg(_work)


# Full Disk Access is no longer a standalone step — it's walked as the second
# half of the macOS antivirus step (_AntivirusStepMac phase 4), right after the
# Login Items approval, so both System Settings approvals happen back-to-back.


# ════════════════════════════════════════════════════════════════════
# Endpoint / SIEM agent
# ════════════════════════════════════════════════════════════════════

def _wazuh_mod():
    if _PLATFORM == "Darwin":
        from plugins.wazuh.agent import wazuh_functions_darwin as m
    elif _PLATFORM == "Linux":
        from plugins.wazuh.agent import wazuh_functions_linux as m
    elif _PLATFORM == "Windows":
        from plugins.wazuh.agent import wazuh_functions_windows as m
    else:
        return None
    return m


def _wazuh_installed() -> bool:
    try:
        m = _wazuh_mod()
        return bool(m and m.is_agent_installed())
    except Exception:  # noqa: BLE001
        return False


def _wazuh_running() -> bool:
    try:
        m = _wazuh_mod()
        return bool(m and m.get_agent_status() == "Running")
    except Exception:  # noqa: BLE001
        return False


def _wazuh_start() -> bool:
    """Start the agent service (admin/UAC/password prompt). Worker thread only."""
    try:
        m = _wazuh_mod()
        return bool(m and m.start_agent())
    except Exception as e:  # noqa: BLE001
        logger.error(f"[EP-SETUP] start_agent failed: {e}")
        return False


def _wazuh_connection() -> str:
    """Live manager-connection status: connected/pending/disconnected/unknown.
    Distinct from _wazuh_running() (which only checks the daemon process)."""
    try:
        m = _wazuh_mod()
        return m.get_agent_connection() if m else "unknown"
    except Exception:  # noqa: BLE001
        return "unknown"


def _wazuh_reenroll(on_status) -> bool:
    """Recover a dead/duplicate enrollment (the enroll_rc_* case, common after a
    reinstall): wipe the key + backups, enroll under a fresh unique name, and
    restart. One admin prompt. Returns True if the agent is running afterward.
    Worker thread only."""
    import time
    m = _wazuh_mod()
    if not (m and hasattr(m, "reenroll_agent")):
        logger.warning("[EP-SETUP] reenroll_agent unavailable on this platform")
        return False
    on_status("Reconnecting to the monitoring server…")
    logger.info("[EP-SETUP] reenroll_agent()")
    try:
        ok, msg = m.reenroll_agent()
    except Exception as e:  # noqa: BLE001
        logger.error(f"[EP-SETUP] reenroll_agent error: {e}")
        return False
    logger.info(f"[EP-SETUP] reenroll_agent -> {ok} ({msg})")
    if not ok:
        return False
    deadline = time.time() + 60
    while time.time() < deadline:
        if _wazuh_running():
            logger.info(f"[EP-SETUP] re-enrolled; connection={_wazuh_connection()}")
            return True
        time.sleep(2)
    return _wazuh_running()


# Human-readable messages for Wazuh installer failure reasons. Mirrors the
# mapping the Endpoint plugin's own UI uses (plugins/wazuh/main.py) so the
# wizard explains failures the same clear way instead of "didn't finish".
_WZ_REASON_MSG = {
    "user_canceled": "The install was cancelled.",
    "script_failed": "The installer hit an error. You can try again or skip.",
    "pkg_corrupted": "The downloaded package was corrupted. Try again to re-download.",
    "no_status_file": "The install was interrupted. Try again.",
    "dns_failed": "Couldn't reach the download server. Check your connection and try again.",
    "network_timeout": "The download timed out. Check your connection and try again.",
    "signature_invalid": "The package failed signature verification. Try again to re-download.",
    "duplicate_name": (
        "This device is already registered on the monitoring server. "
        "Try again to enroll under a new identifier."
    ),
    "manager_unreachable": (
        "Couldn't reach the monitoring server. Make sure the VPN is connected, "
        "then try again."
    ),
    "enroll_failed": (
        "Enrollment with the monitoring server failed. Make sure the VPN is "
        "connected, then try again."
    ),
}


def _wazuh_reason_message(reason) -> str:
    """Turn a Wazuh installer failure_reason into a clear, actionable message."""
    if reason and reason.startswith("enroll_rc_"):
        rc = reason[len("enroll_rc_"):]
        return (f"Enrollment with the monitoring server failed (code {rc}). "
                "Make sure the VPN is connected, then try again.")
    if reason in _WZ_REASON_MSG:
        return _WZ_REASON_MSG[reason]
    if reason:
        return f"Endpoint setup didn't finish ({reason}). You can try again or skip."
    return "Endpoint setup didn't finish. You can try again or skip."


def _maybe_forward_clamav(on_status):
    """Best-effort: once the agent is running, forward ClamAV logs to it if
    ClamAV is also set up. Never fails the endpoint step."""
    try:
        from plugins.wazuh.agent.log_forwarding import ensure_clamav_log_forwarding
        ensure_clamav_log_forwarding(on_status)
    except Exception as e:  # noqa: BLE001
        logger.warning(f"[EP-SETUP] ClamAV forwarding skipped: {e}")


def _wazuh_activate(on_status, cancelled=None):
    """After install, ensure the agent is actually Running. Worker thread only."""
    import time
    if _wazuh_running():
        logger.info("[EP-SETUP] agent already running")
        return True
    logger.info("[EP-SETUP] starting agent")
    on_status("Starting endpoint monitoring…")
    _wazuh_start()
    deadline = time.time() + 60
    while time.time() < deadline:
        if cancelled and cancelled():
            return False
        if _wazuh_running():
            logger.info("[EP-SETUP] agent running")
            return True
        time.sleep(2)
    logger.warning("[EP-SETUP] agent did not reach Running state")
    return False


class _EndpointStepMac(SetupStep):
    key = "endpoint"
    icon = "📡"
    title = "Install Endpoint Monitoring"
    subtitle = "Detect threats with the SIEM agent"
    detail = (
        "The Phoenix endpoint agent watches your device for suspicious "
        "activity and reports it securely. You'll be asked once for your "
        "administrator password."
    )
    instructions = [
        "Click “Install Endpoint Agent”.",
        "Enter your administrator password when macOS asks.",
        "The agent installs and enrolls automatically.",
    ]
    primary_label = "Install Endpoint Agent"
    working_label = "Installing endpoint agent…"

    def is_complete(self) -> bool:
        # Installed AND running AND not a confirmed disconnect. "disconnected"
        # means the daemon is alive but the manager rejected its key (the
        # enroll_rc_* / reinstalled-dead-key case) — not done until re-enrolled.
        # pending/unknown are treated as OK so the step never hangs on a slow or
        # unreadable state file.
        return (_wazuh_installed() and _wazuh_running()
                and _wazuh_connection() != "disconnected")

    def check_failed(self):
        if self._failed:
            return self._failed
        from plugins.wazuh.agent.installer_service import (
            STATE_DOWNLOAD_FAILED,
            STATE_ENROLL_FAILED,
            STATE_INSTALL_FAILED,
            get_failure_reason,
            get_install_state,
        )
        state = get_install_state()
        if state in (
            STATE_DOWNLOAD_FAILED, STATE_INSTALL_FAILED, STATE_ENROLL_FAILED,
        ):
            reason = get_failure_reason()
            if not self._logged_failure:
                self._logged_failure = True
                logger.error(f"[EP-SETUP] FAILED state={state} reason={reason!r}")
            return _wazuh_reason_message(reason)
        return None

    def begin(self, on_status):
        import time
        from plugins.wazuh.agent import installer_service as wz

        if wz.get_install_state() in (
            wz.STATE_DOWNLOAD_FAILED, wz.STATE_INSTALL_FAILED, wz.STATE_ENROLL_FAILED,
        ):
            wz.retry()
        self._failed = None

        def _work():
            needs_reenroll = False

            # Phase 1: package download (kicked off at login; wait for it).
            if not _wazuh_installed():
                wz.ensure_download_started()
                on_status("Downloading endpoint agent…")
                deadline = time.time() + 180
                while time.time() < deadline:
                    if self.cancelled():
                        return
                    state = wz.get_install_state()
                    if state == wz.STATE_DOWNLOADED:
                        break
                    if state in (wz.STATE_INSTALLED, wz.STATE_READY):
                        break
                    if state == wz.STATE_DOWNLOAD_FAILED:
                        self._failed = _wazuh_reason_message(
                            wz.get_failure_reason() or "dns_failed")
                        return
                    time.sleep(2)
                else:
                    self._failed = "Download timed out. You can try again or skip."
                    return

            # Phase 2 + 3: install (admin prompt) + watch to completion, unless
            # the agent is already on disk.
            if not _wazuh_installed():
                on_status("Approve the administrator prompt to install…")
                if not wz.trigger_install(self.app):
                    self._failed = _wazuh_reason_message(
                        wz.get_failure_reason() or "user_canceled")
                    return
                _STEPS = {
                    "install_pkg": "Installing package…",
                    "patch_config": "Configuring agent…",
                    "enrollment": "Enrolling agent…",
                    "key_backup": "Backing up keys…",
                    "launchd": "Starting agent service…",
                    "done": "Finishing up…",
                }
                while True:
                    if self.cancelled():
                        return
                    result = wz.poll_install_progress()
                    step = result.get("step", "")
                    if step:
                        on_status(_STEPS.get(step, "Installing…"))
                    if result.get("finished"):
                        if not result.get("success"):
                            reason = wz.get_failure_reason() or ""
                            logger.error(f"[EP-SETUP] install failed reason={reason!r} "
                                         f"result={result}")
                            # A pure ENROLLMENT failure (enroll_rc_*, duplicate
                            # name, manager unreachable) leaves the package
                            # installed — recover by re-enrolling under a fresh
                            # identity instead of dead-ending. Anything else
                            # (download/pkg/script) is a real install failure.
                            enroll_like = (reason.startswith("enroll")
                                           or reason in ("duplicate_name",
                                                         "manager_unreachable"))
                            if enroll_like and _wazuh_installed():
                                logger.info("[EP-SETUP] enrollment failed but pkg "
                                            "installed — will re-enroll")
                                needs_reenroll = True
                                break
                            self._failed = _wazuh_reason_message(reason)
                            return
                        break
                    time.sleep(2)

            # Phase 4: get the agent running AND connected to the manager.
            if needs_reenroll:
                # Skip the pointless start-with-dead-key; re-enroll directly.
                if not _wazuh_reenroll(on_status):
                    self._failed = (
                        "Couldn't enroll the endpoint agent with the monitoring "
                        "server. Make sure the VPN is connected, then try again.")
                    return
            else:
                if not _wazuh_activate(on_status, self.cancelled):
                    # Can't even start — a dead key can't be fixed by a restart,
                    # so fall back to a fresh enrollment.
                    if not _wazuh_reenroll(on_status):
                        self._failed = ("Endpoint agent installed but isn't running "
                                        "yet. You can start it from the Endpoint "
                                        "page, or skip.")
                        return
                elif _wazuh_connection() == "disconnected":
                    # Running but the manager rejected the key (classic reinstall
                    # dead-key). Recover by re-enrolling under a fresh identity.
                    logger.info("[EP-SETUP] running but disconnected — re-enrolling")
                    _wazuh_reenroll(on_status)

            # Phase 5: link ClamAV → Wazuh if antivirus is also set up.
            _maybe_forward_clamav(on_status)

        self._run_bg(_work)


class _EndpointStepDirect(SetupStep):
    """Windows/Linux endpoint install via full_install() on a worker thread."""

    key = "endpoint"
    icon = "📡"
    title = "Install Endpoint Monitoring"
    subtitle = "Detect threats with the SIEM agent"
    detail = (
        "The Phoenix endpoint agent watches your device for suspicious "
        "activity and reports it securely. You may be asked to approve an "
        "administrator prompt."
    )
    primary_label = "Install Endpoint Agent"
    working_label = "Installing endpoint agent…"

    def is_complete(self) -> bool:
        # Installed AND running AND not a confirmed disconnect (dead key) — see
        # _EndpointStepMac.is_complete for the reasoning.
        return (_wazuh_installed() and _wazuh_running()
                and _wazuh_connection() != "disconnected")

    def begin(self, on_status):
        # Windows/Linux full_install() returns only a bool, so classify the
        # failure from what's observable: the last progress line (download vs
        # install) and the post-run installed/running state (enrollment).
        self._last_progress = ""

        def _status(msg):
            self._last_progress = str(msg)
            on_status(str(msg))

        def _work():
            if not _wazuh_installed():
                if _PLATFORM == "Linux":
                    from plugins.wazuh.agent.wazuh_functions_linux import full_install
                else:
                    from plugins.wazuh.agent.wazuh_functions_windows import full_install

                ok = full_install(progress_callback=_status)
                if not ok and not _wazuh_installed():
                    logger.error("[EP-SETUP] full_install failed; "
                                 f"last_progress={self._last_progress!r}")
                    self._failed = self._install_fail_message()
                    return

            # Ensure the agent is running. On Windows/Linux a failed enrollment
            # leaves the agent installed-but-not-running (agent-auth ran inside
            # the privileged script but couldn't register with the manager).
            if not _wazuh_activate(_status, self.cancelled):
                logger.error("[EP-SETUP] agent not running after install; "
                             f"installed={_wazuh_installed()} "
                             f"last_progress={self._last_progress!r}")
                # A dead key survives a restart — recover with a fresh enrollment.
                if not _wazuh_reenroll(_status):
                    self._failed = (
                        "The endpoint agent installed but couldn't reach the "
                        "monitoring server to finish enrolling. Make sure the VPN "
                        "is connected, then try again."
                    )
                    return
            elif _wazuh_connection() == "disconnected":
                # Running but the manager rejected the key (reinstall dead-key) —
                # re-enroll under a fresh identity to recover.
                logger.info("[EP-SETUP] running but disconnected — re-enrolling")
                _wazuh_reenroll(_status)
            # Link ClamAV → Wazuh if antivirus is also set up.
            _maybe_forward_clamav(_status)
        self._run_bg(_work)

    def _install_fail_message(self) -> str:
        """Classify a full_install() failure from its last progress line."""
        lp = (self._last_progress or "").lower()
        if "download" in lp:
            return ("Couldn't download the endpoint agent. Check your connection "
                    "and try again.")
        if "admin" in lp or "approve" in lp or "cancel" in lp:
            return ("The administrator prompt was declined. Try again and approve "
                    "it to install the endpoint agent.")
        return "Couldn't install the endpoint agent. You can try again or skip."


# ════════════════════════════════════════════════════════════════════
# Factory
# ════════════════════════════════════════════════════════════════════

def build_steps(app):
    """Return the ordered list of applicable SetupSteps for this platform.

    Steps whose plugin fails to import (or whose is_applicable() raises) are
    dropped so a single unavailable capability never blocks the wizard.
    """
    if _PLATFORM == "Darwin":
        candidates = [
            _VPNStepMac,
            _AntivirusStepMac,  # now also walks Full Disk Access
            _EndpointStepMac,
        ]
    elif _PLATFORM == "Windows":
        candidates = [
            _AntivirusStepDefender,
            _VPNStepWindows,
            _EndpointStepDirect,
        ]
    elif _PLATFORM == "Linux":
        candidates = [
            _AntivirusStepDefender,
            _VPNStepLinux,
            _EndpointStepDirect,
        ]
    else:
        candidates = []

    steps = []
    for cls in candidates:
        try:
            step = cls(app)
            if step.is_applicable():
                steps.append(step)
        except Exception as e:  # noqa: BLE001
            logger.warning(f"[SETUP] Skipping step {cls.__name__}: {e}")
    return steps
