"""SIEM Agent Plugin (PyQt6).

Faithful PyQt6 port of the original CustomTkinter "Endpoint" screen. Installs
and manages the SIEM (Wazuh) agent from the Phoenix Desktop sidebar.

The screen is a flat page (gui/page_kit.py), state-driven:

  * not installed  -> install action (state-machine on macOS, one-click elsewhere)
  * needs re-enroll -> reinstall action
  * installed      -> status pill + Agent Service toggle in the header, agent
                      details, and a Reconnect action when not connected

Backend platform functions are called, never reimplemented. All blocking
subprocess work runs on worker threads and is marshalled back onto the GUI
thread via ``self.app.after(0, ...)``.

Author: Resistine Team
Copyright (c) Resistine 2025
Licensed under the GNU General Public License v2 or later
"""

from __future__ import annotations

import os
import platform
import threading

from PyQt6.QtWidgets import QProgressBar, QWidget

from gui.page_kit import KVList, MenuRow, Page, PageHeader, muted
from gui.toggle import ToggleSwitch
from plugins.base_plugin import BasePlugin
from plugins.wazuh.config import WAZUH_MANAGER
from utils import settings
from utils.logger import logger

_PLATFORM = platform.system()
_PLUGIN_DIR = os.path.dirname(os.path.realpath(__file__))

# Platform-conditional backend import (current platform only, guarded so this
# module imports on any OS).
_platform_supported = False
try:
    if _PLATFORM == "Darwin":
        from plugins.wazuh.agent.wazuh_functions_darwin import (  # noqa: F401
            full_install,
            get_agent_connection,
            get_agent_group,
            get_agent_name,
            get_agent_status,
            is_agent_installed,
            needs_reenrollment,
            reenroll_agent,
            restore_client_key_if_needed,
            start_agent,
            stop_agent,
        )
        _platform_supported = True
    elif _PLATFORM == "Linux":
        from plugins.wazuh.agent.wazuh_functions_linux import (  # noqa: F401
            full_install,
            get_agent_connection,
            get_agent_group,
            get_agent_name,
            get_agent_status,
            is_agent_installed,
            needs_reenrollment,
            reenroll_agent,
            restore_client_key_if_needed,
            start_agent,
            stop_agent,
        )
        _platform_supported = True
    elif _PLATFORM == "Windows":
        from plugins.wazuh.agent.wazuh_functions_windows import (  # noqa: F401
            full_install,
            get_agent_connection,
            get_agent_group,
            get_agent_name,
            get_agent_status,
            is_agent_installed,
            needs_reenrollment,
            reenroll_agent,
            restore_client_key_if_needed,
            start_agent,
            stop_agent,
        )
        _platform_supported = True
except Exception as e:  # pragma: no cover - defensive
    logger.warning(f"SIEM backend import failed on {_PLATFORM}: {e}")
    _platform_supported = False


_POLL_INTERVAL_MS = 10_000


def _safe(fn, default=None):
    """Call a guarded backend function, swallowing any exception."""
    try:
        return fn()
    except Exception as e:
        logger.warning(f"SIEM backend call failed: {e}")
        return default


def is_agent_running():
    """Return True if the SIEM agent service is currently running.

    Cross-platform; returns False on unsupported platforms or any error.
    Unlike is_agent_installed(), this reflects the live service state, so the
    chat access gate re-locks the instant the agent is toggled off. We have no
    readable "connected to manager" signal (the agent state file is root-owned),
    so a running service is the best silent proxy for "connected".
    """
    if not _platform_supported:
        return False
    try:
        return get_agent_status() == "Running"
    except Exception:
        return False


class Plugin(BasePlugin):
    """Plugin class for the Wazuh SIEM agent."""

    def __init__(self, app):
        super().__init__(
            id="011",
            version="2026.01.04-alpha",
            order=5,
            name="Endpoint",
            status=None,
            description="Monitor this device with the Phoenix endpoint agent.",
            supported_systems=["Darwin", "Linux", "Windows"],
            translations={"US": "Endpoint", "ES": "Endpoint", "FR": "Endpoint"},
            icon_light_path=os.path.join(_PLUGIN_DIR, "add_user_light.png"),
            icon_dark_path=os.path.join(_PLUGIN_DIR, "add_user_dark.png"),
            uninstall_enabled=True,
        )
        self.app = app
        self._status_poll_id = None
        self._installing = False
        self._destroyed = False
        self.main_container = None
        # Cheap cached agent-state string; refreshed by the background poll.
        self._cached_state = None
        self._cached_conn = None
        self._reconnect_btn = None
        self._reconnecting = False
        self.status = self.get_status()
        # Populate the cache in the background so the DASHBOARD tile shows the
        # real status without the user first opening the Endpoint screen.
        # Without this the cache stays None until _build_status_section runs,
        # so the tile reads "Warning" on a fresh dashboard (was macOS-visible;
        # the per-screen poll only exists once the screen is built).
        if _platform_supported:
            threading.Thread(
                target=self._probe_initial_status, daemon=True).start()

    def _probe_initial_status(self):
        """One-shot background status read to seed the dashboard tile."""
        state = _safe(get_agent_status)
        if state is None:
            return
        conn = (_safe(get_agent_connection, "unknown")
                if state == "Running" else "unknown")

        def _apply(s=state, c=conn):
            if self._destroyed:
                return
            self._cached_state = s
            self._cached_conn = c
            new_status = self.check_status()
            if new_status != self.status:
                self.status = new_status
                self.app.update_plugin(self.id)

        try:
            self.app.after(0, _apply)
        except Exception:
            pass

    # ── Status ─────────────────────────────────────────────────────────

    def check_status(self):
        """Cheap, non-blocking status from the cached state string."""
        if not _platform_supported:
            return None
        state = self._cached_state
        if state == "Running":
            # "Running" only means the daemon is alive. If we positively know
            # it's not connected to the manager (e.g. its key was invalidated
            # server-side), surface a Warning so the dashboard tile and the
            # Reconnect affordance reflect reality. "unknown" is NOT
            # downgraded — we don't guess. Uses the poll-maintained cache;
            # falls back to a live read the first time through.
            conn = self._cached_conn
            if conn is None:
                try:
                    conn = get_agent_connection()
                except Exception:
                    conn = "unknown"
                self._cached_conn = conn
            if conn == "disconnected":
                return "Warning"
            return "OK"
        if state == "Stopped":
            return "Error"
        return "Warning"

    def on_theme_changed(self):
        """Rebuild the Wazuh screen on theme toggle."""
        if getattr(self, "app", None):
            self.app.update_plugin(self.id)

    # ── Main screen ────────────────────────────────────────────────────

    def create_main_screen(self):
        self._stop_status_polling()
        self._destroyed = False
        if not _platform_supported:
            self.main_container = self._unsupported_screen()
            return self.main_container
        self.main_container = self._agent_screen()
        return self.main_container

    def _unsupported_screen(self) -> QWidget:
        page = Page()
        page.add(PageHeader(
            "Endpoint",
            f"SIEM agent management is not yet available on {_PLATFORM}.",
            ("info", "Unsupported")))
        page.stretch()
        return page.widget

    def _agent_screen(self) -> QWidget:
        installed = _safe(is_agent_installed, False)
        logger.info(f"SIEM _agent_screen: is_agent_installed={installed}")
        reenroll = installed and _safe(needs_reenrollment, False)

        page = Page()
        self._header = PageHeader("Endpoint")
        self._status_label = self._header.pill
        page.add(self._header)

        if reenroll:
            self._build_reenroll_section(page)
        elif installed:
            self._build_status_section(page)
        else:
            self._build_install_section(page)

        page.stretch()

        if installed and not reenroll:
            self._start_status_polling()
            # Refresh real state in the background and, if stopped, restore
            # client.keys from backup (covers key loss). Mirrors the original.
            threading.Thread(
                target=self._deferred_restore, daemon=True).start()

        return page.widget

    # ── UI helpers ─────────────────────────────────────────────────────

    def _add_progress_label(self, page: Page, text: str = "") -> None:
        self._progress_label = muted(text)
        self._progress_label.setContentsMargins(0, 8, 0, 0)
        self._progress_label.setVisible(bool(text))  # shown by _set_progress
        page.add(self._progress_label)

    def _add_busy_bar(self, page: Page) -> QProgressBar:
        bar = QProgressBar()
        bar.setRange(0, 0)  # indeterminate
        bar.setTextVisible(False)
        bar.setFixedHeight(4)
        page.spacing(10)
        page.add(bar)
        return bar

    def _add_detail_rows(self, page: Page, details: dict,
                         title: str = "Agent") -> KVList:
        page.section(title)
        kv = KVList(details.items())
        page.add(kv)
        return kv

    def _agent_details(self) -> dict:
        return {
            "Agent name": _safe(get_agent_name, "—"),
            "Group": _safe(get_agent_group, "—"),
            "Manager": WAZUH_MANAGER,
        }

    def _action(self, page: Page, icon: str, title: str, hint: str,
                handler, section: str = "Actions") -> MenuRow:
        page.section(section)
        row = MenuRow(icon, title, hint, on_click=handler)
        page.add(row)
        return row

    # ── Re-enrollment required (account change) ────────────────────────

    def _build_reenroll_section(self, page: Page) -> None:
        enrolled = settings.get("wazuh", "enrolled_email", "unknown")
        current = settings.get("auth", "email", "unknown")

        self._header.set_status("error", "Re-enrollment required")
        self._header.set_subtitle(
            f"This agent was enrolled under a different account ({enrolled}). "
            f"Reinstall to register it under the current account ({current}).")
        self._install_btn = self._action(
            page, "rotate-ccw", "Reinstall agent",
            "Re-registers this device under your account",
            self._start_reinstall)
        self._add_progress_label(page)

    # ── Not installed ──────────────────────────────────────────────────

    def _build_install_section(self, page: Page) -> None:
        if _PLATFORM == "Darwin":
            return self._build_install_section_darwin(page)
        return self._build_install_section_direct(page)

    def _build_install_section_direct(self, page: Page) -> None:
        """Install screen for Windows/Linux — one click, no VPN needed."""
        self._header.set_status("warning", "Not installed")
        self._header.set_subtitle(
            "The endpoint agent collects security telemetry from this "
            "machine and reports to the Phoenix SIEM dashboard.")

        self._install_btn = self._action(
            page, "download", "Install agent",
            "Download and install the agent (needs admin rights)",
            self._start_installation)
        self._add_progress_label(page)
        # Indeterminate progress bar, hidden until install starts — the direct
        # install runs several download/MSI/elevation phases with only the text
        # label as feedback, which can look frozen on a slow machine.
        self._install_bar = self._add_busy_bar(page)
        self._install_bar.hide()

        self._add_detail_rows(page, self._agent_details())

    def _build_install_section_darwin(self, page: Page) -> None:
        """State-machine install screen for macOS — download + install."""
        from plugins.wazuh.agent.installer_service import (
            STATE_DOWNLOAD_FAILED,
            STATE_DOWNLOADED,
            STATE_DOWNLOADING,
            STATE_INSTALL_FAILED,
            STATE_INSTALLING,
            STATE_NOT_STARTED,
            get_failure_reason,
            get_install_state,
        )

        state = _safe(get_install_state, STATE_NOT_STARTED)
        logged_in = settings.get("auth", "logged_in", False)
        header = self._header

        # Without login the download normally never starts, but a user who
        # imported a VPN config manually (or removed the Login plugin) still
        # has a valid path to enrollment — offer an explicit install attempt
        # instead of the log-in dead end.
        can_attempt = (self._has_vpn_config()
                       or not self._login_plugin_installed())

        if state == STATE_NOT_STARTED and not logged_in and not can_attempt:
            header.set_status("warning", "Not installed")
            header.set_subtitle("Log in to enable endpoint protection.")

        elif state == STATE_NOT_STARTED and not logged_in:
            header.set_status("warning", "Not installed")
            header.set_subtitle(
                "You're not signed in, but a VPN configuration is available "
                "— you can install the security agent now.")
            self._action(page, "download", "Download & install agent",
                         "Fetches the agent package, then installs it",
                         self._force_download_start)

        elif state in (STATE_NOT_STARTED, STATE_DOWNLOADING):
            header.set_status("info", "Downloading…")
            header.set_subtitle("Downloading security agent...")
            self._add_busy_bar(page)

        elif state == STATE_DOWNLOAD_FAILED:
            reason = _safe(get_failure_reason, "")
            _REASON_MSG = {
                "dns_failed": "Download failed — check your internet connection.",
                "network_timeout": "Download timed out. Please try again.",
                "signature_invalid": "Package signature invalid. Will retry with a fresh download.",
            }
            header.set_status("error", "Download failed")
            header.set_subtitle(
                _REASON_MSG.get(reason, f"Download failed ({reason})."))
            self._action(page, "refresh-cw", "Retry download", "",
                         self._retry_download)

        elif state == STATE_DOWNLOADED:
            header.set_status("warning", "Ready to install")
            header.set_subtitle(
                "We're about to install a system security component that "
                "monitors your device for threats.")
            self._install_btn = self._action(
                page, "shield-check", "Install security",
                "Requires your password to allow the installation",
                self._start_installation)
            self._add_progress_label(page)
            self._add_detail_rows(page, self._agent_details())

        elif state == STATE_INSTALLING:
            header.set_status("info", "Installing…")
            header.set_subtitle("Installing the security agent.")
            self._add_progress_label(page, "Installing...")
            self._add_busy_bar(page)
            self._poll_install()

        elif state == STATE_INSTALL_FAILED:
            reason = _safe(get_failure_reason, "")
            _REASON_MSG = {
                "user_canceled": "Installation was cancelled.",
                "script_failed": "Installation script encountered an error.",
                "pkg_corrupted": "Package file is corrupted. Retry to re-download.",
                "no_status_file": "Installation was interrupted. Click Retry.",
                "duplicate_name": (
                    "This device is already registered on the SIEM manager. "
                    "Retry to enroll under a new identifier."
                ),
                "manager_unreachable": (
                    "Couldn't reach the SIEM manager. Check your internet connection and retry."
                ),
                "enroll_failed": (
                    "Enrollment with the SIEM manager failed. "
                    "Check your internet connection and retry."
                ),
            }
            if reason.startswith("enroll_rc_"):
                msg = (
                    "Enrollment with the SIEM manager failed. "
                    "Check your internet connection and retry."
                )
            else:
                msg = _REASON_MSG.get(reason, f"Installation failed ({reason}).")
            header.set_status(
                "warning" if reason == "user_canceled" else "error",
                "Cancelled" if reason == "user_canceled" else "Install failed")
            header.set_subtitle(msg)
            if reason != "user_canceled":
                self._action(page, "refresh-cw", "Retry", "",
                             self._retry_install)
            else:
                self._install_btn = self._action(
                    page, "shield-check", "Install security",
                    "Requires your password to allow the installation",
                    self._start_installation)

    # ── Installed (status + controls) ──────────────────────────────────

    def _build_status_section(self, page: Page) -> None:
        state = _safe(get_agent_status, "Stopped")
        self._cached_state = state
        is_running = state == "Running"
        # Live manager-connection status — distinct from "process running".
        # Resolution: wazuh-agentd.state file → unprivileged socket probe
        # (the state file is root-owned on macOS/Linux GUI sessions, which
        # used to read as "Unknown" on perfectly healthy agents) →
        # ossec.log tail. "disconnected" remains the only hard fault.
        connection = (_safe(get_agent_connection, "unknown")
                      if is_running else "unknown")
        self._cached_conn = connection
        not_connected = is_running and connection == "disconnected"

        if not is_running:
            kind, status_text = "error", "Stopped"
            subtitle = "The agent service is stopped — this device is not monitored"
        elif not_connected:
            kind, status_text = "error", "Not connected"
            subtitle = "The agent is running but can't reach the SIEM manager"
        elif connection == "connected":
            kind, status_text = "ok", "Connected"
            subtitle = "This device reports to the Phoenix SIEM"
        elif connection == "pending":
            kind, status_text = "warning", "Connecting…"
            subtitle = "The agent is connecting to the SIEM manager"
        else:
            kind, status_text = "ok", "Running"
            subtitle = "The agent service is running"
        self._header.set_status(kind, status_text)
        self._header.set_subtitle(subtitle)

        # Agent Service toggle — the same sliding switch the VPN page uses.
        self._agent_toggle = ToggleSwitch()
        self._agent_toggle.setToolTip("Agent service")
        self._agent_toggle.setAccessibleName("Agent service")
        self._agent_toggle.setChecked(is_running)
        self._agent_toggle.toggled.connect(self._toggle_agent)
        self._header.add_control(self._agent_toggle)

        self._add_detail_rows(page, {
            "Status": state,
            # "Unknown" reads as a fault to users; a quiet dash is honest
            # ("we can't read it") without implying something is wrong.
            "Connection": ("—" if connection == "unknown"
                           else connection.capitalize()),
            **self._agent_details(),
            "Platform": f"{_PLATFORM} {platform.release()}",
        })

        # Recovery affordance — ONLY when the connection is not confirmed
        # healthy. A connected agent shows no Reconnect at all.
        # Running-but-not-connected (e.g. the key was invalidated server-side
        # after a reinstall) gets an explanation + action; it re-registers
        # under a fresh identity — the actual fix, since a plain toggle
        # restarts the daemon with the same dead key. Recovery is
        # user-initiated (one admin prompt), never a surprise background
        # dialog.
        if is_running and connection != "connected":
            hint = ("If the old agent was removed on the server, reconnect "
                    "to re-register under a new identity."
                    if not_connected else
                    "Connection can't be confirmed. If the dashboard shows "
                    "this device offline, reconnect to re-register the agent.")
            self._reconnect_btn = self._action(
                page, "refresh-cw", "Reconnect", hint,
                self._reconnect_agent, section="Troubleshooting")
        else:
            self._reconnect_btn = None

    def _reconnect_agent(self):
        """Force a fresh manager re-enrollment to recover a stuck agent.

        Wipes the (invalidated) key + backups and re-registers under a new
        unique name via reenroll_agent(), so the manager creates a brand-new
        record instead of the deleted one. One admin prompt; runs off-thread.
        """
        if self._reconnecting:
            return
        self._reconnecting = True
        if self._reconnect_btn is not None:
            try:
                self._reconnect_btn.setEnabled(False)
                self._reconnect_btn.setText("Reconnecting…")
            except RuntimeError:
                pass

        def _run():
            try:
                ok, msg = reenroll_agent()
            except Exception as e:
                ok, msg = False, str(e)

            # reenroll_agent() already restarts the service. Wait for it to
            # actually report Running before refreshing, so the toggle shows ON
            # and the user isn't left flipping it back on (a second admin
            # prompt). systemctl restart can return while still "activating".
            if ok:
                import time as _t
                for _ in range(10):
                    if _safe(get_agent_status) == "Running":
                        break
                    _t.sleep(0.5)

            def _done():
                self._reconnecting = False
                self.app.show_notification(
                    "Re-enrolled — reconnecting to SIEM manager"
                    if ok else f"Reconnect failed: {msg}",
                    type="info" if ok else "error",
                )
                self._refresh_screen()

            self.app.after(0, _done)

        threading.Thread(target=_run, daemon=True).start()

    # ── Key restore (background thread) ────────────────────────────────

    def _deferred_restore(self):
        """Refresh cached state; if stopped, restore keys after launchd settle.

        After a fresh install the agent may read "Stopped" for a few seconds
        while launchd bootstraps wazuh-agentd. The delay avoids a pointless
        admin prompt (the key is usually already in place).
        """
        import time

        state = _safe(get_agent_status)
        if state is not None and state != self._cached_state:
            self._cached_state = state
            new_status = self.check_status()
            if new_status != self.status:
                self.status = new_status
                self.app.after(0, self._refresh_screen)
                self.app.after(0, lambda: self.app.update_plugin(self.id))

        if state == "Running":
            return
        _LAUNCHD_SETTLE_SECONDS = 8
        time.sleep(_LAUNCHD_SETTLE_SECONDS)
        if _safe(get_agent_status) == "Running":
            return
        _safe(restore_client_key_if_needed)

    # ── Installation (background thread) ───────────────────────────────

    def _start_installation(self):
        """User clicked Install — route to platform-specific install flow."""
        if _PLATFORM == "Darwin":
            return self._start_installation_darwin()
        return self._start_installation_direct()

    def _start_installation_direct(self):
        """Windows/Linux: run full_install() in a background daemon thread."""
        if self._installing:
            return
        self._installing = True
        self._set_install_btn("Installing...", enabled=False)
        bar = getattr(self, "_install_bar", None)
        if bar is not None:
            try:
                bar.show()
            except RuntimeError:
                pass  # widget from a previous rebuild

        def _progress(msg):
            self.app.after(0, lambda m=msg: self._set_progress(m))

        def _done(success):
            self._installing = False
            if success:
                self.app.show_notification(
                    "SIEM agent installed!", type="success")
            else:
                self.app.show_notification(
                    "Installation failed", type="error")
            self.app.after(0, self._refresh_screen)

        def _run():
            try:
                ok = full_install(progress_callback=_progress)
            except Exception as e:
                logger.error(f"Installation error: {e}")
                ok = False
            self.app.after(100, lambda s=ok: _done(s))

        threading.Thread(target=_run, daemon=True).start()

    def _start_installation_darwin(self):
        """macOS: trigger via the installer service state machine."""
        from plugins.wazuh.agent.installer_service import (
            STATE_INSTALL_FAILED,
            get_install_state,
            retry,
            trigger_install,
        )

        if self._installing:
            return
        if _safe(get_install_state) == STATE_INSTALL_FAILED:
            _safe(retry)
        self._installing = True
        self._install_poll_count = 0
        self._set_install_btn("Installing...", enabled=False)

        def _run():
            try:
                launched = trigger_install(self.app)
            except Exception as e:
                logger.error(f"Installation trigger error: {e}")
                launched = False
            if launched:
                self.app.after(0, self._poll_install)
            else:
                self._installing = False
                self.app.after(0, self._refresh_screen)

        threading.Thread(target=_run, daemon=True).start()

    _MAX_POLL_COUNT = 100  # 100 * 3s = 5 minutes max

    def _poll_install(self):
        """Poll the installer service for progress and update the UI."""
        from plugins.wazuh.agent.installer_service import poll_install_progress

        if self._destroyed:
            self._installing = False
            return

        self._install_poll_count = getattr(self, "_install_poll_count", 0) + 1
        if self._install_poll_count > self._MAX_POLL_COUNT:
            self._installing = False
            self.app.show_notification(
                "Installation timed out", type="error")
            self._refresh_screen()
            return

        result = _safe(poll_install_progress, {}) or {}
        step = result.get("step", "")

        _STEP_LABELS = {
            "install_pkg": "Installing package...",
            "patch_config": "Configuring agent...",
            "enrollment": "Enrolling agent...",
            "key_backup": "Backing up keys...",
            "launchd": "Starting agent service...",
            "done": "Finishing up...",
        }
        label = _STEP_LABELS.get(
            step, f"Installing... ({step})" if step else "Installing...")
        self._set_progress(label)

        if result.get("finished"):
            self._installing = False
            if result.get("success"):
                self.app.show_notification(
                    "Security agent installed!", type="success")
            else:
                self.app.show_notification(
                    "Installation failed", type="error")
            self._refresh_screen()
        else:
            self.app.after(3000, self._poll_install)

    def _has_vpn_config(self) -> bool:
        """True if any WireGuard config has been imported/registered."""
        try:
            from plugins.vpn.main import _config_manager
            return bool(_config_manager.get_active_config_name()
                        or _config_manager.list_configs())
        except Exception:
            return False

    def _login_plugin_installed(self) -> bool:
        """True if the Login plugin (id 007) is installed."""
        return any(
            getattr(p, "id", None) == "007"
            for p in getattr(self.app, "plugins", None)
            or getattr(self.app, "plugin_list", [])
            or []
        )

    def _force_download_start(self):
        """Explicit user request: start the agent download without login."""
        from plugins.wazuh.agent.installer_service import (
            ensure_download_started,
        )
        threading.Thread(
            target=lambda: _safe(lambda: ensure_download_started(force=True)),
            daemon=True).start()
        self.app.after(500, self._refresh_screen)

    def _retry_download(self):
        """User clicked Retry on download failure."""
        from plugins.wazuh.agent.installer_service import retry
        threading.Thread(target=lambda: _safe(retry), daemon=True).start()
        self.app.after(500, self._refresh_screen)

    def _retry_install(self):
        """User clicked Retry on install failure."""
        from plugins.wazuh.agent.installer_service import retry
        _safe(retry)
        self._refresh_screen()

    def _start_reinstall(self):
        """Re-enrollment: remove the agent and run full_install directly."""
        if self._installing:
            return
        self._installing = True
        self._set_install_btn("Reinstalling...", enabled=False)

        def _progress(msg):
            self.app.after(0, lambda m=msg: self._set_progress(m))

        def _run():
            try:
                if _PLATFORM == "Darwin":
                    from plugins.wazuh.agent.wazuh_functions_darwin import (
                        remove_agent,
                    )
                elif _PLATFORM == "Linux":
                    from plugins.wazuh.agent.wazuh_functions_linux import (
                        remove_agent,
                    )
                else:
                    from plugins.wazuh.agent.wazuh_functions_windows import (
                        remove_agent,
                    )
                _progress("Removing old agent...")
                remove_agent()
                ok = full_install(progress_callback=_progress)
            except Exception as e:
                logger.error(f"Reinstall error: {e}")
                ok = False
            self._installing = False
            if ok:
                self.app.after(0, lambda: self.app.show_notification(
                    "Agent reinstalled!", type="success"))
            else:
                self.app.after(0, lambda: self.app.show_notification(
                    "Reinstall failed", type="error"))
            self.app.after(100, self._refresh_screen)

        threading.Thread(target=_run, daemon=True).start()

    # ── Start / Stop toggle ────────────────────────────────────────────

    def _toggle_agent(self, checked: bool):
        is_running = _safe(get_agent_status) == "Running"
        want_start = bool(checked)

        if want_start == is_running:
            return

        self._agent_toggle.setEnabled(False)
        action = start_agent if want_start else stop_agent
        ok_msg = "SIEM agent started" if want_start else "SIEM agent stopped"
        fail_msg = ("Failed to start agent" if want_start
                    else "Failed to stop agent")

        def _run():
            try:
                success = action()
            except Exception as e:
                logger.error(f"Agent toggle error: {e}")
                success = False

            def _on_done():
                if self._destroyed:
                    return
                self._agent_toggle.setEnabled(True)
                if success:
                    self.app.show_notification(ok_msg, type="info")
                else:
                    self.app.show_notification(fail_msg, type="error")
                    if not want_start:
                        self._set_toggle_checked(True)
                self._refresh_screen()

            self.app.after(0, _on_done)

        threading.Thread(target=_run, daemon=True).start()

    def _set_toggle_checked(self, checked: bool) -> None:
        """Set toggle state without re-triggering the toggled handler."""
        tog = getattr(self, "_agent_toggle", None)
        if tog is None:
            return
        tog.blockSignals(True)
        tog.setChecked(checked)
        tog.blockSignals(False)

    def _set_progress(self, text: str) -> None:
        lbl = getattr(self, "_progress_label", None)
        if lbl is not None and not self._destroyed:
            try:
                lbl.setText(text)
                lbl.setVisible(bool(text))
            except RuntimeError:
                pass

    def _set_install_btn(self, text: str, enabled: bool) -> None:
        btn = getattr(self, "_install_btn", None)
        if btn is not None and not self._destroyed:
            try:
                btn.setText(text)
                btn.setEnabled(enabled)
            except RuntimeError:
                pass

    # ── Status polling ─────────────────────────────────────────────────

    def _start_status_polling(self):
        if not _platform_supported:
            return
        self._stop_status_polling()
        self._status_poll_id = self.app.after(_POLL_INTERVAL_MS, self._poll_tick)

    def _poll_tick(self):
        """Re-arming background poll: read status on a worker, marshal back."""
        if self._destroyed:
            self._status_poll_id = None
            return

        def _check():
            state = _safe(get_agent_status)
            # Connection is only meaningful while the daemon runs; reading
            # it here (worker thread) keeps netstat/file I/O off the GUI.
            conn = (_safe(get_agent_connection, "unknown")
                    if state == "Running" else "unknown")
            self.app.after(
                0, lambda s=state, c=conn: self._on_poll_result(s, c))

        threading.Thread(target=_check, daemon=True).start()

    def _on_poll_result(self, state, conn="unknown"):
        if self._destroyed:
            self._status_poll_id = None
            return
        changed = False
        if state is not None and state != self._cached_state:
            self._cached_state = state
            changed = True
        if conn is not None and conn != self._cached_conn:
            # Connection transitions (connected → disconnected and back)
            # matter even when the process state hasn't changed — they flip
            # the header label and the Reconnect affordance.
            self._cached_conn = conn
            changed = True
        if changed:
            new_status = self.check_status()
            logger.info(
                f"SIEM agent poll: state={state} conn={conn} "
                f"tile {self.status} -> {new_status}")
            self.status = new_status
            self.app.update_plugin(self.id)
            # update_plugin rebuilds this screen; the new instance arms its
            # own poll, so stop here.
            self._status_poll_id = None
            return
        self._status_poll_id = self.app.after(
            _POLL_INTERVAL_MS, self._poll_tick)

    def _stop_status_polling(self):
        if self._status_poll_id is not None:
            try:
                self.app.after_cancel(self._status_poll_id)
            except Exception:
                pass
            self._status_poll_id = None

    # ── Helpers ────────────────────────────────────────────────────────

    def _refresh_screen(self):
        """Refresh status and rebuild the screen if it is currently displayed.

        self.status is updated unconditionally so the dashboard tile reflects
        the new state even when the install finished after the user navigated
        away.
        """
        try:
            self.status = self.check_status()
        except Exception:
            pass
        try:
            self.app.update_plugin(self.id)
        except Exception as e:
            logger.warning(f"SIEM refresh failed: {e}")

    def destroy(self):
        """Clean up polling. Agent removal is handled by uninstallers."""
        self._destroyed = True
        self._stop_status_polling()
        if self.main_container is not None:
            try:
                self.main_container.deleteLater()
            except Exception:
                pass
            self.main_container = None
