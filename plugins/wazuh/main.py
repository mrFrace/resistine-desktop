"""
SIEM Agent Plugin
Install and manage the SIEM agent from the Resistine Desktop sidebar.
Author: Resistine Team
Copyright (c) Resistine 2025
Licensed under the GNU General Public License v2 or later
"""

import os
import platform
import threading

import customtkinter
from customtkinter import ThemeManager

from plugins.base_plugin import BasePlugin
from plugins.wazuh.config import WAZUH_MANAGER
from utils import settings
from utils.logger import logger

_PLATFORM = platform.system()
_PLUGIN_DIR = os.path.dirname(os.path.realpath(__file__))

try:
    from plugins.vpn.main import is_vpn_connected
except ImportError:
    def is_vpn_connected():
        return True

# Platform-conditional imports
_platform_supported = False
if _PLATFORM == "Darwin":
    from plugins.wazuh.agent.wazuh_functions_darwin import (
        full_install,
        get_agent_group,
        get_agent_name,
        get_agent_status,
        is_agent_installed,
        needs_reenrollment,
        restore_client_key_if_needed,
        start_agent,
        stop_agent,
    )
    _platform_supported = True
elif _PLATFORM == "Linux":
    from plugins.wazuh.agent.wazuh_functions_linux import (
        full_install,
        get_agent_group,
        get_agent_name,
        get_agent_status,
        is_agent_installed,
        needs_reenrollment,
        restore_client_key_if_needed,
        start_agent,
        stop_agent,
    )
    _platform_supported = True
elif _PLATFORM == "Windows":
    from plugins.wazuh.agent.wazuh_functions_windows import (
        full_install,
        get_agent_group,
        get_agent_name,
        get_agent_status,
        is_agent_installed,
        needs_reenrollment,
        restore_client_key_if_needed,
        start_agent,
        stop_agent,
    )
    _platform_supported = True

# Shared UI constants
_COLOR_MUTED = ("#666666", "#aaaaaa")
_COLOR_ERROR = ("#C5221F", "#FF474C")
_COLOR_OK = ("#1E8E3E", "#2CC985")
_COLOR_ACCENT = ("#3a7ebf", "#5b9bd5")
_COLOR_SEPARATOR = ("#e0e0e0", "#2a2a2a")
_COLOR_CARD_BG = ("#ffffff", "#141414")
_COLOR_CARD_BORDER = ("#dddddd", "#333333")
_FONT_LABEL = dict(size=13)
_FONT_VALUE = dict(family="Inter", size=13, weight="bold")
_FONT_TITLE = dict(family="Inter", size=18, weight="bold")
_POLL_INTERVAL_MS = 10_000


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
            description="Install and manage the SIEM agent.",
            supported_systems=["Darwin", "Linux", "Windows"],
            translations={"US": "Endpoint", "ES": "Endpoint", "FR": "Endpoint"},
            icon_light_path=os.path.join(_PLUGIN_DIR, "add_user_light.png"),
            icon_dark_path=os.path.join(_PLUGIN_DIR, "add_user_dark.png"),
            uninstall_enabled=True,
        )
        self.app = app
        self._status_poll_id = None
        self._installing = False
        self.status = self.get_status()

    # --- Status ---

    def check_status(self):
        if not _platform_supported:
            return None
        try:
            state = get_agent_status()
        except Exception as e:
            logger.warning(f"SIEM check_status failed: {e}")
            return "Warning"
        if state == "Running":
            return "OK"
        if state == "Stopped":
            return "Error"
        return "Warning"

    # --- Main Screen ---

    def create_main_screen(self):
        self._stop_status_polling()
        if not _platform_supported:
            return self._unsupported_screen()
        return self._agent_screen()

    def _unsupported_screen(self):
        self.main_container = customtkinter.CTkFrame(
            self.app, corner_radius=0, fg_color="transparent"
        )
        self.main_container.grid_columnconfigure(0, weight=1)
        self.main_container.grid_rowconfigure(0, weight=1)

        customtkinter.CTkLabel(
            self.main_container,
            text="Unsupported Platform",
            font=customtkinter.CTkFont(size=20, weight="bold"),
        ).grid(row=0, column=0, padx=20, pady=(40, 5))

        customtkinter.CTkLabel(
            self.main_container,
            text=f"SIEM agent management is not yet available on {_PLATFORM}.",
            font=customtkinter.CTkFont(size=14),
            text_color=_COLOR_MUTED,
        ).grid(row=1, column=0, padx=20, pady=5)

        return self.main_container

    def _agent_screen(self):
        corner_radius = ThemeManager.theme.get("Theme", {}).get("corner_radius", 15)
        installed = is_agent_installed()
        logger.info(f"SIEM _agent_screen: is_agent_installed={installed}")

        self.main_container = customtkinter.CTkFrame(
            self.app, corner_radius=0, fg_color="transparent"
        )
        self.main_container.grid_columnconfigure(0, weight=1)
        self.main_container.grid_rowconfigure(0, weight=1)

        scroll = customtkinter.CTkScrollableFrame(
            self.main_container, corner_radius=0, fg_color="transparent"
        )
        scroll.grid(row=0, column=0, sticky="nsew", padx=20, pady=10)
        scroll.grid_columnconfigure(0, weight=1)

        card = customtkinter.CTkFrame(
            scroll,
            corner_radius=corner_radius,
            fg_color=_COLOR_CARD_BG,
            border_width=1,
            border_color=_COLOR_CARD_BORDER,
        )
        card.grid(row=0, column=0, sticky="ew", pady=(10, 10))
        card.grid_columnconfigure(1, weight=1)

        row = 0
        if installed and needs_reenrollment():
            row = self._build_reenroll_section(card, row)
        elif installed:
            row = self._build_status_section(card, row)
        else:
            row = self._build_install_section(card, row)

        customtkinter.CTkLabel(card, text="", height=8).grid(
            row=row, column=0, columnspan=2
        )

        if installed and not needs_reenrollment():
            self._start_status_polling()
            # If the agent is stopped, try restoring client.keys from backup
            # (covers key loss from disk corruption, manual deletion, etc.).
            # Wrapped in _deferred_restore to avoid a spurious admin prompt
            # right after fresh install (launchd may still be bootstrapping).
            if get_agent_status() != "Running":
                threading.Thread(target=self._deferred_restore, daemon=True).start()

        return self.main_container

    # --- UI Helpers ---

    @staticmethod
    def _add_separator(card, row):
        customtkinter.CTkFrame(
            card, height=1, fg_color=_COLOR_SEPARATOR
        ).grid(row=row, column=0, columnspan=2, sticky="ew", padx=15)
        return row + 1

    @staticmethod
    def _add_detail_rows(card, row, details):
        for label, value in details.items():
            customtkinter.CTkLabel(
                card,
                text=label,
                text_color=_COLOR_MUTED,
                font=customtkinter.CTkFont(**_FONT_LABEL),
            ).grid(row=row, column=0, padx=20, pady=(8, 0), sticky="w")
            customtkinter.CTkLabel(
                card,
                text=value,
                font=customtkinter.CTkFont(**_FONT_VALUE),
            ).grid(row=row, column=1, padx=20, pady=(8, 0), sticky="e")
            row += 1
        return row

    # --- Card: Re-enrollment required (account change) ---

    def _build_reenroll_section(self, card, row):
        from utils import settings as app_settings
        enrolled = app_settings.get("wazuh", "enrolled_email", "unknown")
        current = app_settings.get("auth", "email", "unknown")

        customtkinter.CTkLabel(
            card,
            text="Re-enrollment Required",
            font=customtkinter.CTkFont(**_FONT_TITLE),
        ).grid(row=row, column=0, columnspan=2, padx=20, pady=(20, 4), sticky="w")
        row += 1

        customtkinter.CTkLabel(
            card,
            text=(
                f"This agent was enrolled under a different account ({enrolled}).\n"
                f"Reinstall to register it under the current account ({current})."
            ),
            font=customtkinter.CTkFont(size=13),
            text_color=_COLOR_ERROR,
            wraplength=460,
            justify="left",
        ).grid(row=row, column=0, columnspan=2, padx=20, pady=(0, 12), sticky="w")
        row += 1

        row = self._add_separator(card, row)

        self._progress_label = customtkinter.CTkLabel(
            card,
            text="",
            font=customtkinter.CTkFont(size=13),
            text_color=_COLOR_ACCENT,
        )
        self._progress_label.grid(row=row, column=0, columnspan=2, padx=20, pady=(12, 0), sticky="w")
        row += 1

        self._install_btn = customtkinter.CTkButton(
            card,
            text="Reinstall Agent",
            height=40,
            corner_radius=8,
            font=customtkinter.CTkFont(size=14, weight="bold"),
            command=self._start_reinstall,
        )
        self._install_btn.grid(row=row, column=0, columnspan=2, sticky="ew", padx=20, pady=(8, 20))
        row += 1

        return row

    # --- Card: Not Installed ---

    def _build_install_section(self, card, row):
        if _PLATFORM == "Darwin":
            return self._build_install_section_darwin(card, row)
        return self._build_install_section_direct(card, row)

    def _build_install_section_direct(self, card, row):
        """Simple install card for Windows/Linux — requires VPN, one-click install."""
        customtkinter.CTkLabel(
            card, text="Security Agent",
            font=customtkinter.CTkFont(**_FONT_TITLE),
        ).grid(row=row, column=0, columnspan=2, padx=20, pady=(20, 4), sticky="w")
        row += 1

        customtkinter.CTkLabel(
            card,
            text=(
                "The SIEM agent collects security telemetry from this machine "
                "and reports to the Resistine SIEM dashboard."
            ),
            font=customtkinter.CTkFont(size=13),
            text_color=_COLOR_MUTED, wraplength=460, justify="left",
        ).grid(row=row, column=0, columnspan=2, padx=20, pady=(0, 12), sticky="w")
        row += 1

        row = self._add_separator(card, row)
        row = self._add_detail_rows(card, row, {
            "Agent Name": get_agent_name(),
            "Agent Group": get_agent_group(),
            "Manager": WAZUH_MANAGER,
        })

        vpn_ok = is_vpn_connected()
        if not vpn_ok:
            customtkinter.CTkLabel(
                card,
                text="Connect VPN to install the SIEM agent",
                font=customtkinter.CTkFont(size=13, weight="bold"),
                text_color=_COLOR_ERROR,
            ).grid(row=row, column=0, columnspan=2, padx=20, pady=(12, 0), sticky="w")
            row += 1

        self._progress_label = customtkinter.CTkLabel(
            card, text="",
            font=customtkinter.CTkFont(size=13), text_color=_COLOR_ACCENT,
        )
        self._progress_label.grid(
            row=row, column=0, columnspan=2, padx=20, pady=(12, 0), sticky="w"
        )
        row += 1

        self._install_btn = customtkinter.CTkButton(
            card, text="Install Agent", height=40, corner_radius=8,
            font=customtkinter.CTkFont(size=14, weight="bold"),
            command=self._start_installation,
            state="normal" if vpn_ok else "disabled",
        )
        self._install_btn.grid(
            row=row, column=0, columnspan=2, sticky="ew", padx=20, pady=(8, 20)
        )
        row += 1

        # Indeterminate progress bar, hidden until install starts — the direct
        # install runs several download/MSI/elevation phases with only the text
        # label as feedback, which can look frozen on a slow machine. Revealed
        # and animated by _start_installation_direct.
        self._install_bar = customtkinter.CTkProgressBar(
            card, mode="indeterminate", width=300,
        )
        self._install_bar.grid(
            row=row, column=0, columnspan=2, padx=20, pady=(0, 20), sticky="ew"
        )
        self._install_bar.grid_remove()
        row += 1
        return row

    def _build_install_section_darwin(self, card, row):
        """State-machine install card for macOS — download + install phases."""
        from plugins.wazuh.agent.installer_service import (
            STATE_DOWNLOADED,
            STATE_DOWNLOAD_FAILED,
            STATE_DOWNLOADING,
            STATE_INSTALL_FAILED,
            STATE_INSTALLING,
            STATE_NOT_STARTED,
            get_failure_reason,
            get_install_state,
        )

        state = get_install_state()
        logged_in = settings.get("auth", "logged_in", False)

        customtkinter.CTkLabel(
            card, text="Security Agent",
            font=customtkinter.CTkFont(**_FONT_TITLE),
        ).grid(row=row, column=0, columnspan=2, padx=20, pady=(20, 4), sticky="w")
        row += 1

        if state == STATE_NOT_STARTED and not logged_in:
            customtkinter.CTkLabel(
                card, text="Log in to enable endpoint protection.",
                font=customtkinter.CTkFont(size=13),
                text_color=_COLOR_MUTED, wraplength=460, justify="left",
            ).grid(row=row, column=0, columnspan=2, padx=20, pady=(0, 20), sticky="w")
            row += 1

        elif state in (STATE_NOT_STARTED, STATE_DOWNLOADING):
            customtkinter.CTkLabel(
                card, text="Downloading security agent...",
                font=customtkinter.CTkFont(size=13),
                text_color=_COLOR_ACCENT, wraplength=460, justify="left",
            ).grid(row=row, column=0, columnspan=2, padx=20, pady=(0, 8), sticky="w")
            row += 1
            bar = customtkinter.CTkProgressBar(card, mode="indeterminate", width=300)
            bar.grid(row=row, column=0, columnspan=2, padx=20, pady=(0, 20), sticky="ew")
            bar.start()
            row += 1

        elif state == STATE_DOWNLOAD_FAILED:
            reason = get_failure_reason()
            _REASON_MSG = {
                "dns_failed": "Download failed — check your internet connection.",
                "network_timeout": "Download timed out. Please try again.",
                "signature_invalid": "Package signature invalid. Will retry with a fresh download.",
            }
            msg = _REASON_MSG.get(reason, f"Download failed ({reason}).")
            customtkinter.CTkLabel(
                card, text=msg,
                font=customtkinter.CTkFont(size=13),
                text_color=_COLOR_ERROR, wraplength=460, justify="left",
            ).grid(row=row, column=0, columnspan=2, padx=20, pady=(0, 8), sticky="w")
            row += 1
            customtkinter.CTkButton(
                card, text="Retry", height=36, corner_radius=8,
                font=customtkinter.CTkFont(size=13, weight="bold"),
                command=self._retry_download,
            ).grid(row=row, column=0, columnspan=2, sticky="ew", padx=20, pady=(4, 20))
            row += 1

        elif state == STATE_DOWNLOADED:
            customtkinter.CTkLabel(
                card,
                text=(
                    "We're about to install a system security component "
                    "that monitors your device for threats."
                ),
                font=customtkinter.CTkFont(size=13),
                text_color=_COLOR_MUTED, wraplength=460, justify="left",
            ).grid(row=row, column=0, columnspan=2, padx=20, pady=(0, 4), sticky="w")
            row += 1
            customtkinter.CTkLabel(
                card, text="This requires your password to allow the installation.",
                font=customtkinter.CTkFont(size=13),
                text_color=_COLOR_MUTED, wraplength=460, justify="left",
            ).grid(row=row, column=0, columnspan=2, padx=20, pady=(0, 12), sticky="w")
            row += 1

            row = self._add_separator(card, row)
            row = self._add_detail_rows(card, row, {
                "Agent Name": get_agent_name(),
                "Agent Group": get_agent_group(),
                "Manager": WAZUH_MANAGER,
            })

            self._progress_label = customtkinter.CTkLabel(
                card, text="",
                font=customtkinter.CTkFont(size=13), text_color=_COLOR_ACCENT,
            )
            self._progress_label.grid(
                row=row, column=0, columnspan=2, padx=20, pady=(12, 0), sticky="w"
            )
            row += 1

            self._install_btn = customtkinter.CTkButton(
                card, text="Install Security", height=40, corner_radius=8,
                font=customtkinter.CTkFont(size=14, weight="bold"),
                command=self._start_installation,
            )
            self._install_btn.grid(
                row=row, column=0, columnspan=2, sticky="ew", padx=20, pady=(8, 20)
            )
            row += 1

        elif state == STATE_INSTALLING:
            self._progress_label = customtkinter.CTkLabel(
                card, text="Installing...",
                font=customtkinter.CTkFont(size=13), text_color=_COLOR_ACCENT,
            )
            self._progress_label.grid(
                row=row, column=0, columnspan=2, padx=20, pady=(0, 8), sticky="w"
            )
            row += 1
            bar = customtkinter.CTkProgressBar(card, mode="indeterminate", width=300)
            bar.grid(row=row, column=0, columnspan=2, padx=20, pady=(0, 20), sticky="ew")
            bar.start()
            row += 1
            self._poll_install()

        elif state == STATE_INSTALL_FAILED:
            reason = get_failure_reason()
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
                    "Couldn't reach the SIEM manager. Connect the VPN and retry."
                ),
                "enroll_failed": (
                    "Enrollment with the SIEM manager failed. "
                    "Connect the VPN and retry."
                ),
            }
            if reason.startswith("enroll_rc_"):
                msg = (
                    "Enrollment with the SIEM manager failed. "
                    "Connect the VPN and retry."
                )
            else:
                msg = _REASON_MSG.get(reason, f"Installation failed ({reason}).")
            customtkinter.CTkLabel(
                card, text=msg,
                font=customtkinter.CTkFont(size=13),
                text_color=_COLOR_ERROR, wraplength=460, justify="left",
            ).grid(row=row, column=0, columnspan=2, padx=20, pady=(0, 8), sticky="w")
            row += 1

            if reason != "user_canceled":
                customtkinter.CTkButton(
                    card, text="Retry", height=36, corner_radius=8,
                    font=customtkinter.CTkFont(size=13, weight="bold"),
                    command=self._retry_install,
                ).grid(row=row, column=0, columnspan=2, sticky="ew", padx=20, pady=(4, 20))
                row += 1
            else:
                self._install_btn = customtkinter.CTkButton(
                    card, text="Install Security", height=40, corner_radius=8,
                    font=customtkinter.CTkFont(size=14, weight="bold"),
                    command=self._start_installation,
                )
                self._install_btn.grid(
                    row=row, column=0, columnspan=2, sticky="ew", padx=20, pady=(4, 20)
                )
                row += 1

        return row

    # --- Card: Installed (status + controls) ---

    def _build_status_section(self, card, row):
        state = get_agent_status()
        is_running = state == "Running"
        status_color = _COLOR_OK if is_running else _COLOR_ERROR

        header = customtkinter.CTkFrame(card, fg_color="transparent")
        header.grid(row=row, column=0, columnspan=2, sticky="ew", padx=20, pady=(16, 4))
        header.grid_columnconfigure(1, weight=1)

        customtkinter.CTkLabel(
            header, text="\u25CF", text_color=status_color,
            font=customtkinter.CTkFont(size=16),
        ).grid(row=0, column=0, padx=(0, 8), sticky="w")

        customtkinter.CTkLabel(
            header, text="SIEM Agent",
            font=customtkinter.CTkFont(**_FONT_TITLE),
        ).grid(row=0, column=1, sticky="w")

        customtkinter.CTkLabel(
            header, text="Running" if is_running else "Stopped",
            text_color=status_color,
            font=customtkinter.CTkFont(family="Inter", size=14, weight="bold"),
        ).grid(row=0, column=2, padx=(8, 0), sticky="e")
        row += 1

        self._agent_toggle = customtkinter.CTkSwitch(
            card,
            text="Agent Service",
            command=lambda: self._toggle_agent(self._agent_toggle.get()),
            switch_width=46, switch_height=24,
            onvalue=1, offvalue=0,
        )
        if is_running:
            self._agent_toggle.select()
        else:
            self._agent_toggle.deselect()
        self._agent_toggle.grid(row=row, column=0, columnspan=2, padx=20, pady=(4, 12), sticky="w")
        row += 1

        row = self._add_separator(card, row)

        row = self._add_detail_rows(card, row, {
            "Status": state,
            "Agent Name": get_agent_name(),
            "Agent Group": get_agent_group(),
            "Manager": WAZUH_MANAGER,
            "Platform": f"{_PLATFORM} {platform.release()}",
        })

        return row

    # --- Key Restore (background thread) ---

    def _deferred_restore(self):
        """Wait briefly for launchd to finish bootstrapping, then restore keys if needed.

        After a fresh install the agent may appear "Stopped" for a few seconds
        while launchd is still starting wazuh-agentd.  Without this delay,
        restore_client_key_if_needed would fire immediately and show a
        pointless admin password prompt (the key is already in place).
        """
        import time

        # Allow launchd time to fully bootstrap wazuh-agentd after install.
        _LAUNCHD_SETTLE_SECONDS = 8
        time.sleep(_LAUNCHD_SETTLE_SECONDS)
        if get_agent_status() == "Running":
            return
        restore_client_key_if_needed()

    # --- Installation (background thread) ---

    def _start_installation(self):
        """User clicked Install — route to platform-specific install flow."""
        if _PLATFORM == "Darwin":
            return self._start_installation_darwin()
        return self._start_installation_direct()

    def _start_installation_direct(self):
        """Windows/Linux: run full_install() directly in a background thread."""
        if self._installing:
            return
        self._installing = True
        if hasattr(self, "_install_btn") and self._install_btn.winfo_exists():
            self._install_btn.configure(state="disabled", text="Installing...")
        if hasattr(self, "_install_bar") and self._install_bar.winfo_exists():
            self._install_bar.grid()
            self._install_bar.start()

        def _progress(msg):
            if hasattr(self, "_progress_label") and self._progress_label.winfo_exists():
                self.app.after(0, lambda: (
                    self._progress_label.configure(text=msg)
                    if self._progress_label.winfo_exists() else None
                ))

        def _done(success):
            self._installing = False
            if success:
                self.app.show_notification("SIEM agent installed!", type="success")
            else:
                self.app.show_notification("Installation failed", type="error")
            if hasattr(self, "main_container") and self.main_container.winfo_exists():
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
        """macOS: trigger via installer service state machine."""
        from plugins.wazuh.agent.installer_service import (
            get_install_state,
            retry,
            trigger_install,
            STATE_INSTALL_FAILED,
        )

        if self._installing:
            return
        if get_install_state() == STATE_INSTALL_FAILED:
            retry()
        self._installing = True
        self._install_poll_count = 0
        if hasattr(self, "_install_btn") and self._install_btn.winfo_exists():
            self._install_btn.configure(state="disabled", text="Installing...")

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
        """Poll installer service for progress, update UI."""
        from plugins.wazuh.agent.installer_service import poll_install_progress

        if not hasattr(self, "main_container") or not self.main_container.winfo_exists():
            self._installing = False
            return

        self._install_poll_count = getattr(self, "_install_poll_count", 0) + 1
        if self._install_poll_count > self._MAX_POLL_COUNT:
            self._installing = False
            self.app.show_notification("Installation timed out", type="error")
            self._refresh_screen()
            return

        result = poll_install_progress()
        step = result.get("step", "")

        _STEP_LABELS = {
            "install_pkg": "Installing package...",
            "patch_config": "Configuring agent...",
            "enrollment": "Enrolling agent...",
            "key_backup": "Backing up keys...",
            "launchd": "Starting agent service...",
            "done": "Finishing up...",
        }

        if hasattr(self, "_progress_label") and self._progress_label.winfo_exists():
            label = _STEP_LABELS.get(step, f"Installing... ({step})" if step else "Installing...")
            self._progress_label.configure(text=label)

        if result["finished"]:
            self._installing = False
            if result["success"]:
                self.app.show_notification("Security agent installed!", type="success")
            else:
                self.app.show_notification("Installation failed", type="error")
            self._refresh_screen()
        else:
            # Poll again in 3 seconds
            self.app.after(3000, self._poll_install)

    def _retry_download(self):
        """User clicked Retry on download failure."""
        from plugins.wazuh.agent.installer_service import retry
        threading.Thread(target=retry, daemon=True).start()
        # Refresh to show downloading state
        self.app.after(500, self._refresh_screen)

    def _retry_install(self):
        """User clicked Retry on install failure."""
        from plugins.wazuh.agent.installer_service import retry
        retry()
        self._refresh_screen()

    def _start_reinstall(self):
        """Re-enrollment: remove agent and run full_install directly."""
        if self._installing:
            return
        self._installing = True
        if hasattr(self, "_install_btn") and self._install_btn.winfo_exists():
            self._install_btn.configure(state="disabled", text="Reinstalling...")

        def _progress(msg):
            if hasattr(self, "_progress_label") and self._progress_label.winfo_exists():
                self.app.after(0, lambda: (
                    self._progress_label.configure(text=msg)
                    if self._progress_label.winfo_exists() else None
                ))

        def _run():
            if _PLATFORM == "Darwin":
                from plugins.wazuh.agent.wazuh_functions_darwin import remove_agent
            elif _PLATFORM == "Linux":
                from plugins.wazuh.agent.wazuh_functions_linux import remove_agent
            elif _PLATFORM == "Windows":
                from plugins.wazuh.agent.wazuh_functions_windows import remove_agent
            _progress("Removing old agent...")
            remove_agent()
            try:
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

    # --- Start / Stop toggle ---

    def _toggle_agent(self, switch_value):
        is_running = get_agent_status() == "Running"
        want_start = switch_value == 1

        if want_start == is_running:
            return

        if _PLATFORM != "Darwin" and want_start and not is_vpn_connected():
            self.app.show_notification("Connect VPN first", type="error")
            self._agent_toggle.deselect()
            return

        self._agent_toggle.configure(state="disabled")
        action = start_agent if want_start else stop_agent
        ok_msg = "SIEM agent started" if want_start else "SIEM agent stopped"
        fail_msg = "Failed to start agent" if want_start else "Failed to stop agent"

        def _run():
            success = action()
            def _on_done():
                self._agent_toggle.configure(state="normal")
                if success:
                    self.app.show_notification(ok_msg, type="info")
                else:
                    self.app.show_notification(fail_msg, type="error")
                    if not want_start:
                        self._agent_toggle.select()
                self._refresh_screen()
            self.app.after(0, _on_done)

        threading.Thread(target=_run, daemon=True).start()

    # --- Status polling ---

    def _start_status_polling(self):
        if not _platform_supported:
            return
        self._stop_status_polling()

        def poll():
            if not hasattr(self, "main_container") or not self.main_container.winfo_exists():
                self._status_poll_id = None
                return

            new_status = self.check_status()
            if new_status != self.status:
                logger.info(f"SIEM agent status changed: {self.status} -> {new_status}")
                self.status = new_status
                self._refresh_screen()
                return

            self._status_poll_id = self.app.after(_POLL_INTERVAL_MS, poll)

        self._status_poll_id = self.app.after(_POLL_INTERVAL_MS, poll)

    def _stop_status_polling(self):
        if self._status_poll_id:
            self.app.after_cancel(self._status_poll_id)
            self._status_poll_id = None

    # --- Helpers ---

    def _refresh_screen(self):
        """Refresh status and rebuild the screen if it is currently displayed.

        self.status is updated unconditionally so the dashboard tile reflects
        the new state even when the install finished after the user navigated
        away. The in-place rebuild only runs when the Endpoint screen is the one
        on display; otherwise the next navigation rebuilds it fresh (Endpoint
        isn't cached).
        """
        try:
            self.status = self.check_status()
        except Exception:
            pass
        current = getattr(self.app, "current_frame_name", "")
        if current != f"frame_{self.get_name()}":
            return
        if hasattr(self, "main_container"):
            try:
                self.main_container.destroy()
            except Exception:
                pass
        self.create_main_screen().grid(row=0, column=1, sticky="nsew")

    def destroy(self):
        """Clean up polling. Agent removal is handled by platform-specific uninstallers."""
        self._stop_status_polling()
