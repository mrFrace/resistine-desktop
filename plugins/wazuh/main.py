"""SIEM Agent Plugin (PyQt6).

Faithful PyQt6 port of the original CustomTkinter "Endpoint" screen. Installs
and manages the SIEM (Wazuh) agent from the Phoenix Desktop sidebar.

The screen is state-driven from a single bordered "Surface" card:

  * not installed  -> install card (state-machine on macOS, one-click elsewhere)
  * needs re-enroll -> re-enrollment card
  * installed      -> running/stopped status card with the Agent Service toggle

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

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QGridLayout,
    QFrame,
    QHBoxLayout,
    QLabel,
    QProgressBar,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from gui import theme
from gui.qt_widgets import scroll_page
from plugins.base_plugin import BasePlugin
from plugins.wazuh.config import WAZUH_MANAGER
from utils import settings
from utils.logger import logger

_PLATFORM = platform.system()
_PLUGIN_DIR = os.path.dirname(os.path.realpath(__file__))

# VPN gate (install on non-macOS requires an active VPN). Guarded so the
# plugin imports even when the VPN plugin is unavailable.
try:
    from plugins.vpn.main import is_vpn_connected
except Exception:  # pragma: no cover - defensive
    def is_vpn_connected():
        return True


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


# Colours (light, dark) mirroring the original CTk constants.
_COLOR_MUTED = ("#666666", "#aaaaaa")
_COLOR_ERROR = ("#C5221F", "#FF474C")
_COLOR_OK = ("#1E8E3E", "#2CC985")
_COLOR_ACCENT = ("#3a7ebf", "#5b9bd5")
_COLOR_WARN = ("#B45309", "#FBBF24")

_POLL_INTERVAL_MS = 10_000


def _c(pair) -> str:
    """Resolve a (light, dark) colour pair for the active mode."""
    return pair[1] if theme.is_dark() else pair[0]


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
        inner = QWidget()
        col = QVBoxLayout(inner)
        col.setContentsMargins(20, 40, 20, 20)
        col.setSpacing(5)

        title = QLabel("Unsupported Platform")
        title.setStyleSheet("font-size: 20px; font-weight: 700;")
        title.setAlignment(Qt.AlignmentFlag.AlignHCenter)
        col.addWidget(title)

        msg = QLabel(
            f"SIEM agent management is not yet available on {_PLATFORM}.")
        msg.setStyleSheet(f"font-size: 14px; color: {_c(_COLOR_MUTED)};")
        msg.setAlignment(Qt.AlignmentFlag.AlignHCenter)
        col.addWidget(msg)
        col.addStretch(1)
        return scroll_page(inner)

    def _agent_screen(self) -> QWidget:
        installed = _safe(is_agent_installed, False)
        logger.info(f"SIEM _agent_screen: is_agent_installed={installed}")
        reenroll = installed and _safe(needs_reenrollment, False)

        inner = QWidget()
        page = QVBoxLayout(inner)
        page.setContentsMargins(20, 10, 20, 10)
        page.setSpacing(0)

        # Single bordered, rounded "Surface" card (CTkFrame analogue).
        card = QFrame()
        card.setObjectName("Surface")
        body = QVBoxLayout(card)
        body.setContentsMargins(20, 16, 20, 20)
        body.setSpacing(0)
        self._card_body = body

        if reenroll:
            self._build_reenroll_section(body)
        elif installed:
            self._build_status_section(body)
        else:
            self._build_install_section(body)

        page.addWidget(card)
        page.addStretch(1)

        scr = scroll_page(inner)

        if installed and not reenroll:
            self._start_status_polling()
            # Refresh real state in the background and, if stopped, restore
            # client.keys from backup (covers key loss). Mirrors the original.
            threading.Thread(
                target=self._deferred_restore, daemon=True).start()

        return scr

    # ── UI helpers ─────────────────────────────────────────────────────

    def _add_separator(self, body: QVBoxLayout) -> None:
        body.addSpacing(4)
        div = QFrame()
        div.setFixedHeight(1)
        div.setObjectName("Divider")
        body.addWidget(div)
        body.addSpacing(4)

    def _title(self, body: QVBoxLayout, text: str) -> None:
        lbl = QLabel(text)
        lbl.setStyleSheet("font-size: 18px; font-weight: 700;")
        body.addSpacing(4)
        body.addWidget(lbl, 0, Qt.AlignmentFlag.AlignLeft)

    def _paragraph(self, body: QVBoxLayout, text: str, color) -> None:
        lbl = QLabel(text)
        lbl.setWordWrap(True)
        lbl.setStyleSheet(f"font-size: 13px; color: {_c(color)};")
        body.addWidget(lbl)

    def _add_detail_rows(self, body: QVBoxLayout, details: dict) -> None:
        # One QGridLayout, not stacked QHBoxLayouts: word-wrapped QLabels
        # inside nested box layouts break Qt's height-for-width propagation,
        # which painted the rows on top of each other. A grid computes each
        # row's height from the wrapped value correctly.
        g = QGridLayout()
        g.setContentsMargins(0, 8, 0, 0)
        g.setHorizontalSpacing(12)
        g.setVerticalSpacing(10)
        g.setColumnStretch(1, 1)
        for r, (label, value) in enumerate(details.items()):
            lk = QLabel(label)
            lk.setStyleSheet(f"font-size: 13px; color: {_c(_COLOR_MUTED)};")
            g.addWidget(lk, r, 0,
                        Qt.AlignmentFlag.AlignLeft
                        | Qt.AlignmentFlag.AlignVCenter)
            lv = QLabel(str(value))
            lv.setStyleSheet("font-size: 13px; font-weight: 700;")
            lv.setWordWrap(True)  # wrap instead of clipping when narrow
            lv.setAlignment(Qt.AlignmentFlag.AlignRight
                            | Qt.AlignmentFlag.AlignVCenter)
            g.addWidget(lv, r, 1)
        body.addLayout(g)

    # ── Card: Re-enrollment required (account change) ──────────────────

    def _build_reenroll_section(self, body: QVBoxLayout) -> None:
        enrolled = settings.get("wazuh", "enrolled_email", "unknown")
        current = settings.get("auth", "email", "unknown")

        self._title(body, "Re-enrollment Required")
        body.addSpacing(2)
        self._paragraph(
            body,
            f"This agent was enrolled under a different account ({enrolled}).\n"
            f"Reinstall to register it under the current account ({current}).",
            _COLOR_ERROR,
        )
        body.addSpacing(8)
        self._add_separator(body)
        body.addSpacing(8)

        self._progress_label = QLabel("")
        self._progress_label.setStyleSheet(
            f"font-size: 13px; color: {_c(_COLOR_ACCENT)};")
        body.addWidget(self._progress_label)
        body.addSpacing(4)

        self._install_btn = QPushButton("Reinstall Agent")
        self._install_btn.setMinimumHeight(40)
        self._install_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self._install_btn.clicked.connect(self._start_reinstall)
        body.addWidget(self._install_btn)

    # ── Card: Not installed ────────────────────────────────────────────

    def _build_install_section(self, body: QVBoxLayout) -> None:
        if _PLATFORM == "Darwin":
            return self._build_install_section_darwin(body)
        return self._build_install_section_direct(body)

    def _build_install_section_direct(self, body: QVBoxLayout) -> None:
        """Simple install card for Windows/Linux — requires VPN, one click."""
        self._title(body, "Security Agent")
        body.addSpacing(2)
        self._paragraph(
            body,
            "The SIEM agent collects security telemetry from this machine "
            "and reports to the Phoenix SIEM dashboard.",
            _COLOR_MUTED,
        )
        body.addSpacing(8)
        self._add_separator(body)

        self._add_detail_rows(body, {
            "Agent Name": _safe(get_agent_name, "—"),
            "Agent Group": _safe(get_agent_group, "—"),
            "Manager": WAZUH_MANAGER,
        })

        vpn_ok = _safe(is_vpn_connected, True)
        if not vpn_ok:
            body.addSpacing(8)
            warn = QLabel("Connect VPN to install the SIEM agent")
            warn.setWordWrap(True)
            warn.setStyleSheet(
                f"font-size: 13px; font-weight: 700; color: {_c(_COLOR_ERROR)};")
            body.addWidget(warn)

        body.addSpacing(8)
        self._progress_label = QLabel("")
        self._progress_label.setStyleSheet(
            f"font-size: 13px; color: {_c(_COLOR_ACCENT)};")
        body.addWidget(self._progress_label)
        body.addSpacing(4)

        # Indeterminate progress bar, hidden until install starts — the direct
        # install runs several download/MSI/elevation phases with only the text
        # label as feedback, which can look frozen on a slow machine.
        self._install_bar = QProgressBar()
        self._install_bar.setRange(0, 0)  # indeterminate
        body.addWidget(self._install_bar)
        self._install_bar.hide()
        body.addSpacing(4)

        self._install_btn = QPushButton("Install Agent")
        self._install_btn.setMinimumHeight(40)
        self._install_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self._install_btn.clicked.connect(self._start_installation)
        self._install_btn.setEnabled(bool(vpn_ok))
        body.addWidget(self._install_btn)

    def _build_install_section_darwin(self, body: QVBoxLayout) -> None:
        """State-machine install card for macOS — download + install phases."""
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

        self._title(body, "Security Agent")
        body.addSpacing(2)

        # Without login the download normally never starts, but a user who
        # imported a VPN config manually (or removed the Login plugin) still
        # has a valid path to enrollment — offer an explicit install attempt
        # instead of the log-in dead end.
        can_attempt = (self._has_vpn_config()
                       or not self._login_plugin_installed())

        if state == STATE_NOT_STARTED and not logged_in and not can_attempt:
            self._paragraph(
                body, "Log in to enable endpoint protection.", _COLOR_MUTED)
            body.addSpacing(8)

        elif state == STATE_NOT_STARTED and not logged_in:
            self._paragraph(
                body,
                "You're not signed in, but a VPN configuration is available "
                "— you can install the security agent now.",
                _COLOR_MUTED,
            )
            body.addSpacing(8)
            install_btn = QPushButton("Download && Install Agent")
            install_btn.setMinimumHeight(40)
            install_btn.setCursor(Qt.CursorShape.PointingHandCursor)
            install_btn.clicked.connect(self._force_download_start)
            body.addWidget(install_btn)
            body.addSpacing(8)

        elif state in (STATE_NOT_STARTED, STATE_DOWNLOADING):
            self._paragraph(
                body, "Downloading security agent...", _COLOR_ACCENT)
            body.addSpacing(8)
            bar = QProgressBar()
            bar.setRange(0, 0)  # indeterminate
            body.addWidget(bar)
            body.addSpacing(8)

        elif state == STATE_DOWNLOAD_FAILED:
            reason = _safe(get_failure_reason, "")
            _REASON_MSG = {
                "dns_failed": "Download failed — check your internet connection.",
                "network_timeout": "Download timed out. Please try again.",
                "signature_invalid": "Package signature invalid. Will retry with a fresh download.",
            }
            msg = _REASON_MSG.get(reason, f"Download failed ({reason}).")
            self._paragraph(body, msg, _COLOR_ERROR)
            body.addSpacing(8)
            retry_btn = QPushButton("Retry")
            retry_btn.setMinimumHeight(36)
            retry_btn.setCursor(Qt.CursorShape.PointingHandCursor)
            retry_btn.clicked.connect(self._retry_download)
            body.addWidget(retry_btn)

        elif state == STATE_DOWNLOADED:
            self._paragraph(
                body,
                "We're about to install a system security component "
                "that monitors your device for threats.",
                _COLOR_MUTED,
            )
            self._paragraph(
                body,
                "This requires your password to allow the installation.",
                _COLOR_MUTED,
            )
            body.addSpacing(8)
            self._add_separator(body)
            self._add_detail_rows(body, {
                "Agent Name": _safe(get_agent_name, "—"),
                "Agent Group": _safe(get_agent_group, "—"),
                "Manager": WAZUH_MANAGER,
            })
            body.addSpacing(8)
            self._progress_label = QLabel("")
            self._progress_label.setStyleSheet(
                f"font-size: 13px; color: {_c(_COLOR_ACCENT)};")
            body.addWidget(self._progress_label)
            body.addSpacing(4)
            self._install_btn = QPushButton("Install Security")
            self._install_btn.setMinimumHeight(40)
            self._install_btn.setCursor(Qt.CursorShape.PointingHandCursor)
            self._install_btn.clicked.connect(self._start_installation)
            body.addWidget(self._install_btn)

        elif state == STATE_INSTALLING:
            self._progress_label = QLabel("Installing...")
            self._progress_label.setStyleSheet(
                f"font-size: 13px; color: {_c(_COLOR_ACCENT)};")
            body.addWidget(self._progress_label)
            body.addSpacing(8)
            bar = QProgressBar()
            bar.setRange(0, 0)
            body.addWidget(bar)
            body.addSpacing(8)
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
            self._paragraph(body, msg, _COLOR_ERROR)
            body.addSpacing(8)
            if reason != "user_canceled":
                retry_btn = QPushButton("Retry")
                retry_btn.setMinimumHeight(36)
                retry_btn.setCursor(Qt.CursorShape.PointingHandCursor)
                retry_btn.clicked.connect(self._retry_install)
                body.addWidget(retry_btn)
            else:
                self._install_btn = QPushButton("Install Security")
                self._install_btn.setMinimumHeight(40)
                self._install_btn.setCursor(Qt.CursorShape.PointingHandCursor)
                self._install_btn.clicked.connect(self._start_installation)
                body.addWidget(self._install_btn)

    # ── Card: Installed (status + controls) ────────────────────────────

    def _build_status_section(self, body: QVBoxLayout) -> None:
        state = _safe(get_agent_status, "Stopped")
        self._cached_state = state
        is_running = state == "Running"
        # Live manager-connection status \u2014 distinct from "process running".
        # Resolution: wazuh-agentd.state file → unprivileged socket probe
        # (the state file is root-owned on macOS/Linux GUI sessions, which
        # used to read as "Unknown" on perfectly healthy agents) →
        # ossec.log tail. "disconnected" remains the only hard fault.
        connection = (_safe(get_agent_connection, "unknown")
                      if is_running else "unknown")
        self._cached_conn = connection
        not_connected = is_running and connection == "disconnected"

        if not is_running:
            status_color, status_text = _COLOR_ERROR, "Stopped"
        elif not_connected:
            status_color, status_text = _COLOR_ERROR, "Not Connected"
        elif connection == "connected":
            status_color, status_text = _COLOR_OK, "Connected"
        elif connection == "pending":
            status_color, status_text = _COLOR_WARN, "Connecting…"
        else:
            status_color, status_text = _COLOR_OK, "Running"

        # Header: indicator dot + "SIEM Agent" + Running/Stopped label.
        body.addSpacing(4)
        header = QHBoxLayout()
        dot = QLabel("●")
        dot.setStyleSheet(
            f"font-size: 16px; color: {_c(status_color)};")
        header.addWidget(dot, 0, Qt.AlignmentFlag.AlignLeft)
        header.addSpacing(8)
        name = QLabel("SIEM Agent")
        name.setStyleSheet("font-size: 18px; font-weight: 700;")
        header.addWidget(name, 0, Qt.AlignmentFlag.AlignLeft)
        header.addStretch(1)
        self._status_label = QLabel(status_text)
        self._status_label.setStyleSheet(
            f"font-size: 14px; font-weight: 700; color: {_c(status_color)};")
        header.addWidget(self._status_label, 0, Qt.AlignmentFlag.AlignRight)
        body.addLayout(header)

        # Agent Service toggle — the same sliding switch the VPN page uses.
        from plugins.vpn.qt_toggle import ToggleSwitch

        body.addSpacing(4)
        toggle_row = QHBoxLayout()
        toggle_label = QLabel("Agent Service")
        toggle_label.setStyleSheet("font-size: 14px;")
        toggle_row.addWidget(toggle_label, 0, Qt.AlignmentFlag.AlignVCenter)
        toggle_row.addStretch(1)
        self._agent_toggle = ToggleSwitch()
        self._agent_toggle.setChecked(is_running)
        self._agent_toggle.toggled.connect(self._toggle_agent)
        toggle_row.addWidget(
            self._agent_toggle, 0, Qt.AlignmentFlag.AlignVCenter)
        body.addLayout(toggle_row)
        body.addSpacing(8)

        self._add_separator(body)

        self._add_detail_rows(body, {
            "Status": state,
            # "Unknown" reads as a fault to users; a quiet dash is honest
            # ("we can't read it") without implying something is wrong.
            "Connection": ("—" if connection == "unknown"
                           else connection.capitalize()),
            "Agent Name": _safe(get_agent_name, "—"),
            "Agent Group": _safe(get_agent_group, "—"),
            "Manager": WAZUH_MANAGER,
            "Platform": f"{_PLATFORM} {platform.release()}",
        })

        # Recovery affordance — bottom of the card, and ONLY when the
        # connection is not confirmed healthy. A connected agent shows no
        # Reconnect at all. Running-but-not-connected (e.g. the key was
        # invalidated server-side after a reinstall) gets an explanation +
        # button; the button re-registers under a fresh identity — the
        # actual fix, since a plain toggle restarts the daemon with the
        # same dead key. Recovery is user-initiated (one admin prompt),
        # never a surprise background dialog.
        if is_running and connection != "connected":
            body.addSpacing(12)
            self._add_separator(body)
            if not_connected:
                warn = QLabel(
                    "Agent is running but not connected to the SIEM "
                    "manager. If the old agent was removed on the server, "
                    "reconnect to re-register under a new identity.")
                warn.setStyleSheet(
                    f"font-size: 13px; color: {_c(_COLOR_ERROR)};")
            else:
                warn = QLabel(
                    "Connection can't be confirmed. If the dashboard "
                    "shows this device offline, reconnect to re-register "
                    "the agent.")
                warn.setStyleSheet(
                    f"font-size: 13px; color: {_c(_COLOR_MUTED)};")
            warn.setWordWrap(True)

            self._reconnect_btn = QPushButton("Reconnect")
            self._reconnect_btn.setMinimumHeight(32)
            self._reconnect_btn.setCursor(Qt.CursorShape.PointingHandCursor)
            accent = _c(_COLOR_ACCENT)
            self._reconnect_btn.setStyleSheet(
                f"QPushButton {{ background: transparent; color: {accent}; "
                f"border: 1px solid {accent}; border-radius: 8px; "
                f"padding: 4px 18px; font-size: 13px; font-weight: 600; }}"
                f"QPushButton:hover {{ background-color: {accent}; "
                f"color: #ffffff; }}"
                f"QPushButton:disabled {{ color: {_c(_COLOR_MUTED)}; "
                f"border-color: {_c(_COLOR_MUTED)}; }}")
            self._reconnect_btn.clicked.connect(self._reconnect_agent)

            recover_row = QHBoxLayout()
            recover_row.setSpacing(16)
            recover_row.addWidget(warn, 1, Qt.AlignmentFlag.AlignVCenter)
            recover_row.addWidget(
                self._reconnect_btn, 0, Qt.AlignmentFlag.AlignVCenter)
            body.addLayout(recover_row)
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
        # Re-check the VPN gate exactly as the original refuses without it.
        if not _safe(is_vpn_connected, True):
            self.app.show_notification(
                "Connect VPN to install the SIEM agent", type="error")
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

        if _PLATFORM != "Darwin" and want_start and not _safe(
                is_vpn_connected, True):
            self.app.show_notification("Connect VPN first", type="error")
            self._set_toggle_checked(False)
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
