"""Antivirus plugin for Phoenix Desktop (PyQt6).

Faithful PyQt6 port of the original CustomTkinter screen. Provides
file/directory scanning, real-time protection status, signature updates,
quarantine management, whitelist + scan exclusions (settings sub-view) via
ClamAV (macOS/Linux) or Windows Defender.

Author: Resistine Team
Copyright (c) Resistine 2025
Licensed under the GNU General Public License v2 or later
"""
from __future__ import annotations

import os
import platform
import random
import threading
import time

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QPushButton,
    QWidget,
)

from gui import theme
from gui.page_kit import SlideStack
from plugins.antivirus import clamav
from plugins.base_plugin import BasePlugin
from utils import settings
from utils.logger import logger

_PLUGIN_DIR = os.path.dirname(os.path.realpath(__file__))


def _send_notification(title: str, body: str, urgency: str = "critical"):
    """Send a native OS notification (macOS + Windows + Linux)."""
    import platform as _platform

    system = _platform.system()
    if system == "Darwin":
        _send_notification_darwin(title, body)
    elif system == "Windows":
        _send_notification_windows(title, body)
    elif system == "Linux":
        try:
            from utils.notifications import send as _send

            _send(title, body, urgency=urgency)
        except Exception as e:
            logger.debug(f"Linux notification failed: {e}")


def _send_notification_darwin(title: str, body: str):
    """macOS: NSUserNotification or osascript fallback."""
    try:
        from Foundation import NSUserNotification, NSUserNotificationCenter

        notification = NSUserNotification.alloc().init()
        notification.setTitle_(title)
        notification.setInformativeText_(body)
        notification.setSoundName_("default")
        center = NSUserNotificationCenter.defaultUserNotificationCenter()
        center.deliverNotification_(notification)
    except ImportError:
        import subprocess

        safe_body = body.replace("\\", "\\\\").replace('"', '\\"')
        safe_title = title.replace("\\", "\\\\").replace('"', '\\"')
        script = (
            f'display notification "{safe_body}" '
            f'with title "{safe_title}" sound name "default"'
        )
        try:
            subprocess.Popen(
                ["osascript", "-e", script],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except Exception:
            pass


_TOAST_COUNTER = 0

# PowerShell's registered AUMID — ensures toasts always display reliably.
_PS_AUMID = (
    r"{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}"
    r"\WindowsPowerShell\v1.0\powershell.exe"
)


def _send_notification_windows(title: str, body: str):
    """Windows 10/11: native Action Center toast with Phoenix logo.

    Toast XML is written to a temp file and read by PowerShell via
    Get-Content -Raw rather than interpolated into the script. The previous
    inline escape (replacing `"` with backtick-`"`) broke for threat names
    containing backticks, dollar signs, or backslashes — which would either
    break out of the PowerShell string or be eaten by PowerShell's parser
    before LoadXml ever saw the content. The tempfile detour means the
    notification body travels as bytes, never as PowerShell source.
    """
    global _TOAST_COUNTER
    import subprocess
    import tempfile

    # Resolve logo path (works for both dev and PyInstaller builds)
    logo = os.path.join(
        os.path.dirname(os.path.dirname(_PLUGIN_DIR)),
        "resources", "icons", "app_icon.png",
    )

    def _esc(s: str) -> str:
        """Escape for XML content."""
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    esc_title = _esc(title)
    esc_body = _esc(body)

    # Unique tag per toast so Windows doesn't suppress repeats
    _TOAST_COUNTER += 1
    tag = f"resistine_{_TOAST_COUNTER}"

    img_xml = ""
    if os.path.isfile(logo):
        img_xml = f'<image placement="appLogoOverride" src="{_esc(logo)}" />'

    xml_str = (
        "<toast>"
        '<visual><binding template="ToastGeneric">'
        f"<text>{esc_title}</text>"
        f"<text>{esc_body}</text>"
        f"{img_xml}"
        "</binding></visual>"
        "</toast>"
    )

    # Write XML to a temp file so PowerShell can read it as raw bytes —
    # avoids any need to escape the threat name / body for the shell.
    xml_path = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".xml", prefix="resistine_toast_",
            encoding="utf-8", delete=False,
        ) as tf:
            tf.write(xml_str)
            xml_path = tf.name
    except Exception as e:
        logger.debug(f"Failed to write toast XML tempfile: {e}")
        return

    # PowerShell loads the XML from disk via Get-Content -Raw, so the only
    # untrusted-ish value left in the script is the path itself (which we
    # control) and the AUMID / tag (also controlled).
    safe_path = xml_path.replace("'", "''")  # PS single-quote escape
    ps_script = (
        "[Windows.UI.Notifications.ToastNotificationManager,"
        " Windows.UI.Notifications, ContentType = WindowsRuntime]"
        " | Out-Null; "
        "[Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom,"
        " ContentType = WindowsRuntime] | Out-Null; "
        f"$raw = Get-Content -Raw -LiteralPath '{safe_path}'; "
        "$xml = New-Object Windows.Data.Xml.Dom.XmlDocument; "
        "$xml.LoadXml($raw); "
        "$toast = [Windows.UI.Notifications.ToastNotification]::new($xml); "
        f"$toast.Tag = '{tag}'; "
        "[Windows.UI.Notifications.ToastNotificationManager]"
        f"::CreateToastNotifier('{_PS_AUMID}').Show($toast); "
        # Best-effort: clean the tempfile from PS once Windows has the toast.
        f"Remove-Item -LiteralPath '{safe_path}' -ErrorAction SilentlyContinue"
    )
    try:
        subprocess.Popen(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass",
             "-Command", ps_script],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=0x08000000,
        )
    except Exception as e:
        logger.debug(f"Failed to spawn toast powershell: {e}")
        # Fall back to cleaning up the tempfile ourselves on spawn failure.
        try:
            os.unlink(xml_path)
        except OSError:
            pass


class Plugin(BasePlugin):
    """Antivirus plugin powered by ClamAV / Defender (PyQt6)."""

    defer_reveal_until_settled = True

    def __init__(self, app):
        super().__init__(
            id="012",
            version="2026.01.04-alpha",
            order=6,
            name="Antivirus",
            status=None,
            description="Scan, quarantine and protect against malware.",
            supported_systems=["Darwin", "Linux", "Windows"],
            translations={"US": "Antivirus", "ES": "Antivirus",
                          "FR": "Antivirus"},
            icon_light_path=os.path.join(_PLUGIN_DIR, "antivirus_light.png"),
            icon_dark_path=os.path.join(_PLUGIN_DIR, "antivirus_dark.png"),
            uninstall_enabled=True,
        )
        self.app = app
        self._auto_update_on = settings.get(
            "antivirus", "auto_update_enabled", True,
        )
        self._action_buttons: dict = {}
        self._banner_frame = None
        self._banner_label = None
        self._banner_subtitle = None
        self._banner_action_btn = None
        self._banner_progress = None
        self._scanning = False
        self._scan_handle = None
        self._scan_lock = threading.Lock()
        self._cancel_requested = False
        self._scan_log_buffer: list[str] = []
        self._scan_file_count = 0
        self._scan_total_files = 0
        self._last_state = None
        self._last_status = None
        self._auto_update_timer = None
        self._auto_update_stop = threading.Event()
        self._rtd_watcher = None
        self._settings_gear_btn = None
        self._current_view = "main"
        self._init_ready = threading.Event()
        self._win_rtd_thread = None
        self._rtd_stop = threading.Event()
        self._seen_threat_ids: set[tuple[str, str]] = set()
        self._destroyed = False
        self._status_poll_token = None
        self.main_container = None
        self.status = self.get_status()

        # macOS: register system-level ClamAV daemons + resume pending install.
        if platform.system() == "Darwin":
            def _darwin_daemon_init():
                try:
                    clamav.ensure_daemons_registered()
                except Exception as exc:
                    logger.error(
                        f"Antivirus: ensure_daemons_registered failed: {exc}")
                try:
                    clamav.refresh_system_configs()
                except Exception as exc:
                    logger.error(
                        f"Antivirus: refresh_system_configs failed: {exc}")
                self._init_ready.set()
                try:
                    from plugins.antivirus.installer_service import (
                        check_and_advance,
                    )
                    check_and_advance()
                except Exception:
                    pass

            threading.Thread(target=_darwin_daemon_init, daemon=True).start()
        else:
            self._init_ready.set()

        # Pre-start clamd so the signature DB is loaded before first scan.
        threading.Thread(target=self._ensure_clamd_warm, daemon=True).start()

        # Poll status once at startup so the sidebar icon shows correct state.
        threading.Thread(target=self._poll_initial_status, daemon=True).start()

        # On macOS, signature auto-updates are owned by the OS-level freshclam
        # LaunchDaemon (registered via _darwin_daemon_init above), not an
        # in-process thread — so we do NOT start the scheduler here.
        if platform.system() != "Darwin" and self._auto_update_on:
            self._start_auto_update_scheduler()

        if platform.system() == "Windows":
            threading.Thread(
                target=self._deferred_start_win_rtd, daemon=True,
            ).start()

    _INITIAL_POLL_RETRIES = 8
    _INITIAL_POLL_INTERVAL = 2

    def _poll_initial_status(self):
        """Poll daemon state so the sidebar icon AND dashboard tile are right."""
        self._init_ready.wait(timeout=10)
        for attempt in range(1 + self._INITIAL_POLL_RETRIES):
            try:
                status = clamav.get_realtime_status()
            except Exception:
                logger.debug("Antivirus: initial status poll failed")
                return
            self._last_state = status.get("state")
            self._last_status = status
            new_status = self.check_status()
            # Refresh the dashboard tile when the real status finally lands.
            # Without this, the tile keeps the stale "Warning" set in __init__
            # (before this async poll ran) — visible on macOS, where the poll
            # waits up to 10s for daemon init before the first read.
            if new_status != self.status:
                self.status = new_status
                try:
                    self.app.after(
                        0, lambda: self.app.update_plugin(self.id))
                except Exception:
                    pass

            if status.get("runtime_state") != "offline":
                return
            if status.get("setup_state") != "completed":
                return
            if attempt < self._INITIAL_POLL_RETRIES:
                time.sleep(self._INITIAL_POLL_INTERVAL)

    @staticmethod
    def _ensure_clamd_warm():
        """Start clamd if it isn't already running (and a DB exists)."""
        try:
            if clamav.is_clamd_running() or not clamav.has_database():
                return
            if not clamav.is_clamav_installed():
                return
            logger.info("Antivirus: pre-starting clamd for faster scans")
            ok, msg = clamav.start_clamd()
            if not ok:
                logger.warning(f"Antivirus: clamd warm-up failed: {msg}")
        except Exception:
            logger.debug("Antivirus: clamd warm-up errored")

    def check_status(self):
        """Cheap, cached status — never calls the blocking backend."""
        if self._last_state == "protected":
            return "OK"
        if self._last_state == "error":
            return "Error"
        return "Warning"

    def on_theme_changed(self):
        """Rebuild the AV screen on theme toggle to re-evaluate hardcoded colours."""
        if getattr(self, "app", None):
            self.app.update_plugin(self.id)

    def _is_active_screen(self):
        try:
            return getattr(self.app, "_current_main_screen", None) is (
                self.main_container)
        except Exception:
            return True

    def screen_signature(self):
        """Cache the antivirus screen across navigation (rebuild on theme)."""
        try:
            return ("antivirus", theme.get_mode())
        except Exception:
            return None

    def on_screen_shown(self):
        """Re-sync live data when returning to the cached screen."""
        try:
            self.app.after(0, self._refresh_db_info)
            self.app.after(0, self._refresh_quarantine)
            self.app.after(0, self._refresh_whitelist)
            self.app.after(0, self._refresh_exclusions)
            self.app.after(0, self._update_realtime_status)
        except Exception:
            pass

    # ── Main screen ──────────────────────────────────────────

    def create_main_screen(self):
        from plugins.antivirus import qt_ui

        self._destroyed = False
        self._current_view = "main"

        self._view_stack = SlideStack(fit_height=False)
        self._main_view = qt_ui.build_main_view(self).widget
        self._view_stack.addWidget(self._main_view)
        # Settings view: built eagerly but only shown on gear click.
        self._settings_view = qt_ui.build_settings_view(self).widget
        self._view_stack.addWidget(self._settings_view)
        self._view_stack.setCurrentWidget(self._main_view)
        self.main_container = self._view_stack

        # Populate live data after build (non-blocking, marshalled).
        self.app.after(100, self._refresh_db_info)
        self.app.after(200, self._refresh_whitelist)
        self.app.after(300, self._refresh_quarantine)
        self.app.after(400, self._refresh_exclusions)

        # Apply any known status immediately so the banner doesn't flash.
        if self._last_status is not None:
            self._apply_realtime_status_ui(self._last_status)
        self.app.after(500, self._update_realtime_status)

        # Restore scan UI if a scan is still running from before navigation.
        if self._scanning:
            self._restore_scan_ui()

        # Start the recurring status poll.
        self.app.after(2000, self._status_poll_tick)

        return self.main_container

    def destroy(self):
        self._destroyed = True
        if self._status_poll_token is not None:
            try:
                self.app.after_cancel(self._status_poll_token)
            except Exception:
                pass
            self._status_poll_token = None
        self._stop_rtd_watcher()
        self._stop_win_rtd_watcher()
        self._stop_auto_update_scheduler()
        self._action_buttons = {}
        self._banner_frame = None
        self._banner_label = None
        self._banner_subtitle = None
        self._banner_action_btn = None
        self._banner_progress = None
        self._settings_gear_btn = None
        self._current_view = "main"
        if self.main_container is not None:
            try:
                self.main_container.deleteLater()
            except Exception:
                pass
            self.main_container = None

    # ── Recurring status poll ────────────────────────────────

    def _status_poll_tick(self):
        """Re-arming poll: read status on a worker, marshal back, re-arm."""
        if self._destroyed:
            return

        def _check():
            try:
                status = clamav.get_realtime_status()
            except Exception:
                status = None
            try:
                self.app.after(0, self._on_status_poll_result, status)
            except Exception:
                pass

        threading.Thread(target=_check, daemon=True).start()

    def _on_status_poll_result(self, status):
        if self._destroyed:
            return
        if status is not None:
            self._apply_realtime_status(status)
        # Re-arm. Faster cadence during active setup.
        setup_active = bool(
            self._last_status
            and self._last_status.get("setup_state", "completed") != "completed"
        )
        interval = 2000 if setup_active else 10000
        try:
            self._status_poll_token = self.app.after(
                interval, self._status_poll_tick)
        except Exception:
            pass

    # ── View Switching ─────────────────────────────────────

    def _show_settings_view(self):
        if self._current_view == "settings":
            return
        self._view_stack.push(self._settings_view)
        self._current_view = "settings"
        self.app.after(20, self._refresh_whitelist)
        self.app.after(40, self._refresh_exclusions)
        # Re-sync the cached SIEM forwarding controls with the live agent
        # state (the agent may have been installed since the view was built).
        self.app.after(60, self._refresh_siem_switch)

    def _show_main_view(self):
        if self._current_view == "main":
            return
        self._view_stack.back(self._main_view)
        self._current_view = "main"

    # ── Realtime status handling ─────────────────────────────

    def _update_realtime_status(self):
        """Poll daemon state on a worker thread and update the banner."""
        def _check():
            try:
                status = clamav.get_realtime_status()
            except Exception:
                logger.debug("Antivirus: error during status poll")
                return
            try:
                self.app.after(0, self._apply_realtime_status, status)
            except Exception:
                logger.debug("Antivirus: app destroyed during status check")

        threading.Thread(target=_check, daemon=True).start()

    def _apply_realtime_status(self, status: dict):
        prev_setup = (
            self._last_status.get("setup_state") if self._last_status else None
        )
        state = status.get("state")
        self._last_state = state
        self._last_status = status
        self.status = self.check_status()
        try:
            self._apply_realtime_status_ui(status)
        except Exception:
            pass
        if status.get("setup_state") == "completed" and prev_setup != "completed":
            self._refresh_db_info()

        clamonacc_on = bool(status.get("clamonacc_running"))
        if clamonacc_on and self._rtd_watcher is None:
            self._start_rtd_watcher()
        elif not clamonacc_on and self._rtd_watcher is not None:
            self._stop_rtd_watcher()

        if platform.system() == "Windows":
            if clamonacc_on and self._win_rtd_thread is None:
                self._start_win_rtd_watcher()
            elif not clamonacc_on and self._win_rtd_thread is not None:
                self._stop_win_rtd_watcher()

    def _apply_realtime_status_ui(self, status: dict):
        """Update the banner widgets from the two-dimensional state model."""
        if self._banner_frame is None:
            return
        if not self._is_active_screen():
            return

        setup_state = status.get("setup_state", "completed")
        runtime_state = status.get("runtime_state", "offline")

        _is_win = platform.system() == "Windows"
        is_linux = platform.system() == "Linux"
        try:
            _engine = clamav.engine_name()
        except Exception:
            _engine = "ClamAV"

        if not status.get("installed"):
            cfg = {
                "kind": "error", "title": "Not Installed",
                "subtitle": (
                    f"{_engine} is not available."
                    if _is_win
                    else "ClamAV is not installed. Tap Install ClamAV to fetch "
                    "it from your distribution's package manager."
                    if is_linux else
                    "ClamAV binaries were not found.\n"
                    "Reinstall Phoenix or run the build script "
                    "to set up antivirus protection."
                ),
                "action": (
                    ("Install ClamAV", self._start_system_setup)
                    if is_linux else None
                ),
            }
        elif setup_state != "completed":
            cfg = self._get_setup_banner_cfg(setup_state, status)
        else:
            cfg = self._get_runtime_banner_cfg(runtime_state, status)

        from plugins.antivirus.qt_ui import set_status_pill
        set_status_pill(self._banner_frame, cfg["kind"], cfg["title"])
        self._banner_subtitle.setText(cfg["subtitle"])

        show_progress = setup_state in ("seeding_db", "installing")
        if self._banner_progress:
            self._banner_progress.setVisible(show_progress)

        if cfg["action"]:
            label, handler = cfg["action"]
            self._banner_action_btn.setText(label)
            try:
                self._banner_action_btn.clicked.disconnect()
            except Exception:
                pass
            self._banner_action_btn.clicked.connect(
                lambda _=False, h=handler: h())
            self._banner_action_btn.setEnabled(True)
            self._banner_action_btn.show()
        else:
            self._banner_action_btn.hide()

        # An active scan wins: the recurring status poll must not re-enable
        # the scan buttons mid-scan.
        can_scan = bool(status.get("installed") and status.get("db_present")
                        and not self._scanning)
        self._set_scan_buttons_state("normal" if can_scan else "disabled")

    def _get_setup_banner_cfg(self, setup_state, status) -> dict:
        if setup_state == "seeding_db":
            return {
                "kind": "warn", "title": "Downloading Definitions...",
                "subtitle": "Downloading malware signature database. "
                            "This may take a few minutes.",
                "action": None,
            }
        if setup_state == "seed_failed":
            try:
                from plugins.antivirus.installer_service import (
                    get_failure_reason,
                )
                reason = get_failure_reason()
            except Exception:
                reason = ""
            reason_text = {
                "dns_failed": "Could not reach the update server. "
                              "Check your internet connection.",
                "network_timeout": "Download timed out. "
                                   "Check your internet connection.",
                "certs_missing": "Certificate verification failed. "
                                 "Try reinstalling Phoenix.",
                "binary_missing": "ClamAV binaries not found. "
                                  "Reinstall Phoenix.",
                "partial_download": "Download was incomplete. "
                                    "Tap Retry to try again.",
                "freshclam_failed": "Signature download failed. "
                                    "Tap Retry to try again.",
            }.get(reason, "Download failed. Tap Retry to try again.")
            return {
                "kind": "error", "title": "Download Failed",
                "subtitle": reason_text,
                "action": ("Retry", self._retry_setup),
            }
        if setup_state == "db_ready":
            return {
                "kind": "warn", "title": "Set Up Protection",
                "subtitle": (
                    "Signature database downloaded. "
                    "Tap below to enable real-time protection "
                    "(requires administrator password)."
                ),
                "action": ("Set Up Protection", self._start_system_setup),
            }
        if setup_state == "installing":
            return {
                "kind": "warn", "title": "Setting Up...",
                "subtitle": "Configuring system-level protection. "
                            "This may take a moment.",
                "action": None,
            }
        if setup_state == "install_failed":
            try:
                from plugins.antivirus.installer_service import (
                    get_failure_reason,
                )
                reason = get_failure_reason()
            except Exception:
                reason = ""
            if reason == "user_canceled":
                subtitle = "Setup was cancelled. Tap Retry when ready."
            else:
                subtitle = "System setup failed. Tap Retry to try again."
            return {
                "kind": "error", "title": "Setup Failed",
                "subtitle": subtitle,
                "action": ("Retry", self._retry_setup),
            }
        return {
            "kind": "warn", "title": "Starting Setup...",
            "subtitle": "Preparing to download malware definitions...",
            "action": None,
        }

    def _get_runtime_banner_cfg(self, runtime_state, status) -> dict:
        if runtime_state == "healthy":
            return {
                "kind": "ok", "title": "Protected",
                "subtitle": (
                    "Real-time malware protection is active"
                    if status.get("clamonacc_running")
                    else "On-demand scanning is active"
                ),
                "action": None,
            }
        if runtime_state == "degraded":
            return {
                "kind": "warn", "title": "Protection Degraded",
                "subtitle": (
                    "Scanning is available but real-time file monitoring "
                    "is not running. Full Disk Access may be needed."
                ),
                "action": ("Open Settings", self._safe(clamav, "open_fda_settings")),
            }
        if runtime_state == "approval_required":
            return {
                "kind": "warn", "title": "Approval Required",
                "subtitle": (
                    "Enable ClamAV daemons in System Settings "
                    "› General › Login Items "
                    "for real-time protection."
                ),
                "action": ("Open Login Items",
                           self._safe(clamav, "open_login_items_settings")),
            }
        if runtime_state == "fda_required":
            return {
                "kind": "warn", "title": "Full Disk Access Required",
                "subtitle": (
                    "Phoenix needs Full Disk Access to monitor files "
                    "in real time. Grant access in System Settings "
                    "› Privacy & Security › Full Disk Access."
                ),
                "action": ("Open Settings", self._safe(clamav, "open_fda_settings")),
            }
        _is_win = platform.system() == "Windows"
        is_linux = platform.system() == "Linux"
        try:
            _engine = clamav.engine_name()
        except Exception:
            _engine = "ClamAV"
        return {
            "kind": "error", "title": "Protection Offline",
            "subtitle": (
                f"{_engine} protection is offline"
                if _is_win
                else "ClamAV daemons are not running."
                if status.get("in_bundle")
                else (
                    "On-demand scanning available. "
                    "Enable systemd to start real-time protection."
                    if is_linux else
                    "On-demand scanning available. "
                    "Install the Phoenix app for real-time protection."
                )
            ),
            "action": (
                ("Start Protection", self._start_protection)
                if (_is_win or status.get("in_bundle"))
                else None
            ),
        }

    @staticmethod
    def _safe(module, name):
        """Return module.name if it exists, else a no-op (platform guard)."""
        fn = getattr(module, name, None)
        return fn if callable(fn) else (lambda *a, **k: None)

    # ── RTD Threat Watcher (Windows Defender) ─────────────────

    def _deferred_start_win_rtd(self):
        self._init_ready.wait(timeout=15)
        try:
            status = clamav.get_realtime_status()
            if status.get("clamonacc_running"):
                self._start_win_rtd_watcher()
            else:
                logger.info(
                    "Antivirus: Defender RT not active, skipping RTD watcher")
        except Exception:
            logger.debug("Antivirus: could not check Defender RTD status")

    def _start_win_rtd_watcher(self):
        if self._win_rtd_thread is not None:
            return
        self._rtd_stop.clear()
        self._win_rtd_thread = threading.Thread(
            target=self._rtd_poll_loop, daemon=True,
        )
        self._win_rtd_thread.start()
        logger.info("Antivirus: Windows RTD watcher started")

    def _stop_win_rtd_watcher(self):
        if self._win_rtd_thread is None:
            return
        self._rtd_stop.set()
        self._win_rtd_thread = None
        logger.info("Antivirus: Windows RTD watcher stopped")

    def _rtd_poll_loop(self):
        while not self._rtd_stop.is_set():
            try:
                threats = clamav.get_recent_threats(since_seconds=30)
                new_threats = []
                for t in threats:
                    resource = (t.get("resources") or [""])[0]
                    key = (t["threat_id"], resource)
                    if key not in self._seen_threat_ids:
                        self._seen_threat_ids.add(key)
                        new_threats.append(t)
                if new_threats:
                    try:
                        self.app.after(
                            0, self._handle_rtd_threats, new_threats,
                        )
                    except Exception:
                        break
            except Exception:
                logger.debug("Antivirus: RTD poll error")
            self._rtd_stop.wait(15)

    def _handle_rtd_threats(self, threats: list[dict]):
        from plugins.antivirus import threat_log
        for t in threats:
            name = t["name"]
            resources = t.get("resources", [])
            path = resources[0] if resources else "unknown location"
            _send_notification(
                "Phoenix — Threat Blocked",
                f"{name} was blocked at {os.path.basename(path)}",
            )
            try:
                threat_log.log_threat_detected(name, path)
            except Exception:
                pass
            logger.warning(f"Antivirus RTD: {name} at {path}")

    def _toggle_auto_update(self, *args):
        # macOS has no auto-update toggle: signature updates are always on,
        # owned by the OS-level freshclam LaunchDaemon. Guard defensively in
        # case it's ever called without a switch widget.
        if platform.system() == "Darwin" or getattr(
                self, "_auto_update_switch", None) is None:
            return
        self._auto_update_on = bool(self._auto_update_switch.isChecked())
        settings.set("antivirus", "auto_update_enabled", self._auto_update_on)
        logger.info(
            f"Antivirus: auto-update toggled "
            f"{'on' if self._auto_update_on else 'off'}",
        )
        if self._auto_update_on:
            self._start_auto_update_scheduler()
        else:
            self._stop_auto_update_scheduler()

    # ── Real-Time Detection Watcher (clamd log) ────────────────

    def _get_clamd_log_path(self) -> str:
        sys_dir = getattr(clamav, "_SYSTEM_LOG_DIR", None)
        if sys_dir:
            system_log = os.path.join(sys_dir, "clamd.log")
            if os.path.isfile(system_log):
                return system_log
        return os.path.join(clamav._LOG_DIR, "clamd.log")

    def _start_rtd_watcher(self):
        if platform.system() == "Windows":
            return
        try:
            from plugins.antivirus.rtd_watcher import ClamdLogWatcher
            log_path = self._get_clamd_log_path()
            self._rtd_watcher = ClamdLogWatcher(
                log_path, self._on_rtd_threat, self._on_rtd_summary,
            )
            self._rtd_watcher.start()
            logger.info(f"Antivirus: RTD watcher started on {log_path}")
        except Exception:
            logger.debug("Antivirus: could not start RTD watcher")

    def _stop_rtd_watcher(self):
        if self._rtd_watcher is not None:
            try:
                self._rtd_watcher.stop()
            except Exception:
                pass
            self._rtd_watcher = None
            logger.info("Antivirus: RTD watcher stopped")

    def _on_rtd_threat(self, filepath: str, signature: str):
        try:
            self.app.after(0, self._handle_rtd_on_main, filepath, signature)
        except Exception:
            pass

    def _on_rtd_summary(self, count: int):
        try:
            self.app.after(0, self._handle_rtd_summary_on_main, count)
        except Exception:
            pass

    def _handle_rtd_on_main(self, filepath: str, signature: str):
        from utils import notifications
        basename = os.path.basename(filepath)
        notifications.send(
            "Phoenix — Threat Blocked",
            f"Malware detected: {signature}\n{basename}",
            urgency="critical",
        )

    def _handle_rtd_summary_on_main(self, count: int):
        from utils import notifications
        notifications.send(
            "Phoenix — Threat Blocked",
            f"{count} additional threat(s) detected",
            urgency="critical",
        )

    # ── Auto-Update Scheduler ─────────────────────────────────

    _AUTO_UPDATE_HOUR = 4
    _AUTO_UPDATE_JITTER_SECS = 7200

    def _start_auto_update_scheduler(self):
        if self._auto_update_timer and self._auto_update_timer.is_alive():
            return
        self._auto_update_stop = threading.Event()
        self._auto_update_timer = threading.Thread(
            target=self._auto_update_loop, daemon=True,
        )
        self._auto_update_timer.start()
        logger.info("Antivirus: auto-update scheduler started")

    def _stop_auto_update_scheduler(self):
        self._auto_update_stop.set()
        timer = self._auto_update_timer
        if timer is not None:
            timer.join(timeout=2)
        self._auto_update_timer = None
        logger.info("Antivirus: auto-update scheduler stopped")

    def _seconds_until_next_run(self) -> float:
        now = time.time()
        local = time.localtime(now)
        target = time.mktime((
            local.tm_year, local.tm_mon, local.tm_mday,
            self._AUTO_UPDATE_HOUR, 0, 0,
            local.tm_wday, local.tm_yday, local.tm_isdst,
        ))
        if target <= now:
            target += 86400
        jitter = random.randint(
            -self._AUTO_UPDATE_JITTER_SECS,
            self._AUTO_UPDATE_JITTER_SECS,
        )
        return max(60, (target - now) + jitter)

    def _sig_update_stale(self) -> bool:
        """True if signatures haven't updated in ~a day (or never recorded)."""
        last = settings.get("antivirus", "last_sig_update_ts", 0) or 0
        try:
            return (time.time() - float(last)) >= 86400
        except (TypeError, ValueError):
            return True

    def _run_auto_update(self):
        """Run the signature update and record the time on success."""
        try:
            ok, msg = clamav.run_freshclam()
        except Exception as exc:
            ok, msg = False, str(exc)
        if ok:
            settings.set("antivirus", "last_sig_update_ts", time.time())
            logger.info(f"Antivirus: auto-update succeeded — {msg}")
        else:
            logger.warning(f"Antivirus: auto-update failed — {msg}")
        try:
            self.app.after(0, self._refresh_db_info)
        except Exception:
            logger.debug("Antivirus: app destroyed during auto-update")

    def _auto_update_loop(self):
        """Background loop: catch up if stale, then update daily near 4 AM."""
        # Catch-up: if signatures are stale (>24h, or never recorded), the
        # 4 AM schedule alone could leave a laptop that's asleep overnight
        # perpetually outdated — update now.
        if (not self._auto_update_stop.is_set() and self._auto_update_on
                and self._sig_update_stale()):
            logger.info("Antivirus: signatures stale — running catch-up update")
            self._run_auto_update()

        while not self._auto_update_stop.is_set():
            delay = self._seconds_until_next_run()
            logger.info(
                f"Antivirus: next auto-update in {delay / 3600:.1f} hours")
            if self._auto_update_stop.wait(timeout=delay):
                break
            if not self._auto_update_on:
                break
            logger.info("Antivirus: running scheduled signature update")
            self._run_auto_update()

    # ── Scan Log Helpers ──────────────────────────────────────

    def _log_append(self, text: str):
        """Append a line to the scan activity log. Main thread only."""
        self._scan_log_buffer.append(text)
        try:
            self._scan_log.appendPlainText(text)
            self._scan_log.show()
        except Exception:
            pass

    def _log_clear(self):
        self._scan_log_buffer.clear()
        try:
            self._scan_log.clear()
        except Exception:
            pass

    def _set_scan_buttons_state(self, state: str):
        enabled = state == "normal"
        for key in ("scan", "scan_computer", "scan_files", "scan_folder"):
            btn = self._action_buttons.get(key)
            if btn is not None:
                try:
                    btn.setEnabled(enabled)
                except Exception:
                    pass

    def _restore_scan_ui(self):
        """Rebuild scan UI state after navigating back during an active scan."""
        self._set_scan_buttons_state("disabled")

        if self._scan_log_buffer:
            try:
                self._scan_log.setPlainText("\n".join(self._scan_log_buffer))
                self._scan_log.show()
            except Exception:
                pass

        total = self._scan_total_files
        count = self._scan_file_count
        try:
            self._scan_progress.show()
            if total > 0 and count < total:
                self._scan_progress.setRange(0, 1000)
                self._scan_progress.setValue(int(1000 * count / total))
                self._scan_status_label.setText(
                    f"Scanned {count} / {total} files")
            else:
                self._scan_progress.setRange(0, 0)  # indeterminate
        except Exception:
            pass

        cancel_btn = self._action_buttons.get("cancel_scan")
        if cancel_btn:
            cancel_btn.show()

    # ── System Daemon Activation ────────────────────────────────

    def _start_system_setup(self):
        if self._banner_action_btn:
            self._banner_action_btn.setEnabled(False)
            self._banner_action_btn.setText("Starting...")

        if platform.system() == "Darwin":
            def _run():
                try:
                    from plugins.antivirus.installer_service import (
                        trigger_system_setup,
                    )
                    ok = trigger_system_setup()
                except Exception:
                    ok = False
                if ok:
                    self.app.after(0, self._poll_setup_progress)
                else:
                    self.app.after(0, self._update_realtime_status)
        elif platform.system() == "Linux":
            def _run():
                try:
                    from plugins.antivirus.clamav_platform_linux import (
                        activate_system_daemons,
                    )
                    ok, msg = activate_system_daemons()
                except Exception as e:
                    ok, msg = False, str(e)
                # Same as Start Protection: say why it failed (e.g. NixOS).
                self.app.after(0, self._handle_protection_started, ok, msg)
        else:
            # Windows: Defender setup is owned by the OS; nothing to do here.
            self._update_realtime_status()
            return

        threading.Thread(target=_run, daemon=True).start()

    def _start_protection(self):
        if self._banner_action_btn:
            self._banner_action_btn.setEnabled(False)
            self._banner_action_btn.setText("Starting...")
        if self._banner_progress:
            self._banner_progress.setRange(0, 0)
            self._banner_progress.show()

        def _run():
            try:
                fn = getattr(clamav, "activate_system_daemons", None)
                if fn is None:
                    ok, msg = False, "Not supported on this platform"
                else:
                    ok, msg = fn()
            except Exception as e:
                ok, msg = False, str(e)
            self.app.after(0, self._handle_protection_started, ok, msg)

        threading.Thread(target=_run, daemon=True).start()

    def _handle_protection_started(self, ok: bool, msg: str):
        try:
            if self._banner_progress:
                self._banner_progress.hide()
            if not ok:
                self.app.show_notification(
                    msg or "Failed to start protection", type="error")
            self._update_realtime_status()
        except Exception:
            pass

    def _retry_setup(self):
        if self._banner_action_btn:
            self._banner_action_btn.setEnabled(False)
            self._banner_action_btn.setText("Retrying...")

        def _run():
            try:
                from plugins.antivirus.installer_service import retry
                retry()
            except Exception:
                pass
            self.app.after(0, self._update_realtime_status)

        threading.Thread(target=_run, daemon=True).start()

    _MAX_SETUP_POLLS = 100

    def _poll_setup_progress(self):
        def _check():
            try:
                from plugins.antivirus.installer_service import (
                    poll_setup_progress,
                )
                result = poll_setup_progress()
            except Exception:
                return
            try:
                self.app.after(0, self._handle_setup_poll, result)
            except Exception:
                pass

        threading.Thread(target=_check, daemon=True).start()

    def _handle_setup_poll(self, result: dict):
        if result["finished"]:
            self._setup_poll_count = 0
            self._update_realtime_status()
            if result["success"]:
                logger.info("Antivirus: system setup completed")
                self._refresh_db_info()
            else:
                self._log_append(
                    f"Setup error: {result.get('error', 'unknown')}")
                logger.error(f"Antivirus: setup failed: {result.get('error')}")
            return

        self._setup_poll_count = getattr(self, "_setup_poll_count", 0) + 1
        if self._setup_poll_count >= self._MAX_SETUP_POLLS:
            logger.error("Antivirus: setup poll exceeded max attempts")
            self._setup_poll_count = 0
            self._update_realtime_status()
            return

        step = result.get("step", "")
        try:
            if step and self._banner_subtitle:
                step_labels = {
                    "create_dirs": "Creating system directories...",
                    "write_configs": "Writing configuration files...",
                    "set_permissions": "Setting permissions...",
                    "seed_db": "Copying signature database...",
                    "cleanup_legacy": "Cleaning up legacy daemons...",
                    "load_daemons": "Loading daemons...",
                }
                label = step_labels.get(step, f"Running: {step}...")
                self._banner_subtitle.setText(label)
        except Exception:
            pass

        try:
            self.app.after(3000, self._poll_setup_progress)
        except Exception:
            pass

    # ── Action Router ─────────────────────────────────────────

    def _on_action(self, action_key: str):
        logger.info(f"Antivirus: action triggered — {action_key}")
        actions = {
            "scan": self._show_scan_choices,
            "scan_files": lambda: self._choose_and_scan("files"),
            "scan_folder": lambda: self._choose_and_scan("folder"),
            "scan_back": self._hide_scan_choices,
            "scan_computer": self._start_computer_scan,
            "update_sigs": self._start_sig_update,
            "whitelist_add": self._add_whitelist_entry,
        }
        handler = actions.get(action_key)
        if handler:
            handler()

    # ── File / Directory Scan ─────────────────────────────────

    def _show_scan_choices(self):
        """Slide the action rows over to the files / folder choice."""
        stack = getattr(self, "_scan_actions", None)
        if stack is not None and not self._scanning:
            stack.push(self._scan_actions_choices)

    def _hide_scan_choices(self):
        stack = getattr(self, "_scan_actions", None)
        if stack is not None:
            try:
                stack.back(self._scan_actions_main)
            except RuntimeError:  # screen rebuilt
                pass

    def _choose_and_scan(self, kind: str):
        # Slide back first so the main rows are in place once the picker
        # closes (whether or not something was chosen).
        self._hide_scan_choices()
        self._start_scan(kind)

    def _pick_scan_targets(self, kind: str = "files") -> list[str]:
        """Pick files (``kind="files"``) or a folder to scan."""
        if kind == "folder":
            directory = QFileDialog.getExistingDirectory(
                None,  # no parent: movable panel, not a fixed macOS sheet
                "Select Folder to Scan")
            return [directory] if directory else []
        files, _ = QFileDialog.getOpenFileNames(
            None,  # no parent: movable panel, not a fixed macOS sheet
            "Select Files to Scan")
        return list(files)

    def _start_scan(self, kind: str = "files"):
        if self._scanning:
            return
        paths = self._pick_scan_targets(kind)
        if not paths:
            return
        targets = []
        skipped = []
        for path in dict.fromkeys(paths):
            try:
                whitelisted = clamav.is_path_whitelisted(path)
            except Exception:
                whitelisted = False
            if whitelisted:
                skipped.append(os.path.basename(path))
            else:
                targets.append(path)
        if skipped:
            QMessageBox.information(
                self.app, "Whitelisted",
                f"{len(skipped)} item(s) skipped (whitelisted):\n"
                + "\n".join(skipped[:10]),
            )
        if not targets:
            return
        self._run_multi_scan(targets, label="Scan")

    def _computer_scan_targets(self) -> list[str]:
        system = platform.system()
        home = os.path.expanduser("~")
        if system == "Darwin":
            candidates = [
                home, "/Applications", "/Library/LaunchAgents",
                "/Library/LaunchDaemons", "/usr/local/bin",
                "/opt/homebrew/bin", "/tmp",
            ]
        elif system == "Windows":
            candidates = [
                home,
                os.environ.get("PROGRAMFILES", r"C:\Program Files"),
                os.environ.get("PROGRAMFILES(X86)",
                               r"C:\Program Files (x86)"),
                os.environ.get("PROGRAMDATA", r"C:\ProgramData"),
                os.environ.get("TEMP", r"C:\Windows\Temp"),
            ]
        else:
            candidates = [home, "/opt", "/usr/local/bin", "/tmp"]
        targets = []
        for path in candidates:
            if not path or not os.path.isdir(path):
                continue
            try:
                if clamav.is_path_whitelisted(path):
                    continue
            except Exception:
                pass
            targets.append(path)
        return targets

    def _start_computer_scan(self):
        if self._scanning:
            return
        targets = self._computer_scan_targets()
        if not targets:
            QMessageBox.information(
                self.app, "Nothing to Scan",
                "No scannable directories found. Check your whitelist.",
            )
            return
        self._run_multi_scan(targets)

    def _run_multi_scan(self, targets: list[str], label: str = "Computer"):
        from plugins.antivirus.scanner import ScanResult, scan

        self._scanning = True
        self._cancel_requested = False
        self._scan_file_count = 0
        self._scan_total_files = 0
        self._set_scan_buttons_state("disabled")
        self._log_clear()

        self._scan_progress.show()
        self._scan_progress.setRange(0, 0)  # indeterminate

        cancel_btn = self._action_buttons.get("cancel_scan")
        if cancel_btn:
            cancel_btn.setEnabled(True)
            cancel_btn.show()

        self._log_append(
            f"Scanning {label.lower()} ({len(targets)} location"
            f"{'s' if len(targets) != 1 else ''})...",
        )
        for t in targets:
            self._log_append(f"  • {t}")

        agg = {
            "scanned": 0, "infected": 0, "infections": [],
            "files_seen": 0, "total_files": 0, "cancelled": False,
        }

        def _worker():
            start = time.monotonic()
            for idx, target in enumerate(targets, 1):
                if agg["cancelled"] or self._cancel_requested:
                    agg["cancelled"] = True
                    break
                self.app.after(
                    0, self._on_multi_scan_target_start,
                    idx, len(targets), target,
                )
                self.app.after(
                    0, self._log_append,
                    f"[{idx}/{len(targets)}] Indexing {target}...",
                )
                done = threading.Event()

                def on_total(total: int):
                    self.app.after(
                        0, self._on_scan_total_known_multi, total, agg)

                def on_progress(line: str):
                    self.app.after(0, self._log_append, line)
                    if ":" in line and ("OK" in line or "FOUND" in line):
                        agg["files_seen"] += 1
                        total = agg["total_files"]
                        if total > 0:
                            status = (
                                f"Scanned {agg['files_seen']} / {total} files")
                            pct = agg["files_seen"] / total
                        else:
                            status = f"Scanned {agg['files_seen']} files"
                            pct = None
                        self.app.after(
                            0, self._on_scan_file_done, status, pct)

                def on_complete(result):
                    if result.error and "cancelled" in result.error.lower():
                        agg["cancelled"] = True
                    elif result.error:
                        self.app.after(
                            0, self._log_append,
                            f"Error scanning {result.target}: {result.error}",
                        )
                    else:
                        agg["scanned"] += result.scanned
                        agg["infected"] += result.infected
                        agg["infections"].extend(result.infections)
                    done.set()

                handle = scan(
                    target, on_progress=on_progress,
                    on_complete=on_complete, on_total=on_total,
                )
                with self._scan_lock:
                    self._scan_handle = handle
                done.wait()
                with self._scan_lock:
                    self._scan_handle = None

            elapsed = time.monotonic() - start
            mins, secs = divmod(int(elapsed), 60)
            duration = (
                f"{elapsed:.3f} sec ({mins} m {secs} s)"
                if mins else f"{elapsed:.3f} sec ({secs} s)"
            )
            final = ScanResult(
                target=label, scanned=agg["scanned"],
                infected=agg["infected"], infections=agg["infections"],
                duration=duration,
                error="Scan cancelled." if agg["cancelled"] else "",
            )
            self.app.after(0, self._handle_scan_complete, final)

        threading.Thread(target=_worker, daemon=True).start()

    def _on_multi_scan_target_start(self, idx: int, total: int, target: str):
        short = os.path.basename(target.rstrip(os.sep)) or target
        try:
            self._scan_status_label.setText(
                f"[{idx}/{total}] Scanning: {short}")
        except Exception:
            pass

    def _on_scan_total_known_multi(self, total: int, agg: dict):
        agg["total_files"] += total
        if agg["total_files"] > 0:
            try:
                self._scan_progress.setRange(0, 1000)
                if agg["files_seen"] > 0:
                    pct = min(agg["files_seen"] / agg["total_files"], 1.0)
                    self._scan_progress.setValue(int(1000 * pct))
                else:
                    self._scan_progress.setValue(0)
            except Exception:
                pass

    def _cancel_scan(self):
        self._cancel_requested = True
        with self._scan_lock:
            handle = self._scan_handle
        if handle and not handle.cancelled:
            handle.cancel()
        self._log_append("Cancelling scan...")
        cancel_btn = self._action_buttons.get("cancel_scan")
        if cancel_btn:
            cancel_btn.setEnabled(False)

    def _on_scan_file_done(self, status: str, pct):
        try:
            self._scan_status_label.setText(status)
            if pct is not None:
                self._scan_progress.setRange(0, 1000)
                self._scan_progress.setValue(int(1000 * min(pct, 1.0)))
        except Exception:
            pass

    def _handle_scan_complete(self, result):
        from utils import notifications

        self._scanning = False
        with self._scan_lock:
            self._scan_handle = None
        self._cancel_requested = False
        try:
            self._scan_progress.setRange(0, 1000)
            self._scan_progress.setValue(1000 if not result.error else 0)
            self._scan_progress.hide()
        except Exception:
            pass

        can_scan = self._last_state not in ("not_installed", "no_database")
        self._set_scan_buttons_state("normal" if can_scan else "disabled")

        cancel_btn = self._action_buttons.get("cancel_scan")
        if cancel_btn:
            cancel_btn.setEnabled(True)
            cancel_btn.hide()

        if not (result.error and "cancelled" in result.error.lower()):
            # For the Dashboard's Antivirus panel (counts only, no paths).
            settings.set("antivirus", "last_scan", {
                "ts": time.time(), "scanned": int(result.scanned or 0),
                "infected": int(result.infected or 0), "error": bool(result.error)})

        if result.error:
            if "cancelled" in result.error.lower():
                self._scan_status_label.setText("Scan cancelled")
                self._log_append("Scan cancelled.")
            else:
                self._scan_status_label.setText("Scan failed")
                self._log_append(f"Error: {result.error}")
            return

        self._log_append(
            f"Done — {result.scanned} files scanned, "
            f"{result.infected} infected",
        )
        if result.duration:
            self._log_append(f"Time: {result.duration}")

        if result.infected > 0:
            self._scan_status_label.setText(
                f"Threats found: {result.infected}")
            try:
                notifications.send(
                    "Phoenix — Threats Detected",
                    f"{result.infected} infected file(s) found during scan.",
                    urgency="critical",
                )
            except Exception:
                pass
            from plugins.antivirus import threat_log
            infections: dict[str, str] = {}
            for infection_line in result.infections:
                try:
                    filepath, sig = threat_log.parse_infection_line(
                        infection_line)
                    infections[filepath] = sig
                    threat_log.log_threat_detected(sig, filepath)
                except Exception:
                    pass
            if infections:
                self._offer_quarantine_batch(infections)
        else:
            self._scan_status_label.setText("No threats found")

    def _offer_quarantine_batch(self, infections: dict[str, str]):
        from plugins.antivirus import threat_log

        filepaths = list(infections)
        names = [os.path.basename(p) for p in filepaths]
        listing = "\n".join(f"  • {n}" for n in names[:20])
        if len(names) > 20:
            listing += f"\n  ... and {len(names) - 20} more"

        answer = QMessageBox.question(
            self.app, "Threats Detected",
            f"{len(filepaths)} infected file(s) found:\n\n"
            f"{listing}\n\nMove all to quarantine?",
        ) == QMessageBox.StandardButton.Yes
        if not answer:
            return

        quarantined = 0
        for filepath in filepaths:
            try:
                ok, dest = clamav.quarantine_file(filepath)
            except Exception as e:
                ok, dest = False, str(e)
            basename = os.path.basename(filepath)
            if ok:
                self._log_append(f"Quarantined: {basename}")
                try:
                    threat_log.log_threat_quarantined(
                        infections[filepath], filepath, dest)
                except Exception:
                    pass
                quarantined += 1
            else:
                self._log_append(f"Quarantine failed ({basename}): {dest}")
        self._refresh_quarantine()
        self._log_append(f"Quarantined {quarantined}/{len(filepaths)} files")

    # ── Signature Updates ─────────────────────────────────────

    def _start_sig_update(self):
        btn = self._action_buttons.get("update_sigs")
        if btn:
            btn.setEnabled(False)
            btn.setText("Updating...")

        self._log_clear()
        self._log_append("Updating signature database...")
        try:
            self._scan_status_label.setText("Updating signatures...")
        except Exception:
            pass

        def _run():
            def on_line(line):
                self.app.after(0, self._log_append, line)
            try:
                ok, msg = clamav.run_freshclam(on_line=on_line)
            except Exception as e:
                ok, msg = False, str(e)
            self.app.after(0, self._handle_update_complete, ok, msg)

        threading.Thread(target=_run, daemon=True).start()

    def _handle_update_complete(self, ok: bool, msg: str):
        self._log_append(msg)
        try:
            btn = self._action_buttons.get("update_sigs")
            if btn:
                btn.setEnabled(True)
                btn.setText("Update Now")
            if ok:
                settings.set("antivirus", "last_sig_update_ts", time.time())
                self._scan_status_label.setText("Signatures updated")
            else:
                self._scan_status_label.setText("Update failed")
        except Exception:
            pass
        self._refresh_db_info()

    def _refresh_db_info(self):
        try:
            info = clamav.get_db_info()
        except Exception:
            return
        labels = getattr(self, "_db_labels", {})
        for key in ("Signatures", "Last Updated"):
            widget = labels.get(key)
            if widget is None:
                continue
            try:
                widget.setText(
                    info["signatures" if key == "Signatures"
                         else "last_updated"])
            except Exception:
                pass

    # ── Dynamic list helpers ───────────────────────────────────

    @staticmethod
    def _clear_layout(layout):
        while layout.count():
            item = layout.takeAt(0)
            w = item.widget()
            if w is not None:
                w.deleteLater()

    def _list_row(self, text: str) -> tuple[QWidget, QHBoxLayout]:
        row = QWidget()
        row.setObjectName("Transparent")
        h = QHBoxLayout(row)
        h.setContentsMargins(0, 6, 0, 6)
        h.setSpacing(8)
        lbl = QLabel(text)
        lbl.setObjectName("Val")
        h.addWidget(lbl, 1)
        return row, h

    @staticmethod
    def _remove_button(on_click) -> QPushButton:
        from gui.page_kit import icon_button
        btn = icon_button("x", "Remove", 16)
        btn.clicked.connect(on_click)
        return btn

    # ── Whitelist ──────────────────────────────────────────────

    def _add_whitelist_entry(self):
        path = QFileDialog.getExistingDirectory(
            None,  # no parent: movable panel, not a fixed macOS sheet
            "Select Folder to Whitelist")
        if not path:
            return
        try:
            clamav.add_to_whitelist(path)
        except Exception:
            pass
        self._refresh_whitelist()

    def _refresh_whitelist(self):
        layout = getattr(self, "_whitelist_layout", None)
        if layout is None:
            return
        try:
            self._clear_layout(layout)
            entries = clamav.get_whitelist()
        except Exception:
            return
        if not entries:
            from plugins.antivirus.qt_ui import muted
            layout.addWidget(muted("No whitelisted paths"))
            return
        for entry in entries:
            row, h = self._list_row(os.path.basename(entry) or entry)
            h.addWidget(self._remove_button(
                lambda _=False, p=entry: self._remove_whitelist(p)))
            layout.addWidget(row)

    def _remove_whitelist(self, path: str):
        try:
            clamav.remove_from_whitelist(path)
        except Exception:
            pass
        self._refresh_whitelist()

    # ── Scan Exclusions ───────────────────────────────────────

    def _add_excluded_extension(self):
        raw = self._ext_entry.text().strip()
        if not raw:
            return
        exts = [part.strip() for part in raw.split(",") if part.strip()]
        if exts:
            try:
                clamav.add_excluded_extensions(exts)
            except Exception:
                pass
        self._ext_entry.clear()
        self._refresh_exclusions()

    def _remove_excluded_extension(self, ext: str):
        try:
            clamav.remove_excluded_extension(ext)
        except Exception:
            pass
        self._refresh_exclusions()

    def _save_max_file_size(self):
        raw = self._size_entry.text().strip()
        try:
            size = int(raw) if raw else 0
            size = max(0, min(size, 10000))
        except ValueError:
            size = 0
        try:
            clamav.set_max_file_size(size)
        except Exception:
            pass

    def _debounced_save_max_file_size(self):
        job = getattr(self, "_size_save_job", None)
        if job is not None:
            try:
                self.app.after_cancel(job)
            except Exception:
                pass
        self._size_save_job = self.app.after(500, self._save_max_file_size)

    def _refresh_exclusions(self):
        layout = getattr(self, "_exclusions_layout", None)
        if layout is None:
            return
        try:
            self._clear_layout(layout)
            excl = clamav.get_scan_exclusions()
        except Exception:
            return

        if not excl["extensions"]:
            from plugins.antivirus.qt_ui import muted
            layout.addWidget(muted("No excluded extensions"))
        else:
            for ext in excl["extensions"]:
                row, h = self._list_row(ext)
                h.addWidget(self._remove_button(
                    lambda _=False, e=ext: self._remove_excluded_extension(e)))
                layout.addWidget(row)

        size_entry = getattr(self, "_size_entry", None)
        if size_entry is not None:
            try:
                size_entry.setText(str(excl["max_size_mb"]))
            except Exception:
                pass

    # ── SIEM Forwarding ───────────────────────────────────────

    def _setup_wazuh_forwarding(self):
        # Forwarding needs the endpoint agent: route the user to the
        # Endpoint plugin instead of failing the configure step.
        from plugins.antivirus import threat_log as _tl
        try:
            wazuh_installed = _tl.is_wazuh_installed()
        except Exception:
            wazuh_installed = False
        if not wazuh_installed:
            self.app.show_notification(
                "Install the endpoint agent to forward AV detections.",
                type="info")
            self._open_endpoint()
            return
        btn = getattr(self, "_siem_btn", None)
        if btn:
            btn.setEnabled(False)
            btn.setText("Configuring...")

        def _run():
            from plugins.antivirus import threat_log
            try:
                ok, msg = threat_log.setup_wazuh_forwarding()
            except Exception as e:
                ok, msg = False, str(e)
            self.app.after(0, self._handle_wazuh_setup, ok, msg)

        threading.Thread(target=_run, daemon=True).start()

    def _handle_wazuh_setup(self, ok: bool, msg: str):
        btn = getattr(self, "_siem_btn", None)
        lbl = getattr(self, "_siem_status_label", None)
        if ok:
            self._log_append(f"SIEM: {msg}")
            if btn:
                btn.setText("Configured")
                btn.setEnabled(False)
            if lbl:
                lbl.setText("Forwarding active")
        else:
            self._log_append(f"SIEM setup failed: {msg}")
            if btn:
                btn.setEnabled(True)
                btn.setText("Configure Forwarding")

    def _open_endpoint(self):
        """Navigate to the Endpoint (SIEM agent) plugin screen."""
        try:
            self.app.navigate("Endpoint")
        except Exception:
            logger.debug("Antivirus: could not navigate to Endpoint")

    def _refresh_siem_switch(self):
        """Re-sync the SIEM forwarding button with the live agent state."""
        btn = getattr(self, "_siem_btn", None)
        lbl = getattr(self, "_siem_status_label", None)
        if btn is None:
            return
        from plugins.antivirus import threat_log as _tl
        try:
            installed = _tl.is_wazuh_installed()
            on = _tl.is_forwarding_enabled()
        except Exception:
            installed, on = False, False
        try:
            if on:
                btn.setText("Configured")
                btn.setEnabled(False)
                if lbl:
                    lbl.setText("Forwarding active")
            else:
                btn.setText("Configure Forwarding")
                btn.setEnabled(True)
                if lbl:
                    lbl.setText(
                        "Ready — configure to forward AV detections"
                        if installed else
                        "Install the endpoint agent to enable forwarding")
        except RuntimeError:
            pass  # widget destroyed

    # ── Quarantine ─────────────────────────────────────────────

    def _refresh_quarantine(self):
        layout = getattr(self, "_quarantine_layout", None)
        if layout is None:
            return
        try:
            self._clear_layout(layout)
            entries = clamav.list_quarantined()
        except Exception:
            return
        if not entries:
            from plugins.antivirus.qt_ui import muted
            layout.addWidget(muted("No threats quarantined"))
            return
        for qpath in entries:
            name = os.path.basename(qpath).replace(".quarantined", "")
            row, h = self._list_row(name)
            restore = QPushButton("Restore")
            restore.setObjectName("Link")
            restore.setCursor(Qt.CursorShape.PointingHandCursor)
            restore.clicked.connect(
                lambda _=False, p=qpath: self._restore_quarantined(p))
            h.addWidget(restore)
            delete = QPushButton("Delete")
            delete.setObjectName("Link")
            delete.setCursor(Qt.CursorShape.PointingHandCursor)
            delete.setStyleSheet(
                f"color: {theme.badge_colors('error')[1]};")
            delete.clicked.connect(
                lambda _=False, p=qpath: self._delete_quarantined(p))
            h.addWidget(delete)
            layout.addWidget(row)

    def _restore_quarantined(self, qpath: str):
        name = os.path.basename(qpath).replace(".quarantined", "")
        dest = QFileDialog.getExistingDirectory(
            None,  # no parent: movable panel, not a fixed macOS sheet
            f"Restore '{name}' to...")
        if not dest:
            return
        target = os.path.join(dest, name)
        try:
            ok, msg = clamav.restore_quarantined(qpath, target)
        except Exception as e:
            ok, msg = False, str(e)
        if ok:
            self._refresh_quarantine()
        else:
            QMessageBox.critical(self.app, "Restore Failed", msg)

    def _delete_quarantined(self, qpath: str):
        name = os.path.basename(qpath).replace(".quarantined", "")
        confirmed = QMessageBox.question(
            self.app, "Delete Quarantined File",
            f"Permanently delete '{name}'?",
        ) == QMessageBox.StandardButton.Yes
        if not confirmed:
            return
        try:
            clamav.delete_quarantined(qpath)
            from plugins.antivirus import threat_log
            threat_log.log_threat_deleted(name)
        except Exception:
            pass
        self._refresh_quarantine()
