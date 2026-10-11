"""Antivirus plugin for Resistine Desktop.

Provides file/directory scanning, real-time protection, signature updates,
quarantine management, and whitelist via ClamAV binaries.

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
from tkinter import TclError, filedialog, messagebox

import customtkinter
from customtkinter import ThemeManager

from plugins.antivirus import clamav, threat_log
from plugins.antivirus.scan_picker import pick_scan_targets
from plugins.antivirus.scanner import ScanHandle, ScanResult, scan
from plugins.antivirus.theme import font
from plugins.antivirus.ui_builders import (
    build_scan_activity,
    build_scan_and_protection,
    build_status_banner,
)
from plugins.antivirus.ui_cards import (
    build_db_info_card,
    build_quarantine_card,
)
from plugins.antivirus.ui_settings import build_settings_view
from plugins.base_plugin import BasePlugin
from utils import notifications, settings
from utils.logger import logger

_PLUGIN_DIR = os.path.dirname(os.path.realpath(__file__))


def _send_notification(title: str, body: str, urgency: str = "critical"):
    """Send a native OS notification (macOS + Windows + Linux).

    In practice only the Windows Defender RTD poll (_handle_rtd_threats)
    calls this. macOS/Linux real-time detections go through
    utils.notifications directly (see _handle_rtd_on_main), so on those
    platforms the branches below are a defensive fallback that normally
    never fires — this is what keeps Linux from double-notifying.
    """
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
# Unregistered app IDs (like a plain 'Resistine' string) are silently
# dropped by Windows after the first toast.
_PS_AUMID = (
    r"{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}"
    r"\WindowsPowerShell\v1.0\powershell.exe"
)


def _send_notification_windows(title: str, body: str):
    """Windows 10/11: native Action Center toast with Resistine logo.

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
    """Antivirus plugin powered by ClamAV."""

    # Scrollbar auto-hide + content-column centering settle just after build
    # (the canvas reflows when the scrollbar toggles); defer the reveal until
    # the layout is quiescent so the page doesn't visibly "shift right" after
    # appearing. (Mirrors the VPN plugin, which shares this layout.)
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
            translations={"US": "Antivirus", "ES": "Antivirus", "FR": "Antivirus"},
            icon_light_path=os.path.join(_PLUGIN_DIR, "antivirus_light.png"),
            icon_dark_path=os.path.join(_PLUGIN_DIR, "antivirus_dark.png"),
            uninstall_enabled=True,
        )
        self.app = app
        self._auto_update_on = settings.get(
            "antivirus", "auto_update_enabled", True,
        )
        self._action_buttons = {}
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
        self._auto_update_switch = None
        self._rtd_watcher = None
        self._settings_gear_btn = None
        self._settings_frame = None
        self._current_view = "main"
        self._init_ready = threading.Event()
        self._rtd_watcher = None
        self._win_rtd_thread = None
        self._rtd_stop = threading.Event()
        self._seen_threat_ids: set[tuple[str, str]] = set()
        self.status = self.get_status()

        # Register system-level ClamAV daemons via SMAppService, refresh
        # system configs, and resume any pending install via the state machine.
        if platform.system() == "Darwin":
            def _darwin_daemon_init():
                try:
                    clamav.ensure_daemons_registered()
                except Exception as exc:
                    logger.error(f"Antivirus: ensure_daemons_registered failed: {exc}")
                try:
                    clamav.refresh_system_configs()
                except Exception as exc:
                    logger.error(f"Antivirus: refresh_system_configs failed: {exc}")
                # Always set the event so the plugin doesn't hang
                self._init_ready.set()
                # Resume any pending ClamAV install
                from plugins.antivirus.installer_service import check_and_advance
                check_and_advance()

            threading.Thread(target=_darwin_daemon_init, daemon=True).start()
        else:
            self._init_ready.set()

        # Pre-start clamd so the signature DB is already loaded when the
        # user clicks scan. Without this, the first scan blocks for minutes
        # while clamd loads ~500 MB of signatures into memory.
        threading.Thread(target=self._ensure_clamd_warm, daemon=True).start()

        # Poll status once at startup so the sidebar icon shows the
        # correct state before the user clicks the Antivirus plugin.
        # Waits for daemon registration to finish first.
        threading.Thread(target=self._poll_initial_status, daemon=True).start()

        # Start the auto-update scheduler if enabled.
        # On macOS, signature auto-updates are owned by the OS-level freshclam
        # LaunchDaemon (registered via ensure_daemons_registered() in
        # _darwin_daemon_init above), not an in-process thread — so we do NOT
        # start the scheduler here. On Linux/Windows the in-process scheduler
        # remains the only updater and starts exactly as before.
        if platform.system() != "Darwin" and self._auto_update_on:
            self._start_auto_update_scheduler()

        # Start the Windows RTD watcher at init so threat notifications
        # fire even when the Antivirus tab isn't visible.
        if platform.system() == "Windows":
            threading.Thread(
                target=self._deferred_start_win_rtd, daemon=True,
            ).start()

    _INITIAL_POLL_RETRIES = 8  # up to ~16s of retries (8 × 2s)
    _INITIAL_POLL_INTERVAL = 2  # seconds between retries

    def _poll_initial_status(self):
        """Poll daemon state so the sidebar shows the right icon.

        After a fresh login, launchd may still be starting the ClamAV
        daemons. Retry a few times when the result is "offline" but
        setup is already completed — the daemons *should* be running
        but haven't started yet.
        """
        self._init_ready.wait(timeout=10)
        for attempt in range(1 + self._INITIAL_POLL_RETRIES):
            try:
                status = clamav.get_realtime_status()
            except Exception:
                logger.debug("Antivirus: initial status poll failed")
                return
            self._last_state = status["state"]
            self._last_status = status
            self.status = self.check_status()

            # If daemons are up (or setup isn't done yet), stop retrying
            if status.get("runtime_state") != "offline":
                return
            if status.get("setup_state") != "completed":
                return

            if attempt < self._INITIAL_POLL_RETRIES:
                logger.debug(
                    f"Antivirus: daemons offline on attempt {attempt + 1}, "
                    f"retrying in {self._INITIAL_POLL_INTERVAL}s",
                )
                time.sleep(self._INITIAL_POLL_INTERVAL)

    @staticmethod
    def _ensure_clamd_warm():
        """Start clamd if it isn't already running (and a DB exists)."""
        if clamav.is_clamd_running() or not clamav.has_database():
            return
        if not clamav.is_clamav_installed():
            return
        logger.info("Antivirus: pre-starting clamd for faster scans")
        ok, msg = clamav.start_clamd()
        if not ok:
            logger.warning(f"Antivirus: clamd warm-up failed: {msg}")

    def check_status(self):
        if self._last_state == "protected":
            return "OK"
        if self._last_state == "error":
            return "Error"
        return "Warning"

    def _is_active_screen(self):
        """True only while the antivirus screen is the active navigation target.

        Because the screen is cached (kept alive when navigated away), its
        recurring status poll would otherwise keep re-rendering the banner even
        after you've navigated off — including during the brief swap window,
        which showed up as a blip. The moment a different screen is selected,
        ``_current_main_screen`` points elsewhere (set synchronously, before the
        deferred swap completes), so this returns False and the poll goes quiet.
        """
        try:
            return getattr(self.app, "_current_main_screen", None) is getattr(
                self, "main_container", None
            )
        except Exception:
            return True

    def screen_signature(self):
        """Cache the antivirus screen across navigation.

        This is the heaviest plugin screen; rebuilding/destroying its widget
        tree on every visit is expensive, and the synchronous destroy on the way
        OUT froze the swap-in of the next page (the antivirus→store "blip"). With
        a stable signature the screen is hidden with grid_remove() (instant) and
        re-shown as-is — no destroy, no freeze. Live data is kept current by the
        status poller and re-synced in on_screen_shown(); we only force a rebuild
        when the appearance mode changes (so theme colors re-render).
        """
        try:
            return ("antivirus", customtkinter.get_appearance_mode())
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
            self.app.after(0, self._refresh_siem_switch)
        except Exception:
            pass

    # ── Main screen ──────────────────────────────────────────

    def create_main_screen(self):
        self.main_container = customtkinter.CTkFrame(
            self.app, corner_radius=0, fg_color="transparent",
        )
        # Compute a reasonable initial content width so the first frame
        # isn't squeezed to 100px while _do_layout hasn't fired yet.
        # _init_w is LOGICAL; winfo_width() is PHYSICAL, so normalize via CTk's
        # widget scaling (1.0 on macOS, real OS ratio on Windows/HiDPI) and
        # re-scale when setting minsize (which wants physical px).
        try:
            _s = customtkinter.ScalingTracker.get_widget_scaling(self.app) or 1.0
        except Exception:
            _s = getattr(self.app, "_hidpi_factor", 1.0) or 1.0
        _init_w = 750
        try:
            _app_w = self.app.winfo_width() / _s
            _nav = getattr(self.app, "navigation_frame", None)
            _nav_w = (_nav.winfo_width() / _s) if (_nav and _nav.winfo_exists()) else 250
            _nav_w = max(_nav_w, 250)
            _avail = _app_w - _nav_w
            _breathing = 60 if platform.system() == "Windows" else 40
            if _avail > 750 + 40:
                _init_w = 750
            elif _avail > 10:
                _init_w = max(100, _avail - _breathing)
        except Exception:
            pass
        self.main_container.grid_columnconfigure(0, weight=1)
        self.main_container.grid_columnconfigure(1, weight=0, minsize=int(_init_w * _s))
        self.main_container.grid_columnconfigure(2, weight=1)
        self.main_container.grid_rowconfigure(0, weight=1)

        self.main_frame = customtkinter.CTkScrollableFrame(
            self.main_container, corner_radius=0, fg_color="transparent",
        )
        self.main_frame.grid(row=0, column=1, sticky="nsew", pady=10)
        self.main_frame.grid_columnconfigure(0, weight=1)

        # Build synchronously and fully — select_frame_by_name() in
        # gui/user_interface.py uses build-first-swap-last, so the previous
        # plugin stays visible until this method returns. Chunking the build
        # via app.after() makes the new screen visible *partially*, which
        # the user perceives as the gray-empty-bottom "loading box".
        row = 0
        row = build_status_banner(self, self.main_frame, row)
        row = build_scan_and_protection(self, self.main_frame, row)
        row = build_scan_activity(self, self.main_frame, row)
        row = build_quarantine_card(self, self.main_frame, row)
        row = build_db_info_card(self, self.main_frame, row)

        customtkinter.CTkLabel(
            self.main_frame, text="", height=12,
        ).grid(row=row, column=0)

        # Settings view is built lazily on first gear-button click. Building
        # the 4 settings cards eagerly added ~1-2s to every plugin mount on
        # macOS even though most users never visit Settings.
        self._settings_frame = None
        self._current_view = "main"

        # Populate live data on screen creation
        self.app.after(100, self._refresh_db_info)
        self.app.after(200, self._refresh_whitelist)
        self.app.after(300, self._refresh_quarantine)
        self.app.after(400, self._refresh_exclusions)

        # If we already know the status from a previous poll, apply it
        # immediately so the card doesn't flash "Checking..." on every visit.
        # Then kick off the live poll after a short delay.
        if self._last_status is not None:
            self._apply_realtime_status_ui(self._last_status)
        self.app.after(500, self._update_realtime_status)

        # Restore scan UI if a scan is still running from before navigation
        if self._scanning:
            self._restore_scan_ui()

        MAX_CONTENT_WIDTH = 750
        _is_windows = platform.system() == "Windows"
        _resize_job = [None]

        def _do_layout():
            _resize_job[0] = None
            if (
                not hasattr(self, "main_container")
                or not self.main_container
                or not self.main_container.winfo_exists()
            ):
                return

            # --- Auto-hide Scrollbar Logic ---
            active = (
                self._settings_frame
                if self._current_view == "settings"
                else self.main_frame
            )
            try:
                if hasattr(active, "_parent_canvas") and hasattr(active, "_scrollbar"):
                    yview = active._parent_canvas.yview()
                    is_mapped = bool(active._scrollbar.grid_info())
                    if yview and (yview[0] <= 0.01 and yview[1] >= 0.99):
                        if is_mapped:
                            active._saved_sb_grid = active._scrollbar.grid_info()
                            active._scrollbar.grid_remove()
                    else:
                        if not is_mapped:
                            if hasattr(active, "_saved_sb_grid") and active._saved_sb_grid:
                                active._scrollbar.grid(**active._saved_sb_grid)
                            else:
                                # CTk grids the vertical scrollbar at row=1
                                # (row 0 is the label row). row=0 dropped a
                                # default height=200 scrollbar into the empty
                                # label row, pushing the canvas down 200px.
                                active._scrollbar.grid(row=1, column=1, sticky="ns", pady=0)
            except Exception:
                pass
            # --- End Auto-hide ---

            # winfo_width() returns PHYSICAL px; MAX_CONTENT_WIDTH is LOGICAL, so
            # convert via CTk's widget scaling (the real OS-DPI ratio: 2.0 at
            # 200% on Windows, 1.0 on macOS, == _hidpi_factor on Linux) and
            # re-scale the minsize at the end. _hidpi_factor alone is 1.0 on
            # Windows even when CTk scales 2x, which left the content column
            # sized in physical px and rendered it half-width.
            try:
                _scale = customtkinter.ScalingTracker.get_widget_scaling(self.app) or 1.0
            except Exception:
                _scale = getattr(self.app, "_hidpi_factor", 1.0) or 1.0
            app_w = self.app.winfo_width() / _scale
            if app_w < 10:
                return
            try:
                nav = getattr(self.app, "navigation_frame", None)
                nav_w = (nav.winfo_width() / _scale) if (nav and nav.winfo_exists()) else 250
                nav_w = max(nav_w, 250)
            except Exception:
                nav_w = 250
            width = app_w - nav_w  # logical
            if width < 10:
                return
            breathing = 60 if _is_windows else 40
            if width > MAX_CONTENT_WIDTH + 40:
                col_w = MAX_CONTENT_WIDTH
            else:
                col_w = max(100, width - breathing)
            try:
                # grid_columnconfigure(minsize=) wants physical pixels — scale up.
                self.main_container.grid_columnconfigure(
                    1, weight=0, minsize=int(col_w * _scale),
                )
            except Exception:
                return

        def _on_resize(event):
            if _resize_job[0] is not None:
                try:
                    self.app.after_cancel(_resize_job[0])
                except Exception:
                    pass
            _resize_job[0] = self.app.after_idle(_do_layout)

        self.main_container.bind("<Configure>", _on_resize)
        # Synchronous finalizer: _settle_screen() runs the initial layout pass
        # before reveal, so the content column is sized on first paint instead
        # of jumping ~50 ms later. (<Configure> still handles genuine resizes.)
        self.main_container._resistine_finalize = _do_layout

        return self.main_container

    def destroy(self):
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
        self._settings_frame = None
        self._current_view = "main"
        if hasattr(self, "main_container") and self.main_container:
            self.main_container.destroy()
            self.main_container = None

    # ── View Switching ─────────────────────────────────────

    def _show_settings_view(self):
        """Switch from main view to settings view, building it on demand."""
        if self._current_view == "settings":
            return
        first_build = self._settings_frame is None
        if first_build:
            self._settings_frame = customtkinter.CTkScrollableFrame(
                self.main_container, corner_radius=0, fg_color="transparent",
            )
            self._settings_frame.grid(row=0, column=1, sticky="nsew", pady=10)
            self._settings_frame.grid_columnconfigure(0, weight=1)
            build_settings_view(self, self._settings_frame)
        self.main_frame.grid_remove()
        self._settings_frame.grid()
        self._current_view = "settings"
        # Re-sync the SIEM forwarding switch every time the (cached) settings
        # view is shown, so it reflects a Wazuh agent installed since it built.
        self._refresh_siem_switch()
        if first_build:
            # Populate live data into the freshly-built whitelist + exclusions
            # cards. Done after the swap so the user sees the static layout
            # immediately and the data fills in a frame later.
            self.app.after(20, self._refresh_whitelist)
            self.app.after(40, self._refresh_exclusions)
        self._finalize_view_swap()

    def _show_main_view(self):
        """Switch from settings view back to main view."""
        if self._current_view == "main":
            return
        if self._settings_frame is not None:
            self._settings_frame.grid_remove()
        self.main_frame.grid()
        self._current_view = "main"
        self._finalize_view_swap()

    def _finalize_view_swap(self):
        """Force layout + repaint after a main/settings view swap.

        CTkScrollableFrame sizes its inner canvas window only on the canvas's
        <Configure>. Re-grid()'ing a frame at the same outer geometry doesn't
        reliably re-fire that event (and update_idletasks() never dispatches
        it), so the re-mapped frame keeps a stale inner width and paints blank
        until the next window resize. Mirror _settle_screen's refit + finalize.
        """
        mc = getattr(self, "main_container", None)
        if not mc or not mc.winfo_exists():
            return
        # 1) Flush the grid map/unmap + canvas resize queued by the swap.
        try:
            mc.update_idletasks()
        except Exception:
            return
        # 2) Re-fit the now-visible scrollable frame's inner window to its
        #    canvas (replicates CTk's _fit_frame_dimensions_to_canvas, vertical
        #    branch — same technique as gui/user_interface.py _refit). This is
        #    what un-blanks the content.
        active = (
            self._settings_frame
            if self._current_view == "settings"
            else self.main_frame
        )
        try:
            canvas = active._parent_canvas
            canvas.itemconfigure(
                active._create_window_id, width=canvas.winfo_width(),
            )
        except Exception:
            pass
        # 3) Re-run the resize-time layout (scrollbar auto-hide for the new
        #    view + content-column minsize) via the existing finalizer.
        fin = getattr(mc, "_resistine_finalize", None)
        if callable(fin):
            try:
                fin()
            except Exception:
                pass
        # 4) Flush the resulting redraw to screen now.
        try:
            mc.update_idletasks()
        except Exception:
            pass

    # ── UI Event Handlers ────────────────────────────────────

    def _update_realtime_status(self):
        """Poll daemon state and update the banner."""
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
        """Handle a fresh poll result: cache state, update UI, schedule next."""
        prev_setup = (
            self._last_status.get("setup_state") if self._last_status else None
        )
        state = status["state"]
        self._last_state = state
        self._last_status = status
        self.status = self.check_status()
        try:
            self._apply_realtime_status_ui(status)
            self._schedule_status_poll()
        except (TclError, AttributeError):
            pass
        # Refresh DB info when setup transitions to completed
        if status.get("setup_state") == "completed" and prev_setup != "completed":
            self._refresh_db_info()

        # Start/stop RTD watcher based on clamonacc state
        clamonacc_on = bool(status.get("clamonacc_running"))
        if clamonacc_on and self._rtd_watcher is None:
            self._start_rtd_watcher()
        elif not clamonacc_on and self._rtd_watcher is not None:
            self._stop_rtd_watcher()

        # Start/stop Windows RTD watcher based on Defender real-time state
        if platform.system() == "Windows":
            if clamonacc_on and self._win_rtd_thread is None:
                self._start_win_rtd_watcher()
            elif not clamonacc_on and self._win_rtd_thread is not None:
                self._stop_win_rtd_watcher()

    def _apply_realtime_status_ui(self, status: dict):
        """Update the status card widgets using two-dimensional state model.

        setup_state drives the UI during initial setup.
        runtime_state drives the UI after setup is complete.
        Safe to call even if UI is gone.
        """
        if self._banner_frame is None:
            return

        # Don't re-render the banner while the antivirus screen isn't the active
        # one — the poll keeps running because the screen is cached, but touching
        # the widgets during/after navigation causes a visible blip.
        if not self._is_active_screen():
            return

        try:
            if not self._banner_frame.winfo_exists():
                self._banner_frame = None
                return
        except Exception:
            self._banner_frame = None
            return

        setup_state = status.get("setup_state", "completed")
        runtime_state = status.get("runtime_state", "offline")

        t = ThemeManager.theme.get("Theme", {})
        ok_bg = t.get("protection_bg_ok")
        ok_tx = t.get("protection_text_ok")
        warn_bg = t.get("protection_bg_warn")
        warn_tx = t.get("protection_text_warn")
        err_bg = t.get("status_badge_bg", {}).get("error")
        err_tx = t.get("status_badge_text", {}).get("error")

        _is_win = platform.system() == "Windows"
        is_linux = platform.system() == "Linux"
        _engine = clamav.engine_name()
        cfg = None

        if not status.get("installed"):
            cfg = {
                "bg": err_bg, "title": "Not Installed", "title_color": err_tx,
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
            # Setup phase — derive from setup_state
            cfg = self._get_setup_banner_cfg(
                setup_state, status, ok_bg, ok_tx, warn_bg, warn_tx, err_bg, err_tx,
            )
        else:
            # Setup complete — derive from runtime_state
            cfg = self._get_runtime_banner_cfg(
                runtime_state, status, ok_bg, ok_tx, warn_bg, warn_tx, err_bg, err_tx,
            )

        self._banner_frame.configure(fg_color=cfg["bg"])
        self._banner_label.configure(
            text=cfg["title"], text_color=cfg["title_color"],
        )
        self._banner_subtitle.configure(text=cfg["subtitle"])

        # Show/hide progress bar based on active setup
        show_progress = setup_state in ("seeding_db", "installing")
        if self._banner_progress:
            if show_progress:
                self._banner_progress.grid()
                self._banner_progress.start()
            else:
                self._banner_progress.stop()
                self._banner_progress.grid_remove()

        if cfg["action"]:
            label, handler = cfg["action"]
            self._banner_action_btn.configure(
                text=label, command=handler, state="normal",
            )
            self._banner_action_btn.grid()
        else:
            self._banner_action_btn.grid_remove()

        # Disable scan buttons when ClamAV can't actually scan
        can_scan = status.get("installed") and status.get("db_present")
        self._set_scan_buttons_state("normal" if can_scan else "disabled")

        computer_btn = self._action_buttons.get("scan_computer")
        if computer_btn:
            computer_btn.configure(
                state="normal" if can_scan else "disabled",
            )

    def _get_setup_banner_cfg(
        self, setup_state, status, ok_bg, ok_tx, warn_bg, warn_tx, err_bg, err_tx,
    ) -> dict:
        """Return banner config for setup phase states."""
        if setup_state == "seeding_db":
            return {
                "bg": warn_bg, "title": "Downloading Definitions...",
                "title_color": warn_tx,
                "subtitle": "Downloading malware signature database. This may take a few minutes.",
                "action": None,
            }
        if setup_state == "seed_failed":
            from plugins.antivirus.installer_service import get_failure_reason

            reason = get_failure_reason()
            reason_text = {
                "dns_failed": "Could not reach the update server. Check your internet connection.",
                "network_timeout": "Download timed out. Check your internet connection.",
                "certs_missing": "Certificate verification failed. Try reinstalling Phoenix.",
                "binary_missing": "ClamAV binaries not found. Reinstall Phoenix.",
                "partial_download": "Download was incomplete. Tap Retry to try again.",
                "freshclam_failed": "Signature download failed. Tap Retry to try again.",
            }.get(reason, "Download failed. Tap Retry to try again.")
            return {
                "bg": err_bg, "title": "Download Failed",
                "title_color": err_tx, "subtitle": reason_text,
                "action": ("Retry", self._retry_setup),
            }
        if setup_state == "db_ready":
            return {
                "bg": warn_bg, "title": "Set Up Protection",
                "title_color": warn_tx,
                "subtitle": (
                    "Signature database downloaded. "
                    "Tap below to enable real-time protection "
                    "(requires administrator password)."
                ),
                "action": ("Set Up Protection", self._start_system_setup),
            }
        if setup_state == "installing":
            return {
                "bg": warn_bg, "title": "Setting Up...",
                "title_color": warn_tx,
                "subtitle": "Configuring system-level protection. This may take a moment.",
                "action": None,
            }
        if setup_state == "install_failed":
            from plugins.antivirus.installer_service import get_failure_reason

            reason = get_failure_reason()
            if reason == "user_canceled":
                subtitle = "Setup was cancelled. Tap Retry when ready."
            else:
                subtitle = "System setup failed. Tap Retry to try again."
            return {
                "bg": err_bg, "title": "Setup Failed",
                "title_color": err_tx, "subtitle": subtitle,
                "action": ("Retry", self._retry_setup),
            }
        # not_started — seed is about to begin automatically
        return {
            "bg": warn_bg, "title": "Starting Setup...",
            "title_color": warn_tx,
            "subtitle": "Preparing to download malware definitions...",
            "action": None,
        }

    def _get_runtime_banner_cfg(
        self, runtime_state, status, ok_bg, ok_tx, warn_bg, warn_tx, err_bg, err_tx,
    ) -> dict:
        """Return banner config for post-setup runtime states."""
        if runtime_state == "healthy":
            return {
                "bg": ok_bg, "title": "Protected", "title_color": ok_tx,
                "subtitle": (
                    "Real-time malware protection is active"
                    if status.get("clamonacc_running")
                    else "On-demand scanning is active"
                ),
                "action": None,
            }
        if runtime_state == "degraded":
            return {
                "bg": warn_bg, "title": "Protection Degraded",
                "title_color": warn_tx,
                "subtitle": (
                    "Scanning is available but real-time file monitoring "
                    "is not running. Full Disk Access may be needed."
                ),
                "action": ("Open Settings", clamav.open_fda_settings),
            }
        if runtime_state == "approval_required":
            return {
                "bg": warn_bg, "title": "Approval Required",
                "title_color": warn_tx,
                "subtitle": (
                    "Enable ClamAV daemons in System Settings "
                    "\u203A General \u203A Login Items "
                    "for real-time protection."
                ),
                "action": ("Open Login Items", clamav.open_login_items_settings),
            }
        if runtime_state == "fda_required":
            return {
                "bg": warn_bg, "title": "Full Disk Access Required",
                "title_color": warn_tx,
                "subtitle": (
                    "Phoenix needs Full Disk Access to monitor files "
                    "in real time. Grant access in System Settings "
                    "\u203A Privacy & Security \u203A Full Disk Access."
                ),
                "action": ("Open Settings", clamav.open_fda_settings),
            }
        # offline
        _is_win = platform.system() == "Windows"
        is_linux = platform.system() == "Linux"
        _engine = clamav.engine_name()
        return {
            "bg": err_bg, "title": "Protection Offline",
            "title_color": err_tx,
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
                    "Install Resistine.app for real-time protection."
                )
            ),
            "action": (
                ("Start Protection", self._start_protection)
                if (_is_win or status.get("in_bundle"))
                else None
            ),
        }

    def _schedule_status_poll(self):
        """Schedule the next realtime status poll if the UI is still alive.

        Polls faster (2s) during active setup so the UI doesn't look stuck.
        Normal interval (10s) after setup is complete.
        """
        try:
            alive = (
                (hasattr(self, "main_frame") and self.main_frame.winfo_exists())
                or (
                    self._settings_frame
                    and self._settings_frame.winfo_exists()
                )
            )
            # Pause the poll when the screen isn't the active one so it doesn't
            # re-render the banner in the background during/after navigation.
            # EXCEPTION: on Windows the poll is the ONLY thing that restarts the
            # RTD threat watcher when Defender's real-time state flips (see the
            # start/stop block in _apply_realtime_status), so it must keep running
            # even while the tab is backgrounded — otherwise a watcher stopped
            # while hidden never restarts and threat toasts silently stop. The
            # banner re-render is independently suppressed in
            # _apply_realtime_status_ui (early-returns when not active), so the
            # background poll on Windows costs nothing visually. On macOS/Linux
            # on_screen_shown() restarts the poll when we return to the screen.
            if alive and (
                self._is_active_screen() or platform.system() == "Windows"
            ):
                setup_active = self._last_status and self._last_status.get(
                    "setup_state", "completed",
                ) != "completed"
                interval = 2000 if setup_active else 10000
                self.app.after(interval, self._update_realtime_status)
        except Exception:
            logger.debug("Antivirus: could not schedule next status poll")

    # ── RTD Threat Watcher (Windows Defender) ─────────────────

    def _deferred_start_win_rtd(self):
        """Wait for initial status, then start the RTD watcher if Defender RT is on."""
        self._init_ready.wait(timeout=15)
        try:
            status = clamav.get_realtime_status()
            if status.get("clamonacc_running"):
                self._start_win_rtd_watcher()
            else:
                logger.info("Antivirus: Defender RT not active, skipping RTD watcher")
        except Exception:
            logger.debug("Antivirus: could not check Defender status for RTD watcher")

    def _start_win_rtd_watcher(self):
        """Start polling Defender for real-time threat detections."""
        if self._win_rtd_thread is not None:
            return
        self._rtd_stop.clear()
        self._win_rtd_thread = threading.Thread(
            target=self._rtd_poll_loop, daemon=True,
        )
        self._win_rtd_thread.start()
        logger.info("Antivirus: Windows RTD watcher started")

    def _stop_win_rtd_watcher(self):
        """Stop the Windows RTD polling thread."""
        if self._win_rtd_thread is None:
            return
        self._rtd_stop.set()
        self._win_rtd_thread = None
        logger.info("Antivirus: Windows RTD watcher stopped")

    def _rtd_poll_loop(self):
        """Background: poll Defender threat detections every 15s."""
        while not self._rtd_stop.is_set():
            try:
                threats = clamav.get_recent_threats(since_seconds=30)
                new_threats = []
                for t in threats:
                    # Dedup on (threat_id, first_resource) so the same
                    # threat type at different paths still notifies.
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
        """UI thread: show notification + log each new RTD threat."""
        for t in threats:
            name = t["name"]
            resources = t.get("resources", [])
            path = resources[0] if resources else "unknown location"
            _send_notification(
                "Phoenix — Threat Blocked",
                f"{name} was blocked at {os.path.basename(path)}",
            )
            threat_log.log_threat_detected(name, path)
            logger.warning(f"Antivirus RTD: {name} at {path}")

    def _toggle_auto_update(self):
        # macOS has no auto-update toggle: signature updates are always on,
        # owned by the OS-level freshclam LaunchDaemon (registered in
        # _darwin_daemon_init). The settings card shows a read-only
        # "Automatic" status there, so this handler is only wired to the
        # Linux/Windows switch. Guard defensively in case it's ever called
        # without a switch widget.
        if platform.system() == "Darwin" or self._auto_update_switch is None:
            return
        self._auto_update_on = bool(self._auto_update_switch.get())
        settings.set("antivirus", "auto_update_enabled", self._auto_update_on)
        logger.info(
            f"Antivirus: auto-update toggled "
            f"{'on' if self._auto_update_on else 'off'}",
        )
        if self._auto_update_on:
            self._start_auto_update_scheduler()
        else:
            self._stop_auto_update_scheduler()

    # ── Real-Time Detection Watcher ─────────────────────────────

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
        from plugins.antivirus.rtd_watcher import ClamdLogWatcher

        log_path = self._get_clamd_log_path()
        self._rtd_watcher = ClamdLogWatcher(
            log_path, self._on_rtd_threat, self._on_rtd_summary,
        )
        self._rtd_watcher.start()
        logger.info(f"Antivirus: RTD watcher started on {log_path}")

    def _stop_rtd_watcher(self):
        if self._rtd_watcher is not None:
            self._rtd_watcher.stop()
            self._rtd_watcher = None
            logger.info("Antivirus: RTD watcher stopped")

    def _on_rtd_threat(self, filepath: str, signature: str):
        # threat_log.log_threat_detected is already called by the watcher
        # (for both notified and rate-limited detections); don't double-log.
        try:
            self.app.after(0, self._handle_rtd_on_main, filepath, signature)
        except Exception:
            pass  # app destroyed

    def _on_rtd_summary(self, count: int):
        try:
            self.app.after(0, self._handle_rtd_summary_on_main, count)
        except Exception:
            pass

    def _handle_rtd_on_main(self, filepath: str, signature: str):
        basename = os.path.basename(filepath)
        notifications.send(
            "Phoenix \u2014 Threat Blocked",
            f"Malware detected: {signature}\n{basename}",
            urgency="critical",
        )

    def _handle_rtd_summary_on_main(self, count: int):
        notifications.send(
            "Phoenix \u2014 Threat Blocked",
            f"{count} additional threat(s) detected",
            urgency="critical",
        )

    # ── Auto-Update Scheduler ─────────────────────────────────

    _AUTO_UPDATE_HOUR = 4  # Target hour (4:00 AM)
    _AUTO_UPDATE_JITTER_SECS = 7200  # ±2 hours

    def _start_auto_update_scheduler(self):
        """Start the background thread that triggers freshclam daily."""
        if self._auto_update_timer and self._auto_update_timer.is_alive():
            return
        # Fresh event per thread to avoid races with a previous thread
        self._auto_update_stop = threading.Event()
        self._auto_update_timer = threading.Thread(
            target=self._auto_update_loop, daemon=True,
        )
        self._auto_update_timer.start()
        logger.info("Antivirus: auto-update scheduler started")

    def _stop_auto_update_scheduler(self):
        """Signal the scheduler thread to stop and wait for it to exit."""
        self._auto_update_stop.set()
        timer = self._auto_update_timer
        if timer is not None:
            timer.join(timeout=2)
        self._auto_update_timer = None
        logger.info("Antivirus: auto-update scheduler stopped")

    def _seconds_until_next_run(self) -> float:
        """Calculate seconds until the next 4 AM (±2 hr jitter)."""
        now = time.time()
        local = time.localtime(now)
        # Build today's target time
        target = time.mktime((
            local.tm_year, local.tm_mon, local.tm_mday,
            self._AUTO_UPDATE_HOUR, 0, 0,
            local.tm_wday, local.tm_yday, local.tm_isdst,
        ))
        # Roll to tomorrow first if today's 4 AM already passed
        if target <= now:
            target += 86400
        # Apply jitter after rollover so the base is always "next 4 AM"
        jitter = random.randint(
            -self._AUTO_UPDATE_JITTER_SECS,
            self._AUTO_UPDATE_JITTER_SECS,
        )
        return max(60, (target - now) + jitter)

    def _sig_update_stale(self) -> bool:
        """True if signatures haven't updated in ~a day (or were never recorded)."""
        last = settings.get("antivirus", "last_sig_update_ts", 0) or 0
        try:
            return (time.time() - float(last)) >= 86400
        except (TypeError, ValueError):
            return True

    def _run_auto_update(self):
        """Run the signature update and record the time on success."""
        ok, msg = clamav.run_freshclam()
        if ok:
            settings.set("antivirus", "last_sig_update_ts", time.time())
            logger.info(f"Antivirus: auto-update succeeded — {msg}")
        else:
            logger.warning(f"Antivirus: auto-update failed — {msg}")
        # Refresh the UI if it's visible
        try:
            self.app.after(0, self._refresh_db_info)
        except Exception:
            logger.debug("Antivirus: app destroyed during auto-update")

    def _auto_update_loop(self):
        """Background loop: catch up if stale, then update daily near 4 AM.

        Linux/Windows only. On macOS the OS-level freshclam LaunchDaemon owns
        auto-updates (runs even when the app is closed), so this in-process
        loop is never started there.
        """
        # Catch-up: if signatures are stale (>24h, or never recorded), update
        # now. The 4 AM schedule alone misses machines that are never running
        # at that hour, so this is what actually makes "once a day" hold.
        if (not self._auto_update_stop.is_set() and self._auto_update_on
                and self._sig_update_stale()):
            logger.info("Antivirus: signatures stale — running catch-up update")
            self._run_auto_update()

        while not self._auto_update_stop.is_set():
            delay = self._seconds_until_next_run()
            logger.info(
                f"Antivirus: next auto-update in "
                f"{delay / 3600:.1f} hours",
            )
            # Sleep in short intervals so we can exit promptly
            if self._auto_update_stop.wait(timeout=delay):
                break
            if not self._auto_update_on:
                break
            logger.info("Antivirus: running scheduled signature update")
            self._run_auto_update()

    # ── Scan Log Helpers ──────────────────────────────────────

    def _log_append(self, text: str):
        """Append a line to the scan activity textbox.

        Must be called on the main thread — use app.after() from workers.
        Buffers lines while the UI is destroyed so they can be replayed.
        """
        self._scan_log_buffer.append(text)
        try:
            self._scan_log.configure(state="normal")
            self._scan_log.insert("end", text + "\n")
            self._scan_log.see("end")
            self._scan_log.configure(state="disabled")
        except (TclError, AttributeError):
            pass

    def _log_clear(self):
        self._scan_log_buffer.clear()
        self._scan_log.configure(state="normal")
        self._scan_log.delete("1.0", "end")
        self._scan_log.configure(state="disabled")

    # Muted fill for a disabled scan button so it reads as inactive instead of
    # keeping its highlighted blue look while a scan is running.
    _SCAN_BTN_DISABLED_FG = ("#D1D5DB", "#3A3A3C")
    # Muted label color paired with _SCAN_BTN_DISABLED_FG. Gray-400 on the
    # light background, gray-500 on the dark — readable but unmistakably
    # inactive, so the buttons match macOS's standard disabled-control look.
    _SCAN_BTN_DISABLED_TEXT = ("#9CA3AF", "#71717A")

    def _set_scan_buttons_state(self, state: str):
        # While a scan is running the buttons must stay nullified. Without this
        # guard the realtime-status poll (which runs after the screen rebuilds
        # when you navigate back) would call this with "normal" and re-enable
        # them mid-scan. Force "disabled" whenever a scan is active.
        if self._scanning:
            state = "disabled"
        for key in ("scan", "scan_computer"):
            btn = self._action_buttons.get(key)
            if not btn:
                continue
            # Remember the enabled fill + text color once so we can restore them
            # exactly. The buttons are created in ui_builders with a fixed near-
            # white text — without re-applying that color, a previous disable
            # would leave the text muted forever once the scan ended.
            if not hasattr(btn, "_enabled_fg"):
                btn._enabled_fg = btn.cget("fg_color")
            if not hasattr(btn, "_enabled_text_color"):
                btn._enabled_text_color = btn.cget("text_color")
            if state == "disabled":
                # Both Scan and Scan Computer need the SAME visual treatment
                # throughout the entire scan — including the LABEL text, not
                # just the background. Previously only fg_color was muted,
                # leaving white-on-grey buttons that read as "active but
                # unresponsive" on Mac.
                btn.configure(
                    state="disabled", hover=False,
                    fg_color=self._SCAN_BTN_DISABLED_FG,
                    text_color=self._SCAN_BTN_DISABLED_TEXT,
                )
            else:
                btn.configure(
                    state="normal", hover=True,
                    fg_color=btn._enabled_fg,
                    text_color=btn._enabled_text_color,
                )

    def _restore_scan_ui(self):
        """Rebuild scan UI state after navigating back during an active scan."""
        self._set_scan_buttons_state("disabled")

        # Replay buffered log lines
        if self._scan_log_buffer:
            self._scan_log.configure(state="normal")
            self._scan_log.insert("end", "\n".join(self._scan_log_buffer) + "\n")
            self._scan_log.see("end")
            self._scan_log.configure(state="disabled")

        # Restore progress bar
        total = self._scan_total_files
        count = self._scan_file_count
        if total > 0 and count < total:
            self._scan_progress.grid()
            self._scan_progress.configure(mode="determinate")
            self._scan_progress.set(count / total)
            self._scan_status_label.configure(
                text=f"Scanned {count} / {total} files",
            )
        else:
            self._scan_progress.grid()
            self._scan_progress.configure(mode="indeterminate")
            self._scan_progress.start()

        # Show cancel button
        cancel_btn = self._action_buttons.get("cancel_scan")
        if cancel_btn:
            cancel_btn.grid()

    # ── System Daemon Activation ────────────────────────────────

    def _start_system_setup(self):
        """Launch ClamAV system setup (platform-aware)."""
        if self._banner_action_btn:
            self._banner_action_btn.configure(
                state="disabled", text="Starting...",
            )

        if platform.system() == "Darwin":
            from plugins.antivirus.installer_service import trigger_system_setup

            def _run():
                ok = trigger_system_setup()
                if ok:
                    self.app.after(0, self._poll_setup_progress)
                else:
                    self.app.after(0, self._update_realtime_status)
        elif platform.system() == "Linux":
            from plugins.antivirus.clamav_platform_linux import activate_system_daemons

            def _run():
                ok, _msg = activate_system_daemons()
                self.app.after(0, self._update_realtime_status)
        else:
            # Windows: Defender setup is owned by the OS; nothing to do here.
            self._update_realtime_status()
            return

        threading.Thread(target=_run, daemon=True).start()

    def _start_protection(self):
        """Start protection (Windows Defender toggle or macOS daemon start)."""
        if self._banner_action_btn:
            self._banner_action_btn.configure(
                state="disabled", text="Starting...",
            )
        if self._banner_progress:
            self._banner_progress.grid()
            self._banner_progress.configure(mode="indeterminate")
            self._banner_progress.start()

        def _run():
            try:
                ok, msg = clamav.activate_system_daemons()
            except Exception as e:
                ok, msg = False, str(e)
            self.app.after(0, self._handle_protection_started, ok, msg)

        threading.Thread(target=_run, daemon=True).start()

    def _handle_protection_started(self, ok: bool, msg: str):
        try:
            self._handle_protection_started_ui(ok, msg)
        except (TclError, AttributeError):
            pass

    def _handle_protection_started_ui(self, ok: bool, msg: str):
        if self._banner_progress:
            self._banner_progress.stop()
            self._banner_progress.grid_remove()
        if not ok:
            self.app.show_notification(msg or "Failed to start protection", type="error")
        self._update_realtime_status()

    def _retry_setup(self):
        """Manual retry — reset backoff and restart the current phase."""
        from plugins.antivirus.installer_service import retry

        if self._banner_action_btn:
            self._banner_action_btn.configure(state="disabled", text="Retrying...")

        def _run():
            retry()
            self.app.after(0, self._update_realtime_status)

        threading.Thread(target=_run, daemon=True).start()

    _MAX_SETUP_POLLS = 100  # ~5 min at 3s intervals

    def _poll_setup_progress(self):
        """Poll the postinstall status file every 3 seconds."""
        from plugins.antivirus.installer_service import poll_setup_progress

        def _check():
            result = poll_setup_progress()
            try:
                self.app.after(0, self._handle_setup_poll, result)
            except Exception:
                pass  # App destroyed

        threading.Thread(target=_check, daemon=True).start()

    def _handle_setup_poll(self, result: dict):
        """Handle a setup progress poll result."""
        if result["finished"]:
            self._setup_poll_count = 0
            self._update_realtime_status()
            if result["success"]:
                logger.info("Antivirus: system setup completed")
                self._refresh_db_info()
            else:
                self._log_append(f"Setup error: {result.get('error', 'unknown')}")
                logger.error(f"Antivirus: setup failed: {result.get('error')}")
            return

        # Still running — update step label and poll again
        self._setup_poll_count = getattr(self, "_setup_poll_count", 0) + 1
        if self._setup_poll_count >= self._MAX_SETUP_POLLS:
            logger.error("Antivirus: setup poll exceeded max attempts")
            self._setup_poll_count = 0
            self._update_realtime_status()
            return

        step = result.get("step", "")
        try:
            if (
                step
                and self._banner_subtitle
                and self._banner_subtitle.winfo_exists()
            ):
                step_labels = {
                    "create_dirs": "Creating system directories...",
                    "write_configs": "Writing configuration files...",
                    "set_permissions": "Setting permissions...",
                    "seed_db": "Copying signature database...",
                    "cleanup_legacy": "Cleaning up legacy daemons...",
                    "load_daemons": "Loading daemons...",
                }
                label = step_labels.get(step, f"Running: {step}...")
                self._banner_subtitle.configure(text=label)
        except Exception:
            pass  # Widget destroyed

        # Schedule next poll
        try:
            if hasattr(self, "main_frame") and self.main_frame.winfo_exists():
                self.app.after(3000, self._poll_setup_progress)
        except Exception:
            pass

    # ── Action Router ─────────────────────────────────────────

    def _on_action(self, action_key: str):
        logger.info(f"Antivirus: action triggered — {action_key}")

        actions = {
            "scan": self._start_scan,
            "scan_computer": self._start_computer_scan,
            "update_sigs": self._start_sig_update,
            "whitelist_add": self._add_whitelist_entry,
        }
        handler = actions.get(action_key)
        if handler:
            handler()

    # ── File / Directory Scan ─────────────────────────────────

    def _start_scan(self):
        if self._scanning:
            return
        paths = pick_scan_targets(self.app)
        if not paths:
            return
        targets = []
        skipped = []
        for path in dict.fromkeys(paths):
            if clamav.is_path_whitelisted(path):
                skipped.append(os.path.basename(path))
            else:
                targets.append(path)
        if skipped:
            messagebox.showinfo(
                "Whitelisted",
                f"{len(skipped)} item(s) skipped (whitelisted):\n"
                + "\n".join(skipped[:10]),
                parent=self.app,
            )
        if not targets:
            return
        if len(targets) == 1:
            self._run_scan(targets[0])
        else:
            self._run_multi_scan(targets, label="Scan")

    def _computer_scan_targets(self) -> list[str]:
        """Return the fixed list of directories scanned by 'Scan Computer'.

        Picks user-data and app dirs that exist on disk and aren't
        whitelisted. Skips system roots that would balloon scan time
        (/System on macOS, C:\\Windows on Windows) — clamonacc handles
        real-time coverage there.
        """
        system = platform.system()
        home = os.path.expanduser("~")
        if system == "Darwin":
            candidates = [
                home,
                "/Applications",
                "/Library/LaunchAgents",
                "/Library/LaunchDaemons",
                "/usr/local/bin",
                "/opt/homebrew/bin",
                "/tmp",
            ]
        elif system == "Windows":
            candidates = [
                home,
                os.environ.get("PROGRAMFILES", r"C:\Program Files"),
                os.environ.get("PROGRAMFILES(X86)", r"C:\Program Files (x86)"),
                os.environ.get("PROGRAMDATA", r"C:\ProgramData"),
                os.environ.get("TEMP", r"C:\Windows\Temp"),
            ]
        else:  # Linux / other POSIX
            candidates = [
                home,
                "/opt",
                "/usr/local/bin",
                "/tmp",
            ]
        targets = []
        for path in candidates:
            if not path or not os.path.isdir(path):
                continue
            if clamav.is_path_whitelisted(path):
                continue
            targets.append(path)
        return targets

    def _start_computer_scan(self):
        """Scan a fixed set of directories (Documents, Applications, etc.)."""
        if self._scanning:
            return
        targets = self._computer_scan_targets()
        if not targets:
            messagebox.showinfo(
                "Nothing to Scan",
                "No scannable directories found. Check your whitelist.",
                parent=self.app,
            )
            return
        self._run_multi_scan(targets)

    def _run_multi_scan(self, targets: list[str], label: str = "Computer"):
        """Run scans on multiple targets sequentially, aggregating results."""
        self._scanning = True
        self._cancel_requested = False
        self._scan_file_count = 0
        self._scan_total_files = 0
        self._set_scan_buttons_state("disabled")
        self._log_clear()

        self._scan_progress.grid()
        self._scan_progress.configure(mode="indeterminate")
        self._scan_progress.start()

        cancel_btn = self._action_buttons.get("cancel_scan")
        if cancel_btn:
            cancel_btn.grid()

        self._log_append(
            f"Scanning {label.lower()} ({len(targets)} location"
            f"{'s' if len(targets) != 1 else ''})...",
        )
        for t in targets:
            self._log_append(f"  • {t}")

        # Cumulative counters across all targets
        agg = {
            "scanned": 0,
            "infected": 0,
            "infections": [],
            "files_seen": 0,
            "total_files": 0,
            "cancelled": False,
        }

        def _worker():
            start = time.monotonic()
            for idx, target in enumerate(targets, 1):
                if agg["cancelled"] or self._cancel_requested:
                    agg["cancelled"] = True
                    break
                self.app.after(
                    0, self._on_multi_scan_target_start, idx, len(targets), target,
                )
                # Visibility: $HOME and similar large dirs spend 30s–2min in
                # _walk_files before scan_path emits anything. Print the
                # target so the UI doesn't look frozen during the walk.
                self.app.after(
                    0, self._log_append,
                    f"[{idx}/{len(targets)}] Indexing {target}...",
                )
                done = threading.Event()
                target_total = [0]

                def on_total(total: int, _t=target_total):
                    _t[0] = total
                    self.app.after(
                        0, self._on_scan_total_known_multi, total, agg,
                    )

                def on_progress(line: str):
                    self.app.after(0, self._log_append, line)
                    if ":" in line and ("OK" in line or "FOUND" in line):
                        agg["files_seen"] += 1
                        total = agg["total_files"]
                        if total > 0:
                            status = (
                                f"Scanned {agg['files_seen']} / {total} files"
                            )
                            pct = agg["files_seen"] / total
                        else:
                            status = f"Scanned {agg['files_seen']} files"
                            pct = None
                        self.app.after(
                            0, self._on_scan_file_done, status, pct,
                        )

                def on_complete(result: ScanResult):
                    if result.error and "cancelled" in result.error.lower():
                        agg["cancelled"] = True
                    elif result.error:
                        # Don't abort the whole sweep on a single-dir error;
                        # log it and move on.
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
                    target,
                    on_progress=on_progress,
                    on_complete=on_complete,
                    on_total=on_total,
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
                if mins
                else f"{elapsed:.3f} sec ({secs} s)"
            )
            final = ScanResult(
                target=label,
                scanned=agg["scanned"],
                infected=agg["infected"],
                infections=agg["infections"],
                duration=duration,
                error="Scan cancelled." if agg["cancelled"] else "",
            )
            self.app.after(0, self._handle_scan_complete, final)

        threading.Thread(target=_worker, daemon=True).start()

    def _on_multi_scan_target_start(
        self, idx: int, total: int, target: str,
    ):
        """Update the status label as each directory in the sweep starts."""
        short = os.path.basename(target.rstrip(os.sep)) or target
        self._scan_status_label.configure(
            text=f"[{idx}/{total}] Scanning: {short}",
        )

    def _on_scan_total_known_multi(self, total: int, agg: dict):
        """Add this directory's file count to the aggregate progress total."""
        agg["total_files"] += total
        if agg["total_files"] > 0:
            self._scan_progress.stop()
            self._scan_progress.configure(mode="determinate")
            if agg["files_seen"] > 0:
                self._scan_progress.set(
                    min(agg["files_seen"] / agg["total_files"], 1.0),
                )
            else:
                self._scan_progress.set(0)

    def _run_scan(self, target: str):
        self._scanning = True
        self._scan_file_count = 0
        self._scan_total_files = 0
        self._set_scan_buttons_state("disabled")
        self._log_clear()

        self._scan_progress.grid()
        self._scan_progress.configure(mode="indeterminate")
        self._scan_progress.start()

        # Show cancel button
        cancel_btn = self._action_buttons.get("cancel_scan")
        if cancel_btn:
            cancel_btn.grid()

        short = os.path.basename(target) or target
        self._scan_status_label.configure(text=f"Scanning: {short}")
        self._log_append(f"Scanning: {target}")

        def on_total(total: int):
            self._scan_total_files = total
            self.app.after(0, self._on_scan_total_known, total)

        def on_progress(line: str):
            self.app.after(0, self._log_append, line)
            if ":" in line and ("OK" in line or "FOUND" in line):
                self._scan_file_count += 1
                total = self._scan_total_files
                if total > 0:
                    status = f"Scanned {self._scan_file_count} / {total} files"
                    pct = self._scan_file_count / total
                else:
                    status = f"Scanned {self._scan_file_count} files"
                    pct = None
                self.app.after(
                    0, self._on_scan_file_done, status, pct,
                )

        def on_complete(result: ScanResult):
            self.app.after(0, self._handle_scan_complete, result)

        with self._scan_lock:
            self._scan_handle = scan(
                target, on_progress=on_progress, on_complete=on_complete,
                on_total=on_total,
            )

    def _cancel_scan(self):
        """Cancel the running scan."""
        # Set the multi-scan cancel flag first so the worker loop won't
        # start the next directory even if the click lands between targets
        # (when self._scan_handle is briefly None).
        self._cancel_requested = True
        with self._scan_lock:
            handle = self._scan_handle
        if handle and not handle.cancelled:
            handle.cancel()
        self._log_append("Cancelling scan...")
        cancel_btn = self._action_buttons.get("cancel_scan")
        if cancel_btn:
            cancel_btn.configure(state="disabled")

    def _on_scan_total_known(self, total: int):
        """Switch progress bar to determinate mode when file count is known."""
        try:
            self._scan_progress.stop()
            if total == 0:
                self._scan_progress.grid_remove()
                self._scan_status_label.configure(text="No files matched filters")
                return
            self._scan_progress.configure(mode="determinate")
            self._scan_progress.set(0)
        except (TclError, AttributeError):
            pass

    def _on_scan_file_done(self, status: str, pct: float | None):
        """Update scan progress label and bar after each file."""
        try:
            self._scan_status_label.configure(text=status)
            if pct is not None:
                self._scan_progress.set(min(pct, 1.0))
        except (TclError, AttributeError):
            pass

    def _handle_scan_complete(self, result: ScanResult):
        self._scanning = False
        with self._scan_lock:
            self._scan_handle = None
        self._cancel_requested = False
        self._scan_progress.stop()
        self._scan_progress.set(1.0 if not result.error else 0)
        self._scan_progress.configure(mode="determinate")
        self._scan_progress.grid_remove()

        # Re-enable scan buttons only if ClamAV is in a scannable state
        can_scan = self._last_state not in ("not_installed", "no_database")
        self._set_scan_buttons_state("normal" if can_scan else "disabled")

        # Hide cancel button and reset its state for next scan
        cancel_btn = self._action_buttons.get("cancel_scan")
        if cancel_btn:
            cancel_btn.configure(state="normal")
            cancel_btn.grid_remove()

        if result.error:
            if "cancelled" in result.error.lower():
                self._scan_status_label.configure(text="Scan cancelled")
                self._log_append("Scan cancelled.")
            else:
                self._scan_status_label.configure(text="Scan failed")
                self._log_append(f"Error: {result.error}")
            return

        self._log_append(
            f"Done — {result.scanned} files scanned, "
            f"{result.infected} infected",
        )
        if result.duration:
            self._log_append(f"Time: {result.duration}")

        if result.infected > 0:
            self._scan_status_label.configure(
                text=f"Threats found: {result.infected}",
            )
            notifications.send(
                "Phoenix — Threats Detected",
                f"{result.infected} infected file(s) found during scan.",
                urgency="critical",
            )
            infections: dict[str, str] = {}
            for infection_line in result.infections:
                filepath, sig = threat_log.parse_infection_line(
                    infection_line,
                )
                infections[filepath] = sig
                threat_log.log_threat_detected(sig, filepath)
            if infections:
                self._offer_quarantine_batch(infections)
        else:
            self._scan_status_label.configure(text="No threats found")

    def _offer_quarantine_batch(self, infections: dict[str, str]):
        """Ask user whether to quarantine all infected files.

        infections: dict mapping filepath -> ClamAV signature name.
        """
        filepaths = list(infections)
        names = [os.path.basename(p) for p in filepaths]
        listing = "\n".join(f"  \u2022 {n}" for n in names[:20])
        if len(names) > 20:
            listing += f"\n  ... and {len(names) - 20} more"

        answer = messagebox.askyesno(
            "Threats Detected",
            f"{len(filepaths)} infected file(s) found:\n\n"
            f"{listing}\n\nMove all to quarantine?",
            parent=self.app,
        )
        if not answer:
            return

        quarantined = 0
        for filepath in filepaths:
            ok, dest = clamav.quarantine_file(filepath)
            basename = os.path.basename(filepath)
            if ok:
                self._log_append(f"Quarantined: {basename}")
                threat_log.log_threat_quarantined(
                    infections[filepath], filepath, dest,
                )
                quarantined += 1
            else:
                self._log_append(f"Quarantine failed ({basename}): {dest}")
        self._refresh_quarantine()
        self._log_append(
            f"Quarantined {quarantined}/{len(filepaths)} files",
        )

    # ── Signature Updates ─────────────────────────────────────

    def _start_sig_update(self):
        btn = self._action_buttons.get("update_sigs")
        if btn:
            btn.configure(state="disabled", text="Updating...")

        self._log_clear()
        self._log_append("Updating signature database...")
        self._scan_status_label.configure(text="Updating signatures...")

        def _run():
            def on_line(line):
                self.app.after(0, self._log_append, line)

            ok, msg = clamav.run_freshclam(on_line=on_line)
            self.app.after(0, self._handle_update_complete, ok, msg)

        threading.Thread(target=_run, daemon=True).start()

    def _handle_update_complete(self, ok: bool, msg: str):
        self._log_append(msg)
        try:
            btn = self._action_buttons.get("update_sigs")
            if btn:
                btn.configure(state="normal", text="Update Now")
            if ok:
                settings.set("antivirus", "last_sig_update_ts", time.time())
                self._scan_status_label.configure(text="Signatures updated")
            else:
                self._scan_status_label.configure(text="Update failed")
        except (TclError, AttributeError):
            pass

        self._refresh_db_info()

    def _refresh_db_info(self):
        """Update the Signature Updates card with live DB info."""
        info = clamav.get_db_info()
        labels = getattr(self, "_db_labels", {})
        for key in ("Signatures", "Last Updated"):
            widget = labels.get(key)
            if widget is None:
                continue
            try:
                if not widget.winfo_exists():
                    continue
                widget.configure(
                    text=info[
                        "signatures" if key == "Signatures" else "last_updated"
                    ],
                )
            except Exception:
                pass

    # ── Whitelist ──────────────────────────────────────────────

    def _add_whitelist_entry(self):
        path = filedialog.askdirectory(
            title="Select Folder to Whitelist", parent=self.app,
        )
        if not path:
            return
        clamav.add_to_whitelist(path)
        self._refresh_whitelist()

    def _refresh_whitelist(self):
        """Rebuild the whitelist card contents."""
        frame = getattr(self, "_whitelist_frame", None)
        if frame is None:
            return
        try:
            if not frame.winfo_exists():
                # Widget tree was destroyed (e.g. user navigated away before
                # this deferred refresh fired). Drop the stale reference.
                self._whitelist_frame = None
                return
        except Exception:
            self._whitelist_frame = None
            return
        for w in frame.winfo_children():
            w.destroy()

        entries = clamav.get_whitelist()
        if not entries:
            customtkinter.CTkLabel(
                frame, text="No whitelisted paths",
                font=font(12),
                text_color=ThemeManager.theme.get("Theme", {}).get(
                    "text_secondary",
                ),
            ).grid(row=0, column=0, sticky="w")
            return

        for i, entry in enumerate(entries):
            row_frame = customtkinter.CTkFrame(frame, fg_color="transparent")
            row_frame.grid(row=i, column=0, sticky="ew", pady=1)
            row_frame.grid_columnconfigure(0, weight=1)

            customtkinter.CTkLabel(
                row_frame, text=os.path.basename(entry) or entry,
                font=font(11), anchor="w",
            ).grid(row=0, column=0, sticky="w")

            customtkinter.CTkButton(
                row_frame, text="\u2715", width=24, height=24,
                font=font(10), fg_color="transparent",
                hover_color=("#E5E7EB", "#2A2A2C"),
                command=lambda p=entry: self._remove_whitelist(p),
            ).grid(row=0, column=1, sticky="e")

    def _remove_whitelist(self, path: str):
        clamav.remove_from_whitelist(path)
        self._refresh_whitelist()

    # ── Scan Exclusions ───────────────────────────────────────

    def _add_excluded_extension(self):
        """Add extension(s) from the entry field."""
        raw = self._ext_entry.get().strip()
        if not raw:
            return
        exts = [part.strip() for part in raw.split(",") if part.strip()]
        if exts:
            clamav.add_excluded_extensions(exts)
        self._ext_entry.delete(0, "end")
        self._refresh_exclusions()

    def _remove_excluded_extension(self, ext: str):
        clamav.remove_excluded_extension(ext)
        self._refresh_exclusions()

    def _save_max_file_size(self):
        """Persist the max file size from the entry field."""
        raw = self._size_entry.get().strip()
        try:
            size = int(raw) if raw else 0
            size = max(0, min(size, 10000))  # Clamp 0–10 GB
        except ValueError:
            size = 0
        clamav.set_max_file_size(size)

    def _debounced_save_max_file_size(self):
        """Save max file size after a short delay to avoid saving on every keystroke."""
        job = getattr(self, "_size_save_job", None)
        if job is not None:
            try:
                self.app.after_cancel(job)
            except Exception:
                pass
        self._size_save_job = self.app.after(500, self._save_max_file_size)

    def _refresh_exclusions(self):
        """Rebuild the scan exclusions card contents."""
        frame = getattr(self, "_exclusions_frame", None)
        if frame is None:
            return
        try:
            if not frame.winfo_exists():
                self._exclusions_frame = None
                return
        except Exception:
            self._exclusions_frame = None
            return
        for w in frame.winfo_children():
            w.destroy()

        excl = clamav.get_scan_exclusions()

        if not excl["extensions"]:
            customtkinter.CTkLabel(
                frame, text="No excluded extensions",
                font=font(12),
                text_color=ThemeManager.theme.get("Theme", {}).get(
                    "text_secondary",
                ),
            ).grid(row=0, column=0, sticky="w")
        else:
            for i, ext in enumerate(excl["extensions"]):
                row_frame = customtkinter.CTkFrame(
                    frame, fg_color="transparent",
                )
                row_frame.grid(row=i, column=0, sticky="ew", pady=1)
                row_frame.grid_columnconfigure(0, weight=1)

                customtkinter.CTkLabel(
                    row_frame, text=ext, font=font(11), anchor="w",
                ).grid(row=0, column=0, sticky="w")

                customtkinter.CTkButton(
                    row_frame, text="\u2715", width=24, height=24,
                    font=font(10), fg_color="transparent",
                    hover_color=("#E5E7EB", "#2A2A2C"),
                    command=lambda e=ext: self._remove_excluded_extension(e),
                ).grid(row=0, column=1, sticky="e")

        size_entry = getattr(self, "_size_entry", None)
        if size_entry:
            size_entry.delete(0, "end")
            size_entry.insert(0, str(excl["max_size_mb"]))

    # ── SIEM Forwarding ───────────────────────────────────────

    def _on_forwarding_toggle(self):
        """SIEM forwarding switch toggled in the AV settings view.

        Forwarding requires the endpoint (Wazuh) agent. If it isn't installed,
        flipping the switch on bounces the user to the Endpoint page to install
        it. Once installed, forwarding is already on (the installer enables it),
        so this mainly keeps the switch in sync.
        """
        sw = getattr(self, "_siem_switch", None)
        if sw is None:
            return
        turning_on = bool(sw.get())
        if not threat_log.is_wazuh_installed():
            # Can't forward without the agent — revert and route to Endpoint.
            sw.deselect()
            self.app.show_notification(
                "Install the endpoint agent to forward AV detections.",
                type="info")
            self._open_endpoint()
            return
        if turning_on:
            if threat_log.is_forwarding_enabled():
                return  # already on (Windows install auto-enables it)
            self._setup_wazuh_forwarding()
        else:
            # Forwarding is managed by the endpoint agent; keep it on.
            sw.select()
            self.app.show_notification(
                "SIEM forwarding stays on while the endpoint agent is installed.",
                type="info")

    def _open_endpoint(self):
        """Navigate to the Endpoint (SIEM agent) plugin screen."""
        try:
            p = next((pl for pl in self.app.plugin_list
                      if pl.get_name() == "Endpoint"), None)
            if p is not None:
                self.app.select_frame_by_name(
                    "frame_Endpoint", button=p.get_button())
        except Exception:
            logger.debug("Antivirus: could not navigate to Endpoint")

    def _refresh_siem_switch(self):
        """Re-sync the SIEM forwarding switch with the live agent state.

        The settings view is built once and cached, so without this the switch
        keeps its build-time state and never reflects a Wazuh agent installed
        afterwards (which auto-enables forwarding on Windows). Safe to call when
        the switch doesn't exist (settings view not built yet).
        """
        sw = getattr(self, "_siem_switch", None)
        if sw is None:
            return
        try:
            if not sw.winfo_exists():
                return
        except Exception:
            return
        installed = threat_log.is_wazuh_installed()
        on = threat_log.is_forwarding_enabled()
        if on:
            sw.select()
        else:
            sw.deselect()
        lbl = getattr(self, "_siem_status_label", None)
        if lbl is not None:
            try:
                if on:
                    lbl.configure(text="Forwarding active",
                                  text_color=("#1E8E3E", "#2CC985"))
                elif installed:
                    lbl.configure(
                        text="Ready — turn on to forward AV detections",
                        text_color=("#666666", "#aaaaaa"))
                else:
                    lbl.configure(
                        text="Install the endpoint agent to enable forwarding",
                        text_color=("#666666", "#aaaaaa"))
            except Exception:
                pass

    def _setup_wazuh_forwarding(self):
        """Configure the Wazuh agent to forward AV detections (macOS/Linux path).

        On Windows the endpoint installer already injects the Defender localfile,
        so this is only the manual fallback for platforms that don't.
        """
        def _run():
            ok, msg = threat_log.setup_wazuh_forwarding()
            self.app.after(0, self._handle_wazuh_setup, ok, msg)

        threading.Thread(target=_run, daemon=True).start()

    def _handle_wazuh_setup(self, ok: bool, msg: str):
        if not hasattr(self, "main_frame") or not self.main_frame:
            return
        sw = getattr(self, "_siem_switch", None)
        lbl = getattr(self, "_siem_status_label", None)
        if ok:
            self._log_append(f"SIEM: {msg}")
            if sw:
                sw.select()
            if lbl:
                lbl.configure(text="Forwarding active")
        else:
            self._log_append(f"SIEM setup failed: {msg}")
            if sw:
                sw.deselect()
            if lbl:
                lbl.configure(text="Could not enable forwarding")

    # ── Quarantine ─────────────────────────────────────────────

    def _refresh_quarantine(self):
        """Rebuild the quarantine card contents."""
        frame = getattr(self, "_quarantine_frame", None)
        if frame is None:
            return
        try:
            if not frame.winfo_exists():
                self._quarantine_frame = None
                return
        except Exception:
            self._quarantine_frame = None
            return
        for w in frame.winfo_children():
            w.destroy()

        entries = clamav.list_quarantined()
        if not entries:
            customtkinter.CTkLabel(
                frame, text="No threats quarantined",
                font=font(12),
                text_color=ThemeManager.theme.get("Theme", {}).get(
                    "text_secondary",
                ),
            ).grid(row=0, column=0, sticky="w")
            return

        for i, qpath in enumerate(entries):
            name = os.path.basename(qpath).replace(".quarantined", "")
            row_frame = customtkinter.CTkFrame(frame, fg_color="transparent")
            row_frame.grid(row=i, column=0, sticky="ew", pady=1)
            row_frame.grid_columnconfigure(0, weight=1)

            customtkinter.CTkLabel(
                row_frame, text=name, font=font(11), anchor="w",
            ).grid(row=0, column=0, sticky="w")

            customtkinter.CTkButton(
                row_frame, text="Restore", width=50, height=22,
                font=font(10), fg_color="transparent",
                hover_color=("#DBEAFE", "#1E2A3A"),
                text_color=("#2563EB", "#60A5FA"),
                command=lambda p=qpath: self._restore_quarantined(p),
            ).grid(row=0, column=1, sticky="e", padx=(4, 0))

            customtkinter.CTkButton(
                row_frame, text="Delete", width=50, height=22,
                font=font(10), fg_color="transparent",
                hover_color=("#FEE2E2", "#3B1010"),
                text_color=("#DC2626", "#F87171"),
                command=lambda p=qpath: self._delete_quarantined(p),
            ).grid(row=0, column=2, sticky="e", padx=(4, 0))

    def _restore_quarantined(self, qpath: str):
        name = os.path.basename(qpath).replace(".quarantined", "")
        dest = filedialog.askdirectory(
            title=f"Restore '{name}' to...", parent=self.app,
        )
        if not dest:
            return
        target = os.path.join(dest, name)
        ok, msg = clamav.restore_quarantined(qpath, target)
        if ok:
            self._refresh_quarantine()
        else:
            messagebox.showerror("Restore Failed", msg, parent=self.app)

    def _delete_quarantined(self, qpath: str):
        name = os.path.basename(qpath).replace(".quarantined", "")
        if messagebox.askyesno(
            "Delete Quarantined File",
            f"Permanently delete '{name}'?",
            parent=self.app,
        ):
            clamav.delete_quarantined(qpath)
            threat_log.log_threat_deleted(name)
            self._refresh_quarantine()
