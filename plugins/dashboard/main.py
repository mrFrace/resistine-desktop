## @file plugins/dashboard/main.py
## @package dashboard_plugin
## @namespace dashboard_plugin
## @class dashboard_plugin::Plugin

"""Dashboard plugin UI.

This implementation ports the UI_Dev dashboard layout ideas (protection panel + grid cards)
while preserving existing functionality (plugin list + navigation via App.select_frame_by_name).

IMPORTANT:
- UI only (no backend changes)
- Logo is in side menu only (not on dashboard)
- Does NOT use Resistine shield / RSheild assets

Author: P3, Peres J. and the Resistine Team
Copyright (c) Resistine 2025
Licensed under the GNU General Public License v2 or later
"""

import os

import customtkinter
from customtkinter import ThemeManager

from plugins.base_plugin import BasePlugin
from plugins.plugin_manager import PluginManager
from utils import settings as app_settings


class Plugin(BasePlugin):
    """Dashboard plugin."""

    def __init__(self, app):
        super().__init__(
            id="001",
            version="2025.01.01",
            order=1,
            name="Dashboard",
            status=None,
            description="See your protection status at a glance.",
            supported_systems=["Windows", "Linux", "Mac"],
            translations={"US": "Dashboard", "ES": "Panel", "FR": "Tableau de bord"},
            icon_light_path=os.path.join(
                os.path.dirname(os.path.realpath(__file__)), "home_light.png"
            ),
            icon_dark_path=os.path.join(
                os.path.dirname(os.path.realpath(__file__)), "home_dark.png"
            ),
            uninstall_enabled=False,
        )
        self.app = app
        self._dashboard_logo_image = None
        self.status = self.get_status()

    def _effective_appearance_mode(self) -> str:
        # Use user_interface's detection if available
        try:
            # Accessing the internal function if necessary, or just rely on ctk
            # But user_interface has `_effective_appearance_mode`.
            # Let's just use ctk for now or replicate logic.
            # Actually, user_interface exposed it? No, it's `def _effective_appearance_mode`.
            pass
        except Exception:
            pass
        mode = customtkinter.get_appearance_mode()
        return mode

    def _widget_scale(self):
        """Physical→logical scale factor for the app window.

        winfo_width() returns *physical* pixels under CTk's DPI scaling, so it
        must be divided by the real OS-DPI ratio before being compared against
        the logical 480/680 column thresholds. CTk's widget scaling gives that
        ratio on every platform (2.0 at 200% on Windows, 1.0 on macOS, and
        == _hidpi_factor on Linux). Using _hidpi_factor alone was wrong on
        Windows, where it stays 1.0 while CTk still scales the UI 2x — so
        physical px leaked into the thresholds and over-counted columns,
        squishing the plugin cards.
        """
        try:
            return customtkinter.ScalingTracker.get_widget_scaling(self.app)
        except Exception:
            return getattr(self.app, "_hidpi_factor", 1.0) or 1.0

    def create_main_screen(self):
        # Use a ScrollableFrame for the dashboard to prevent clipping on smaller screens
        self.main_frame = customtkinter.CTkScrollableFrame(
            self.app,
            corner_radius=0,
            fg_color="transparent",
        )
        self.main_frame.grid_columnconfigure(0, weight=1)
        
        # We don't need fixed row weights in a scrollable frame as much, 
        # but we'll ensure the grid is clean.
        
        appearance_mode = self._effective_appearance_mode()
        is_dark = appearance_mode == "Dark"

        # --- Plugins list (needed for banner + grid) ---
        if not hasattr(self.app, "plugin_list") or not self.app.plugin_list:
            plugin_list = PluginManager(self.app).plugins
        else:
            plugin_list = self.app.plugin_list

        # --- Protection Status Bar ---
        top_margin_spacer = customtkinter.CTkLabel(self.main_frame, text="", height=16)
        top_margin_spacer.grid(row=0, column=0, sticky="ew")

        vpn_plugin = next(
            (p for p in plugin_list if p.get_name() == "VPN"), None
        )
        vpn_ok = vpn_plugin and vpn_plugin.get_status() == "OK" if vpn_plugin else False

        if vpn_ok:
            banner_bg = ThemeManager.theme.get("Theme", {}).get(
                "protection_bg_ok", ["#DCFCE7", "#0A2F1A"]
            )
            banner_text_color = ThemeManager.theme.get("Theme", {}).get(
                "protection_text_ok", ["#15803D", "#4ADE80"]
            )
            banner_text = "\u2713  Protected"
        else:
            banner_bg = ThemeManager.theme.get("Theme", {}).get(
                "protection_bg_warn", ["#FEF3C7", "#2D1F05"]
            )
            banner_text_color = ThemeManager.theme.get("Theme", {}).get(
                "protection_text_warn", ["#B45309", "#FBBF24"]
            )
            banner_text = "\u26A0  Not Protected"

        protection_frame = customtkinter.CTkFrame(
            self.main_frame,
            fg_color=banner_bg,
            corner_radius=12,
            height=48,
        )
        protection_frame.grid(row=1, column=0, sticky="ew", padx=20, pady=(0, 16))
        protection_frame.grid_propagate(False)
        protection_frame.grid_columnconfigure(0, weight=1)
        protection_frame.grid_rowconfigure(0, weight=1)

        protection_label = customtkinter.CTkLabel(
            protection_frame,
            text=banner_text,
            font=customtkinter.CTkFont(family="Inter", size=15, weight="bold"),
            text_color=banner_text_color,
            justify="center",
            anchor="center",
        )
        protection_label.place(relx=0.5, rely=0.5, anchor="center")

        # Filter plugins for the grid:
        # Exclude Dashboard itself.
        # Exclude non-navigable plugins (order <= 0) by default — *except*
        # Login (id "007"), which surfaces here only when the user isn't
        # signed in, as a clear call-to-action card that opens the
        # full-screen login when clicked.
        logged_in = app_settings.get("auth", "logged_in", False)
        plugins = [
            p for p in plugin_list
            if p.get_name() != "Dashboard"
            and (p.order > 0 or (not logged_in and getattr(p, "id", None) == "007"))
        ]
        
        # Store plugins for responsive rebuild
        self._dashboard_plugins = plugins
        
        # Responsive layout: determine max columns based on content width.
        # Use absolute pixel thresholds (not screen percentages) so the layout
        # is consistent regardless of screen size. winfo_width() is physical px
        # under CTk DPI scaling, so normalize it to logical units via
        # _widget_scale() before comparing against the logical 480/680 cutoffs.
        import platform as _plat
        _sidebar = 250
        _padding = 60 if _plat.system() == "Windows" else 40
        _scale = self._widget_scale()
        # Force pending geometry to be applied so winfo_width() returns the
        # actual window size rather than a stale pre-layout value.
        self.app.update_idletasks()
        window_width = self.app.winfo_width()
        if window_width <= 1:
            # Window not yet mapped — fall back to the geometry-targeted size
            # (1920 * 0.7 logical = 1344, then scaled to physical).
            window_width = int(1344 * _scale)
        window_width = int(window_width / _scale)

        content_width = max(1, window_width - _sidebar - _padding)
        # Set hint for AppUI to use in create_grid synchronously
        self.app._content_width_hint = content_width

        # Column thresholds based on content width:
        # < 480px  → 1 col  (very narrow, ~750px window)
        # < 680px  → 2 cols
        # else     → up to 4 cols (natural sqrt layout)
        if content_width < 480:
            max_cols = 1
        elif content_width < 680:
            max_cols = 2
        else:
            max_cols = 4
        min_cols = None
        rows, cols = self.app.calculate_rows_cols(len(plugins), max_cols=max_cols, min_cols=min_cols)

        # Store current column count to detect changes
        self._current_cols = len(cols)
        self._current_max_cols = max_cols

        content_frame = customtkinter.CTkFrame(
            self.main_frame, corner_radius=0, fg_color="transparent"
        )
        # Place grid at row 2
        content_frame.grid(row=2, column=0, sticky="new", padx=15, pady=0)
        content_frame.grid_columnconfigure(0, weight=1)
        
        # Store reference for rebuilding
        self._content_frame = content_frame

        self.grid_frame = self.app.create_grid(
            frame=content_frame,
            row=0,
            column=0,
            plugins=plugins,
            color="transparent",
            sticky="nsew",
            max_cols=max_cols,
            min_cols=min_cols,
            aspect_ratio=1.0
        )

        def open_plugin(p):
            # Preserve existing functionality: use app frame switching (updates sidebar state)
            try:
                self.app.select_frame_by_name(
                    f"frame_{p.get_name()}", button=p.get_button()
                )
            except Exception:
                p.create_main_screen().grid(row=0, column=1, sticky="nsew")

        for index, plugin in enumerate(plugins):
            r = index // len(cols)
            c = index % len(cols)
            self.app.create_plugin_card(
                r, c, self.grid_frame, plugin, 
                show_description=True
            )
        
        # Bind resize handler to app window for responsive layout
        self._bind_responsive_resize()

        return self.main_frame
    
    def _resolve_max_cols(self):
        """Column count for the current content width (mirrors create_main_screen)."""
        import platform as _plat
        _sidebar = 250
        _padding = 60 if _plat.system() == "Windows" else 40
        # Match create_main_screen/on_resize: winfo_width() is physical px, so
        # normalize to logical units before comparing against the logical 480/680
        # thresholds. Without this, the cache signature uses the wrong column
        # count on any HiDPI display (Windows 200%, HiDPI Linux) and makes stale
        # keep/rebuild decisions.
        _scale = self._widget_scale()
        window_width = self.app.winfo_width()
        if window_width <= 1:
            window_width = int(1344 * _scale)
        window_width = int(window_width / _scale)
        content_width = max(1, window_width - _sidebar - _padding)
        if content_width < 480:
            return 1
        if content_width < 680:
            return 2
        return 4

    def screen_signature(self):
        """Cache the built dashboard until something it displays actually changes.

        Captures every volatile input the build bakes in: appearance mode, the
        VPN "Protected" banner state, each card's status badge, and the column
        count (which depends on window width). Any change → unequal signature →
        full rebuild; otherwise the screen is re-shown instantly.
        """
        try:
            if not hasattr(self.app, "plugin_list") or not self.app.plugin_list:
                plugin_list = PluginManager(self.app).plugins
            else:
                plugin_list = self.app.plugin_list

            plugins = [
                p for p in plugin_list
                if p.get_name() != "Dashboard" and p.order != -1
            ]
            statuses = tuple((p.get_name(), p.get_status()) for p in plugins)

            vpn_plugin = next(
                (p for p in plugin_list if p.get_name() == "VPN"), None
            )
            vpn_ok = bool(vpn_plugin and vpn_plugin.get_status() == "OK")

            return (
                "dashboard",
                self._effective_appearance_mode(),
                vpn_ok,
                self._resolve_max_cols(),
                statuses,
            )
        except Exception:
            # Any failure → no caching (rebuild as before).
            return None

    def _bind_responsive_resize(self):
        """
        Bind a resize handler to rebuild grid when the column count needs to change.

        Uses a 250ms debounce so the grid is only rebuilt once the user finishes (or
        pauses) resizing — not on every pixel during a drag.  Position-only Configure
        events (window moved but not resized) are filtered out immediately so they
        never queue a rebuild at all.
        """
        def on_resize(event=None):
            if not hasattr(self, '_dashboard_plugins') or not hasattr(self, '_content_frame'):
                return
            try:
                if not self._content_frame.winfo_exists():
                    return
            except Exception:
                return

            _scale = self._widget_scale()
            window_width = int(self.app.winfo_width() / _scale)
            content_width = max(1, window_width - 250 - self._padding_offset)

            if content_width < 480:
                max_cols = 1
            elif content_width < 680:
                max_cols = 2
            else:
                max_cols = 4
            min_cols = None

            target_cols = len(self.app.calculate_rows_cols(
                len(self._dashboard_plugins), max_cols=max_cols, min_cols=min_cols)[1])

            if getattr(self, '_current_cols', None) == target_cols:
                return

            self._rebuild_grid(max_cols, min_cols)

        self._resize_after_id = None
        # Track the last known window dimensions so we can ignore position-only events.
        self._last_win_size = [0, 0]
        import platform as _plat
        self._padding_offset = 60 if _plat.system() == "Windows" else 40

        def debounced_resize(event=None):
            # Filter: ignore Configure events that only changed position, not size.
            if event:
                if event.width == self._last_win_size[0] and event.height == self._last_win_size[1]:
                    return
                self._last_win_size[0] = event.width
                self._last_win_size[1] = event.height

            # Skip if dashboard is no longer visible or has been destroyed.
            if not hasattr(self, 'main_frame'):
                return
            try:
                if not self.main_frame.winfo_exists() or not self.main_frame.winfo_ismapped():
                    return
            except Exception:
                return

            # Always debounce — never fire mid-drag, even on threshold crossings.
            # Rebuilding the grid while the user is still dragging causes the visible
            # flash/glitch on Windows; waiting until they pause/stop eliminates it.
            if self._resize_after_id:
                self.app.after_cancel(self._resize_after_id)
            self._resize_after_id = self.app.after(250, on_resize)

        # LEAK PREVENTION: unbind any handler left over from a previous tab visit.
        if hasattr(self, '_resize_handler_id') and self._resize_handler_id:
            try:
                self.app.unbind("<Configure>", self._resize_handler_id)
            except Exception:
                pass

        self._resize_handler_id = self.app.bind("<Configure>", debounced_resize, add="+")
    
    def destroy(self):
        """Cleanup handler for uninstallation."""
        if hasattr(self, '_resize_after_id') and self._resize_after_id:
            try:
                self.app.after_cancel(self._resize_after_id)
            except:
                pass
        
        if hasattr(self, '_resize_handler_id') and self._resize_handler_id:
            try:
                self.app.unbind("<Configure>", self._resize_handler_id)
            except:
                pass
        
        super().destroy()
    
    def _rebuild_grid(self, max_cols, min_cols=None):
        """Rebuild the plugin grid with new column count."""
        if not hasattr(self, '_dashboard_plugins') or not hasattr(self, '_content_frame'):
            return
        
        plugins = self._dashboard_plugins
        
        # Destroy old grid
        if hasattr(self, 'grid_frame') and self.grid_frame:
            try:
                self.grid_frame.destroy()
            except:
                pass
        
        rows, cols = self.app.calculate_rows_cols(len(plugins), max_cols=max_cols, min_cols=min_cols)
        self._current_cols = len(cols)
        self._current_max_cols = max_cols

        # Refresh the content_width hint with the current window size.
        # Without this, create_grid would walk up to find the stale hint that
        # was set during the initial dashboard load (when winfo_width hadn't
        # been applied yet), giving wrong target_height on the rebuilt grid.
        _scale = self._widget_scale()
        window_width = int(self.app.winfo_width() / _scale)
        content_width = max(1, window_width - 250 - self._padding_offset)
        self.app._content_width_hint = content_width

        self.grid_frame = self.app.create_grid(
            frame=self._content_frame,
            row=0,
            column=0,
            plugins=plugins,
            color="transparent",
            sticky="nsew",
            max_cols=max_cols,
            min_cols=min_cols,
            aspect_ratio=1.0,
        )

        for index, plugin in enumerate(plugins):
            r = index // len(cols)
            c = index % len(cols)
            self.app.create_plugin_card(
                r, c, self.grid_frame, plugin,
                show_description=True
            )

        # Settle the rebuilt cards synchronously so a column-count change during
        # resize lands in its final layout in one pass (no post-rebuild reflow).
        try:
            self.app._settle_screen(self.main_frame)
        except Exception:
            pass
