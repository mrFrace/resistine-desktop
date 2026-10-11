import os
import sys
import math
import platform
import tkinter as tk

import customtkinter
from customtkinter import ThemeManager
from PIL import Image, ImageDraw

from gui.notifications import ToastNotification
from utils.logger import logger
from utils import branding
from utils.functions import get_resource_path


class AppUI(customtkinter.CTk):
    """
    Base application class handling UI creation and management.
    Inherits from CTk to serve as the main window base.
    """

    status_colors = {
        "ok": "#22C55E",
        "info": "#3B82F6",
        "warning": "#F59E0B",
        "error": "#EF4444",
        "critical": "#DC2626",
    }

    @staticmethod
    def _add_rounded_corners(image, radius):
        """Add rounded corners to a PIL Image."""
        # Create a mask with rounded corners
        mask = Image.new('L', image.size, 0)
        draw = ImageDraw.Draw(mask)
        draw.rounded_rectangle([(0, 0), image.size], radius=radius, fill=255)
        
        # Apply the mask to the image
        output = Image.new('RGBA', image.size, (0, 0, 0, 0))
        output.paste(image, (0, 0))
        output.putalpha(mask)
        
        return output

    @classmethod
    def create_tab_button(cls, frame, name, icon, command=None, row=0, col=0):
        """Create a sidebar button with filled-pill active state."""
        text_color = cls._get_theme_color("CTkLabel", "text_color")
        hover_bg = ThemeManager.theme.get("Theme", {}).get(
            "sidebar_hover_bg", ["#F0F0F5", "#1F1F22"]
        )

        btn = customtkinter.CTkButton(
            frame,
            corner_radius=10,
            height=40,
            border_spacing=10,
            text=name,
            fg_color="transparent",
            text_color=text_color,
            hover_color=hover_bg,
            border_width=0,
            border_color=hover_bg,
            image=icon,
            anchor="w",
            font=customtkinter.CTkFont(size=14, weight="normal"),
            command=command,
        )

        btn.grid(row=row, column=col, sticky="ew", padx=12, pady=2)
        return btn

    @classmethod
    def update_tab_button_active_state(
        cls, button: customtkinter.CTkButton, is_active: bool
    ):
        """Apply filled-pill active/inactive styling."""
        active_bg = ThemeManager.theme.get("Theme", {}).get(
            "sidebar_active_bg", ["#EBF0FF", "#1A2744"]
        )
        active_text = ThemeManager.theme.get("Theme", {}).get(
            "sidebar_active_text", ["#0D5394", "#60A5FA"]
        )
        default_text = cls._get_theme_color("CTkLabel", "text_color")

        try:
            if not button or not button.winfo_exists():
                return

            if is_active:
                button.configure(
                    fg_color=active_bg,
                    text_color=active_text,
                    border_width=0,
                )
            else:
                button.configure(
                    fg_color="transparent",
                    text_color=default_text,
                    border_width=0,
                )
        except (tk.TclError, RuntimeError, AttributeError):
            pass


    @classmethod
    def create_plugin_card(cls, row, column, container_frame, plugin, show_description=False, extra_buttons_func=None, truncate=False):
        """Create a compact plugin card with inline icon, title, and status badge."""
        card_bg = cls._get_theme_color("CTkFrame", "fg_color")
        border_color = cls._get_theme_color("CTkFrame", "border_color")
        text_primary = cls._get_theme_color("CTkLabel", "text_color")
        text_secondary = ThemeManager.theme.get("Theme", {}).get(
            "text_secondary", ["#6B7280", "#9CA3AF"]
        )
        hover_bg = ThemeManager.theme.get("Theme", {}).get(
            "sidebar_hover_bg", ["#F0F0F5", "#1F1F22"]
        )
        corner_radius = 12

        frame = customtkinter.CTkFrame(
            container_frame,
            corner_radius=corner_radius,
            fg_color=card_bg,
            border_width=1,
            border_color=border_color,
        )
        frame._resistine_plugin_card = True
        frame.grid(row=row, column=column, padx=8, pady=8, sticky="nsew")
        frame.grid_columnconfigure(0, weight=1)
        frame.grid_rowconfigure(0, weight=0)  # header
        frame.grid_rowconfigure(1, weight=0)  # description
        frame.grid_rowconfigure(2, weight=1)  # spacer / extra buttons

        # --- Header: icon (left) + title/badge stack (right) ---
        header = customtkinter.CTkFrame(frame, fg_color="transparent")
        header.grid(row=0, column=0, sticky="new", padx=16, pady=(16, 0))
        header.grid_columnconfigure(1, weight=1, minsize=40)
        header.grid_rowconfigure(0, weight=0)  # title row
        header.grid_rowconfigure(1, weight=0)  # badge row

        # --- Compute initial wraplength BEFORE creating labels ---
        # Walk ancestors to find total content-area width and column count so the very
        # first render uses a realistic wraplength instead of an arbitrary small fallback.
        _init_tw = 150
        _init_dw = 200
        try:
            _hw, _nc = 0, 0
            _p = container_frame
            while _p:
                if not _hw and hasattr(_p, "_content_width_hint") and _p._content_width_hint:
                    _hw = _p._content_width_hint
                if not _nc and hasattr(_p, "_resistine_num_cols"):
                    _nc = _p._resistine_num_cols
                if _hw and _nc:
                    break
                _p = getattr(_p, "master", None)
            if _hw > 10 and _nc > 0:
                _cw = max(100, _hw // _nc - 20)
                _init_tw = max(80, _cw - 80)
                _init_dw = max(100, _cw - 40)
        except Exception:
            pass

        icon_image = plugin.get_icon_large() if hasattr(plugin, 'get_icon_large') else plugin.get_icon()
        if icon_image:
            icon_label = customtkinter.CTkLabel(header, image=icon_image, text="")
            icon_label.grid(row=0, column=0, rowspan=2, sticky="nw", padx=(0, 12))

        title_label = customtkinter.CTkLabel(
            header,
            text=plugin.get_name(),
            font=customtkinter.CTkFont(size=16, weight="bold"),
            text_color=text_primary,
            anchor="w",
            wraplength=_init_tw,
        )
        title_label.grid(row=0, column=1, sticky="ew")

        # Status badge (pill) — placed below the title so it doesn't squeeze it
        current_status = plugin.get_status()
        if current_status is not None and str(current_status).strip():
            status_key = str(current_status).lower()
            badge_bg = ThemeManager.theme.get("Theme", {}).get(
                "status_badge_bg", {}
            ).get(status_key, ["#F3F4F6", "#374151"])
            badge_text_color = ThemeManager.theme.get("Theme", {}).get(
                "status_badge_text", {}
            ).get(status_key, ["#6B7280", "#9CA3AF"])

            badge = customtkinter.CTkLabel(
                header,
                text=str(current_status).title(),
                font=customtkinter.CTkFont(size=11, weight="bold"),
                text_color=badge_text_color,
                fg_color=badge_bg,
                corner_radius=6,
                height=22,
            )
            badge.grid(row=1, column=1, sticky="w", pady=(4, 0))

        # --- Description ---
        _desc_lbl = None
        if show_description:
            description = plugin.get_description()
            if truncate and len(description) > 80:
                description = description[:77] + "..."

            desc_label = customtkinter.CTkLabel(
                frame,
                text=description,
                font=customtkinter.CTkFont(size=12),
                text_color=text_secondary,
                wraplength=_init_dw,
                justify="left",
                anchor="nw",
            )
            desc_label.grid(row=1, column=0, sticky="new", padx=16, pady=(8, 0))
            _desc_lbl = desc_label

        # --- Extra buttons (Store page) ---
        if extra_buttons_func:
            buttons_area = customtkinter.CTkFrame(frame, fg_color="transparent")
            buttons_area.grid(row=2, column=0, sticky="sew", padx=16, pady=(8, 16))
            extra_buttons_func(buttons_area, plugin)

        # --- Wraplength: update once after resize stops ---
        # During active resize the card fires <Configure> on every layout pass.
        # We debounce the actual configure(wraplength=…) call so it only runs
        # once — 150 ms after the card stops changing size.  This eliminates the
        # N×card label canvas-redraws that happened on every pixel of drag on Win.
        _wrap_state = [_init_tw, _init_dw]
        _wrap_job = [None]
        _tl = title_label
        _dl = _desc_lbl if show_description else None

        def _apply_wraplength(_f=frame, _tl=_tl, _dl=_dl, _s=_wrap_state, _j=_wrap_job):
            _j[0] = None
            try:
                # winfo_width() is physical px; CTkLabel.configure(wraplength=)
                # re-applies widget scaling internally, so feed it logical units.
                # Divide by the SAME scaling CTk re-applies — its widget scaling
                # — NOT _hidpi_factor. On Windows _hidpi_factor is unset (1.0) but
                # CTk's widget scaling is ~1.25 at 125%, so dividing by
                # _hidpi_factor left card_w physical and the re-applied scaling
                # made wraplength ~25% too wide → the description never wrapped
                # and got clipped. get_widget_scaling == _hidpi_factor on Linux,
                # 1.25 on Windows 125%, 1.0 on macOS.
                try:
                    _scale = customtkinter.ScalingTracker.get_widget_scaling(_f)
                except Exception:
                    _scale = getattr(
                        _f.winfo_toplevel(), "_hidpi_factor", 1.0) or 1.0
                card_w = _f.winfo_width() / _scale
                if card_w <= 4:
                    return
                new_tw = max(80, card_w - 80)
                new_dw = max(100, card_w - 40)
                if abs(new_tw - _s[0]) >= 4:
                    _s[0] = new_tw
                    _tl.configure(wraplength=new_tw)
                if _dl and abs(new_dw - _s[1]) >= 4:
                    _s[1] = new_dw
                    _dl.configure(wraplength=new_dw)
            except Exception:
                pass

        def _schedule_wraplength(event=None, _f=frame, _j=_wrap_job):
            if _j[0] is not None:
                try:
                    _f.after_cancel(_j[0])
                except Exception:
                    pass
            _j[0] = _f.after(150, _apply_wraplength)

        # <Configure> only schedules (cheap) — for genuine resizes after load.
        frame.bind("<Configure>", _schedule_wraplength)
        # Synchronous finalizer: _settle_screen() calls this once, after layout,
        # so the wraplength is correct on first paint. This replaces the old
        # <Map> + after(1) correction timers that made the text reflow visibly.
        frame._resistine_finalize = _apply_wraplength

        # --- Interaction ---
        def on_click(_e=None):
            curr = container_frame
            while curr and not hasattr(curr, "select_frame_by_name"):
                curr = curr.master
            if not curr:
                return
            # Login plugin's create_main_screen() does a full-window takeover
            # (parents to the App root, grids at 0,0). Routing it through
            # select_frame_by_name would re-grid it into the content column
            # and produce a broken half-rendered login. Special-case it here.
            if getattr(plugin, "id", None) == "007" and hasattr(curr, "show_login_screen"):
                curr.show_login_screen()
                return
            curr.select_frame_by_name(f"frame_{plugin.get_name()}")

        _hovered = [False]

        def on_enter(_e):
            try:
                if not _hovered[0] and frame.winfo_exists():
                    _hovered[0] = True
                    frame.configure(fg_color=hover_bg, corner_radius=corner_radius)
            except (tk.TclError, AttributeError, RuntimeError):
                pass

        def on_leave(e):
            try:
                if not _hovered[0] or not frame.winfo_exists():
                    return
                x = e.x_root - frame.winfo_rootx()
                y = e.y_root - frame.winfo_rooty()
                if 0 <= x < frame.winfo_width() and 0 <= y < frame.winfo_height():
                    return  # still inside the frame
                _hovered[0] = False
                frame.configure(fg_color=card_bg, corner_radius=corner_radius)
            except (tk.TclError, AttributeError, RuntimeError):
                pass

        def bind_recursive(widget):
            try:
                if isinstance(widget, customtkinter.CTkButton):
                    return
                if not widget.winfo_exists():
                    return
                widget.bind("<Button-1>", on_click)
                widget.bind("<Enter>", on_enter)
                widget.bind("<Leave>", on_leave)
                for child in widget.winfo_children():
                    bind_recursive(child)
            except (tk.TclError, AttributeError, RuntimeError):
                pass

        bind_recursive(frame)
        return frame

    def show_readme(self, plugin):
        """
        Open a new window to show the plugin's README.md file.
        """
        from plugins.help.markdown_viewer import MarkdownViewer
        
        # Determine the README path
        plugin_module = plugin.__class__.__module__
        # Assuming plugin modules are in plugins.name.main or name.main
        # We can try to get the file path from the module
        module = sys.modules.get(plugin_module)
        if not module or not hasattr(module, "__file__"):
            self.show_notification("Could not find plugin source for README", type="error")
            return
            
        plugin_dir = os.path.dirname(module.__file__)
        readme_path = os.path.join(plugin_dir, "README.md")
        
        if not os.path.exists(readme_path):
            self.show_notification(f"README.md not found for {plugin.get_name()}", type="warning")
            return

        # Create Toplevel window
        window = customtkinter.CTkToplevel(self)
        window.title(f"{plugin.get_name()} - Documentation")
        window.geometry("800x600")
        window.attributes("-topmost", True) # Keep on top for visibility
        window.after(100, lambda: window.attributes("-topmost", False)) # But allow moving behind

        viewer = MarkdownViewer(window, docs_dir=plugin_dir)
        viewer.pack(fill="both", expand=True, padx=20, pady=20)
        viewer.load_file(readme_path)

    @classmethod
    def get_font(cls, key="CTkFont"):
        """Resolves the font family from ThemeManager."""
        try:
            return ThemeManager.theme[key]["family"]
        except (KeyError, TypeError):
            # Fallback if the specific structure isn't exactly as expected for 'family'
            # The JSON shows CTkFont -> macOS/Windows/Linux -> family
            # But ThemeManager might flatten it or we need to check platform manually if ThemeManager doesn't.
            # Actually, ThemeManager.theme["CTkFont"] in the user's JSON has "macOS" etc.
            # Standard ThemeManager.theme usually resolves this?
            # Let's check how the user's JSON was ("CTkFont": { "macOS": ... }).
            # If ThemeManager loads it directly, we might need platform check or rely on CTkFont default.
            # However, usage of `customtkinter.CTkFont` usually handles family automatically if not specified?
            # Or we can just use "Inter" if we know it.
            # Let's try to lookup properly.
            # The JSON has "CTkFont": { "macOS": ... }
            # If we want to be safe, we just use the name "Inter" if available or leave it to CTk default.
            return "Inter"

    @classmethod
    def _get_theme_color(cls, widget_type, attribute):
        """Helper to safely get color tuple from ThemeManager."""
        try:
            return ThemeManager.theme[widget_type][attribute]
        except KeyError:
            return None

    @classmethod
    def _get_theme_corner_radius(cls):
        """Helper to get the global corner radius from theme."""
        try:
            return ThemeManager.theme["Theme"]["corner_radius"]
        except KeyError:
            return 15  # Default fallback

    @classmethod
    def calculate_rows_cols(cls, num_plugins, max_cols=None, min_cols=None):
        """Calculate rows and columns for a grid layout.
        
        Args:
            num_plugins: Number of plugins to display
            max_cols: Optional maximum number of columns (for responsive layouts)
            min_cols: Optional minimum number of columns (for responsive layouts)
        """
        cols = math.ceil(math.sqrt(num_plugins))
        if max_cols is not None and cols > max_cols:
            cols = max_cols
        if min_cols is not None and cols < min_cols:
            cols = min_cols
        rows = math.ceil(num_plugins / cols) if cols > 0 else 1
        return tuple(range(rows)), tuple(range(cols))


    @classmethod
    def create_grid(cls, frame, row, column, plugins, color, sticky="nsew", aspect_ratio=1.3, max_cols=None, min_cols=None):
        """Create a mathematically uniform grid layout for plugins with a consistent aspect ratio.
        
        Args:
            max_cols: Optional maximum number of columns (for responsive layouts)
            min_cols: Optional minimum number of columns (for responsive layouts)
        """
        rows_tuple, cols_tuple = cls.calculate_rows_cols(len(plugins), max_cols=max_cols, min_cols=min_cols)

        container = customtkinter.CTkFrame(frame, corner_radius=0, fg_color=color)
        container.grid(row=row, column=column, sticky=sticky)
        
        # Force uniform sizing for columns; weight=1 makes them expand/shrink together
        container.grid_columnconfigure(cols_tuple, weight=1, uniform="plugin_grid")

        # Optimization properties
        container._resistine_last_w = -1
        container._resistine_last_height = -1
        container._resistine_num_cols = len(cols_tuple)
        container._resistine_resize_job = None

        def update_aspect_ratio(event=None, force_width=None):
            if event and not force_width:
                if container._resistine_resize_job:
                    try:
                        container.after_cancel(container._resistine_resize_job)
                    except:
                        pass
                # 200 ms debounce: matches the CTkScrollableFrame inner-frame freeze so
                # both the frame snap and the row-height update fire in the same pass,
                # avoiding a second wave of card redraws shortly after the first.
                container._resistine_resize_job = container.after(200, lambda: _do_update_aspect_ratio())
                return
            _do_update_aspect_ratio(force_width=force_width)

        def _do_update_aspect_ratio(force_width=None):
            container._resistine_resize_job = None
            try:
                if not container.winfo_exists():
                    return
                # CTk's widget scaling is the real OS-DPI ratio on every
                # platform (2.0 at 200% on Windows, 1.0 on macOS, == _hidpi_factor
                # on Linux). _hidpi_factor alone is 1.0 on Windows even when CTk
                # scales 2x, which left card heights mis-proportioned there.
                try:
                    _scale = customtkinter.ScalingTracker.get_widget_scaling(container)
                except Exception:
                    _scale = getattr(
                        container.winfo_toplevel(), "_hidpi_factor", 1.0) or 1.0
                # force_width (from hint) is already in logical units;
                # winfo_width() is physical pixels — normalise to logical.
                if force_width:
                    total_width = force_width
                else:
                    total_width = container.winfo_width() / _scale
                if total_width <= 1:
                    return
                if container._resistine_last_w != -1 and abs(total_width - container._resistine_last_w) < 4:
                    return
                container._resistine_last_w = total_width
                num_cols = container._resistine_num_cols
                if num_cols == 0:
                    return
                col_width = total_width / num_cols
                card_width = max(1, col_width - 20)
                # Bounds are in logical units; convert to physical for grid_rowconfigure.
                target_height = max(160, min(300, int(card_width / aspect_ratio) + 20))
                container._resistine_target_height = target_height
                if target_height != container._resistine_last_height:
                    container._resistine_last_height = target_height
                    for r in rows_tuple:
                        container.grid_rowconfigure(r, minsize=int(target_height * _scale))
            except (tk.TclError, AttributeError, RuntimeError):
                pass

        container.bind("<Configure>", update_aspect_ratio)

        # Synchronous finalizer: _settle_screen() calls this once, after the
        # screen is gridded, to set row heights from the real measured width —
        # so the first paint is final. (The <Configure> handler above only
        # fires for genuine resizes afterwards.)
        container._resistine_finalize = lambda: _do_update_aspect_ratio()

        # Best-effort eager pass from the width hint so the pre-settle layout is
        # already close (avoids a large jump if anything paints before settle).
        hint = None
        parent = container.master
        while parent:
            if hasattr(parent, "_content_width_hint") and parent._content_width_hint:
                hint = parent._content_width_hint
                break
            parent = getattr(parent, "master", None)

        if hint and hint > 1:
            update_aspect_ratio(force_width=hint)
        elif container.winfo_width() > 1:
            update_aspect_ratio()

        return container

    def refresh_navigation(self):
        """
        Surgical update: Rebuild only the navigation sidebar buttons.
        """
        if not hasattr(self, "navigation_frame") or not self.navigation_frame.winfo_exists():
            # If sidebar doesn't exist, we must do a full dashboard creation
            return self.create_dashboard()

        # Clear existing buttons from navigation frame
        try:
            for widget in self.navigation_frame.winfo_children():
                if not widget.winfo_exists():
                    continue
                # Keep the logo (row 0) and separator (row 1)
                info = widget.grid_info()
                if info and int(info.get("row", 0)) > 1:
                    widget.destroy()
        except Exception as e:
            logger.warning(f"Error while clearing navigation frame: {e}")

        # Reset grid row configurations to avoid gaps from uninstalled plugins
        # We assume a reasonable maximum number of plugins (e.g. 50) to clear weights
        for r in range(50):
            self.navigation_frame.grid_rowconfigure(r, weight=0)

        # Update plugin list from manager
        self.plugin_list = self.get_plugin_manager().plugins
        # Spacer row: logo(0) + separator(1) + plugins + 1
        spacer_row = len(self.plugin_list) + 2
        self.navigation_frame.grid_rowconfigure(spacer_row, weight=1)

        self.frames = {}
        row = 2
        for plugin in self.plugin_list:
            # Plugins with order <= 0 aren't navigable from the dashboard
            # (no sidebar button, no card click-through). Login is the
            # canonical case: its create_main_screen() takes over the whole
            # window for the auth flow, not a content-column widget.
            if plugin.order <= 0:
                continue
            frame_name = f"frame_{plugin.get_name()}"
            self.frames[frame_name] = plugin

            try:
                # Create sidebar button
                btn = self.create_tab_button(
                    self.navigation_frame,
                    plugin.get_name(),
                    plugin.get_icon(),
                    lambda p=plugin: self.select_frame_by_name(
                        f"frame_{p.get_name()}", button=p.get_button()
                    ),
                    row,
                    0,
                )
                plugin.set_button(btn)
                # Ensure the button reflects the current active state if we are on this plugin's frame
                if frame_name == getattr(self, "current_frame_name", ""):
                    self.update_tab_button_active_state(btn, is_active=True)
            except Exception as e:
                logger.error(f"Error loading plugin button {plugin.get_name()}: {e}")
            row += 1

        # Invalidate cached screens for plugins that no longer exist
        # (e.g. after an uninstall) so we don't leak their widget trees.
        if hasattr(self, "_screen_cache"):
            for cached_name in list(self._screen_cache.keys()):
                if cached_name in self.frames:
                    continue
                widget, _sig = self._screen_cache.pop(cached_name)
                try:
                    if (
                        widget is not getattr(self, "_current_main_screen", None)
                        and widget.winfo_exists()
                    ):
                        widget.destroy()
                except Exception:
                    pass

    def create_dashboard(self):
        """
        Create the main dashboard of the application.
        """
        for widget in self.winfo_children():
            if isinstance(widget, (tk.Toplevel, customtkinter.CTkToplevel)):
                continue
            widget.destroy()

        # All main screens were just destroyed; drop their (now-dead) cache refs
        # and the current-screen pointer so navigation rebuilds from scratch.
        self._screen_cache = {}
        self._current_main_screen = None

        # Re-configure the main window
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=0)  # Navigation column
        self.grid_columnconfigure(1, weight=1)  # Content column

        # Theme-aware sidebar colors
        sidebar_bg = ThemeManager.theme.get("Theme", {}).get(
            "sidebar_bg", self._get_theme_color("CTkFrame", "fg_color")
        )
        sidebar_text_color = self._get_theme_color("CTkLabel", "text_color")

        self.navigation_frame = customtkinter.CTkFrame(
            self, corner_radius=0, fg_color=sidebar_bg
        )
        self.navigation_frame.grid(row=0, column=0, sticky="nsew", padx=0, pady=0)
        self.grid_columnconfigure(0, minsize=250)
        self.navigation_frame.grid_columnconfigure(0, weight=1)

        # Logo: Phoenix mark + product name
        logo_image = None
        mark_path = get_resource_path(
            os.path.join("resources", "icons", branding.LOGO_MARK))
        if os.path.exists(mark_path):
            try:
                mark = Image.open(mark_path)
                logo_image = customtkinter.CTkImage(
                    light_image=mark, dark_image=mark, size=(40, 40))
            except Exception as e:
                logger.error(f"Error loading logo: {e}")

        self.navigation_frame_label = customtkinter.CTkLabel(
            self.navigation_frame,
            text=f"  {branding.APP_NAME}",
            image=logo_image,
            compound="left",
            anchor="w",
            font=customtkinter.CTkFont(family="Inter", size=20, weight="bold"),
            text_color=sidebar_text_color,
        )
        self.navigation_frame_label.grid(
            row=0, column=0, padx=12, pady=(20, 8), sticky="ew"
        )

        # Separator below logo
        separator_color = ThemeManager.theme.get("Theme", {}).get(
            "divider_color", ["#E5E7EB", "#2A2A2A"]
        )
        self._nav_separator = customtkinter.CTkFrame(
            self.navigation_frame,
            height=1,
            fg_color=separator_color,
            corner_radius=0,
        )
        self._nav_separator.grid(row=1, column=0, sticky="ew", padx=16, pady=(0, 8))

        # Use the surgical refresh to handle the buttons
        self.refresh_navigation()

        self.select_frame_by_name("frame_Dashboard")

    def select_frame_by_name(self, name, button=None):
        """
        Select and display the specified frame.
        """
        self.current_frame_name = name

        # Precompute content width hint for smooth initial plugin rendering.
        try:
            total_w = self.winfo_width()
            if total_w > 1:
                # Use actual navigation sidebar width if available, fallback to 250 (sidebar minsize)
                nav_w = self.navigation_frame.winfo_width() if hasattr(self, "navigation_frame") else 250
                if nav_w < 100: nav_w = 250  # Fallback for unmapped frame

                # Windows CTkScrollableFrame scrollbar is ~20px wider than macOS overlay scrollbar
                _scroll_offset = 60 if platform.system() in ("Windows", "Linux") else 40
                self._content_width_hint = total_w - nav_w - _scroll_offset
        except:
            self._content_width_hint = None

        # Update button active states up-front so the click feels responsive
        # even if the new screen takes a moment to build.
        for frame_name, frame in getattr(self, "frames", {}).items():
            btn = frame.get_button() if hasattr(frame, "get_button") else None
            if not btn:
                continue
            self.update_tab_button_active_state(btn, is_active=(frame_name == name))

        # Resolve target plugin
        frame = self.frames.get(name) if hasattr(self, "frames") else None
        if not frame:
            return

        # Build the new screen BEFORE touching the old one. It is parented to
        # self.app and gridded but stacked *below* the currently visible screen,
        # so the old screen stays on display until the new one is ready to swap
        # in — the user never sees an empty/partial rectangle.
        #
        # Each navigation gets a sequence number so a *deferred* reveal (used for
        # async-rendering screens) can detect that a newer navigation superseded
        # it while it was waiting to settle, and bow out cleanly.
        self._nav_seq = getattr(self, "_nav_seq", 0) + 1
        _my_seq = self._nav_seq

        # Per-frame cache of built screens: {name: (widget, signature)}.
        # A plugin opts into caching by returning a non-None screen_signature();
        # when that signature is unchanged we re-show the existing widget tree
        # instead of rebuilding it (rebuilds re-run hundreds of canvas draws).
        if not hasattr(self, "_screen_cache"):
            self._screen_cache = {}

        def _alive(w):
            try:
                return w is not None and w.winfo_exists()
            except Exception:
                return False

        try:
            signature = frame.screen_signature() if hasattr(frame, "screen_signature") else None
        except Exception:
            signature = None

        cached_widget, cached_sig = self._screen_cache.get(name, (None, None))
        cache_hit = (
            signature is not None
            and _alive(cached_widget)
            and cached_sig == signature
        )

        try:
            if cache_hit:
                # Re-show the existing widget tree. grid_remove() preserved its
                # grid options, so a bare grid() restores placement exactly.
                main_screen = cached_widget
                main_screen.grid(row=0, column=1, sticky="nsew")
            else:
                # Stale cache entry for this frame (signature changed): drop the
                # old widget so we don't leak it. Skip if it's the currently
                # shown screen — that's handled by the teardown step below.
                if (
                    _alive(cached_widget)
                    and cached_widget is not getattr(self, "_visible_screen", None)
                ):
                    try:
                        cached_widget.destroy()
                    except Exception:
                        pass

                main_screen = frame.create_main_screen()

                main_screen.grid(row=0, column=1, sticky="nsew")
                main_screen.grid_columnconfigure(0, weight=1)
                main_screen.grid_rowconfigure(0, weight=1)

                # Attach smooth scrolling + auto-hide scrollbars for any
                # CTkScrollableFrames in this screen (idempotent; build-only).
                try:
                    self._install_scroll_behaviors(main_screen)
                except Exception:
                    pass

                # Cache the freshly built screen if the plugin opted in.
                if signature is not None:
                    self._screen_cache[name] = (main_screen, signature)
                else:
                    self._screen_cache.pop(name, None)

            # Stack the new screen directly BELOW the one it's replacing while we
            # settle its layout, so the old screen stays visible during the
            # settle (no provisional-layout flash). Lower it relative to the
            # *currently visible* screen — NOT to the absolute bottom — otherwise
            # it ends up beneath other cached/grid_removed screens (e.g. the
            # Dashboard), which then surface for a frame when the old screen is
            # removed during the swap.
            try:
                _vis = getattr(self, "_visible_screen", None)
                if _vis is not None and _vis is not main_screen and _alive(_vis):
                    main_screen.lower(_vis)
                else:
                    main_screen.lower()
            except Exception:
                pass

            # Resolve all size-dependent layout synchronously, now, against the
            # real geometry — instead of via a cascade of post-paint timers.
            self._settle_screen(main_screen)

            def _reveal(_seq=_my_seq, _screen=main_screen, _hit=cache_hit):
                # Superseded by a newer navigation while we waited to settle?
                # Abandon this reveal and clean up our now-orphaned screen.
                if _seq != getattr(self, "_nav_seq", _seq):
                    if _screen is not getattr(self, "_visible_screen", None):
                        _cached = any(
                            _screen is w for (w, _s) in self._screen_cache.values()
                        )
                        try:
                            if _cached:
                                _screen.grid_remove()
                            elif _alive(_screen):
                                _screen.destroy()
                        except Exception:
                            pass
                    return

                if _hit:
                    try:
                        if hasattr(frame, "on_screen_shown"):
                            frame.on_screen_shown()
                    except Exception:
                        pass

                # Bring the new screen to the front, then hide EVERY other screen
                # that could be occupying the content cell — the previously
                # visible one AND any other cached (grid_removed) screen. Hiding
                # only the previous screen left other cached screens (e.g. the
                # Dashboard) able to surface for a frame during the swap. Cached
                # screens are hidden (grid_remove, kept for reuse); uncached ones
                # are destroyed.
                try:
                    _screen.lift()
                except Exception:
                    pass

                _cached_widgets = [w for (w, _s) in self._screen_cache.values()]
                to_hide = []
                pv = getattr(self, "_visible_screen", None)
                if pv is not None and pv is not _screen:
                    to_hide.append(pv)
                for w in _cached_widgets:
                    if w is not _screen and w not in to_hide:
                        to_hide.append(w)
                for w in to_hide:
                    if not _alive(w):
                        continue
                    try:
                        if any(w is cw for cw in _cached_widgets):
                            w.grid_remove()
                        else:
                            w.grid_forget()
                            w.destroy()
                    except Exception:
                        pass
                self._visible_screen = _screen

            # Reveal immediately for cached screens (already fully drawn) and for
            # the very first screen (nothing to hide behind — startup reveal is
            # timed by main.py). For screens that opt into deferred reveal
            # (async rendering, e.g. Chat), keep the current screen visible until
            # the new one stops changing, then swap — so it doesn't tear mid-render.
            _defer = (
                not cache_hit
                and getattr(self, "_visible_screen", None) is not None
                and getattr(frame, "defer_reveal_until_settled", False)
            )
            if _defer:
                _ready = getattr(frame, "is_screen_ready", None)
                self._reveal_when_settled(
                    main_screen, _reveal, min_ms=120, quiet_ms=400,
                    cap_ms=4000, ready=_ready,
                )
            else:
                _reveal()

            self._current_main_screen = main_screen
        except Exception as e:
            logger.error(f"Error loading plugin frame {name}: {e}")
            self.show_notification(
                f"Error loading plugin {name.replace('frame_', '')}: {e}", type="error"
            )

            # Update status to error so it shows on the dashboard
            if hasattr(frame, "set_status"):
                frame.set_status("Error")

            # Show error message in place of the plugin content
            error_frame = customtkinter.CTkFrame(self)
            error_frame.grid(row=0, column=1, sticky="nsew")
            error_frame.grid_columnconfigure(0, weight=1)
            error_frame.grid_rowconfigure(0, weight=1)

            error_label = customtkinter.CTkLabel(
                error_frame,
                text=f"Error loading plugin:\n{e}",
                text_color="#FF3333",
                wraplength=400,
                font=customtkinter.CTkFont(size=14, weight="bold"),
            )
            error_label.pack(expand=True, padx=20, pady=20)
            self._current_main_screen = error_frame

    def _settle_screen(self, root_widget):
        """Resolve all size-dependent layout synchronously, before reveal.

        This replaces the old cascade of post-paint ``after()`` timers
        (per-card wraplength, grid row heights, scrollbar auto-hide) that made
        screens visibly reflow/"dance" after they appeared. Widgets register a
        synchronous finalizer and ``_settle_screen`` runs them all, in order,
        against the real measured geometry:

          1. ``_resistine_finalize_scroll`` — decide scrollbar visibility first,
             since removing an unneeded scrollbar widens the content area.
          2. ``_resistine_finalize`` — grid row heights and card wraplengths,
             now measured at their final width.

        Genuine user resizes are still handled by the debounced ``<Configure>``
        handlers each widget keeps; this only governs the first paint.
        """
        try:
            self.update_idletasks()
        except Exception:
            return

        # If the screen isn't mapped yet (startup, before the window is shown),
        # child widgets report size 1 — measuring would produce garbage. The
        # build-time (hint-based) sizing stands; main.py settles again once the
        # window is mapped (transparently) so the real measurement happens then.
        try:
            if not root_widget.winfo_ismapped():
                return
        except Exception:
            return

        def _walk(widget, attr):
            fn = getattr(widget, attr, None)
            if callable(fn):
                try:
                    fn()
                except Exception:
                    pass
            try:
                for child in widget.winfo_children():
                    _walk(child, attr)
            except Exception:
                pass

        # 1) Scrollbar visibility — before measuring card widths.
        _walk(root_widget, "_resistine_finalize_scroll")
        try:
            self.update_idletasks()
        except Exception:
            pass

        # 1b) Re-fit each scrollable frame's inner content to its canvas.
        #     Showing/hiding the scrollbar in step 1 changes the canvas width,
        #     but the inner-frame refit is normally driven by a <Configure>
        #     event — which update_idletasks() does NOT dispatch (only the event
        #     loop does). Without this, the content keeps the old width until the
        #     loop catches up after reveal (a visible correction: the scrollbar
        #     is right but the page is sized as if it weren't there).
        def _refit(widget):
            if isinstance(widget, customtkinter.CTkScrollableFrame):
                # Fit directly via itemconfigure rather than
                # _fit_frame_dimensions_to_canvas(): on Windows that method is
                # the throttled (leading-edge) patch, which suppresses an
                # immediate fit when a trailing job is already pending. We need
                # the fit to happen NOW, synchronously, so we replicate its body.
                try:
                    canvas = widget._parent_canvas
                    if widget._orientation == "horizontal":
                        canvas.itemconfigure(
                            widget._create_window_id, height=canvas.winfo_height()
                        )
                    elif widget._orientation == "vertical":
                        canvas.itemconfigure(
                            widget._create_window_id, width=canvas.winfo_width()
                        )
                except Exception:
                    pass
            try:
                for child in widget.winfo_children():
                    _refit(child)
            except Exception:
                pass

        _refit(root_widget)
        try:
            self.update_idletasks()
        except Exception:
            pass

        # 2) Grid + card sizing, measured against the now-final geometry.
        #    Pre-order walk sizes each grid container before its child cards.
        _walk(root_widget, "_resistine_finalize")
        try:
            self.update_idletasks()
        except Exception:
            pass

    def _reveal_when_settled(self, screen, reveal, interval_ms=40,
                             quiet_ms=300, min_ms=300, cap_ms=2500, ready=None):
        """Call ``reveal()`` once ``screen``'s layout has stopped changing.

        Tk resolves wraplength-driven heights, scroll regions and the auto-hide
        scrollbar over several feedback passes that take a few hundred ms to
        damp out — in *bursts* with gaps between them. Rather than fight to make
        that synchronous, we let it run while the window is still invisible and
        reveal only once the layout signature has been unchanged for ``quiet_ms``
        — longer than the biggest debounce gap (~250 ms), so we don't reveal in
        a lull mid-cascade.

        ``min_ms`` keeps us past the brief quiet window before the debounced
        handlers (60–250 ms) even begin. ``cap_ms`` is a hard ceiling so a
        never-quiescent screen still appears.
        """
        import time as _time

        start = _time.perf_counter()
        state = {"prev": None, "last_change": start, "done": False}

        def _signature():
            try:
                parts = [
                    screen.winfo_width(), screen.winfo_height(),
                    screen.winfo_reqwidth(), screen.winfo_reqheight(),
                ]
                stack = [screen]
                while stack:
                    w = stack.pop()
                    canvas = getattr(w, "_parent_canvas", None)
                    if canvas is not None:
                        try:
                            parts.append(canvas.bbox("all"))
                        except Exception:
                            pass
                    try:
                        stack.extend(w.winfo_children())
                    except Exception:
                        pass
                return tuple(repr(p) for p in parts)
            except Exception:
                return None

        def _finish(reason):
            if state["done"]:
                return
            state["done"] = True
            try:
                reveal()
            except Exception:
                pass

        def _tick():
            if state["done"]:
                return
            now = _time.perf_counter()
            sig = _signature()
            if sig != state["prev"]:
                state["prev"] = sig
                state["last_change"] = now
            elapsed = (now - start) * 1000.0
            quiet = (now - state["last_change"]) * 1000.0
            # Gate the "stable" reveal on the plugin reporting its content ready
            # (e.g. an async fetch returned). cap_ms still forces a reveal.
            try:
                ready_ok = ready is None or bool(ready())
            except Exception:
                ready_ok = True
            if ready_ok and elapsed >= min_ms and quiet >= quiet_ms:
                _finish("stable")
            elif elapsed >= cap_ms:
                _finish("cap")
            else:
                try:
                    self.after(interval_ms, _tick)
                except Exception:
                    _finish("error")

        try:
            self.after(interval_ms, _tick)
        except Exception:
            _finish("error")

    def refresh_ui_theme(self):
        """Refresh sidebar colors (if needed beyond automatic CTk updates)."""
        # Most CTk widgets update automatically if initialized with tuple colors.
        # We only really need to re-render to catch dynamic checks if any.
        try:
            name = getattr(self, "current_frame_name", None)
            if name:
                # Invalidate per-plugin theme/font caches so the next build
                # picks up the new appearance-mode colors.
                try:
                    from plugins.antivirus.theme import clear_theme_cache
                    clear_theme_cache()
                except Exception:
                    pass
                self.select_frame_by_name(name)
        except Exception:
            pass

    # ----------------------------
    # Scroll behavior improvements
    # ----------------------------
    def _install_scroll_behaviors(self, root_widget):
        """Recursively attach smooth scroll + auto-hide scrollbar to any CTkScrollableFrame widgets."""
        try:
            if isinstance(root_widget, customtkinter.CTkScrollableFrame):
                self._enable_smooth_scroll_and_autohide(root_widget)
        except Exception:
            pass

        try:
            for child in root_widget.winfo_children():
                self._install_scroll_behaviors(child)
        except Exception:
            pass

    def _smooth_wheel_dispatch(self, event):
        """Global <MouseWheel> router for smooth scrolling.

        Sends the wheel event to whichever registered CTkScrollableFrame
        contains the widget under the cursor, so multiple scroll frames on one
        screen (chat messages + history sidebar) each scroll when hovered. A
        per-frame bind_all can't do this — bind_all is global and last-wins.
        Dead frames are pruned as they're encountered.
        """
        handlers = getattr(self, "_smooth_scroll_handlers", None)
        if not handlers:
            return None

        # CTk 5.x exposed CTkScrollableFrame.check_if_master_is_canvas; CTk
        # 6.0 removed it. Walk the master chain inline to stay portable.
        def _is_inside(scroll_frame, widget):
            canvas = getattr(scroll_frame, "_parent_canvas", None)
            cur = widget
            while cur is not None:
                if cur is canvas:
                    return True
                try:
                    cur = cur.master
                except Exception:
                    return False
            return False

        target = None
        alive = []
        for sc, fn in handlers:
            try:
                if not sc.winfo_exists():
                    continue
            except Exception:
                continue
            alive.append((sc, fn))
            if target is None:
                try:
                    if _is_inside(sc, event.widget):
                        target = fn
                except Exception:
                    pass
        if len(alive) != len(handlers):
            self._smooth_scroll_handlers = alive
        if target is not None:
            return target(event)
        return None

    def _enable_smooth_scroll_and_autohide(self, scrollable: customtkinter.CTkScrollableFrame):
        """
        Make scrolling feel smoother and hide the scrollbar when the content fits.
        Works by targeting CTkScrollableFrame internals when available.
        """
        # Avoid double-install
        if getattr(scrollable, "_resistine_scroll_installed", False):
            return
        scrollable._resistine_scroll_installed = True

        canvas = getattr(scrollable, "_parent_canvas", None)
        scrollbar = getattr(scrollable, "_scrollbar", None)
        if canvas is None:
            return

        # ---- Smooth scrolling (mouse wheel) ----
        from utils.scroll import (
            FRAME_SCROLL_DELTA, FRAME_WHEEL_SCALE, FRAME_VEL_CLAMP,
            FRAME_VEL_THRESHOLD, FRAME_VEL_DECAY,
        )

        # Enable 1-pixel scroll increments so yview_scroll moves exact pixels
        canvas.configure(yscrollincrement=1)

        state = {"vel": 0.0, "job": None}

        _is_mac = platform.system() == "Darwin"
        _is_win = platform.system() == "Windows"

        def _step():
            try:
                if not canvas.winfo_exists():
                    return
                v = state["vel"]
                if abs(v) < FRAME_VEL_THRESHOLD:
                    state["vel"] = 0.0
                    state["job"] = None
                    return

                # Pixel-based scroll — same approach as chat text widget
                before = canvas.yview()
                scroll_px = int(round(v)) or (1 if v > 0 else -1)
                canvas.yview_scroll(-scroll_px, "units")
                # Windows leaves ghost/smear trails when a Tk canvas with
                # embedded windows is scrolled (CTkScrollableFrame's content is
                # one embedded window, itself full of nested CTk canvases): Tk
                # repositions them but doesn't repaint the exposed regions during
                # the move. Force a synchronous repaint each step so they redraw
                # cleanly. macOS/Linux repaint correctly on their own, so this is
                # Windows-only to avoid the per-step flush cost elsewhere.
                if _is_win:
                    canvas.update_idletasks()
                after = canvas.yview()

                # Hit boundary — stop
                if abs(after[0] - before[0]) < 0.0001:
                    state["vel"] = 0.0
                    state["job"] = None
                    return

                state["vel"] *= FRAME_VEL_DECAY
                state["job"] = canvas.after(8, _step)
            except Exception:
                state["job"] = None

        def _on_mousewheel(event):
            try:
                d = getattr(event, "delta", 0) or 0
                if d == 0:
                    return "break"

                # Same delta handling as chat: raw on macOS, normalized on others
                if _is_mac:
                    state["vel"] += d * FRAME_WHEEL_SCALE
                else:
                    state["vel"] += (d / 120.0) * FRAME_WHEEL_SCALE
                state["vel"] = max(-FRAME_VEL_CLAMP, min(FRAME_VEL_CLAMP, state["vel"]))

                if state["job"] is None:
                    state["job"] = canvas.after(1, _step)
            except Exception:
                pass
            return "break"

        def _on_linux_scroll_up(_e):
            state["vel"] = max(-FRAME_VEL_CLAMP, min(FRAME_VEL_CLAMP, state["vel"] + FRAME_SCROLL_DELTA))
            if state["job"] is None:
                state["job"] = canvas.after(1, _step)
            return "break"

        def _on_linux_scroll_down(_e):
            state["vel"] = max(-FRAME_VEL_CLAMP, min(FRAME_VEL_CLAMP, state["vel"] - FRAME_SCROLL_DELTA))
            if state["job"] is None:
                state["job"] = canvas.after(1, _step)
            return "break"

        # On Linux, a single scroll notch can fire BOTH <Button-4>/<Button-5>
        # AND <MouseWheel>.  We handle them via separate paths:
        #   - <Button-4>/<Button-5>: direct bind on canvas + scrollable (no add="+")
        #   - <MouseWheel>: override _mouse_wheel_all (bind_all path for descendants)
        # To prevent double-fire, the direct <MouseWheel> bind is set to a no-op
        # on Linux — _mouse_wheel_all already covers it.  On other platforms
        # <Button-4>/<Button-5> don't fire, so <MouseWheel> via _mouse_wheel_all
        # is the only path and no duplication occurs.
        _is_linux = platform.system() == "Linux"

        for w in (canvas, scrollable):
            try:
                if _is_linux:
                    w.bind("<Button-4>", _on_linux_scroll_up)
                    w.bind("<Button-5>", _on_linux_scroll_down)
                    w.bind("<MouseWheel>", _on_mousewheel)
                else:
                    w.bind("<MouseWheel>", _on_mousewheel)
            except Exception:
                pass

        # Route <MouseWheel> through a SINGLE global dispatcher rather than a
        # per-frame bind_all. bind_all is global and unbind_all clears every
        # handler, so a per-frame "bind_all + check_if_master_is_canvas" closure
        # meant only the LAST-attached scrollable responded — when a screen has
        # more than one (e.g. the chat messages plus the history sidebar's list,
        # which attaches last), the others stopped scrolling everywhere except
        # widgets that explicitly forward the wheel. The dispatcher sends the
        # event to whichever registered frame the cursor is actually over, so
        # they all coexist. As a side benefit, this avoids CTk 5.x's
        # ``check_if_master_is_canvas`` method which was removed in CTk 6.0.
        if not hasattr(self, "_smooth_scroll_handlers"):
            self._smooth_scroll_handlers = []
        if not any(s is scrollable for s, _ in self._smooth_scroll_handlers):
            self._smooth_scroll_handlers.append((scrollable, _on_mousewheel))
        try:
            # Clear CTk's per-frame default (jerky) handler + any prior
            # dispatcher, then bind the one shared dispatcher as the sole
            # global <MouseWheel> handler.
            scrollable.unbind_all("<MouseWheel>")
            scrollable.bind_all(
                "<MouseWheel>", self._smooth_wheel_dispatch, add="+")
        except Exception:
            scrollable._mouse_wheel_all = self._smooth_wheel_dispatch

        # bind_all for <Button-4>/<Button-5> on Linux so child widgets are covered
        if _is_linux:
            # Inline ancestor-walk for the Linux button-scroll path. Mirrors
            # the helper in _smooth_wheel_dispatch but stays per-frame so we
            # don't have to plumb a separate registry through bind_all.
            def _inside_this(widget, _sc=scrollable):
                canvas = getattr(_sc, "_parent_canvas", None)
                cur = widget
                while cur is not None:
                    if cur is canvas:
                        return True
                    try:
                        cur = cur.master
                    except Exception:
                        return False
                return False

            def _bind_all_button4(event):
                if _inside_this(event.widget):
                    return _on_linux_scroll_up(event)

            def _bind_all_button5(event):
                if _inside_this(event.widget):
                    return _on_linux_scroll_down(event)

            scrollable.bind_all("<Button-4>", _bind_all_button4, add="+")
            scrollable.bind_all("<Button-5>", _bind_all_button5, add="+")

        # ---- Auto-hide scrollbar when not needed ----
        # Actually remove the widget from the grid when content fits, and
        # grid() it back when it overflows. The previous "paint it
        # transparent" approach left the scrollbar visible on plugin
        # pages whose background didn't match the CTkScrollbar fg colour.
        # grid_remove() preserves the widget's grid options so a bare
        # grid() call restores its former placement exactly.
        #
        # Start HIDDEN: a CTkScrollableFrame is created with its scrollbar shown,
        # so pages that don't need one would otherwise build at the narrower
        # "scrollbar-present" width and then visibly widen when the bar is
        # removed. Hiding it up front means pages that fit never flash; pages
        # that genuinely overflow get the bar added by _update_scrollbar_visibility
        # (which runs during _settle_screen, before the screen is revealed).
        hide_state = {"job": None, "hidden": True}
        try:
            if scrollbar is not None and scrollbar.winfo_exists():
                scrollbar.grid_remove()
        except Exception:
            pass

        def _update_scrollbar_visibility():
            try:
                if scrollbar is None or not scrollbar.winfo_exists() or not canvas.winfo_exists():
                    return

                # Determine if content exceeds viewport height
                bbox = canvas.bbox("all")
                content_h = 0 if bbox is None else (bbox[3] - bbox[1])
                viewport_h = canvas.winfo_height()

                # Hysteresis to avoid flicker during resize
                if hide_state["hidden"]:
                    should_hide = content_h <= (viewport_h + 16)
                else:
                    should_hide = content_h <= (viewport_h - 16)

                if should_hide and not hide_state["hidden"]:
                    hide_state["hidden"] = True
                    try:
                        scrollbar.grid_remove()
                    except Exception:
                        pass
                elif (not should_hide) and hide_state["hidden"]:
                    hide_state["hidden"] = False
                    try:
                        scrollbar.grid()
                    except Exception:
                        pass
            except Exception:
                pass

        def _schedule_visibility_check(_e=None):
            if hide_state["job"] is not None:
                try:
                    canvas.after_cancel(hide_state["job"])
                except Exception:
                    pass
            hide_state["job"] = canvas.after(60, _update_scrollbar_visibility)

        try:
            canvas.bind("<Configure>", _schedule_visibility_check, add="+")
            scrollable.bind("<Configure>", _schedule_visibility_check, add="+")
        except Exception:
            pass

        # Synchronous finalizer: _settle_screen() decides scrollbar visibility
        # before first paint, so the bar never appears and then disappears
        # (which used to shift the content width ~120 ms after load).
        scrollable._resistine_finalize_scroll = _update_scrollbar_visibility

    def get_plugin_manager(self):
        """
        Get the PluginManager instance.
        """
        if not hasattr(self.__class__, "plugin_manager"):
             from plugins.plugin_manager import PluginManager
             self.__class__.plugin_manager = PluginManager(self)
        return self.__class__.plugin_manager

    def show_notification(self, message, type="info", centered=False):
        """
        Show a non-blocking toast notification.
        :param message: The text to display.
        :param type: 'info' (green), 'error' (red), 'warning' (orange).
        :param centered: If True, center in the full window instead of the content area.
        """
        colors = {
            "info": "#00D100",  # Green
            "warning": "#FFA500",  # Orange
            "error": "#FF0000",  # Red
        }
        icon_col = colors.get(type, "#00D100")

        if centered:
            target_relx = 0.5
        else:
            # Calculate centering relative to content area (excluding sidebar)
            try:
                total_w = self.winfo_width()
                nav_w = self.navigation_frame.winfo_width() if hasattr(self, "navigation_frame") else 200
                if nav_w < 100: nav_w = 200 # Fallback

                # relx = (sidebar + remaining/2) / total
                content_center = nav_w + (total_w - nav_w) / 2
                target_relx = content_center / total_w
            except:
                target_relx = 0.5

        # Ensure we use the root window for placement
        root = self.winfo_toplevel()
        toast = ToastNotification(root, text=message, icon_color=icon_col, relx=target_relx)
        toast.show()