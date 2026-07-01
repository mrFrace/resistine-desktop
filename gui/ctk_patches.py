"""
Platform-specific CustomTkinter monkey-patches.

Linux:  Cairo-based smooth rendering (rounded rects, scrollbars, progress bars,
        sliders, dropdown arrows), cursor fixes, keyboard bindings (Ctrl+A,
        Ctrl+Backspace, undo/redo).
Windows: Resize debounce for scrollable frames.
All:    CTkScrollableFrame string-widget bugfix.

Imported once at the top of main.py — all patches apply at import time
except ``patch_linux_keybindings(root)`` which needs a Tk root.
"""

import math
import sys
import tkinter

import customtkinter.windows.widgets.ctk_scrollable_frame as _sf


# ── Cross-platform: CTkScrollableFrame string-widget bugfix ─────────────
# CustomTkinter 5.x had a bug where passing a string widget crashed; 6.0+
# removed the offending method entirely. Guard so this no-ops on newer CTk.
if hasattr(_sf.CTkScrollableFrame, "check_if_master_is_canvas"):
    _orig_check = _sf.CTkScrollableFrame.check_if_master_is_canvas

    def _patched_check(self, widget):
        if isinstance(widget, str):
            return False
        return _orig_check(self, widget)

    _sf.CTkScrollableFrame.check_if_master_is_canvas = _patched_check


# ── Cross-platform: clamp scrollregion (overscroll fix) ──────────────────
# CTkScrollableFrame sets scrollregion = bbox("all"), which is SMALLER than
# the canvas viewport when the content fits — so the smooth scroller can fling
# up past the top of the page (revealing empty space above the start) even
# when there's no scrollbar. Clamp the scrollregion to at least the viewport
# size so the top/left edge is pinned.
#
# Restored from commit 7244710 ("Clamp scrolling so you can't scroll above the
# bounds of a page"), which lived in main.py's patch block and was dropped when
# the patches moved here in a later merge.
_orig_sf_init = _sf.CTkScrollableFrame.__init__


def _clamp_scrollregion(sf):
    try:
        canvas = sf._parent_canvas
        bbox = canvas.bbox("all")
        if bbox is None:
            return
        x1, y1, x2, y2 = bbox
        # Never let the scrollregion be smaller than the viewport, so yview
        # can't move when content fits (no overscroll).
        x2 = max(x2, x1 + canvas.winfo_width())
        y2 = max(y2, y1 + canvas.winfo_height())
        canvas.configure(scrollregion=(x1, y1, x2, y2))
    except Exception:
        pass


def _sf_init_clamp_scroll(self, *args, **kwargs):
    _orig_sf_init(self, *args, **kwargs)
    # Replace CTk's own <Configure> handler (which sets scrollregion =
    # bbox("all")) with the clamped version. Other <Configure> handlers added
    # later via add="+" (e.g. auto-hide scrollbar) are unaffected.
    self.bind("<Configure>", lambda e, s=self: _clamp_scrollregion(s))


_sf.CTkScrollableFrame.__init__ = _sf_init_clamp_scroll


# ── Cross-platform: stop CTkScrollbar from forcing a present on every draw ─
# CTkScrollbar._draw ends with self._canvas.update_idletasks() — a forced,
# synchronous flush of the whole pending-render queue on EVERY scrollbar
# redraw. Its result is unused; it's purely "paint now", and it fires on every
# hover/scroll/resize/theme change across the app. Suppress just that trailing
# flush; the scrollbar still redraws and paints at the next natural idle.
#
# This flush was also (accidentally) load-bearing for CTkScrollableFrame's
# first-paint sizing — it masked the fact that _settle_screen() fits a scroll
# frame's inner content BEFORE a plugin's _resistine_finalize widens its
# column. _settle_screen now re-fits after the finalizers (see its step 3), so
# layout no longer depends on this flush.
from customtkinter.windows.widgets.ctk_scrollbar import (  # noqa: E402
    CTkScrollbar as _CTkScrollbar_perf,
)

_orig_scrollbar_draw = _CTkScrollbar_perf._draw


def _scrollbar_draw_no_flush(self, no_color_updates=False):
    canvas = self._canvas
    # Shadow the canvas's update_idletasks with a no-op for the duration of the
    # draw, so the trailing forced flush inside _draw becomes a no-op. Restored
    # immediately after, so nothing else is affected.
    canvas.update_idletasks = lambda: None
    try:
        return _orig_scrollbar_draw(self, no_color_updates)
    finally:
        try:
            del canvas.update_idletasks  # drop the shadow; class method returns
        except Exception:
            pass


_CTkScrollbar_perf._draw = _scrollbar_draw_no_flush


# ── Cross-platform: clamp scrollregion (overscroll fix) ──────────────────
# CTkScrollableFrame sets scrollregion = bbox("all"), which is SMALLER than
# the canvas viewport when the content fits — so the smooth scroller can fling
# up past the top of the page (revealing empty space above the start) even
# when there's no scrollbar. Clamp the scrollregion to at least the viewport
# size so the top/left edge is pinned.
#
# Restored from commit 7244710 ("Clamp scrolling so you can't scroll above the
# bounds of a page"), which lived in main.py's patch block and was dropped when
# the patches moved here in a later merge.
_orig_sf_init = _sf.CTkScrollableFrame.__init__


def _clamp_scrollregion(sf):
    try:
        canvas = sf._parent_canvas
        bbox = canvas.bbox("all")
        if bbox is None:
            return
        x1, y1, x2, y2 = bbox
        # Never let the scrollregion be smaller than the viewport, so yview
        # can't move when content fits (no overscroll).
        x2 = max(x2, x1 + canvas.winfo_width())
        y2 = max(y2, y1 + canvas.winfo_height())
        canvas.configure(scrollregion=(x1, y1, x2, y2))
    except Exception:
        pass


def _sf_init_clamp_scroll(self, *args, **kwargs):
    _orig_sf_init(self, *args, **kwargs)
    # Replace CTk's own <Configure> handler (which sets scrollregion =
    # bbox("all")) with the clamped version. Other <Configure> handlers added
    # later via add="+" (e.g. auto-hide scrollbar) are unaffected.
    self.bind("<Configure>", lambda e, s=self: _clamp_scrollregion(s))


_sf.CTkScrollableFrame.__init__ = _sf_init_clamp_scroll


# ── Cross-platform: stop CTkScrollbar from forcing a present on every draw ─
# CTkScrollbar._draw ends with self._canvas.update_idletasks() — a forced,
# synchronous flush of the whole pending-render queue on EVERY scrollbar
# redraw. Its result is unused; it's purely "paint now", and it fires on every
# hover/scroll/resize/theme change across the app. Suppress just that trailing
# flush; the scrollbar still redraws and paints at the next natural idle.
#
# This flush was also (accidentally) load-bearing for CTkScrollableFrame's
# first-paint sizing — it masked the fact that _settle_screen() fits a scroll
# frame's inner content BEFORE a plugin's _resistine_finalize widens its
# column. _settle_screen now re-fits after the finalizers (see its step 3), so
# layout no longer depends on this flush.
from customtkinter.windows.widgets.ctk_scrollbar import (  # noqa: E402
    CTkScrollbar as _CTkScrollbar_perf,
)

_orig_scrollbar_draw = _CTkScrollbar_perf._draw


def _scrollbar_draw_no_flush(self, no_color_updates=False):
    canvas = self._canvas
    # Shadow the canvas's update_idletasks with a no-op for the duration of the
    # draw, so the trailing forced flush inside _draw becomes a no-op. Restored
    # immediately after, so nothing else is affected.
    canvas.update_idletasks = lambda: None
    try:
        return _orig_scrollbar_draw(self, no_color_updates)
    finally:
        try:
            del canvas.update_idletasks  # drop the shadow; class method returns
        except Exception:
            pass


_CTkScrollbar_perf._draw = _scrollbar_draw_no_flush


# ── Windows: resize performance patch ───────────────────────────────────
if sys.platform.startswith("win"):
    _orig_fit = _sf.CTkScrollableFrame._fit_frame_dimensions_to_canvas

    def _throttled_fit(self, event):
        # Leading-edge debounce.
        #
        # The original CTk handler re-fits the inner frame to the canvas on
        # *every* <Configure>, which is the resize-time performance problem this
        # patch exists to solve. A pure *trailing* debounce (wait 200 ms, then
        # fit) fixed the drag cost but made the inner frame paint at its
        # requested width on first load and then snap to the canvas width 200 ms
        # later — a visible "bounce" when a screen first loads.
        #
        # Leading-edge fixes both: fit immediately the first time we see a real
        # canvas size (and on the leading edge of each resize burst), then
        # coalesce the flood of <Configure>s during an active drag into a single
        # trailing fit. First paint is correct; drags stay cheap.
        canvas = self._parent_canvas
        if not hasattr(self, "_fit_job"):
            self._fit_job = None

        has_real_size = canvas.winfo_width() > 1 and canvas.winfo_height() > 1
        if has_real_size and (
            not getattr(self, "_did_real_fit", False) or self._fit_job is None
        ):
            # First real size ever, or the leading edge of a new burst → fit now.
            try:
                _orig_fit(self, event)
                self._did_real_fit = True
            except Exception:
                pass

        if self._fit_job is not None:
            try:
                canvas.after_cancel(self._fit_job)
            except Exception:
                pass

        def _do_fit(inst=self, ev=event):
            inst._fit_job = None
            try:
                _orig_fit(inst, ev)
            except Exception:
                pass

        self._fit_job = canvas.after(200, _do_fit)

    _sf.CTkScrollableFrame._fit_frame_dimensions_to_canvas = _throttled_fit


# ── Windows/macOS: geometry cache for the stock draw engine ─────────────
# CTk's font_shapes / polygon_shapes draw_rounded_rect_with_border re-issues
# every find_withtag()/coords() call on EVERY _draw — even when the widget's
# geometry (size, corner radius, border width, drawing method) is identical to
# the previous draw. So a pure *color* change — hover feedback, theme toggle,
# text selection, the chat dim — pays the full geometry re-layout cost. With
# many widgets that adds up to hundreds of ms (measured ~197 ms to recolor ~100
# widgets) and shows up as sluggish, staggered repaints app-wide.
#
# The canvas items are already created and positioned, so when the geometry
# args match the last call we can skip the whole geometry pass. We return False
# ("no new parts created", z-order already managed); the widget's _draw() still
# applies color because it keys off its own no_color_updates flag, not this
# return value. Only the plain rounded-rect is cached — progress/slider/
# scrollbar draws depend on a value, not just geometry, so they're left alone.
#
# Linux swaps the entire draw engine for Cairo (which caches via its own
# _poly_cache_key), so this is for the stock engine on Windows/macOS only.
if not sys.platform.startswith("linux"):
    from customtkinter.windows.widgets.core_rendering import (
        DrawEngine as _DrawEngine,
    )

    _orig_rrb = _DrawEngine.draw_rounded_rect_with_border

    def _cached_rrb(self, width, height, corner_radius, border_width,
                    overwrite_preferred_drawing_method=None):
        key = (width, height, corner_radius, border_width,
               overwrite_preferred_drawing_method
               or self.preferred_drawing_method)
        if getattr(self, "_rrb_geom_key", None) == key:
            return False  # geometry unchanged → items already drawn/positioned
        result = _orig_rrb(self, width, height, corner_radius, border_width,
                           overwrite_preferred_drawing_method)
        self._rrb_geom_key = key
        return result

    _DrawEngine.draw_rounded_rect_with_border = _cached_rrb


# ── Linux: Cairo smooth rendering + cursor / keyboard patches ───────────
if sys.platform.startswith("linux"):
    try:
        import cairo
    except ImportError:
        import cairocffi as cairo
    from PIL import Image, ImageTk
    from customtkinter.windows.widgets.core_rendering import CTkCanvas, DrawEngine

    # ── helpers ──────────────────────────────────────────────────────────

    def _get_rgba(widget, attr_name, default_color="black", alpha=1.0):
        """Resolve any CTk color (list, hex, name) to Cairo RGBA."""
        color_val = getattr(widget, attr_name, None)
        if color_val is None:
            color_val = default_color
        if isinstance(color_val, (list, tuple)):
            color_val = widget._apply_appearance_mode(color_val)

        if color_val == "transparent":
            bg = getattr(widget, "_bg_color", None)
            if bg is None:
                return (0, 0, 0, 0)
            if isinstance(bg, (list, tuple)):
                bg = widget._apply_appearance_mode(bg)
            color_val = bg

        if color_val is None:
            return (0, 0, 0, 0)

        try:
            r, g, b = widget.winfo_rgb(color_val)
            return (r / 65535.0, g / 65535.0, b / 65535.0, alpha)
        except Exception:
            return (0, 0, 0, 0)

    def _render_cairo_to_tk(self, width, height, draw_func):
        """Bridge between Cairo rendering and Tkinter PhotoImage."""
        w, h = math.ceil(width), math.ceil(height)
        surface = cairo.ImageSurface(cairo.FORMAT_ARGB32, w, h)
        ctx = cairo.Context(surface)
        draw_func(ctx, w, h)
        img = Image.frombuffer(
            "RGBA", (w, h), bytes(surface.get_data()), "raw", "BGRA", 0, 1
        )
        photo = ImageTk.PhotoImage(img)
        if not hasattr(self, "_cairo_photos"):
            self._cairo_photos = {}
        return photo

    def _cairo_rounded_rect(ctx, x, y, w, h, r):
        if r <= 0:
            ctx.rectangle(x, y, w, h)
            return
        r = min(r, w / 2, h / 2)
        ctx.new_sub_path()
        ctx.arc(x + w - r, y + r, r, -0.5 * math.pi, 0)
        ctx.arc(x + w - r, y + h - r, r, 0, 0.5 * math.pi)
        ctx.arc(x + r, y + h - r, r, 0.5 * math.pi, math.pi)
        ctx.arc(x + r, y + r, r, math.pi, 1.5 * math.pi)
        ctx.close_path()

    # ── DrawEngine smooth renderers ─────────────────────────────────────

    def _draw_smooth_polygon_shapes(
        self, width, height, corner_radius, border_width, _force=False
    ):
        master = self._canvas.master
        _fg = (
            master._apply_appearance_mode(master._fg_color)
            if hasattr(master, "_fg_color")
            else None
        )
        _bg = (
            master._apply_appearance_mode(master._bg_color)
            if hasattr(master, "_bg_color")
            else None
        )
        _bc = (
            master._apply_appearance_mode(master._border_color)
            if hasattr(master, "_border_color")
            else None
        )
        _cache_key = (width, height, corner_radius, border_width, _fg, _bg, _bc)
        if not _force and getattr(self, "_poly_cache_key", None) == _cache_key:
            return False
        self._poly_cache_key = _cache_key

        def draw(ctx, w, h):
            r, bw = (corner_radius or 0), (border_width or 0)
            ctx.set_source_rgba(*_get_rgba(master, "_bg_color"))
            ctx.paint()
            if bw > 0:
                ctx.set_source_rgba(
                    *_get_rgba(master, "_border_color", default_color="transparent")
                )
                _cairo_rounded_rect(ctx, 0, 0, width, height, r)
                ctx.fill()
            ctx.set_source_rgba(*_get_rgba(master, "_fg_color"))
            _cairo_rounded_rect(
                ctx, bw, bw, width - 2 * bw, height - 2 * bw, max(0, r - bw)
            )
            ctx.fill()

        photo = _render_cairo_to_tk(self, width, height, draw)
        self._cairo_photos["main"] = photo

        if not self._canvas.find_withtag("cairo_main"):
            self._canvas.create_image(
                0, 0, anchor="nw", image=photo, tags=("cairo_main", "inner_parts")
            )
        else:
            self._canvas.itemconfig("cairo_main", image=photo)
        self._canvas.tag_lower("cairo_main")
        if sys.platform == "linux":
            try:
                if _fg and _fg != "transparent":
                    self._canvas.configure(bg=_fg)
                elif _bg and _bg != "transparent":
                    self._canvas.configure(bg=_bg)
            except Exception:
                pass
        return False

    def _draw_smooth_scrollbar(
        self,
        width,
        height,
        corner_radius,
        inner_corner_radius,
        start_value,
        end_value,
        orientation,
    ):
        master = self._canvas.master

        def draw(ctx, w, h):
            ctx.set_source_rgba(*_get_rgba(master, "_fg_color"))
            ctx.rectangle(0, 0, width, height)
            ctx.fill()
            ctx.set_source_rgba(*_get_rgba(master, "_button_color"))
            if orientation == "vertical":
                bar_w = width - 2 * corner_radius
                bar_h = (height - 2 * corner_radius) * (end_value - start_value)
                y = (height - 2 * corner_radius) * start_value + corner_radius
                x = corner_radius
            else:
                bar_w = (width - 2 * corner_radius) * (end_value - start_value)
                bar_h = height - 2 * corner_radius
                x = (width - 2 * corner_radius) * start_value + corner_radius
                y = corner_radius
            _cairo_rounded_rect(
                ctx,
                x - inner_corner_radius,
                y - inner_corner_radius,
                bar_w + 2 * inner_corner_radius,
                bar_h + 2 * inner_corner_radius,
                inner_corner_radius,
            )
            ctx.fill()

        photo = _render_cairo_to_tk(self, width, height, draw)
        self._cairo_photos["scrollbar"] = photo

        if not self._canvas.find_withtag("cairo_scrollbar"):
            self._canvas.create_image(
                0,
                0,
                anchor="nw",
                image=photo,
                tags=("cairo_scrollbar", "scrollbar_parts"),
            )
        else:
            self._canvas.itemconfig("cairo_scrollbar", image=photo)
        if sys.platform == "linux":
            try:
                fg = master._apply_appearance_mode(master._fg_color) if hasattr(master, "_fg_color") else None
                if fg and fg != "transparent":
                    self._canvas.configure(bg=fg)
            except Exception:
                pass
        return False

    def _draw_smooth_progress_bar(
        self, width, height, corner_radius, border_width, v1, v2, orientation
    ):
        master = self._canvas.master

        def draw(ctx, w, h):
            r, bw = (corner_radius or 0), (border_width or 0)
            inner_r = max(0, r - bw)
            ctx.set_source_rgba(*_get_rgba(master, "_bg_color"))
            ctx.paint()
            if bw > 0:
                ctx.set_source_rgba(
                    *_get_rgba(master, "_border_color", default_color="transparent")
                )
                _cairo_rounded_rect(ctx, 0, 0, width, height, r)
                ctx.fill()
            ctx.set_source_rgba(*_get_rgba(master, "_fg_color"))
            _cairo_rounded_rect(
                ctx, bw, bw, width - 2 * bw, height - 2 * bw, inner_r
            )
            ctx.fill()

            if abs(v1 - v2) > 0.0001:
                ctx.set_source_rgba(*_get_rgba(master, "_progress_color"))
                if orientation in ("horizontal", "w", "e"):
                    usable_w = max(0, width - 2 * bw)
                    x_start = bw + usable_w * v1
                    x_end = bw + usable_w * v2
                    _cairo_rounded_rect(
                        ctx,
                        x_start,
                        bw,
                        max(1, x_end - x_start),
                        max(1, height - 2 * bw),
                        inner_r,
                    )
                else:
                    usable_h = max(0, height - 2 * bw)
                    y_start = bw + usable_h * (1 - v2)
                    y_end = bw + usable_h * (1 - v1)
                    _cairo_rounded_rect(
                        ctx,
                        bw,
                        y_start,
                        max(1, width - 2 * bw),
                        max(1, y_end - y_start),
                        inner_r,
                    )
                ctx.fill()

        photo = _render_cairo_to_tk(self, width, height, draw)
        self._cairo_photos["progress"] = photo
        if not self._canvas.find_withtag("cairo_progress"):
            self._canvas.create_image(
                0,
                0,
                anchor="nw",
                image=photo,
                tags=("cairo_progress", "progress_parts"),
            )
        else:
            self._canvas.itemconfig("cairo_progress", image=photo)
        self._canvas.tag_lower("cairo_progress")
        if sys.platform == "linux":
            try:
                fg = master._apply_appearance_mode(master._fg_color) if hasattr(master, "_fg_color") else None
                if fg and fg != "transparent":
                    self._canvas.configure(bg=fg)
            except Exception:
                pass
        return False

    def _draw_smooth_slider(
        self,
        width,
        height,
        corner_radius,
        border_width,
        button_length,
        button_corner_radius,
        slider_value,
        orientation,
        button_color=None,
    ):
        """Render track + progress + button into a single Cairo image."""
        master = self._canvas.master

        corner_radius = min(corner_radius, width / 2, height / 2)
        button_corner_radius = min(button_corner_radius, width / 2, height / 2)
        if button_length == 0 and button_corner_radius == 0:
            button_corner_radius = height / 2

        def draw(ctx, w, h):
            r, bw = (corner_radius or 0), (border_width or 0)
            inner_r = max(0, r - bw)
            ctx.set_source_rgba(*_get_rgba(master, "_bg_color"))
            ctx.paint()
            if bw > 0:
                ctx.set_source_rgba(
                    *_get_rgba(master, "_border_color", default_color="transparent")
                )
                _cairo_rounded_rect(ctx, 0, 0, width, height, r)
                ctx.fill()
            # Track
            ctx.set_source_rgba(*_get_rgba(master, "_fg_color"))
            _cairo_rounded_rect(
                ctx, bw, bw, width - 2 * bw, height - 2 * bw, inner_r
            )
            ctx.fill()
            # Progress fill
            ctx.set_source_rgba(*_get_rgba(master, "_progress_color"))
            br_prog = button_corner_radius
            if orientation in ("horizontal", "w", "e"):
                dot_r_prog = min(br_prog, height / 2)
                usable_w = max(0, width - 2 * dot_r_prog)
                fill_w = usable_w * slider_value
                if fill_w > 0:
                    _cairo_rounded_rect(
                        ctx,
                        bw,
                        bw,
                        (dot_r_prog - bw) + fill_w,
                        height - 2 * bw,
                        inner_r,
                    )
                    ctx.fill()
            else:
                dot_r_prog = min(br_prog, width / 2)
                usable_h = max(0, height - 2 * dot_r_prog)
                fill_h = usable_h * slider_value
                if fill_h > 0:
                    fill_top = dot_r_prog + usable_h * (1 - slider_value)
                    _cairo_rounded_rect(
                        ctx,
                        bw,
                        fill_top - bw,
                        width - 2 * bw,
                        (height - fill_top - bw) + bw,
                        inner_r,
                    )
                    ctx.fill()
            # Button dot/pill
            if button_color is not None:
                try:
                    r2, g2, b2 = master.winfo_rgb(button_color)
                    ctx.set_source_rgba(r2 / 65535.0, g2 / 65535.0, b2 / 65535.0, 1.0)
                except Exception:
                    ctx.set_source_rgba(*_get_rgba(master, "_button_color"))
            else:
                ctx.set_source_rgba(*_get_rgba(master, "_button_color"))
            br = button_corner_radius
            if orientation in ("horizontal", "w", "e"):
                if button_length == 0:
                    dot_r = min(br, height / 2)
                    usable_w = max(0, width - 2 * dot_r)
                    ctx.arc(
                        dot_r + usable_w * slider_value,
                        height / 2,
                        dot_r,
                        0,
                        2 * math.pi,
                    )
                    ctx.fill()
                else:
                    bx = (width - button_length) * slider_value
                    _cairo_rounded_rect(ctx, bx, 0, button_length, height, br)
                    ctx.fill()
            else:
                if button_length == 0:
                    dot_r = min(br, width / 2)
                    usable_h = max(0, height - 2 * dot_r)
                    ctx.arc(
                        width / 2,
                        dot_r + usable_h * (1 - slider_value),
                        dot_r,
                        0,
                        2 * math.pi,
                    )
                    ctx.fill()
                else:
                    by = (height - button_length) * (1 - slider_value)
                    _cairo_rounded_rect(ctx, 0, by, width, button_length, br)
                    ctx.fill()

        photo = _render_cairo_to_tk(self, width, height, draw)
        self._cairo_photos["slider"] = photo
        if not self._canvas.find_withtag("cairo_slider"):
            self._canvas.create_image(
                0,
                0,
                anchor="nw",
                image=photo,
                tags=("cairo_slider", "slider_parts"),
            )
        else:
            self._canvas.itemconfig("cairo_slider", image=photo)
        self._canvas.tag_lower("cairo_slider")
        if sys.platform == "linux":
            try:
                btn_c = None
                if button_color:
                    btn_c = button_color
                elif hasattr(master, "_button_color"):
                    btn_c = master._apply_appearance_mode(master._button_color)
                if btn_c and btn_c != "transparent":
                    self._canvas.configure(bg=btn_c)
                else:
                    fg = master._apply_appearance_mode(master._fg_color) if hasattr(master, "_fg_color") else None
                    if fg and fg != "transparent":
                        self._canvas.configure(bg=fg)
            except Exception:
                pass
        return False

    def _draw_smooth_vertical_split(
        self, width, height, corner_radius, border_width, left_section_width
    ):
        master = self._canvas.master

        def draw(ctx, w, h):
            r, bw, lw = (
                (corner_radius or 0),
                (border_width or 0),
                (left_section_width or 0),
            )
            inner_r = max(0, r - bw)
            ctx.set_source_rgba(*_get_rgba(master, "_bg_color"))
            ctx.paint()
            if bw > 0:
                ctx.set_source_rgba(
                    *_get_rgba(master, "_border_color", default_color="transparent")
                )
                _cairo_rounded_rect(ctx, 0, 0, width, height, r)
                ctx.fill()
            ctx.set_source_rgba(
                *_get_rgba(
                    master,
                    "_left_section_color"
                    if hasattr(master, "_left_section_color")
                    else "_fg_color",
                )
            )
            ctx.new_sub_path()
            ctx.arc(bw + inner_r, height - bw - inner_r, inner_r, 0.5 * math.pi, math.pi)
            ctx.arc(bw + inner_r, bw + inner_r, inner_r, math.pi, 1.5 * math.pi)
            ctx.line_to(lw, bw)
            ctx.line_to(lw, height - bw)
            ctx.close_path()
            ctx.fill()
            ctx.set_source_rgba(
                *_get_rgba(
                    master,
                    "_right_section_color"
                    if hasattr(master, "_right_section_color")
                    else "_button_color",
                )
            )
            ctx.new_sub_path()
            ctx.move_to(lw, bw)
            ctx.arc(
                width - bw - inner_r, bw + inner_r, inner_r, -0.5 * math.pi, 0
            )
            ctx.arc(
                width - bw - inner_r,
                height - bw - inner_r,
                inner_r,
                0,
                0.5 * math.pi,
            )
            ctx.line_to(lw, height - bw)
            ctx.close_path()
            ctx.fill()
            # Draw chevron
            arrow_attr = (
                "_arrow_color"
                if hasattr(master, "_arrow_color")
                else (
                    "_text_color" if hasattr(master, "_text_color") else None
                )
            )
            if arrow_attr:
                ctx.set_source_rgba(*_get_rgba(master, arrow_attr))
                cx = width - (height / 2)
                cy = height / 2
                sz = height / 3
                lw_arrow = max(1.5, sz / 3)
                ctx.set_line_width(lw_arrow)
                ctx.set_line_cap(cairo.LINE_CAP_ROUND)
                ctx.set_line_join(cairo.LINE_JOIN_ROUND)
                ctx.move_to(cx - sz / 2, cy - sz / 5)
                ctx.line_to(cx, cy + sz / 5)
                ctx.line_to(cx + sz / 2, cy - sz / 5)
                ctx.stroke()

        photo = _render_cairo_to_tk(self, width, height, draw)
        self._cairo_photos["vertical_split"] = photo
        if not self._canvas.find_withtag("cairo_vertical_split"):
            self._canvas.create_image(
                0,
                0,
                anchor="nw",
                image=photo,
                tags=("cairo_vertical_split", "inner_parts"),
            )
        else:
            self._canvas.itemconfig("cairo_vertical_split", image=photo)
        self._canvas.tag_lower("cairo_vertical_split")
        if sys.platform == "linux":
            try:
                fg = master._apply_appearance_mode(master._fg_color) if hasattr(master, "_fg_color") else None
                if fg and fg != "transparent":
                    self._canvas.configure(bg=fg)
            except Exception:
                pass
        return False

    # ── Patch dropdown arrow to no-op when Cairo handles it ─────────────

    _orig_draw_dropdown_arrow = DrawEngine.draw_dropdown_arrow

    def _patched_draw_dropdown_arrow(self, x_position, y_position, size):
        if self.preferred_drawing_method == "smooth_polygon_shapes":
            return False
        return _orig_draw_dropdown_arrow(self, x_position, y_position, size)

    DrawEngine.draw_dropdown_arrow = _patched_draw_dropdown_arrow

    # ── Attach smooth renderers to DrawEngine ───────────────────────────

    DrawEngine._draw_smooth_polygon_shapes = _draw_smooth_polygon_shapes
    DrawEngine._draw_smooth_scrollbar = _draw_smooth_scrollbar
    DrawEngine._draw_smooth_progress_bar = _draw_smooth_progress_bar
    DrawEngine._draw_smooth_slider = _draw_smooth_slider
    DrawEngine._draw_smooth_vertical_split = _draw_smooth_vertical_split

    _orig_draw = DrawEngine.draw_rounded_rect_with_border
    _orig_vertical = DrawEngine.draw_rounded_rect_with_border_vertical_split
    _orig_progress = DrawEngine.draw_rounded_progress_bar_with_border
    _orig_slider = DrawEngine.draw_rounded_slider_with_border_and_button
    _orig_scrollbar = DrawEngine.draw_rounded_scrollbar

    def _patched_draw(self, w, h, r, bw, meth=None, *args, **kwargs):
        if (meth or self.preferred_drawing_method) == "smooth_polygon_shapes":
            self._canvas.master._cairo_drawing = True
            try:
                return self._draw_smooth_polygon_shapes(w, h, r, bw)
            finally:
                self._canvas.master._cairo_drawing = False
        return _orig_draw(self, w, h, r, bw, meth, *args, **kwargs)

    def _patched_vertical(self, w, h, r, bw, lw, meth=None, *args, **kwargs):
        if (meth or self.preferred_drawing_method) == "smooth_polygon_shapes":
            return self._draw_smooth_vertical_split(w, h, r, bw, lw)
        return _orig_vertical(self, w, h, r, bw, lw, meth, *args, **kwargs)

    def _patched_progress(self, w, h, r, bw, v1, v2, o, *args, **kwargs):
        if self.preferred_drawing_method == "smooth_polygon_shapes":
            return self._draw_smooth_progress_bar(w, h, r, bw, v1, v2, o)
        return _orig_progress(self, w, h, r, bw, v1, v2, o, *args, **kwargs)

    def _patched_slider(self, w, h, r, bw, bl, bcr, sv, o, *args, **kwargs):
        if self.preferred_drawing_method == "smooth_polygon_shapes":
            return self._draw_smooth_slider(w, h, r, bw, bl, bcr, sv, o)
        return _orig_slider(self, w, h, r, bw, bl, bcr, sv, o, *args, **kwargs)

    def _patched_scrollbar(self, w, h, r, s, sv, ev, o, *args, **kwargs):
        if self.preferred_drawing_method == "smooth_polygon_shapes":
            if getattr(self, "_round_width_to_even_numbers", False):
                w = math.floor(w / 2) * 2
            if getattr(self, "_round_height_to_even_numbers", False):
                h = math.floor(h / 2) * 2
            r = min(r, w / 2, h / 2)
            s = round(s)
            icr = max(0, r - s)
            return self._draw_smooth_scrollbar(w, h, r, icr, sv, ev, o)
        return _orig_scrollbar(self, w, h, r, s, sv, ev, o, *args, **kwargs)

    def _get_corrected_scrollbar_values(master):
        """Mirror CTkScrollbar._get_scrollbar_values_for_minimum_pixel_size."""
        try:
            return master._get_scrollbar_values_for_minimum_pixel_size()
        except Exception:
            return master._start_value, master._end_value

    DrawEngine.draw_rounded_rect_with_border = _patched_draw
    DrawEngine.draw_rounded_rect_with_border_vertical_split = _patched_vertical
    DrawEngine.draw_rounded_progress_bar_with_border = _patched_progress
    DrawEngine.draw_rounded_slider_with_border_and_button = _patched_slider
    DrawEngine.draw_rounded_scrollbar = _patched_scrollbar
    DrawEngine.preferred_drawing_method = "smooth_polygon_shapes"

    # ── Patch CTkCanvas to intercept fill/outline recolors on Cairo images

    _orig_canvas_itemconfigure = CTkCanvas.itemconfigure
    _orig_canvas_itemconfig = CTkCanvas.itemconfig

    def _patched_canvas_itemconfigure(self, tagOrId, cnf=None, **kwargs):
        if not kwargs:
            return _orig_canvas_itemconfigure(self, tagOrId, cnf, **kwargs)

        fill_color = kwargs.get("fill")
        master = self.master
        de = getattr(master, "_draw_engine", None)

        if (
            fill_color
            and de is not None
            and tagOrId
            in ("inner_parts_left", "inner_parts_right", "dropdown_arrow")
            and self.find_withtag("cairo_vertical_split")
        ):
            canvas_w = self.winfo_width()
            canvas_h = self.winfo_height()
            if canvas_w > 1 and canvas_h > 1:
                s = master._apply_widget_scaling
                if tagOrId == "inner_parts_left":
                    master._left_section_color = fill_color
                elif tagOrId == "inner_parts_right":
                    master._right_section_color = fill_color
                else:
                    master._arrow_color = fill_color
                _lsw = s(master._current_width - master._current_height)
                de._draw_smooth_vertical_split(
                    canvas_w,
                    canvas_h,
                    s(getattr(master, "_corner_radius", 0)),
                    s(getattr(master, "_border_width", 0)),
                    _lsw,
                )
            return _orig_canvas_itemconfigure(self, tagOrId, cnf, **kwargs)

        items = self.find_withtag(tagOrId)
        if not items:
            return _orig_canvas_itemconfigure(self, tagOrId, cnf, **kwargs)

        has_image = any(self.type(i) == "image" for i in items)

        if not has_image:
            return _orig_canvas_itemconfigure(self, tagOrId, cnf, **kwargs)

        if fill_color and de is not None:
            canvas_w = self.winfo_width()
            canvas_h = self.winfo_height()
            if canvas_w > 1 and canvas_h > 1:
                s = master._apply_widget_scaling

                if tagOrId == "scrollbar_parts" and self.find_withtag(
                    "cairo_scrollbar"
                ):
                    orig_btn = master._button_color
                    master._button_color = fill_color
                    try:
                        _cr = s(getattr(master, "_corner_radius", 0))
                        _bs = s(getattr(master, "_border_spacing", 0))
                        _sv, _ev = _get_corrected_scrollbar_values(master)
                        de._draw_smooth_scrollbar(
                            canvas_w,
                            canvas_h,
                            min(_cr, canvas_w / 2, canvas_h / 2),
                            max(
                                0,
                                min(_cr, canvas_w / 2, canvas_h / 2) - round(_bs),
                            ),
                            _sv,
                            _ev,
                            getattr(master, "_orientation", "vertical"),
                        )
                    finally:
                        master._button_color = orig_btn

                elif tagOrId == "inner_parts" and self.find_withtag("cairo_main"):
                    if fill_color != getattr(master, "_cairo_last_fg", None):
                        master._cairo_last_fg = fill_color
                        orig_fg = master._fg_color
                        master._fg_color = fill_color
                        try:
                            de._draw_smooth_polygon_shapes(
                                canvas_w,
                                canvas_h,
                                s(getattr(master, "_corner_radius", 0)),
                                s(getattr(master, "_border_width", 0)),
                                _force=True,
                            )
                        finally:
                            master._fg_color = orig_fg

                elif tagOrId == "slider_parts" and self.find_withtag(
                    "cairo_slider"
                ):
                    if hasattr(master, "_check_state"):
                        _val = 1 if master._check_state else 0
                        _ori = "w"
                    else:
                        _val = getattr(master, "_value", 0)
                        _ori = getattr(master, "_orientation", "horizontal")
                    de._draw_smooth_slider(
                        canvas_w,
                        canvas_h,
                        s(getattr(master, "_corner_radius", 0)),
                        s(getattr(master, "_border_width", 0)),
                        s(getattr(master, "_button_length", 0)),
                        s(getattr(master, "_button_corner_radius", 0)),
                        _val,
                        _ori,
                        button_color=fill_color,
                    )

        for item in items:
            item_kwargs = kwargs.copy()
            if self.type(item) == "image":
                item_kwargs.pop("fill", None)
                item_kwargs.pop("outline", None)
            _orig_canvas_itemconfigure(self, item, cnf, **item_kwargs)

    CTkCanvas.itemconfigure = _patched_canvas_itemconfigure

    def _patched_canvas_itemconfig(self, tag_or_id, *args, **kwargs):
        return _patched_canvas_itemconfigure(self, tag_or_id, None, **kwargs)

    CTkCanvas.itemconfig = _patched_canvas_itemconfig

    # ── Cursor patches for Linux ────────────────────────────────────────

    from customtkinter.windows.widgets import CTkButton as _CTkButton
    from customtkinter.windows.widgets import CTkOptionMenu as _CTkOptionMenu
    from customtkinter.windows.widgets import CTkScrollbar as _CTkScrollbar
    from customtkinter.windows.widgets import CTkSlider as _CTkSlider
    from customtkinter.windows.widgets import CTkSwitch as _CTkSwitch

    _orig_btn_cursor = _CTkButton._set_cursor

    def _patched_btn_cursor(self):
        _orig_btn_cursor(self)
        if sys.platform.startswith("linux") and self._cursor_manipulation_enabled:
            if self._state == tkinter.DISABLED:
                self.configure(cursor="arrow")
            elif self._command is not None:
                self.configure(cursor="hand2")

    _CTkButton._set_cursor = _patched_btn_cursor

    _orig_sld_cursor = _CTkSlider._set_cursor

    def _patched_sld_cursor(self):
        _orig_sld_cursor(self)
        if sys.platform.startswith("linux") and self._cursor_manipulation_enabled:
            if self._state == "normal":
                self.configure(cursor="hand2")
            else:
                self.configure(cursor="arrow")

    _CTkSlider._set_cursor = _patched_sld_cursor

    _orig_sld_enter = _CTkSlider._on_enter

    def _patched_sld_enter(self, event=0):
        _orig_sld_enter(self, event)
        if sys.platform.startswith("linux") and self._state == "normal":
            self.configure(cursor="hand2")

    _CTkSlider._on_enter = _patched_sld_enter

    _orig_sld_leave = _CTkSlider._on_leave

    def _patched_sld_leave(self, event=0):
        _orig_sld_leave(self, event)
        if sys.platform.startswith("linux"):
            self.configure(cursor="arrow")

    _CTkSlider._on_leave = _patched_sld_leave

    _orig_sb_create_bindings = _CTkScrollbar._create_bindings

    def _patched_sb_create_bindings(self, sequence=None):
        _orig_sb_create_bindings(self, sequence)
        if sys.platform.startswith("linux"):
            if sequence is None or sequence == "<Button-1>":
                self._canvas.bind("<Button-1>", self._clicked, add=True)

    _CTkScrollbar._create_bindings = _patched_sb_create_bindings

    _orig_om_enter = _CTkOptionMenu._on_enter

    def _patched_om_enter(self, event=0):
        _orig_om_enter(self, event)
        if sys.platform.startswith("linux") and self._state == "normal":
            self._canvas.tk.call(
                self._canvas._w, "configure", "-cursor", "hand2"
            )
            if self._text_label is not None:
                self._text_label.tk.call(
                    self._text_label._w, "configure", "-cursor", "hand2"
                )

    _CTkOptionMenu._on_enter = _patched_om_enter

    _orig_om_leave = _CTkOptionMenu._on_leave

    def _patched_om_leave(self, event=0):
        _orig_om_leave(self, event)
        if sys.platform.startswith("linux"):
            self._canvas.tk.call(
                self._canvas._w, "configure", "-cursor", "arrow"
            )
            if self._text_label is not None:
                self._text_label.tk.call(
                    self._text_label._w, "configure", "-cursor", "arrow"
                )

    _CTkOptionMenu._on_leave = _patched_om_leave

    _orig_sw_init = _CTkSwitch.__init__

    def _patched_sw_init(self, *args, **kwargs):
        _orig_sw_init(self, *args, **kwargs)
        if sys.platform.startswith("linux"):
            self._canvas.bind(
                "<Enter>",
                lambda e, w=self: w._canvas.tk.call(
                    w._canvas._w, "configure", "-cursor", "hand2"
                ),
                add=True,
            )
            self._canvas.bind(
                "<Leave>",
                lambda e, w=self: w._canvas.tk.call(
                    w._canvas._w, "configure", "-cursor", "arrow"
                ),
                add=True,
            )

    _CTkSwitch.__init__ = _patched_sw_init


# ── Linux: keyboard binding patches (needs a Tk root) ──────────────────


def _select_all_entry(event):
    event.widget.select_range(0, "end")
    event.widget.icursor("end")
    return "break"


def _select_all_text(event):
    event.widget.tag_add("sel", "1.0", "end")
    return "break"


def _ctrl_backspace_entry(event):
    """Delete the word before the cursor in an Entry widget."""
    w = event.widget
    pos = w.index("insert")
    if pos == 0:
        return "break"
    text = w.get()[:pos]
    i = len(text) - 1
    while i >= 0 and text[i] == " ":
        i -= 1
    while i >= 0 and text[i] != " ":
        i -= 1
    w.delete(i + 1, pos)
    return "break"


def _ctrl_backspace_text(event):
    """Delete the word before the cursor in a Text widget."""
    w = event.widget
    pos = w.index("insert")
    if pos == "1.0":
        return "break"
    prev = w.index(f"{pos}-1c")
    while prev != "1.0" and w.get(prev) == " ":
        prev = w.index(f"{prev}-1c")
    word_start = w.index(f"{prev} wordstart")
    w.delete(word_start, pos)
    return "break"


def _undo_text(event):
    try:
        event.widget.edit_undo()
    except tkinter.TclError:
        pass
    return "break"


def _redo_text(event):
    try:
        event.widget.edit_redo()
    except tkinter.TclError:
        pass
    return "break"


# Enable undo on all Text widgets by default so Ctrl+Z/Y work.
if sys.platform.startswith("linux"):
    _orig_text_init = tkinter.Text.__init__

    def _text_init_with_undo(self, *args, **kw):
        kw.setdefault("undo", True)
        kw.setdefault("maxundo", -1)
        _orig_text_init(self, *args, **kw)

    tkinter.Text.__init__ = _text_init_with_undo

    # Entry undo/redo (tk.Entry has no built-in undo)
    _orig_entry_init = tkinter.Entry.__init__

    def _entry_init_with_undo(self, *args, **kw):
        _orig_entry_init(self, *args, **kw)
        self._undo_stack = []
        self._redo_stack = []
        self._undo_last = ""

        def _snapshot(*_a):
            current = self.get()
            if current != self._undo_last:
                self._undo_stack.append(self._undo_last)
                self._redo_stack.clear()
                self._undo_last = current

        self.bind("<KeyRelease>", _snapshot, add="+")

    tkinter.Entry.__init__ = _entry_init_with_undo


def _undo_entry(event):
    w = event.widget
    stack = getattr(w, "_undo_stack", None)
    if not stack:
        return "break"
    current = w.get()
    w._redo_stack.append(current)
    prev = stack.pop()
    w._undo_last = prev
    state = str(w.cget("state"))
    w.configure(state="normal")
    w.delete(0, "end")
    w.insert(0, prev)
    if state != "normal":
        w.configure(state=state)
    return "break"


def _redo_entry(event):
    w = event.widget
    stack = getattr(w, "_redo_stack", None)
    if not stack:
        return "break"
    current = w.get()
    w._undo_stack.append(current)
    nxt = stack.pop()
    w._undo_last = nxt
    state = str(w.cget("state"))
    w.configure(state="normal")
    w.delete(0, "end")
    w.insert(0, nxt)
    if state != "normal":
        w.configure(state=state)
    return "break"


def patch_linux_keybindings(root):
    """Bind Ctrl+A, Ctrl+Backspace, Ctrl+Z/Y on a Tk root (Linux only)."""
    if not sys.platform.startswith("linux"):
        return
    root.bind_class("Entry", "<Control-a>", _select_all_entry)
    root.bind_class("Text", "<Control-a>", _select_all_text)
    root.bind_class("Entry", "<Control-BackSpace>", _ctrl_backspace_entry)
    root.bind_class("Text", "<Control-BackSpace>", _ctrl_backspace_text)
    root.bind_class("Text", "<Control-z>", _undo_text)
    root.bind_class("Text", "<Control-y>", _redo_text)
    root.bind_class("Entry", "<Control-z>", _undo_entry)
    root.bind_class("Entry", "<Control-y>", _redo_entry)
