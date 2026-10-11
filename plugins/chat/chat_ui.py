"""Chat UI construction mixin for the Chat plugin."""
from __future__ import annotations

import os
import subprocess
import sys
import tkinter

import customtkinter

from plugins.chat.assistant_bubble import AssistantBubble
from plugins.chat.bubble import BubbleRow, UserBubble, assistant_width, user_width
from plugins.chat.fonts import RESISTINE_BLUE, _is_dark_mode, ui_family
from plugins.chat.sidebar import ChatSidebar
from plugins.chat.welcome_screen import (
    ApiKeyMissingScreen, ChatLockedScreen, WelcomeScreen)
from utils.emoji_entry import EmojiEntry
from utils.logger import logger

# Opacity of the layer that dims the chat behind the open history drawer.
# 0 = invisible, 1 = solid black; this is the "slightly darker" look.
_DIM_ALPHA = 0.4

# Cached result of the X11 compositor probe (see _linux_has_compositor).
# None = not yet probed; True/False = cached probe result. Module-level so
# the subprocess fires at most once per process lifetime.
_LINUX_COMPOSITOR_CACHE: "bool | None" = None


def _linux_has_compositor() -> bool:
    """Return True if the platform supports translucent overrideredirect Toplevels.

    macOS/Windows always do (Quartz / DWM composite unconditionally).
    Wayland always does (the protocol mandates a compositor).
    Plain X11 may or may not — raw i3 / openbox without picom etc. render a
    `-alpha 0.4` borderless Toplevel as SOLID BLACK, which hides the chat
    behind the drawer instead of dimming it. We probe with `xprop -root
    _NET_WM_CM_S0`: the ICCCM-blessed way for a client to discover whether a
    compositing manager owns the screen. Result is cached module-level so we
    only fork xprop on first call.
    """
    global _LINUX_COMPOSITOR_CACHE
    if _LINUX_COMPOSITOR_CACHE is not None:
        return _LINUX_COMPOSITOR_CACHE
    # Non-Linux: the Toplevel approach is known-good.
    if not sys.platform.startswith("linux"):
        _LINUX_COMPOSITOR_CACHE = True
        return True
    try:
        if os.environ.get("XDG_SESSION_TYPE") == "wayland":
            _LINUX_COMPOSITOR_CACHE = True
            return True
        res = subprocess.run(
            ["xprop", "-root", "_NET_WM_CM_S0"],
            capture_output=True, text=True, timeout=0.5,
        )
        out = (res.stdout or "") + (res.stderr or "")
        out_lower = out.lower()
        has_cm = (
            "_net_wm_cm_s0" in out_lower
            and "not found" not in out_lower
        )
        _LINUX_COMPOSITOR_CACHE = bool(has_cm)
        return _LINUX_COMPOSITOR_CACHE
    except Exception:
        # Safe default: assume composited. Bare-X11-no-compositor is rare;
        # the opposite default would silently disable dim everywhere xprop
        # isn't installed (containers, minimal images).
        _LINUX_COMPOSITOR_CACHE = True
        return True


# Symbol-capable UI font for glyph buttons (send arrow, menu, scroll-down).
# These buttons set no family, so CTkFont falls back to the theme family
# "Inter" — not installed on Windows, so Tk substitutes an inconsistent glyph
# for the arrow/dingbat codepoints. "Segoe UI Symbol" ships on every supported
# Windows and draws U+2191/U+2630/U+25BC/U+25A0 crisply and deterministically.
# On macOS/Linux the default already renders well, so leave family unset to
# keep the current appearance exactly (zero visual change off Windows).
_GLYPH_FAMILY = "Segoe UI Symbol" if sys.platform.startswith("win") else None


def _glyph_font(size: int, weight: str = "normal") -> customtkinter.CTkFont:
    """CTkFont for glyph buttons; symbol-capable + deterministic on Windows."""
    if _GLYPH_FAMILY is not None:
        return customtkinter.CTkFont(
            family=_GLYPH_FAMILY, size=size, weight=weight)
    return customtkinter.CTkFont(size=size, weight=weight)


class ChatUIMixin:
    """UI construction methods mixed into the Chat Plugin class."""

    # Drawer overlay starts just below the header bar (header sits at y=4..46).
    _DRAWER_TOP = 46

    def create_main_screen(self):
        is_dark = _is_dark_mode()
        self._ensure_session()

        self.second_frame = customtkinter.CTkFrame(
            self.app, corner_radius=0, fg_color="transparent")

        # Access gate: chat is only available when the VPN is connected AND the
        # SIEM/Endpoint agent is RUNNING. A background poller (_start_gate_poller)
        # re-checks this while chat is open, so toggling the agent off or dropping
        # the VPN snaps chat back to the locked referral screen — and turning them
        # back on unlocks it — without navigating away and back.
        vpn_on, agent_on = self._chat_access_status()
        self._gate_unlocked = bool(vpn_on and agent_on)
        self._start_gate_poller()
        if not self._gate_unlocked:
            self._build_locked_screen(is_dark, vpn_on, agent_on)
            return self.second_frame

        # Build the full-width chat area first. The history sidebar is an
        # OVERLAY drawer over this area (see _show_sidebar) rather than a packed
        # column — so toggling it never resizes/reflows the chat content and the
        # markdown bubbles never re-wrap. That eliminates the toggle jaggedness.
        self._build_chat_area(is_dark)

        self._sidebar = ChatSidebar(
            self.second_frame,
            on_select=self._select_chat,
            on_new_chat=self._new_chat,
            on_delete=self._delete_chat,
            is_dark=is_dark)
        # Same fix as the chat-area caches above. The screen isn't cached
        # (no screen_signature), so navigation away+back builds a new
        # ChatSidebar — but _drawer_placed=True from the dead instance
        # would skip the .place() call in _sync_drawer_geometry, leaving
        # the fresh drawer constructed-but-never-positioned. Same for
        # _last_drawer_h: a height match against the new chat-area would
        # gate out the configure() call and the drawer would render
        # short or zero-height.
        self._drawer_placed = False
        self._last_drawer_h = None
        # Keep the open drawer sized to the chat area as the window resizes.
        self.second_frame.bind(
            "<Configure>", self._on_second_frame_configure, add="+")
        # The dim layer is a separate top-level window, so it must follow the
        # chat screen's visibility: hide it when this screen is unmapped
        # (navigated away / minimized), re-show it on return if the drawer is
        # still open.
        self.second_frame.bind("<Unmap>", self._on_chat_unmapped, add="+")
        self.second_frame.bind("<Map>", self._on_chat_mapped, add="+")
        # CRITICAL: when the user navigates to another plugin,
        # select_frame_by_name destroys the chat's second_frame. The dim
        # Toplevel is parented to self.app, NOT to second_frame, so it
        # survives the destroy as an orphan window — lingering on top of
        # the next plugin (Help, Settings, etc.). Bind <Destroy> on
        # second_frame to tear down the Toplevel and unbind the
        # app-level <Configure> handler that closes over it.
        self.second_frame.bind("<Destroy>", self._on_chat_destroyed, add="+")
        if self._sidebar_visible:
            self._show_sidebar()

        self._refresh_sidebar()
        return self.second_frame

    # -- Access gate (VPN + endpoint agent) --------------------------------

    def _chat_access_status(self) -> tuple[bool, bool]:
        """Return (vpn_connected, endpoint_agent_running) for the gate.

        The agent check is "running" (not merely "installed") so that manually
        toggling the SIEM agent off re-locks chat. A running service is also our
        best silent proxy for "connected to the manager" (the real connection
        state file is root-owned and unreadable without a privileged prompt).
        Falls back to the VPN plugin's status badge if the helper is missing.
        """
        vpn_on = False
        try:
            from plugins.vpn.main import is_vpn_connected
            vpn_on = bool(is_vpn_connected())
        except Exception:
            try:
                vp = next(
                    (p for p in self.app.plugin_list
                     if p.get_name() == "VPN"), None)
                vpn_on = bool(vp and vp.get_status() == "OK")
            except Exception:
                vpn_on = False
        agent_on = False
        try:
            from plugins.wazuh.main import is_agent_running
            agent_on = bool(is_agent_running())
        except Exception:
            agent_on = False
        return vpn_on, agent_on

    # Re-evaluate the access gate this often while chat is visible (ms). VPN is
    # an in-process flag, but the agent check spawns a subprocess, so keep this
    # at a few seconds rather than sub-second.
    _GATE_POLL_MS = 8000

    def _start_gate_poller(self) -> None:
        """Poll the access gate while chat is visible; rebuild on change.

        Detect-only (no privileged actions): when the VPN drops or the SIEM
        agent is toggled off, rebuild the chat plugin screen so the locked
        referral screen shows; when both come back, rebuild to the live chat.
        The poller is bound to second_frame's existence, so navigating away
        (which destroys second_frame) stops it.
        """
        self._stop_gate_poller()

        def poll():
            self._gate_poll_id = None
            frame = getattr(self, "second_frame", None)
            try:
                alive = bool(frame is not None and frame.winfo_exists())
            except Exception:
                alive = False
            if not alive:
                return
            try:
                vpn_on, agent_on = self._chat_access_status()
                unlocked = bool(vpn_on and agent_on)
            except Exception:
                unlocked = self._gate_unlocked
            if unlocked != self._gate_unlocked:
                logger.info(
                    "Chat access gate changed: unlocked=%s -> %s "
                    "(vpn=%s, agent=%s)",
                    self._gate_unlocked, unlocked, vpn_on, agent_on)
                self._gate_unlocked = unlocked
                # create_main_screen re-runs the gate and restarts the poller.
                self._refresh_gate_screen()
                return
            self._gate_poll_id = self.app.after(self._GATE_POLL_MS, poll)

        self._gate_poll_id = self.app.after(self._GATE_POLL_MS, poll)

    def _stop_gate_poller(self) -> None:
        pid = getattr(self, "_gate_poll_id", None)
        if pid is not None:
            try:
                self.app.after_cancel(pid)
            except Exception:
                pass
            self._gate_poll_id = None

    def _refresh_gate_screen(self) -> None:
        """Rebuild the chat plugin screen in place when the gate flips.

        Mirrors the Endpoint/VPN plugins: only rebuild when chat is the screen
        actually on display. Destroying second_frame fires <Destroy>, which
        tears down the dim overlay and stops the poller; create_main_screen then
        builds the locked or live view and starts a fresh poller.
        """
        current = getattr(self.app, "current_frame_name", "")
        if current != f"frame_{self.get_name()}":
            return
        old = getattr(self, "second_frame", None)
        if old is not None:
            try:
                old.destroy()
            except Exception:
                pass
        try:
            self.create_main_screen().grid(row=0, column=1, sticky="nsew")
        except Exception:
            logger.exception("Chat gate screen rebuild failed")

    def _build_locked_screen(
        self, is_dark: bool, vpn_on: bool, agent_on: bool,
    ) -> None:
        screen = ChatLockedScreen(
            self.second_frame, vpn_on, agent_on,
            on_open_vpn=lambda: self._open_plugin("VPN"),
            on_open_endpoint=lambda: self._open_plugin("Endpoint"),
            is_dark=is_dark)
        screen.place(relx=0.5, rely=0.5, anchor="center")

    def _open_plugin(self, name: str) -> None:
        """Navigate to another plugin's screen by its display name."""
        try:
            p = next(
                (p for p in self.app.plugin_list
                 if p.get_name() == name), None)
            if p is not None:
                self.app.select_frame_by_name(
                    f"frame_{name}", button=p.get_button())
        except Exception:
            pass

    def _on_chat_unmapped(self, _event=None) -> None:
        # <Unmap> fires for the second_frame on real navigation away from
        # chat, but ALSO bubbles up from any descendant being unmapped
        # (CTk briefly unmaps widgets during reparent/restack). Filter to
        # the second_frame itself.
        if _event is not None and _event.widget is not self.second_frame:
            return
        # Withdraw the dim aggressively — winfo_viewable() can lie during a
        # nav-driven destroy sequence (the frame is being torn down but
        # winfo_viewable hasn't flipped yet), and lingering dim on top of
        # the next plugin is much worse than an extra withdraw call on
        # a transient unmap (cheap, idempotent).
        for attr in ("_dim_overlay", "_dim_overlay_top"):
            t = getattr(self, attr, None)
            if t is not None:
                try:
                    t.withdraw()
                except Exception:
                    pass
        self._ov_mapped = False

    def _on_chat_destroyed(self, _event=None) -> None:
        # Final-line defense: when select_frame_by_name destroys
        # second_frame on plugin navigation, the Toplevel dim is parented
        # to self.app and would survive as an orphan. Destroy it
        # explicitly, clear the cached reference, and unbind the
        # app-level <Configure> handler so the next chat visit creates
        # a fresh dim Toplevel cleanly. Guard on widget identity — Tk
        # bubbles <Destroy> up from children before firing on the
        # widget itself, so we only act on the second_frame's own event.
        if _event is not None and _event.widget is not self.second_frame:
            return
        # Stop the access-gate poller tied to this (now dying) chat screen.
        # A rebuild re-creates it; navigating away leaves it stopped.
        self._stop_gate_poller()
        # Stream lifecycle: navigation away from chat plugin means the
        # user is leaving WHILE a response may still be streaming.
        # Cancel the stream and persist the canned "you switched chats"
        # message so revisiting the chat shows a clean marker instead
        # of an unfinished partial. Also flushes the now-clean session
        # to disk so the canned message survives an app restart.
        try:
            self._finalize_in_flight_response(persist=True)
            self._save_current_session()
        except Exception:
            pass
        for attr in ("_dim_overlay", "_dim_overlay_top"):
            t = getattr(self, attr, None)
            if t is not None:
                try:
                    t.destroy()
                except Exception:
                    pass
                setattr(self, attr, None)
        self._ov_mapped = False
        self._last_ov_geom = None
        self._last_top_geom = None
        # Cancel the app-level Configure debounce so it doesn't fire on
        # the dead dim handler.
        prev = getattr(self, "_app_cfg_after", None)
        if prev is not None:
            try:
                self.app.after_cancel(prev)
            except Exception:
                pass
            self._app_cfg_after = None
        # Unbind the app-level <Configure> handler we registered in
        # _ensure_dim_overlay. Without this, the bound method holds a
        # strong reference to the now-dead instance state for the
        # app's lifetime.
        bid = getattr(self, "_app_cfg_bid", None)
        if bid is not None:
            try:
                self.app.unbind("<Configure>", bid)
            except Exception:
                pass
            self._app_cfg_bid = None
            self._app_cfg_bound = False

    def _on_chat_mapped(self, _event=None) -> None:
        # Mirror filter on _on_chat_unmapped.
        if _event is not None and _event.widget is not self.second_frame:
            return
        # If the drawer was open before navigation, re-show the dim layer
        # to match. _set_chat_dim is idempotent.
        if getattr(self, "_sidebar_visible", False):
            try:
                self._set_chat_dim(True)
            except Exception:
                pass

    def _on_second_frame_configure(self, _event=None) -> None:
        # Only react when our own frame resizes — bubble / child <Configure>
        # events bubble up here through bindtags and would otherwise re-fire
        # the layout cascade O(bubble_count) times per resize pixel.
        if _event is not None and _event.widget is not self.second_frame:
            return
        if not self._sidebar_visible:
            return
        # Debounce: window-edge drag fires Configure at 60Hz. Coalesce to one
        # drawer-resize per ~16ms so we don't spam configure()/place() calls.
        prev = getattr(self, "_sf_cfg_after", None)
        if prev is not None:
            try:
                self.second_frame.after_cancel(prev)
            except Exception:
                pass
        try:
            self._sf_cfg_after = self.second_frame.after(
                16, self._apply_drawer_layout)
        except Exception:
            self._sf_cfg_after = None

    def _apply_drawer_layout(self) -> None:
        self._sf_cfg_after = None
        try:
            if self._sidebar is None or not self._sidebar.winfo_ismapped():
                return
            self._sync_drawer_geometry()
            # Re-size + reposition the dim Toplevel for the new chat-area
            # bounds. _position_dim_overlay short-circuits if nothing
            # actually changed since the last call, so the Configure burst
            # of a window-edge drag still costs at most one WM round-trip
            # per ~16ms.
            self._position_dim_overlay()
        except Exception:
            pass

    def _build_chat_area(self, is_dark: bool) -> None:
        self._chat_area = customtkinter.CTkFrame(
            self.second_frame, corner_radius=0, fg_color="transparent")
        self._chat_area.pack(side="left", fill="both", expand=True)
        # On a REBUILD (chat switch / new / delete) the history drawer already
        # exists as a sibling of second_frame. A freshly-packed widget stacks
        # ABOVE its siblings, so the new chat area would cover the open drawer
        # for the duration of the (heavy) history restore — the menu appears to
        # vanish for a moment and the drawer's column flashes bright (the dim
        # overlay intentionally doesn't cover the drawer, so covered-drawer ==
        # a visible "gap" in the dimming). Lower the chat area BELOW the drawer
        # NOW, before any repaint, so the drawer stays on top throughout the
        # rebuild. No-op on the initial build (the drawer is created after this
        # and is naturally on top); guarded for the full-rebuild path where
        # self._sidebar may briefly point at a destroyed widget.
        if getattr(self, "_sidebar_visible", False):
            sb = getattr(self, "_sidebar", None)
            try:
                if sb is not None and sb.winfo_exists():
                    self._chat_area.lower(sb)
            except Exception:
                pass
        self._chat_area.grid_columnconfigure(0, weight=1)
        self._chat_area.grid_rowconfigure(0, weight=1)

        self.chat_scroll = customtkinter.CTkScrollableFrame(
            self._chat_area, fg_color="transparent", corner_radius=0)
        # Left buffer so content doesn't touch the edge, but NO right padding so
        # the scrollbar stays flush with the right side of the window (its width
        # already separates the content from the edge).
        self.chat_scroll.grid(
            row=0, column=0, padx=(14, 0), pady=(50, 76), sticky="nsew")
        # Hide scrollbar initially; show only when content overflows
        self._hide_scrollbar()
        # Reset every cache that's keyed on the prior widget instances.
        # These live on the Plugin (not on second_frame), so navigation
        # away+back would otherwise let stale state from the destroyed
        # CTkScrollableFrame block visibility / sizing in the fresh one:
        # _scrollbar_currently_shown=True would gate out _show_scrollbar
        # on the next overflow, _last_avail==N would gate out the bubble
        # walk if the new chat happens to land at the same width.
        self._scrollbar_currently_shown = False
        self._last_avail = None

        self._bubble_rows.clear()
        self._welcome_frame = None
        self._bottom_spacer: customtkinter.CTkFrame | None = None
        self._current_asst_bubble: AssistantBubble | None = None
        self._header_visible = False
        self._header_label = None
        self._build_input_bar(is_dark)
        self._build_overlay_buttons(is_dark)
        self._restore_history(is_dark)
        self.chat_scroll.bind("<Configure>", self._on_resize, add="+")
        try:
            canvas = self.chat_scroll._parent_canvas
            # Debounced scroll-button check on wheel: cancel the previous
            # scheduled call so a 10-notch burst fires _check_scroll_btn
            # ONCE (100 ms after the last notch), not 10 times.
            canvas.bind(
                "<MouseWheel>", self._schedule_scroll_btn_check, add="+")
            canvas.bind(
                "<Button-4>", self._schedule_scroll_btn_check, add="+")
            canvas.bind(
                "<Button-5>", self._schedule_scroll_btn_check, add="+")
            if sys.platform.startswith("win"):
                # CTk sets yscrollincrement=1 on Windows, so the wheel only
                # moves ~20px per notch (delta/6 units * 1px) — too slow, and
                # it feels even slower on long chats. Bump the increment so each
                # notch moves a comfortable, FIXED ~100px regardless of page
                # length (delta/6 = 20 units * 5px = 100px).
                try:
                    canvas.configure(yscrollincrement=5)
                except Exception:
                    pass
                # Clear residual scroll "tracers" (a Windows canvas blit
                # artifact) once the wheel burst SETTLES. Debounced on purpose:
                # the previous per-tick update_idletasks() cost grew with page
                # length and was the real cause of "slower the longer the page."
                canvas.bind("<MouseWheel>", self._win_scroll_redraw, add="+")
        except Exception:
            pass

    def _win_scroll_redraw(self, _event=None) -> None:
        """Debounced repaint to clear Windows scroll tracers after the wheel
        burst settles, without adding per-notch cost that scales with page
        length."""
        try:
            canvas = self.chat_scroll._parent_canvas
            prev = getattr(self, "_scroll_redraw_after", None)
            if prev:
                try:
                    canvas.after_cancel(prev)
                except Exception:
                    pass
            self._scroll_redraw_after = canvas.after(
                60, canvas.update_idletasks)
        except Exception:
            pass

    def _restore_history(self, is_dark: bool) -> None:
        """Rebuild the chat from conversation_history.

        Renders user bubbles synchronously (cheap — they're just text) and
        defers each assistant bubble's MarkdownRenderer through after_idle.
        A 50-message history used to lock the UI for 1–3 seconds while
        every MarkdownRenderer.render() ran back-to-back during chat
        switching. Now we add empty AssistantBubble placeholders up front
        — so the layout is correct — and finalize each one in its own
        idle tick, yielding to the event loop between renders. The user
        sees bubbles fill in progressively instead of a hung window.
        """
        has_history = False
        # Pending (bubble, markdown_text) pairs to render one-per-idle.
        # Reset on every rebuild so a switch mid-render doesn't leak the
        # old queue into the new chat.
        self._restore_queue: list[tuple[AssistantBubble, str]] = []
        # Cancel any in-flight restore from a previous chat.
        prev = getattr(self, "_restore_after", None)
        if prev is not None:
            try:
                self.chat_scroll.after_cancel(prev)
            except Exception:
                pass
            self._restore_after = None

        for msg in self.conversation_history:
            role, content = msg.get("role"), msg.get("content", "")
            if role == "system":
                continue
            has_history = True
            if role == "user":
                self._add_user_bubble(content, is_dark)
            elif role == "assistant":
                # Create the bubble in its placeholder/thinking state and
                # queue the markdown render for later.
                bubble = self._add_assistant_bubble(is_dark)
                self._restore_queue.append((bubble, content))

        if has_history:
            self._show_header()
            if self._restore_queue:
                # Kick the restore pump. after_idle gives every other
                # pending Tk event (Configure cascade from the rebuild,
                # the show-screen reveal) priority over the renders, so
                # the chat-switch transition feels instantaneous.
                try:
                    self._restore_after = self.chat_scroll.after_idle(
                        self._restore_pump)
                except Exception:
                    self._restore_after = None
            return
        if self.client is not None:
            self._welcome_frame = WelcomeScreen(
                self.chat_scroll, self._use_suggestion, is_dark)
        else:
            self._welcome_frame = ApiKeyMissingScreen(
                self.chat_scroll, self._open_settings, is_dark)
        # Modest top inset (not 80px): with widget scaling the greeting +
        # 4 suggestion chips were taller than the viewport, pushing the bottom
        # chips behind the input bar. A smaller inset keeps them all visible.
        self._welcome_frame.pack(expand=True, fill="both", pady=(24, 0))

    def _restore_pump(self) -> None:
        """Render the next pending assistant bubble. Re-schedules itself
        via after(0, ...) so each iteration yields to the event loop —
        the user can scroll, click the sidebar, etc., while a long
        history is still hydrating in the background.
        """
        self._restore_after = None
        queue = getattr(self, "_restore_queue", None)
        if not queue:
            return
        bubble, md = queue.pop(0)
        try:
            # Skip if the bubble (or its parent chat_scroll) was destroyed
            # while we were waiting in the idle queue — happens when the
            # user switches chats again mid-restore.
            if bubble.winfo_exists():
                bubble.finalize_markdown(md)
        except Exception:
            pass
        if queue and self.chat_scroll is not None:
            try:
                self._restore_after = self.chat_scroll.after(
                    0, self._restore_pump)
            except Exception:
                self._restore_after = None

    def _build_input_bar(self, is_dark: bool) -> None:
        fg = "#ffffff" if is_dark else "#000000"
        bg, brd = ("#1A1A1C", "#2A2A2A") if is_dark else ("#F5F5F7", "#E5E7EB")
        bar = customtkinter.CTkFrame(
            self._chat_area, fg_color=bg,
            corner_radius=22, border_width=1, border_color=brd)
        self._input_bar = bar
        bar.place(relx=0.5, rely=1.0, anchor="s", relwidth=0.96, y=-14)
        bar.grid_columnconfigure(0, weight=1)
        self.chat_entry = EmojiEntry(
            bar, placeholder_text="Message Phoenix AI...",
            corner_radius=20, border_width=0, height=44,
            font=customtkinter.CTkFont(family=ui_family(), size=16),
            fg_color="transparent", text_color=fg,
            placeholder_text_color="#8ea8c6" if is_dark else "#9aa5b1")
        self.chat_entry.grid(
            row=0, column=0, padx=(16, 4), pady=0, sticky="ew")
        self.send_button = customtkinter.CTkButton(
            bar, text="\u2191", command=self.send_message,
            corner_radius=18, height=36, width=36,
            font=_glyph_font(18, weight="bold"),
            fg_color=RESISTINE_BLUE, hover_color="#1565B0",
            text_color="#ffffff")
        self.send_button.grid(row=0, column=1, padx=(0, 6), pady=6)
        self.chat_entry.bind("<Return>", lambda _e: self.send_message())
        if self.client is None:
            self.chat_entry.configure(
                state="disabled",
                placeholder_text="API key required \u2014 see Settings")
            self.send_button.configure(state="disabled", fg_color="#6B7280")

    def _build_overlay_buttons(self, is_dark: bool) -> None:
        fg = "#e0e0e0" if is_dark else "#1a1a1a"
        btn_bg = "#2A2A2C" if is_dark else "#E8E8EA"
        hover_bg = "#3A3A3C" if is_dark else "#D8D8DC"

        # Header bar with menu button, title, and new chat button
        header = customtkinter.CTkFrame(
            self._chat_area, fg_color="transparent", height=42)
        header.place(relx=0, rely=0, relwidth=1.0, y=4)
        header.grid_columnconfigure(1, weight=1)

        btn_size = 32
        self._toggle_btn = customtkinter.CTkButton(
            header, text="\u2630", width=btn_size, height=btn_size,
            corner_radius=8, fg_color=btn_bg, hover_color=hover_bg,
            text_color=fg,
            font=_glyph_font(16),
            command=self._toggle_sidebar)
        self._toggle_btn.grid(row=0, column=0, padx=(12, 0), pady=4)

        self._header_label = customtkinter.CTkLabel(
            header, text="Phoenix AI",
            font=customtkinter.CTkFont(
                family=ui_family(), size=16, weight="bold"),
            text_color=fg, fg_color="transparent")
        self._header_label.grid(row=0, column=1, pady=4)
        self._header_visible = True

        self._new_chat_btn = customtkinter.CTkButton(
            header, text="+", width=btn_size, height=btn_size,
            corner_radius=8, fg_color=btn_bg, hover_color=hover_bg,
            text_color=fg,
            font=customtkinter.CTkFont(size=20, weight="bold"),
            command=self._new_chat)
        self._new_chat_btn.grid(row=0, column=2, padx=(0, 12), pady=4)

        self._scroll_btn = customtkinter.CTkButton(
            self._chat_area, text="\u25bc", width=30, height=30,
            corner_radius=15,
            fg_color=RESISTINE_BLUE, hover_color="#1565B0",
            text_color="#ffffff",
            font=_glyph_font(10),
            command=self._scroll_to_bottom)
        self._scroll_btn_visible = False

    def _show_sidebar(self) -> None:
        """Reveal the history drawer as an overlay on the left of the chat area.

        It floats over the chat (below the header bar) instead of pushing it, so
        the chat content keeps its width and never re-wraps.
        """
        # Single source of truth for the open-state: every show/hide path
        # (toggle button, clicking the dim overlay, navigation) updates it here
        # so it can never go stale. Closing via the overlay used to leave this
        # True, which re-opened the drawer on the next chat rebuild (+ New).
        self._sidebar_visible = True
        # Place the drawer first — the dim overlay is sized to the full app
        # window (see _position_dim_overlay), so no need to wait on drawer
        # geometry. Avoid update_idletasks() here: it re-enters the event
        # loop in the middle of a toggle and can crash mid-rebuild.
        self._sync_drawer_geometry()
        self._set_chat_dim(True)
        # Raise the drawer above the dim layer on every show. CTk's place()
        # alone doesn't guarantee a Toplevel ends up below — explicit lift
        # makes the drawer the topmost widget within the App window, while
        # the dim Toplevel sits above the chat content.
        try:
            self._sidebar.lift()
        except Exception:
            pass

    def _set_chat_dim(self, dim: bool) -> None:
        """Show/hide the dim layer over the chat while the drawer is open.

        Uses TWO borderless alpha Toplevels: one covers the chat to the
        right of the drawer (most of the area), one covers the small
        strip above the drawer (x=0..drawer_w, y=0..DRAWER_TOP) so the
        hamburger button area is dimmed too. Without the second one,
        the user sees a bright top-left rectangle that's neither drawer
        nor dim — exactly the symptom reported.

        Two Toplevels rather than one big rectangle because the drawer
        sits at x=0..drawer_w, y=DRAWER_TOP..h and is bright (the user's
        focus). A single Toplevel covering both regions would be a
        rectangle that includes the drawer area, and Toplevels always
        render above in-process Frames — the drawer would be covered.
        """
        self._ensure_dim_overlay()
        main = getattr(self, "_dim_overlay", None)
        top = getattr(self, "_dim_overlay_top", None)
        if main is None or top is None:
            return
        if dim:
            if self._position_dim_overlay():
                # Only deiconify on the False→True transition. deiconify is
                # a WM round-trip that on Windows triggers extra paints when
                # called on an already-mapped window.
                if not getattr(self, "_ov_mapped", False):
                    try:
                        main.deiconify(); main.lift()
                        top.deiconify(); top.lift()
                        self._ov_mapped = True
                    except Exception:
                        pass
        else:
            if getattr(self, "_ov_mapped", False):
                try:
                    main.withdraw()
                    top.withdraw()
                    self._ov_mapped = False
                except Exception:
                    pass

    def _ensure_dim_overlay(self):
        """Create the dim Toplevels once (borderless, alpha).

        Two Toplevels: ``_dim_overlay`` covers the chat area right of
        the drawer; ``_dim_overlay_top`` covers the strip above the
        drawer (where the hamburger button sits). Returns the main one,
        or None on failure. _dim_overlay_top is stored on self.
        """
        ov = getattr(self, "_dim_overlay", None)
        top = getattr(self, "_dim_overlay_top", None)
        try:
            ov_ok = ov is not None and ov.winfo_exists()
            top_ok = top is not None and top.winfo_exists()
            if ov_ok and top_ok:
                return ov
        except Exception:
            ov_ok = top_ok = False

        # X11 without a compositing manager renders `-alpha` borderless
        # Toplevels as opaque solid black instead of translucent, which
        # would hide the chat behind the drawer rather than dim it. The
        # drawer's own background already provides adequate visual
        # separation in that environment, so skip the overlay entirely.
        # All callers null-check the return value of _ensure_dim_overlay.
        if (sys.platform.startswith("linux")
                and not _linux_has_compositor()):
            if not getattr(self, "_dim_skip_logged", False):
                logger.info(
                    "chat dim overlay skipped: X11 without compositor "
                    "(no _NET_WM_CM_S0); drawer alone provides separation"
                )
                self._dim_skip_logged = True
            return None

        def _make() -> "tkinter.Toplevel":
            t = tkinter.Toplevel(self.app)
            t.overrideredirect(True)
            t.configure(bg="#000000")
            try:
                t.attributes("-alpha", _DIM_ALPHA)
            except Exception:
                pass
            try:
                t.transient(self.app)
            except Exception:
                pass
            # macOS: a borderless overrideredirect Toplevel steals focus
            # when clicked. Even after we withdraw() it on click, the
            # main window never re-receives focus — the user has to
            # click on the desktop and back into the app to "wake it
            # up". The standard Tk macOS escape hatch is the
            # `MacWindowStyle` private call: "noActivates" tells the
            # window server the panel never activates, so clicks are
            # received and processed without transferring focus to it.
            if sys.platform == "darwin":
                try:
                    t.tk.call(
                        "::tk::unsupported::MacWindowStyle",
                        "style", t._w, "plain", "noActivates",
                    )
                except Exception:
                    pass
            t.withdraw()
            # Clicking the dimmed area collapses the drawer.
            t.bind("<Button-1>", lambda _e: self._on_dim_click())
            return t

        try:
            if not ov_ok:
                self._dim_overlay = _make()
            if not top_ok:
                self._dim_overlay_top = _make()
            self._ov_mapped = False
            self._last_ov_geom = None
            self._last_top_geom = None
            # Bind once, across chat rebuilds.
            if not getattr(self, "_app_cfg_bound", False):
                try:
                    self._app_cfg_bid = self.app.bind(
                        "<Configure>", self._on_app_configure, add="+")
                    self._app_cfg_bound = True
                except Exception:
                    pass
        except Exception:
            self._dim_overlay = None
            self._dim_overlay_top = None
        return self._dim_overlay

    def _position_dim_overlay(self) -> bool:
        """Size the overlay to cover the chat area to the RIGHT of the
        drawer (not the drawer itself). Returns False if not yet laid out.

        Both winfo_rootx/y/width/height and Toplevel.geometry() use the
        same coordinate system on every platform — Tk's logical pixel
        space, which Tk itself maps to OS pixels via tk scaling. No
        manual rescaling needed: a verified empirical check on macOS
        Retina (tk_scaling ≈ 1.0), Linux HiDPI (CTk window_scaling=1.5
        with winfo already reporting the post-scaling number), and
        Windows DPI-aware (tk_scaling ≈ 1.33+) all show geometry()
        accepting the same units winfo_* reports. The prior multiplier
        produced a 33-78% overshoot, leaving the chat top-and-left
        undimmed (the exact symptom this method was meant to cure).
        """
        ov = getattr(self, "_dim_overlay", None)
        top = getattr(self, "_dim_overlay_top", None)
        if ov is None or top is None:
            return False
        try:
            # winfo_* is already current inside <Configure> handlers — do
            # NOT call update_idletasks() here (re-entry hazard).
            sf = self.second_frame
            x = sf.winfo_rootx()
            y = sf.winfo_rooty()
            w = sf.winfo_width()
            h = sf.winfo_height()
            # Drawer width: actual mapped width if available, else its
            # advertised _WIDTH constant.
            sb = getattr(self, "_sidebar", None)
            try:
                drawer_w = (sb.winfo_width() if sb and sb.winfo_ismapped()
                            else getattr(sb, "_WIDTH", 220))
            except Exception:
                drawer_w = getattr(sb, "_WIDTH", 220) if sb else 220
            ox = x + drawer_w
            ow = w - drawer_w
            top_h = self._DRAWER_TOP
            if ow <= 1 or h <= 1:
                return False
            main_geom = (ow, h, ox, y)
            top_geom = (drawer_w, top_h, x, y)
            # Skip the WM round-trip per Toplevel if nothing changed.
            if getattr(self, "_last_ov_geom", None) != main_geom:
                self._last_ov_geom = main_geom
                ov.geometry(f"{ow}x{h}+{ox}+{y}")
            if getattr(self, "_last_top_geom", None) != top_geom:
                self._last_top_geom = top_geom
                top.geometry(f"{drawer_w}x{top_h}+{x}+{y}")
            return True
        except Exception:
            return False

    def _on_app_configure(self, _event=None) -> None:
        # Only react to the App top-level itself moving — every descendant
        # Configure bubbles through here too (bindtag includes toplevel
        # pathname), which on a long chat fires O(bubble_count) times per
        # drag pixel. Filter aggressively.
        if _event is None or _event.widget is not self.app:
            return
        if not getattr(self, "_ov_mapped", False):
            return
        # Debounce to one reposition per ~16ms frame instead of per drag pixel.
        prev = getattr(self, "_app_cfg_after", None)
        if prev is not None:
            try:
                self.app.after_cancel(prev)
            except Exception:
                pass
        try:
            self._app_cfg_after = self.app.after(
                16, self._position_dim_overlay)
        except Exception:
            self._app_cfg_after = None

    def _sync_drawer_geometry(self) -> None:
        """Size + place the drawer to fill the chat area below the header.

        CTk's place() refuses an absolute height (it must be set via the
        constructor / configure()), so we configure() the height and only pass
        x/y to place(). Width comes from the ChatSidebar constructor.

        Idempotent: skip the configure() round-trip when the height hasn't
        actually changed (e.g. window moved but didn't resize).
        """
        try:
            h = max(1, self.second_frame.winfo_height() - self._DRAWER_TOP)
            if getattr(self, "_last_drawer_h", None) != h:
                self._sidebar.configure(height=h)
                self._last_drawer_h = h
            # place() is a no-op when x/y unchanged but Tk still issues a
            # WM placement command; call it only on the first show.
            if not getattr(self, "_drawer_placed", False):
                self._sidebar.place(x=0, y=self._DRAWER_TOP)
                self._drawer_placed = True
        except Exception:
            pass

    def _on_dim_click(self) -> None:
        """Dim-overlay click handler — closes the drawer and re-anchors
        focus to the main window on macOS.

        The macOS "noActivates" style we set in _ensure_dim_overlay is
        normally enough to prevent focus theft, but on some macOS
        versions / Tk builds the Toplevel still briefly grabs focus
        when clicked. Re-focusing the app here is a no-cost safety
        net — without it the user reports that subsequent clicks in
        the chat go nowhere until they click on the desktop and back.
        """
        self._hide_sidebar()
        if sys.platform == "darwin":
            try:
                self.app.focus_force()
            except Exception:
                pass

    def _hide_sidebar(self) -> None:
        # Single source of truth — see _show_sidebar. Clear it here so closing
        # via the dim-overlay click (which calls _hide_sidebar directly, NOT
        # _toggle_sidebar) doesn't leave a stale "open" flag.
        self._sidebar_visible = False
        self._set_chat_dim(False)
        try:
            if getattr(self, "_sidebar", None) is not None:
                self._sidebar.place_forget()
        except Exception:
            pass
        # Reset the place-once latch so the next show re-places the drawer.
        self._drawer_placed = False

    def _toggle_sidebar(self) -> None:
        # _show_sidebar / _hide_sidebar own _sidebar_visible now, so don't flip
        # it here too (that would double-toggle).
        if self._sidebar_visible:
            self._hide_sidebar()
        else:
            self._show_sidebar()

    def _schedule_scroll_btn_check(self, _event=None) -> None:
        """Debounce wrapper for _check_scroll_btn — fires 100 ms after the
        last wheel notch instead of once per notch."""
        prev = getattr(self, "_scroll_btn_after", None)
        if prev is not None:
            try:
                self.chat_scroll.after_cancel(prev)
            except Exception:
                pass
        try:
            self._scroll_btn_after = self.chat_scroll.after(
                100, self._check_scroll_btn_fire)
        except Exception:
            self._scroll_btn_after = None

    def _check_scroll_btn_fire(self) -> None:
        self._scroll_btn_after = None
        self._check_scroll_btn()

    def _check_scroll_btn(self) -> None:
        if not hasattr(self, "_scroll_btn") or self._scroll_btn is None:
            return
        near = self._is_near_bottom()
        if not near and not self._scroll_btn_visible:
            try:
                self._scroll_btn.place(
                    relx=0.5, rely=1.0, anchor="s", y=-72)
                self._scroll_btn_visible = True
            except Exception:
                pass
        elif near and self._scroll_btn_visible:
            try:
                self._scroll_btn.place_forget()
            except Exception:
                pass
            self._scroll_btn_visible = False

    def _refresh_sidebar(self) -> None:
        if hasattr(self, "_sidebar") and self._sidebar:
            self._sidebar.refresh(
                self._history.list_sessions(),
                self._history.get_active_id())

    def _show_header(self) -> None:
        if not self._header_visible and self._header_label is not None:
            self._header_label.grid(row=0, column=1, pady=4)
            self._header_visible = True

    # -- Bubble helpers ----------------------------------------------------

    def _available_width(self, *, force_idle: bool = False) -> int:
        try:
            # update_idletasks() inside a <Configure> handler re-enters the
            # event loop and can crash. winfo_* is already current during
            # a Configure event; only force idle when called from a
            # non-resize site (initial layout, after a bubble add).
            if force_idle:
                try:
                    self.chat_scroll.update_idletasks()
                except Exception:
                    pass
            # The scrollable INNER frame width is inflated by a wide wrap="none"
            # code block on Windows; the parent canvas is the true viewport and
            # is never inflated by content. Prefer it; fall back to the frame.
            try:
                w = self.chat_scroll._parent_canvas.winfo_width()
            except Exception:
                w = 0
            if w <= 1:
                w = self.chat_scroll.winfo_width()
            return max(w - 20, 300) if w > 1 else 800
        except Exception:
            return 800

    def _make_row(self) -> BubbleRow:
        if self._bottom_spacer is not None:
            self._bottom_spacer.destroy()
        row = BubbleRow(self.chat_scroll)
        self._bubble_rows.append(row)
        self._bottom_spacer = customtkinter.CTkFrame(
            self.chat_scroll, fg_color="transparent", height=16)
        self._bottom_spacer.pack(fill="x")
        return row

    def _add_user_bubble(self, text: str, is_dark: bool) -> BubbleRow:
        row = self._make_row()
        UserBubble(row, text, is_dark=is_dark,
                   max_width=user_width(self._available_width(force_idle=True)))
        return row

    def _add_assistant_bubble(
        self, is_dark: bool, md: str | None = None,
    ) -> AssistantBubble:
        row = self._make_row()
        ab = AssistantBubble(
            row, is_dark=is_dark,
            max_width=assistant_width(self._available_width(force_idle=True)))
        if md is not None:
            ab.finalize_markdown(md)
        return ab

    def _is_near_bottom(self) -> bool:
        try:
            if self.chat_scroll is None:
                return True
            return self.chat_scroll._parent_canvas.yview()[1] > 0.95
        except Exception:
            return True

    def _scroll_to_bottom(self) -> None:
        try:
            if self.chat_scroll is not None:
                self.chat_scroll._parent_canvas.yview_moveto(1.0)
        except Exception:
            pass
        if hasattr(self, "_scroll_btn") and self._scroll_btn_visible:
            try:
                self._scroll_btn.place_forget()
            except Exception:
                pass
            self._scroll_btn_visible = False

    def _on_resize(self, _event=None) -> None:
        # Window-edge drag fires <Configure> at 60+ Hz. Coalesce to one
        # bubble-resize pass per ~30ms so each drag pixel doesn't iterate
        # every bubble. The earlier _in_on_resize re-entry guard is
        # preserved against scrollbar-toggle echoes inside _do_resize.
        prev = getattr(self, "_resize_after", None)
        if prev is not None:
            try:
                self.chat_scroll.after_cancel(prev)
            except Exception:
                pass
        try:
            self._resize_after = self.chat_scroll.after(
                30, self._do_resize)
        except Exception:
            self._resize_after = None

    def _do_resize(self) -> None:
        self._resize_after = None
        # winfo_* is current after the post-Configure tick — safe without
        # update_idletasks(), and force_idle would re-enter here.
        avail = self._available_width()
        # Short-circuit when width didn't actually change — scrollbar
        # auto-hide can echo <Configure> events that don't change the
        # available width, and walking every bubble per echo is wasted.
        if avail == getattr(self, "_last_avail", None):
            self._check_scroll_btn()
            return
        self._last_avail = avail
        if getattr(self, "_in_on_resize", False):
            return
        self._in_on_resize = True
        try:
            uw, aw = user_width(avail), assistant_width(avail)
            for row in self._bubble_rows:
                for child in row.winfo_children():
                    if isinstance(child, UserBubble):
                        child.set_width(uw)
                    elif isinstance(child, AssistantBubble):
                        child.set_width(aw)
            self._check_scroll_btn()
            self._update_scrollbar_visibility()
        finally:
            self._in_on_resize = False

    # -- Scrollbar visibility ----------------------------------------------

    def _hide_scrollbar(self) -> None:
        try:
            scrollbar = self.chat_scroll._scrollbar
            scrollbar.grid_remove()
        except Exception:
            pass

    def _show_scrollbar(self) -> None:
        try:
            scrollbar = self.chat_scroll._scrollbar
            scrollbar.grid()
        except Exception:
            pass

    def _update_scrollbar_visibility(self) -> None:
        try:
            canvas = self.chat_scroll._parent_canvas
            # No update_idletasks() here — runs inside <Configure>; bbox is
            # already current. The forced flush was the source of an echo
            # <Configure> that re-fired _on_resize twice per drag pixel.
            bbox = canvas.bbox("all")
            if not bbox:
                desired = False
            else:
                content_h = bbox[3] - bbox[1]
                visible_h = canvas.winfo_height()
                desired = content_h > visible_h
            # Idempotent: skip grid()/grid_remove() (and the <Configure>
            # echo they cause on the canvas) when state is unchanged.
            cur = getattr(self, "_scrollbar_currently_shown", None)
            if desired == cur:
                return
            self._scrollbar_currently_shown = desired
            if desired:
                self._show_scrollbar()
            else:
                self._hide_scrollbar()
        except Exception:
            pass

    # -- Scroll to last user bubble ----------------------------------------

    def _scroll_to_last_user_bubble(self) -> None:
        """Scroll so the last user message is at the top of the view."""
        try:
            canvas = self.chat_scroll._parent_canvas
            canvas.update_idletasks()
            # Find the last user bubble row
            last_user_row = None
            for row in self._bubble_rows:
                for child in row.winfo_children():
                    if isinstance(child, UserBubble):
                        last_user_row = row
                        break
            if last_user_row is None:
                return
            # Get the y position of the user row relative to the scroll content
            row_y = last_user_row.winfo_y()
            bbox = canvas.bbox("all")
            if not bbox:
                return
            content_h = bbox[3] - bbox[1]
            if content_h <= 0:
                return
            # Scroll so the user row is near the top (with a small offset)
            frac = max(0.0, (row_y - 8) / content_h)
            canvas.yview_moveto(frac)
        except Exception:
            self._scroll_to_bottom()
