"""Chat history sidebar widget for the chat plugin."""
from __future__ import annotations

import time
from typing import Callable

import customtkinter

from plugins.chat.fonts import RESISTINE_BLUE, ui_family


def _time_ago(ts: float) -> str:
    """Human-readable relative time string."""
    delta = time.time() - ts
    if delta < 60:
        return "now"
    if delta < 3600:
        return f"{int(delta / 60)}m"
    if delta < 86400:
        return f"{int(delta / 3600)}h"
    days = int(delta / 86400)
    if days < 7:
        return f"{days}d"
    return f"{int(days / 7)}w"


class ChatSidebar(customtkinter.CTkFrame):
    """Collapsible sidebar listing saved chat sessions."""

    _WIDTH = 220

    def __init__(
        self,
        master: object,
        on_select: Callable[[str], None],
        on_new_chat: Callable[[], None],
        on_delete: Callable[[str], None],
        is_dark: bool = False,
        **kwargs: object,
    ) -> None:
        bg = "#161618" if is_dark else "#ECECEE"
        # Right-edge border: must be DARKER than the dimmed-chat color to
        # the right, otherwise it shows as a bright line at the seam.
        # In dark mode the dim Toplevel renders at roughly
        # 0.6 * chat_bg + 0.4 * black ≈ #0E0E0E. The previous #2A2A2A was
        # MUCH lighter than that — the bright vertical line the user
        # reported. Drop a couple of stops below the dimmed value so the
        # edge reads as a subtle inset shadow. Light-mode value
        # unchanged (the contrast there worked fine).
        border = "#050505" if is_dark else "#D1D1D6"
        super().__init__(
            master, fg_color=bg, corner_radius=0,
            width=self._WIDTH, **kwargs)
        # Right-edge border line
        customtkinter.CTkFrame(
            self, fg_color=border, width=1, corner_radius=0,
        ).place(relx=1.0, rely=0, relheight=1.0, anchor="ne")
        self.grid_propagate(False)

        self._on_select = on_select
        self._on_new_chat = on_new_chat
        self._on_delete = on_delete
        self._is_dark = is_dark
        self._items: dict[str, customtkinter.CTkFrame] = {}
        self._active_id: str | None = None

        self.grid_rowconfigure(1, weight=1)
        self.grid_columnconfigure(0, weight=1)

        # -- header --
        hdr = customtkinter.CTkFrame(self, fg_color="transparent")
        hdr.grid(row=0, column=0, padx=8, pady=(10, 2), sticky="ew")
        hdr.grid_columnconfigure(0, weight=1)

        customtkinter.CTkLabel(
            hdr, text="HISTORY",
            font=customtkinter.CTkFont(
                family=ui_family(), size=10, weight="bold"),
            text_color="#6B7280", anchor="w",
        ).grid(row=0, column=0, sticky="w", padx=4)

        customtkinter.CTkButton(
            hdr, text="+ New",
            font=customtkinter.CTkFont(
                family=ui_family(), size=11, weight="bold"),
            fg_color=RESISTINE_BLUE, hover_color="#1565B0", text_color="#fff",
            corner_radius=7, height=26, width=60,
            command=self._on_new_chat,
        ).grid(row=0, column=1)

        # -- scrollable list --
        self._list = customtkinter.CTkScrollableFrame(
            self, fg_color="transparent", corner_radius=0,
            scrollbar_button_color=bg)
        self._list.grid(row=1, column=0, padx=4, pady=4, sticky="nsew")

    # -- public API --------------------------------------------------------

    def refresh(self, sessions: list[dict], active_id: str | None) -> None:
        """Diff against the current item list and apply minimal mutations.

        The previous implementation destroyed every row and rebuilt it on
        every call — ~4N widget creations per refresh. Called from every
        stream completion and every nav, this was the visible
        sidebar-flash. Now we mutate existing rows in place and only
        create/destroy when sessions actually appear or disappear.
        """
        self._active_id = active_id

        # Empty-state handling — bail early, clear everything if needed.
        if not sessions:
            for w in self._list.winfo_children():
                w.destroy()
            self._items.clear()
            customtkinter.CTkLabel(
                self._list, text="No conversations",
                font=customtkinter.CTkFont(family=ui_family(), size=12),
                text_color="#6B7280",
            ).pack(pady=30)
            return

        # If a "No conversations" placeholder is up, clear it before
        # adding the real rows.
        if not self._items and self._list.winfo_children():
            for w in self._list.winfo_children():
                w.destroy()

        new_ids = {s["id"] for s in sessions}

        # Remove rows whose sessions are gone.
        for sid in list(self._items):
            if sid not in new_ids:
                try:
                    self._items[sid].destroy()
                except Exception:
                    pass
                del self._items[sid]

        # Walk sessions in order. Mutate existing rows; create missing.
        # Use pack_forget+pack to re-order rows in-place so the visible
        # order matches `sessions`.
        active_bg = "#1A2F45" if self._is_dark else "#D6E4F0"
        for s in sessions:
            sid = s["id"]
            title = s.get("title", "New Chat")
            updated = s.get("updated_at", 0)
            row = self._items.get(sid)
            if row is None:
                self._add_item(sid, title, updated)
                continue
            # Mutate in place — no widget recreation.
            try:
                tl = getattr(row, "_resistine_title_lbl", None)
                if tl is not None:
                    tl.configure(text=title)
                ml = getattr(row, "_resistine_meta_lbl", None)
                if ml is not None:
                    ml.configure(text=_time_ago(updated))
                row.configure(
                    fg_color=active_bg if sid == active_id else "transparent")
                # Re-pack to enforce the desired order (cheap when the
                # row is already in the right slot).
                row.pack_forget()
                row.pack(fill="x", pady=1)
            except Exception:
                pass

    def set_active(self, session_id: str | None) -> None:
        """Update which item is highlighted."""
        self._active_id = session_id
        active_bg = "#1A2F45" if self._is_dark else "#D6E4F0"
        for sid, item in self._items.items():
            item.configure(
                fg_color=active_bg if sid == session_id else "transparent")

    # -- internal ----------------------------------------------------------

    def _add_item(
        self, sid: str, title: str, updated: float,
    ) -> None:
        is_active = sid == self._active_id
        active_bg = "#1A2F45" if self._is_dark else "#D6E4F0"
        fg = "#e0e0e0" if self._is_dark else "#1a1a1a"

        row = customtkinter.CTkFrame(
            self._list,
            fg_color=active_bg if is_active else "transparent",
            corner_radius=8, height=36)
        row.pack(fill="x", pady=1)
        row.pack_propagate(False)
        row.grid_columnconfigure(0, weight=1)

        lbl = customtkinter.CTkLabel(
            row, text=title,
            font=customtkinter.CTkFont(family=ui_family(), size=12),
            text_color=fg, anchor="w")
        lbl.grid(row=0, column=0, padx=(8, 2), sticky="ew")

        meta = customtkinter.CTkLabel(
            row, text=_time_ago(updated),
            font=customtkinter.CTkFont(family=ui_family(), size=10),
            text_color="#6B7280", width=24,
        )
        meta.grid(row=0, column=1, padx=2)

        # Stash refs on the row so refresh() can mutate them in place
        # without destroying-and-recreating the whole row.
        row._resistine_title_lbl = lbl  # type: ignore[attr-defined]
        row._resistine_meta_lbl = meta  # type: ignore[attr-defined]

        customtkinter.CTkButton(
            row, text="\u2715", width=24, height=24,
            corner_radius=6, fg_color="transparent",
            hover_color="#3D1515" if self._is_dark else "#FDE8E8",
            text_color="#6B7280",
            font=customtkinter.CTkFont(size=11),
            command=lambda: self._on_delete(sid),
        ).grid(row=0, column=2, padx=(0, 4))

        for w in (row, lbl):
            w.bind("<Button-1>", lambda _e, s=sid: self._on_select(s))

        self._items[sid] = row
