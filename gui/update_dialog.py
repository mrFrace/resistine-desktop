"""
Update Dialog — Sparkle-like update prompt for Linux (and potentially Windows).

Presents release notes, download progress, and restart options in a
CustomTkinter dialog that mirrors the macOS Sparkle update experience.

Author: Resistine Team
Copyright (c) Resistine 2025
Licensed under the GNU General Public License v2 or later
"""

import os
from typing import Callable, Optional

import customtkinter
from PIL import Image

from utils.logger import logger


class UpdateDialog(customtkinter.CTkToplevel):
    """Sparkle-like update dialog with multiple states.

    States:
        PROMPT      — release info + Install / Remind / Skip buttons
        DOWNLOADING — progress bar + Cancel button
        READY       — restart prompt after successful download
        ERROR       — error message + Retry / Dismiss buttons
    """

    def __init__(
        self,
        master,
        current_version: str,
        new_version: str,
        release_notes_html: str,
        on_install: Callable[[], None],
        on_skip: Callable[[str], None],
        on_remind_later: Callable[[], None],
        on_restart: Optional[Callable[[], None]] = None,
    ):
        super().__init__(master)

        self._on_install = on_install
        self._on_skip = on_skip
        self._on_remind_later = on_remind_later
        self._on_restart = on_restart
        self._new_version = new_version
        self._cancelled = False

        self.title("Software Update")
        self.geometry("520x460")
        self.resizable(False, False)
        self.lift()
        self.attributes("-topmost", True)
        self.protocol("WM_DELETE_WINDOW", self._handle_remind_later)

        self.grid_columnconfigure(0, weight=1)

        # --- Header with icon ---
        header = customtkinter.CTkFrame(self, fg_color="transparent")
        header.grid(row=0, column=0, padx=24, pady=(20, 0), sticky="ew")
        header.grid_columnconfigure(1, weight=1)

        icon_path = self._find_icon()
        if icon_path:
            try:
                img = Image.open(icon_path)
                self._icon_image = customtkinter.CTkImage(
                    light_image=img, dark_image=img, size=(56, 56)
                )
                icon_label = customtkinter.CTkLabel(
                    header, image=self._icon_image, text=""
                )
                icon_label.grid(row=0, column=0, rowspan=2, padx=(0, 14))
            except Exception:
                pass

        customtkinter.CTkLabel(
            header,
            text="A new version of Phoenix\nis available!",
            font=customtkinter.CTkFont(size=16, weight="bold"),
            justify="left",
            anchor="w",
        ).grid(row=0, column=1, sticky="sw")

        customtkinter.CTkLabel(
            header,
            text=(
                f"Phoenix {new_version} is now available "
                f"(you have {current_version})."
            ),
            font=customtkinter.CTkFont(size=13),
            justify="left",
            anchor="w",
        ).grid(row=1, column=1, sticky="nw", pady=(2, 0))

        # --- Release notes ---
        customtkinter.CTkLabel(
            self,
            text="Release Notes:",
            font=customtkinter.CTkFont(size=13, weight="bold"),
            anchor="w",
        ).grid(row=1, column=0, padx=24, pady=(14, 4), sticky="w")

        self._notes_box = customtkinter.CTkTextbox(
            self, height=180, font=customtkinter.CTkFont(size=13),
            activate_scrollbars=True,
        )
        self._notes_box.grid(row=2, column=0, padx=24, sticky="ew")
        self._notes_box.insert("1.0", self._html_to_text(release_notes_html))
        self._notes_box.configure(state="disabled")

        # --- Bottom area (buttons / progress) ---
        self._bottom = customtkinter.CTkFrame(self, fg_color="transparent")
        self._bottom.grid(row=3, column=0, padx=24, pady=(16, 20), sticky="ew")

        self._show_prompt_buttons()
        self.after(10, self._center_window)

    # ------------------------------------------------------------------
    # States
    # ------------------------------------------------------------------

    def _show_prompt_buttons(self):
        """PROMPT state: Install / Remind Me Later / Skip This Version."""
        self._clear_bottom()
        self._bottom.grid_columnconfigure(0, weight=1)
        self._bottom.grid_columnconfigure(1, weight=0)
        self._bottom.grid_columnconfigure(2, weight=0)

        customtkinter.CTkButton(
            self._bottom,
            text="Skip This Version",
            fg_color="transparent",
            border_width=1,
            width=130,
            command=self._handle_skip,
        ).grid(row=0, column=0, sticky="w")

        customtkinter.CTkButton(
            self._bottom,
            text="Remind Me Later",
            fg_color="transparent",
            border_width=1,
            width=130,
            command=self._handle_remind_later,
        ).grid(row=0, column=1, padx=(8, 8))

        customtkinter.CTkButton(
            self._bottom,
            text="Install Update",
            width=130,
            command=self._handle_install,
        ).grid(row=0, column=2, sticky="e")

    def _show_downloading(self):
        """DOWNLOADING state: progress bar + cancel."""
        self._clear_bottom()
        self._cancelled = False
        self._bottom.grid_columnconfigure(0, weight=1)
        self._bottom.grid_columnconfigure(1, weight=0)

        progress_frame = customtkinter.CTkFrame(
            self._bottom, fg_color="transparent"
        )
        progress_frame.grid(row=0, column=0, sticky="ew", padx=(0, 12))
        progress_frame.grid_columnconfigure(0, weight=1)

        self._progress_bar = customtkinter.CTkProgressBar(progress_frame)
        self._progress_bar.grid(row=0, column=0, sticky="ew")
        self._progress_bar.set(0)

        self._progress_label = customtkinter.CTkLabel(
            progress_frame,
            text="Downloading... 0%",
            font=customtkinter.CTkFont(size=12),
            anchor="w",
        )
        self._progress_label.grid(row=1, column=0, sticky="w", pady=(4, 0))

        customtkinter.CTkButton(
            self._bottom,
            text="Cancel",
            fg_color="transparent",
            border_width=1,
            width=80,
            command=self._handle_cancel,
        ).grid(row=0, column=1, sticky="e")

    def show_restart_prompt(self):
        """READY state: update downloaded, offer restart."""
        self._clear_bottom()
        self._bottom.grid_columnconfigure(0, weight=1)
        self._bottom.grid_columnconfigure(1, weight=0)

        customtkinter.CTkLabel(
            self._bottom,
            text="Update installed. Restart to complete.",
            font=customtkinter.CTkFont(size=13),
            anchor="w",
        ).grid(row=0, column=0, sticky="w")

        btn_frame = customtkinter.CTkFrame(
            self._bottom, fg_color="transparent"
        )
        btn_frame.grid(row=1, column=0, columnspan=2, sticky="e", pady=(10, 0))

        customtkinter.CTkButton(
            btn_frame,
            text="Later",
            fg_color="transparent",
            border_width=1,
            width=80,
            command=self.destroy,
        ).grid(row=0, column=0, padx=(0, 8))

        customtkinter.CTkButton(
            btn_frame,
            text="Restart Now",
            width=120,
            command=self._handle_restart,
        ).grid(row=0, column=1)

    def show_error(self, message: str, on_retry: Optional[Callable] = None):
        """ERROR state: display error with optional retry."""
        self._clear_bottom()
        self._bottom.grid_columnconfigure(0, weight=1)

        customtkinter.CTkLabel(
            self._bottom,
            text=message,
            font=customtkinter.CTkFont(size=12),
            text_color="#DC3545",
            wraplength=440,
            anchor="w",
            justify="left",
        ).grid(row=0, column=0, sticky="w")

        btn_frame = customtkinter.CTkFrame(
            self._bottom, fg_color="transparent"
        )
        btn_frame.grid(row=1, column=0, sticky="e", pady=(10, 0))

        if on_retry:
            customtkinter.CTkButton(
                btn_frame,
                text="Retry",
                width=80,
                command=on_retry,
            ).grid(row=0, column=0, padx=(0, 8))

        customtkinter.CTkButton(
            btn_frame,
            text="Dismiss",
            fg_color="transparent",
            border_width=1,
            width=80,
            command=self.destroy,
        ).grid(row=0, column=1)

    def set_download_progress(self, fraction: float, status_text: str = ""):
        """Update the progress bar (0.0 – 1.0) and status label."""
        if not hasattr(self, "_progress_bar"):
            return
        try:
            self._progress_bar.set(fraction)
            if status_text:
                self._progress_label.configure(text=status_text)
            else:
                pct = int(fraction * 100)
                self._progress_label.configure(text=f"Downloading... {pct}%")
        except Exception:
            pass

    @property
    def cancelled(self) -> bool:
        return self._cancelled

    # ------------------------------------------------------------------
    # Button handlers
    # ------------------------------------------------------------------

    def _handle_install(self):
        self._show_downloading()
        self._on_install()

    def _handle_skip(self):
        self._on_skip(self._new_version)
        self.destroy()

    def _handle_remind_later(self):
        self._on_remind_later()
        self.destroy()

    def _handle_cancel(self):
        self._cancelled = True
        self._show_prompt_buttons()

    def _handle_restart(self):
        if self._on_restart:
            self._on_restart()

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _clear_bottom(self):
        for child in self._bottom.winfo_children():
            child.destroy()

    def _center_window(self):
        self.update_idletasks()
        w = self.winfo_width()
        h = self.winfo_height()
        x = (self.winfo_screenwidth() // 2) - (w // 2)
        y = (self.winfo_screenheight() // 2) - (h // 2)
        self.geometry(f"{w}x{h}+{x}+{y}")

    @staticmethod
    def _find_icon() -> Optional[str]:
        """Locate the app icon relative to the project root."""
        here = os.path.dirname(os.path.abspath(__file__))
        project_root = os.path.dirname(here)
        path = os.path.join(project_root, "resources", "icons", "app_icon.png")
        if os.path.isfile(path):
            return path
        return None

    @staticmethod
    def _html_to_text(html: str) -> str:
        """Convert HTML release notes to plain text."""
        try:
            import html2text
            h = html2text.HTML2Text()
            h.ignore_links = False
            h.body_width = 70
            return h.handle(html).strip()
        except ImportError:
            # Fallback: strip tags naively
            import re
            text = re.sub(r"<[^>]+>", "", html)
            return text.strip()
