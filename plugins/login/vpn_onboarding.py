# -*- coding: utf-8 -*-
# @file plugins/login/vpn_onboarding.py
# Description: VPN onboarding screen shown after first signup on macOS.
# Guides users through system extension approval for seamless VPN setup.

# Author: Resistine Team
# Copyright: Resistine (c) 2025
# Licensed under the GNU General Public License v2 or later

import os
import platform
import subprocess

import customtkinter
from PIL import Image

from utils import settings
from utils.logger import logger


SUPPORTED_PLATFORMS = {"Darwin", "Linux", "Windows"}

class VPNOnboardingScreen:
    """
    Full-screen onboarding wizard shown after first signup on macOS.
    Guides the user through approving the system extension so VPN works seamlessly.

    3 steps:
      1. Welcome — explain what's needed, "Enable VPN" button
      2. Guidance — step-by-step instructions, poll for approval
      3. Success — confirmed, auto-navigate to VPN page
    """

    def __init__(self, app, on_complete_callback):
        """
        Args:
            app: The main App (CTk) instance.
            on_complete_callback: Called when onboarding finishes or is skipped.
        """
        self.app = app
        self.on_complete = on_complete_callback
        self._polling_id = None
        self._activator_ref = None
        self.platform = platform.system()
        self.is_macos = self.platform == "Darwin"
        self.is_supported = self.platform in SUPPORTED_PLATFORMS
        self.onboarding_frame = None

    def show(self):
        """Create and display the onboarding screen."""
        self.onboarding_frame = customtkinter.CTkFrame(
            self.app, corner_radius=0, fg_color=self.app.cget("fg_color")
        )
        self.onboarding_frame.grid(row=0, column=0, sticky="nsew")
        self.app.grid_rowconfigure(0, weight=1)
        self.app.grid_columnconfigure(0, weight=1)
        self.onboarding_frame.lift()

        if not self.is_supported:
            logger.warning(f"Unsupported platform: {self.platform}")
            self._build_unsupported_platform()
            return

        # Check if extension is already approved
        if self._check_extension_status():
            self._build_step_3_success()
        else:
            self._build_step_1_welcome()

    def destroy(self):
        """Clean up: cancel polling, destroy frame."""
        if self._polling_id:
            self.app.after_cancel(self._polling_id)
            self._polling_id = None
        if self.onboarding_frame:
            self.onboarding_frame.destroy()
            self.onboarding_frame = None

    def _build_unsupported_platform(self):
        """Log a warning and skip onboarding on unsupported platforms."""
        logger.error(f"VPN onboarding not available on {self.platform}")
        self._skip_onboarding()

    # ── Step 1: Welcome ─────────────────────────────────────────────

    def _build_step_1_welcome(self):
        """Build the welcome/explanation screen."""
        self._clear_content()

        container = self._create_centered_container()

        # Shield logo
        self._add_shield_logo(container, row=0)

        # Title
        customtkinter.CTkLabel(
            container,
            text="Almost there! Enable VPN Protection",
            font=customtkinter.CTkFont(family="Inter", size=20, weight="bold"),
            text_color=("#333333", "#FFFFFF"),
        ).grid(row=1, column=0, pady=(0, 15))

        # Subtitle
        if self.is_macos:
            subtitle = (
                "To secure your connection, Phoenix needs to install\n"
                "a system network extension. This is a one-time setup\n"
                "that requires your approval in System Settings."
            )
        else:
            subtitle = (
                "To secure your connection, Phoenix uses WireGuard.\n"
                "Click below to verify your system is ready."
            )

        customtkinter.CTkLabel(
            container,
            text=subtitle,
            font=customtkinter.CTkFont(family="Inter", size=14),
            text_color=("#666666", "#AAAAAA"),
            justify="center",
        ).grid(row=2, column=0, pady=(0, 30))

        # Enable VPN button
        customtkinter.CTkButton(
            container,
            text="Enable VPN",
            command=self._on_enable_clicked,
            width=400,
            height=45,
            corner_radius=22,
            fg_color="#0D5394",
            hover_color="#0A4275",
            font=customtkinter.CTkFont(family="Inter", size=16, weight="bold"),
        ).grid(row=3, column=0, pady=(0, 20))

        # Skip link
        customtkinter.CTkButton(
            container,
            text="Skip for now",
            fg_color="transparent",
            hover_color=("gray90", "gray20"),
            text_color=("#0D5394", "#3a7ebf"),
            font=customtkinter.CTkFont(family="Inter", size=13),
            command=self._skip_onboarding,
        ).grid(row=4, column=0, pady=(0, 10))

    # ── Step 2: Guidance / Waiting ──────────────────────────────────

    def _on_enable_clicked(self):
        """Triggered by Enable VPN button. Activates extension and shows guidance."""
        if self.is_macos:
            try:
                from plugins.vpn.wireguard.vpn_functions_darwin import VPNHelper
                VPNHelper.activate_extension()
                logger.info("System extension activation requested")
            except Exception as e:
                logger.error(f"Failed to trigger extension activation: {e}")

        self._build_step_2_guidance()
        self._start_polling()

    def _build_step_2_guidance(self):
        """Build the guidance screen with instructions and polling."""
        self._clear_content()

        container = self._create_centered_container()

        # Smaller shield logo
        self._add_shield_logo(container, row=0, size=80)

        # Title
        customtkinter.CTkLabel(
            container,
            text="Approve the System Extension",
            font=customtkinter.CTkFont(family="Inter", size=18, weight="bold"),
            text_color=("#333333", "#FFFFFF"),
        ).grid(row=1, column=0, pady=(0, 20))

        # Instructions frame
        instructions_frame = customtkinter.CTkFrame(
            container,
            corner_radius=12,
            fg_color=("#F5F5F5", "#1E1E1E"),
            border_width=1,
            border_color=("#E0E0E0", "#333333"),
        )
        instructions_frame.grid(row=2, column=0, pady=(0, 20), sticky="ew")
        instructions_frame.grid_columnconfigure(0, weight=1)

        if self.is_macos:
            mac_major = int(platform.mac_ver()[0].split(".")[0] or "0")
            if mac_major >= 15:
                setting_path = "General > Login Items & Extensions\n    then select Network Extensions"
            else:
                setting_path = "Privacy & Security\n    scroll to Security and click Allow"
            steps = [
                ("1", "A macOS dialog will appear.\n    Click \"Open System Settings\""),
                ("2", f"Go to {setting_path}"),
                ("3", "Enable the Resistine extension\n    and click Allow"),
            ]
        else:
            steps = [
                ("1", "Ensure WireGuard tools are installed:\n    sudo apt install wireguard-tools"),
                ("2", "The VPN will use wg-quick to manage\n    your connection"),
                ("3", "You may be prompted for your password\n    when connecting"),
            ]

        for i, (num, text) in enumerate(steps):
            step_frame = customtkinter.CTkFrame(instructions_frame, fg_color="transparent")
            step_frame.grid(row=i, column=0, padx=20, pady=(15 if i == 0 else 5, 15 if i == len(steps) - 1 else 5), sticky="w")

            customtkinter.CTkLabel(
                step_frame,
                text=num,
                width=28,
                height=28,
                corner_radius=14,
                fg_color="#0D5394",
                text_color="#FFFFFF",
                font=customtkinter.CTkFont(family="Inter", size=13, weight="bold"),
            ).pack(side="left", padx=(0, 12))

            customtkinter.CTkLabel(
                step_frame,
                text=text,
                font=customtkinter.CTkFont(family="Inter", size=13),
                text_color=("#444444", "#CCCCCC"),
                justify="left",
            ).pack(side="left")

        # Progress bar (indeterminate)
        self._progress_bar = customtkinter.CTkProgressBar(
            container, width=400, mode="indeterminate"
        )
        self._progress_bar.grid(row=3, column=0, pady=(0, 8))
        self._progress_bar.start()

        # Status label
        self._status_label = customtkinter.CTkLabel(
            container,
            text="Waiting for approval...",
            font=customtkinter.CTkFont(family="Inter", size=12),
            text_color=("#888888", "#888888"),
        )
        self._status_label.grid(row=4, column=0, pady=(0, 20))

        # Open System Settings button (macOS only)
        if self.is_macos:
            customtkinter.CTkButton(
                container,
                text="Open System Settings",
                command=self._open_system_settings,
                width=400,
                height=45,
                corner_radius=22,
                fg_color="#0D5394",
                hover_color="#0A4275",
                font=customtkinter.CTkFont(family="Inter", size=14, weight="bold"),
            ).grid(row=5, column=0, pady=(0, 15))

        # Skip link
        customtkinter.CTkButton(
            container,
            text="Skip for now",
            fg_color="transparent",
            hover_color=("gray90", "gray20"),
            text_color=("#0D5394", "#3a7ebf"),
            font=customtkinter.CTkFont(family="Inter", size=13),
            command=self._skip_onboarding,
        ).grid(row=6, column=0, pady=(0, 10))

    # ── Step 3: Success ─────────────────────────────────────────────

    def _build_step_3_success(self):
        """Build the success screen."""
        self._clear_content()

        container = self._create_centered_container()

        # Shield logo
        self._add_shield_logo(container, row=0)

        # Success title
        customtkinter.CTkLabel(
            container,
            text="VPN Protection Enabled!",
            font=customtkinter.CTkFont(family="Inter", size=22, weight="bold"),
            text_color=("#1E8E3E", "#2CC985"),
        ).grid(row=1, column=0, pady=(0, 15))

        # Subtitle
        customtkinter.CTkLabel(
            container,
            text="Your connection is now ready to be secured\nwith Phoenix VPN.",
            font=customtkinter.CTkFont(family="Inter", size=14),
            text_color=("#666666", "#AAAAAA"),
            justify="center",
        ).grid(row=2, column=0, pady=(0, 30))

        # Continue button
        customtkinter.CTkButton(
            container,
            text="Continue",
            command=self._finish_onboarding,
            width=400,
            height=45,
            corner_radius=22,
            fg_color="#1E8E3E",
            hover_color="#177B33",
            font=customtkinter.CTkFont(family="Inter", size=16, weight="bold"),
        ).grid(row=3, column=0, pady=(0, 20))

        # Auto-advance after 3 seconds
        self.app.after(3000, self._finish_onboarding)

    # ── Polling & Detection ─────────────────────────────────────────

    def _check_extension_status(self):
        """Check if the VPN system extension is approved and functional.

        On macOS, checks systemextensionsctl to verify the network extension
        is both activated AND enabled in Login Items & Extensions.
        A NETunnelProviderManager can exist in preferences even when the
        extension is disabled, so CLI status alone is not reliable.
        """
        if not self.is_macos:
            # On Linux, check if wireguard-tools are installed
            try:
                from plugins.vpn.wireguard.vpn_functions_linux import check_wireguard_installed
                return check_wireguard_installed()
            except ImportError:
                return True  # If we can't check, assume OK

        # macOS: check systemextensionsctl to verify the extension is
        # activated AND enabled (not just installed/disabled)
        try:
            from plugins.vpn.wireguard.vpn_functions_darwin import is_extension_enabled
            return is_extension_enabled()
        except Exception as e:
            logger.warning(f"Extension status check failed: {e}")
            return False

    def _start_polling(self):
        """Poll every 2 seconds for extension approval."""
        def poll():
            if self._check_extension_status():
                self._on_extension_approved()
            else:
                self._polling_id = self.app.after(2000, poll)

        # Initial delay of 3 seconds to let macOS show its dialog
        self._polling_id = self.app.after(3000, poll)

    def _on_extension_approved(self):
        """Called when polling detects the extension is approved."""
        if self._polling_id:
            self.app.after_cancel(self._polling_id)
            self._polling_id = None
        self._build_step_3_success()

    def _manual_check(self):
        """Manual status check triggered by the Check Status button."""
        if self._check_extension_status():
            self._on_extension_approved()
        else:
            if hasattr(self, "_status_label") and self._status_label.winfo_exists():
                self._status_label.configure(text="Not approved yet. Please follow the steps above.")
                self.app.after(3000, lambda: (
                    self._status_label.configure(text="Waiting for approval...")
                    if hasattr(self, "_status_label") and self._status_label.winfo_exists()
                    else None
                ))

    def _open_system_settings(self):
        """Open macOS System Settings to Login Items & Extensions."""
        try:
            subprocess.Popen([
                "open", "x-apple.systempreferences:com.apple.LoginItems-Settings.extension"
            ])
        except Exception as e:
            logger.error(f"Failed to open System Settings: {e}")

    # ── Completion ──────────────────────────────────────────────────

    def _finish_onboarding(self):
        """Mark onboarding complete and proceed to dashboard."""
        # Prevent double-fire from auto-advance + manual click
        if not self.onboarding_frame:
            return

        settings.set("vpn", "onboarding_complete", True)
        settings.set("auth", "logged_in", True)
        logger.info("VPN onboarding complete")

        self.destroy()

        if self.on_complete:
            self.on_complete()

    def _skip_onboarding(self):
        """User chose to skip. Mark complete so it doesn't show again."""
        settings.set("vpn", "onboarding_complete", True)
        settings.set("auth", "logged_in", True)
        logger.info("VPN onboarding skipped by user")

        self.destroy()

        if self.on_complete:
            self.on_complete()

    # ── UI Helpers ──────────────────────────────────────────────────

    def _clear_content(self):
        """Remove all children from the onboarding frame."""
        if self.onboarding_frame:
            for widget in self.onboarding_frame.winfo_children():
                widget.destroy()

    def _create_centered_container(self):
        """Create a vertically centered content container."""
        self.onboarding_frame.grid_rowconfigure(0, weight=1)
        self.onboarding_frame.grid_rowconfigure(1, weight=0)
        self.onboarding_frame.grid_rowconfigure(2, weight=1)
        self.onboarding_frame.grid_columnconfigure(0, weight=1)

        container = customtkinter.CTkFrame(
            self.onboarding_frame, corner_radius=0, fg_color="transparent"
        )
        container.grid(row=1, column=0, sticky="n")
        container.grid_columnconfigure(0, weight=1)
        return container

    def _add_shield_logo(self, parent, row=0, size=120):
        """Add the Phoenix logo to the container."""
        from utils.functions import get_resource_path
        shield_path = get_resource_path(os.path.join("resources", "icons", "PhoenixMark.png"))
        try:
            shield_img = Image.open(shield_path)
            shield_ctk = customtkinter.CTkImage(shield_img, size=(size, size))
            customtkinter.CTkLabel(
                parent, text="", image=shield_ctk
            ).grid(row=row, column=0, pady=(0, 25))
        except Exception as e:
            logger.warning(f"Shield logo load failed: {e}")
