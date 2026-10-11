## @file plugins/settings/main.py
## @package settings_plugin
## @namespace settings_plugin
## @class settings_plugin::Plugin

"""
This file contains the main plugin class for the Settings plugin.
The plugin allows users to configure their account settings.
Author: Peres J. and the Resistine Team
Copyright (c) Resistine 2025
Licensed under the GNU General Public License v2 or later
"""

import glob
import os
import re
import sys

import customtkinter

from plugins.base_plugin import BasePlugin
from utils import chat_endpoint
from utils import branding, settings
from utils.i18n import get_text
from utils.logger import logger

_TRANSPORT_LABELS = {
    chat_endpoint.TRANSPORT_OPENAI: "OpenAI API (HTTPS)",
    chat_endpoint.TRANSPORT_MATRIX: "Matrix (end-to-end encrypted)",
}
_MXID_RE = re.compile(r"^@[a-z0-9._=\-/+]+:[A-Za-z0-9.\-]+(:\d+)?$")


class Plugin(BasePlugin):
    """Settings plugin (API key + appearance mode)."""

    def __init__(self, app):
        super().__init__(
            id="010",
            version="2025.01.01",
            order=1020,
            name="Settings",
            status=None,
            description="This plugin allows you to configure your account settings.",
            supported_systems=["Windows", "Linux", "Mac"],
            translations={"US": "Settings", "ES": "Configuracion", "FR": "Paramètres"},
            icon_light_path=os.path.join(
                os.path.dirname(os.path.realpath(__file__)), "settings_light.png"
            ),
            icon_dark_path=os.path.join(
                os.path.dirname(os.path.realpath(__file__)), "settings_dark.png"
            ),
            uninstall_enabled=False,
        )
        self.app = app
        self.status = self.get_status()

    def _effective_appearance_mode(self) -> str:
        mode = customtkinter.get_appearance_mode()
        if mode != "System":
            return mode

        if sys.platform == "darwin":
            try:
                import subprocess

                result = subprocess.run(
                    ["defaults", "read", "-g", "AppleInterfaceStyle"],
                    capture_output=True,
                    text=True,
                )
                return (
                    "Dark"
                    if result.returncode == 0 and "Dark" in result.stdout
                    else "Light"
                )
            except Exception:
                return "Light"

        return "Light"

    def _apply_theme_refresh(self):
        # Prefer a lightweight refresh (no plugin re-instantiation)
        if hasattr(self.app, "refresh_ui_theme"):
            try:
                self.app.refresh_ui_theme()
                return
            except Exception as e:
                logger.error(f"Theme refresh failed: {e}")
                self.app.show_notification(f"Theme refresh failed: {e}", type="error")

        try:
            self.app.update_idletasks()
        except Exception:
            pass

    def create_main_screen(self):
        """Create a denser settings layout (UI_Dev-style cards) with less empty space."""
        from customtkinter import ThemeManager

        # Scrollable so it never leaves a big blank panel on tall windows
        self.frame_5 = customtkinter.CTkScrollableFrame(
            self.app,
            corner_radius=0,
            fg_color="transparent",
        )
        self.frame_5.grid_columnconfigure(0, weight=1)

        corner_radius = ThemeManager.theme.get("Theme", {}).get("corner_radius", 12)
        text_secondary = ThemeManager.theme.get("Theme", {}).get(
            "text_secondary", ["#6B7280", "#9CA3AF"]
        )
        divider_color = ThemeManager.theme.get("Theme", {}).get(
            "divider_color", ["#E5E7EB", "#2A2A2A"]
        )

        # ------------------------------------------------------------------ #
        #  Helper: section title with divider                                 #
        # ------------------------------------------------------------------ #
        def _section_title(parent, text, row):
            lbl = customtkinter.CTkLabel(
                parent,
                text=text,
                font=customtkinter.CTkFont(size=16, weight="bold"),
            )
            lbl.grid(row=row, column=0, padx=16, pady=(16, 0), sticky="w")
            div = customtkinter.CTkFrame(parent, height=1, fg_color=divider_color)
            div.grid(row=row + 1, column=0, padx=16, pady=(8, 12), sticky="ew")

        # --- Profile card ---
        profile_card = customtkinter.CTkFrame(self.frame_5, corner_radius=corner_radius)
        profile_card.grid(row=0, column=0, padx=20, pady=(16, 8), sticky="ew")
        profile_card.grid_columnconfigure(0, weight=1)

        _section_title(profile_card, "Profile", 0)

        logged_in = settings.get("auth", "logged_in", False)
        email = settings.get("auth", "email", None)
        email_label_text = f"Email: {email}" if email else "Not signed in"

        customtkinter.CTkLabel(
            profile_card,
            text=email_label_text,
            font=customtkinter.CTkFont(size=13),
            text_color=text_secondary,
        ).grid(row=2, column=0, padx=16, pady=(0, 10), sticky="w")

        # Load sign-out icon (only shown when logged in)
        signout_icon = None
        if logged_in:
            try:
                from PIL import Image
                plugin_dir = os.path.dirname(os.path.realpath(__file__))
                signout_light = Image.open(os.path.join(plugin_dir, "signout_light.png"))
                signout_dark = Image.open(os.path.join(plugin_dir, "signout_dark.png"))
                signout_icon = customtkinter.CTkImage(
                    light_image=signout_light, dark_image=signout_dark, size=(18, 18)
                )
            except Exception:
                pass

        # Button text/color/action mirrors auth state: logged in -> Log Out
        # (red, destructive); logged out -> Log In (primary blue, action).
        if logged_in:
            btn_text = "Log Out"
            btn_fg = "#DC3545"
            btn_hover = "#C82333"
            btn_command = self._handle_logout
            btn_image = signout_icon
        else:
            btn_text = "Log In"
            btn_fg = "#0D5394"
            btn_hover = "#0a4376"
            btn_command = self._handle_login
            btn_image = None

        self.logout_button = customtkinter.CTkButton(
            profile_card,
            text=btn_text,
            image=btn_image,
            compound="left",
            height=34,
            corner_radius=8,
            fg_color=btn_fg,
            hover_color=btn_hover,
            command=btn_command,
        )
        self.logout_button.grid(row=3, column=0, padx=16, pady=(0, 16), sticky="w")

        # --- API key card ---
        api_card = customtkinter.CTkFrame(self.frame_5, corner_radius=corner_radius)
        api_card.grid(row=1, column=0, padx=20, pady=8, sticky="ew")
        api_card.grid_columnconfigure(0, weight=1)

        _section_title(api_card, get_text("settings.apikey.label"), 0)

        # Transport selector: the OpenAI-compatible HTTPS API, or Matrix.
        customtkinter.CTkLabel(
            api_card,
            text="Chat transport",
            font=customtkinter.CTkFont(size=13),
            text_color=text_secondary,
        ).grid(row=2, column=0, padx=16, pady=(2, 4), sticky="w")

        self.transport_var = customtkinter.StringVar(
            value=_TRANSPORT_LABELS[chat_endpoint.get_transport()])
        customtkinter.CTkOptionMenu(
            api_card,
            values=list(_TRANSPORT_LABELS.values()),
            variable=self.transport_var,
            command=lambda _v: self._show_transport_fields(),
            height=36,
            corner_radius=8,
        ).grid(row=3, column=0, padx=16, pady=(0, 10), sticky="ew")

        # OpenAI fields
        self._openai_fields = customtkinter.CTkFrame(api_card, fg_color="transparent")
        self._openai_fields.grid_columnconfigure(0, weight=1)

        self.api_key_entry = customtkinter.CTkEntry(
            self._openai_fields,
            placeholder_text=get_text("settings.apikey.placeholder"),
            height=36,
            show="*",
        )
        self.api_key_entry.grid(row=0, column=0, padx=16, pady=(0, 10), sticky="ew")

        customtkinter.CTkLabel(
            self._openai_fields,
            text=get_text("settings.apibase.label"),
            font=customtkinter.CTkFont(size=13),
            text_color=text_secondary,
        ).grid(row=1, column=0, padx=16, pady=(2, 4), sticky="w")

        self.api_base_entry = customtkinter.CTkEntry(
            self._openai_fields,
            placeholder_text=get_text("settings.apibase.placeholder"),
            height=36,
        )
        self.api_base_entry.grid(row=2, column=0, padx=16, pady=(0, 10), sticky="ew")

        existing_key = settings.get_secret("chat", "openai_api_key")
        if existing_key:
            self.api_key_entry.insert(0, existing_key)
        self.api_base_entry.insert(0, chat_endpoint.get_base_url())

        # Matrix fields
        self._matrix_fields = customtkinter.CTkFrame(api_card, fg_color="transparent")
        self._matrix_fields.grid_columnconfigure(0, weight=1)

        customtkinter.CTkLabel(
            self._matrix_fields,
            text="Assistant Matrix ID",
            font=customtkinter.CTkFont(size=13),
            text_color=text_secondary,
        ).grid(row=0, column=0, padx=16, pady=(2, 4), sticky="w")

        self.assistant_mxid_entry = customtkinter.CTkEntry(
            self._matrix_fields,
            placeholder_text=branding.CHAT_DEFAULT_ASSISTANT_MXID,
            height=36,
        )
        self.assistant_mxid_entry.grid(row=1, column=0, padx=16, pady=(0, 6), sticky="ew")
        self.assistant_mxid_entry.insert(0, chat_endpoint.get_assistant_mxid())

        customtkinter.CTkLabel(
            self._matrix_fields,
            text=f"Uses your {branding.APP_NAME} account; "
                 "messages are end-to-end encrypted.",
            font=customtkinter.CTkFont(size=12),
            text_color=text_secondary,
        ).grid(row=2, column=0, padx=16, pady=(0, 6), sticky="w")

        self._show_transport_fields()

        # Disable Typing Animation Checkbox
        self.disable_animation_var = customtkinter.BooleanVar(
            value=settings.get("chat", "disable_animation", False)
        )
        self.disable_animation_checkbox = customtkinter.CTkCheckBox(
            api_card,
            text=get_text("settings.chat.disable_animation"),
            variable=self.disable_animation_var,
            onvalue=True,
            offvalue=False,
            command=self.save_animation_setting,
        )
        self.disable_animation_checkbox.grid(
            row=5, column=0, padx=16, pady=(0, 10), sticky="w"
        )

        btn_row = customtkinter.CTkFrame(api_card, fg_color="transparent")
        btn_row.grid(row=6, column=0, padx=16, pady=(0, 16), sticky="ew")
        btn_row.grid_columnconfigure(0, weight=0)
        btn_row.grid_columnconfigure(1, weight=1)

        self.save_key_button = customtkinter.CTkButton(
            btn_row,
            text=get_text("settings.apikey.save"),
            height=34,
            corner_radius=8,
            command=self.save_api_key,
        )
        self.save_key_button.grid(row=0, column=0, sticky="w")

        self.status_label = customtkinter.CTkLabel(
            btn_row,
            text="",
            font=customtkinter.CTkFont(size=12),
        )
        self.status_label.grid(row=0, column=1, padx=(12, 0), sticky="w")

        # --- Appearance card (System/Light/Dark only) ---
        appearance_card = customtkinter.CTkFrame(self.frame_5, corner_radius=corner_radius)
        appearance_card.grid(row=2, column=0, padx=20, pady=8, sticky="ew")
        appearance_card.grid_columnconfigure(0, weight=1)

        _section_title(appearance_card, "Appearance", 0)

        customtkinter.CTkLabel(
            appearance_card,
            text="Mode:",
            font=customtkinter.CTkFont(size=13),
            text_color=text_secondary,
        ).grid(row=2, column=0, padx=16, pady=(0, 4), sticky="w")

        self.appearance_mode_var = customtkinter.StringVar(
            value=customtkinter.get_appearance_mode()
        )
        appearance_menu = customtkinter.CTkOptionMenu(
            appearance_card,
            values=["System", "Light", "Dark"],
            variable=self.appearance_mode_var,
            command=self.change_appearance_mode,
            height=36,
            corner_radius=8,
        )
        appearance_menu.grid(row=3, column=0, padx=16, pady=(0, 16), sticky="ew")

        # --- Software Updates card ---
        updates_card = customtkinter.CTkFrame(self.frame_5, corner_radius=corner_radius)
        updates_card.grid(row=3, column=0, padx=20, pady=8, sticky="ew")
        updates_card.grid_columnconfigure(0, weight=1)

        _section_title(updates_card, "Software Updates", 0)

        customtkinter.CTkLabel(
            updates_card,
            text=f"Current version: {self._get_app_version()}",
            font=customtkinter.CTkFont(size=13),
            text_color=text_secondary,
        ).grid(row=2, column=0, padx=16, pady=(0, 8), sticky="w")

        self.update_status_label = customtkinter.CTkLabel(
            updates_card,
            text="",
            font=customtkinter.CTkFont(size=12),
        )

        check_btn = customtkinter.CTkButton(
            updates_card,
            text="Check for Updates",
            height=34,
            corner_radius=8,
            command=self._check_for_updates,
        )
        check_btn.grid(row=3, column=0, padx=16, pady=(0, 6), sticky="w")
        self.update_status_label.grid(row=4, column=0, padx=16, pady=(0, 16), sticky="w")

        # --- Uninstall card ---
        uninstall_card = customtkinter.CTkFrame(self.frame_5, corner_radius=corner_radius)
        uninstall_card.grid(row=4, column=0, padx=20, pady=(8, 20), sticky="ew")
        uninstall_card.grid_columnconfigure(0, weight=1)

        _section_title(uninstall_card, "Uninstall", 0)

        customtkinter.CTkLabel(
            uninstall_card,
            text="Permanently remove Phoenix and all associated data from this computer.",
            font=customtkinter.CTkFont(size=13),
            text_color=text_secondary,
            wraplength=500,
            justify="left",
        ).grid(row=2, column=0, padx=16, pady=(0, 8), sticky="w")

        self.uninstall_status_label = customtkinter.CTkLabel(
            uninstall_card,
            text="",
            font=customtkinter.CTkFont(size=12),
        )

        self.uninstall_button = customtkinter.CTkButton(
            uninstall_card,
            text="Uninstall Phoenix",
            height=34,
            corner_radius=8,
            fg_color="#DC3545",
            hover_color="#C82333",
            command=self._handle_uninstall,
        )
        self.uninstall_button.grid(row=3, column=0, padx=16, pady=(0, 6), sticky="w")
        self.uninstall_status_label.grid(row=4, column=0, padx=16, pady=(0, 16), sticky="w")

        return self.frame_5

    def save_animation_setting(self):
        """Save the disable animation setting."""
        disable = self.disable_animation_var.get()
        settings.set("chat", "disable_animation", disable)

    def _selected_transport(self) -> str:
        var = getattr(self, "transport_var", None)
        if var is None:  # card not built
            return chat_endpoint.TRANSPORT_OPENAI
        label = var.get()
        return next((k for k, v in _TRANSPORT_LABELS.items() if v == label),
                    chat_endpoint.TRANSPORT_OPENAI)

    def _show_transport_fields(self):
        """Show the field group for the selected transport."""
        if self._selected_transport() == chat_endpoint.TRANSPORT_MATRIX:
            self._openai_fields.grid_forget()
            self._matrix_fields.grid(row=4, column=0, sticky="ew")
        else:
            self._matrix_fields.grid_forget()
            self._openai_fields.grid(row=4, column=0, sticky="ew")

    def save_api_key(self):
        transport = self._selected_transport()
        if transport == chat_endpoint.TRANSPORT_MATRIX:
            mxid = self.assistant_mxid_entry.get().strip()
            if not _MXID_RE.match(mxid):
                self.status_label.configure(
                    text="Enter a Matrix ID like @secagent:phoenix.exposed",
                    text_color="red")
                return
            success_key = settings.set("chat", "assistant_mxid", mxid)
            success_base = settings.set("chat", "transport", transport)
        else:
            api_key = self.api_key_entry.get().strip()
            api_base = self.api_base_entry.get().strip()

            if not api_key and not api_base:
                return

            success_key = (
                settings.set_secret("chat", "openai_api_key", api_key)
                if api_key else True
            )
            # Always set/update base_url, even if empty (to allow clearing it)
            success_base = settings.set(
                "chat", "openai_base_url", api_base if api_base else None
            ) and settings.set("chat", "transport", transport)

        if success_key and success_base:
            self.status_label.configure(
                text=get_text("settings.apikey.saved_success"), text_color="green"
            )

            # Reinitialize the chat plugin's OpenAI client if it's loaded
            if hasattr(self.app, "plugin_list"):
                for plugin in self.app.plugin_list:
                    if plugin.get_name() == "Chat" and hasattr(
                        plugin, "reinitialize_client"
                    ):
                        plugin.reinitialize_client()
                        break

            self.app.after(2500, lambda: self.status_label.configure(text=""))
        else:
            self.status_label.configure(
                text=get_text("settings.apikey.saved_error"), text_color="red"
            )

    def _get_app_version(self):
        """Read the app version from Info.plist (macOS frozen) or Resistine.spec (source)."""
        try:
            if getattr(sys, "frozen", False):
                import plistlib

                contents_dir = os.path.dirname(os.path.dirname(sys.executable))
                plist_path = os.path.join(contents_dir, "Info.plist")
                if os.path.exists(plist_path):
                    with open(plist_path, "rb") as f:
                        info = plistlib.load(f)
                    return info.get("CFBundleShortVersionString", "1.0.0")
        except Exception:
            pass

        # Running from source (Linux, dev mode): read from spec file
        try:
            from utils.updates.version import get_current_version
            version = get_current_version()
            if version != "0.0.0":
                return version
        except Exception:
            pass

        return "1.0.0"

    def _check_for_updates(self):
        """Trigger an interactive update check via the cross-platform update manager.

        On macOS (Sparkle) and Windows (WinSparkle) the native library shows
        its own progress/result UI.  On Linux, the Python updater shows its
        own dialogs.  The status label below the button is a lightweight
        fallback for edge cases (updater unavailable, errors).
        """
        try:
            import webbrowser
            from utils import updates

            if not updates.is_available():
                self.update_status_label.configure(
                    text="Updates not available in this build", text_color="orange"
                )
                self.app.after(5000, lambda: self.update_status_label.configure(text=""))
                return

            self.update_status_label.configure(
                text="Checking for updates...", text_color="green"
            )

            result = updates.check_for_updates()

            if result == "error":
                self.update_status_label.configure(
                    text="Update check failed", text_color="red"
                )
            else:
                # Native Sparkle/WinSparkle UI handles "up to date" and
                # "update available" popups.  Clear the status label.
                self.app.after(3000, lambda: self.update_status_label.configure(text=""))
                return

            self.app.after(5000, lambda: self.update_status_label.configure(text=""))
        except Exception as e:
            logger.error(f"Update check error: {e}")
            self.update_status_label.configure(text=f"Error: {e}", text_color="red")
            self.app.after(5000, lambda: self.update_status_label.configure(text=""))

    def _handle_uninstall(self):
        """Handle the Uninstall button click with confirmation."""
        import tkinter.messagebox

        confirmed = tkinter.messagebox.askyesno(
            "Uninstall Phoenix",
            "Are you sure you want to completely uninstall Phoenix?\n\n"
            "This will remove all VPN configurations, application data, "
            "and the application itself.\n\n"
            "This action cannot be undone.",
        )
        if not confirmed:
            return

        self.uninstall_button.configure(state="disabled")
        self.uninstall_status_label.configure(text="Uninstalling...", text_color="orange")
        self.app.update_idletasks()

        try:
            from utils import uninstall

            def _progress(msg):
                self.uninstall_status_label.configure(text=msg)
                self.app.update_idletasks()

            success, message = uninstall.run_uninstall(self.app, progress_callback=_progress)

            if success:
                self.uninstall_status_label.configure(
                    text="Uninstalled. Closing…",
                    text_color=("#0D5394", "#60A5FA"))
                self.app.update_idletasks()
                try:
                    self.app.destroy()
                except Exception:
                    pass
                if sys.platform == 'darwin':
                    # macOS: keep the 0.3s deferred hard-exit so the Tk teardown
                    # finishes flushing.
                    import os as _os
                    import threading as _th
                    _th.Timer(0.3, lambda: _os._exit(0)).start()
                else:
                    # Windows/Linux: orderly shutdown so any spawned uninstaller
                    # process (Inno's unins000.exe on Windows) and WinSparkle
                    # finish cleanly. Their teardown is independent of ours.
                    try:
                        from utils import updates
                        updates.shutdown()
                    except Exception:
                        pass
                    sys.exit(0)
            else:
                self.uninstall_button.configure(state="normal")
                self.uninstall_status_label.configure(text=message, text_color="red")
        except Exception as e:
            logger.error(f"Uninstall error: {e}")
            self.uninstall_button.configure(state="normal")
            self.uninstall_status_label.configure(text=f"Error: {e}", text_color="red")

    def _handle_logout(self):
        """Handle the Log Out button click with confirmation."""
        # Without the Login plugin installed there's no way to sign back in,
        # so refuse the logout up-front rather than stranding the user on a
        # broken bootstrap path.
        login_installed = any(
            getattr(p, "id", None) == "007"
            for p in getattr(self.app, "plugin_list", []) or []
        )
        if not login_installed:
            self.app.show_notification(
                "Please install the Login plugin from the Store first.",
                type="warning",
                centered=True,
            )
            return

        import tkinter.messagebox

        confirmed = tkinter.messagebox.askyesno(
            "Log Out",
            "Are you sure you want to log out?\n\n"
            "This will sign you out and remove your VPN configurations, "
            "security agent enrollment, chat history, and account data from "
            "this device.\n\n"
            "An administrator password may be required to fully uninstall "
            "the Wazuh agent.\n\n"
            "You will need to sign in again to use Phoenix.",
        )
        if not confirmed:
            return

        # Disconnect VPN before clearing data
        self._disconnect_vpn()

        # Stop and uninstall the Wazuh agent, including its enrollment keys
        self._remove_wazuh_agent()

        # Clear all user-scoped data
        self._clear_user_data()

        # Tear down dashboard and show login screen
        try:
            self.app.show_login_screen()
        except Exception as e:
            logger.error(f"Failed to show login screen: {e}")
            self.app.show_notification(f"Logout failed: {e}", type="error")

    def _handle_login(self):
        """Bring up the full-screen login. No data is cleared — auth namespace
        was already clean (user is logged out / skipped). Guarded the same
        way as logout: if the Login plugin was uninstalled, ask the user to
        reinstall it before continuing.
        """
        login_installed = any(
            getattr(p, "id", None) == "007"
            for p in getattr(self.app, "plugin_list", []) or []
        )
        if not login_installed:
            self.app.show_notification(
                "Please install the Login plugin from the Store first.",
                type="warning",
                centered=True,
            )
            return
        try:
            self.app.show_login_screen()
        except Exception as e:
            logger.error(f"Failed to show login screen: {e}")
            self.app.show_notification(f"Could not open sign-in: {e}", type="error")

    def _disconnect_vpn(self):
        """Disconnect the VPN tunnel (platform-specific)."""
        import platform as plat

        try:
            system = plat.system()
            if system == "Darwin":
                from plugins.vpn.config_manager import VPNConfigManager
                from plugins.vpn.wireguard.vpn_functions_darwin import (
                    get_writable_wireguard_dir,
                    stop_vpn,
                )
                mgr = VPNConfigManager(get_writable_wireguard_dir())
                config_path = mgr.get_active_config_path()
                # The CLI's `stop` is interface-agnostic but the wrapper needs
                # a path to clear its interface cache; if no config is active
                # we still call the wrapper with a sentinel so the tunnel is
                # forcibly torn down.
                stop_vpn(config_path or "")
            elif system == "Windows":
                from plugins.vpn.wireguard.vpn_windows_client import disconnect
                disconnect("resistine")
            elif system == "Linux":
                from plugins.vpn.config_manager import VPNConfigManager
                from plugins.vpn.wireguard.vpn_functions_linux import (
                    get_writable_wireguard_dir,
                    stop_vpn,
                )
                mgr = VPNConfigManager(get_writable_wireguard_dir())
                config_path = mgr.get_active_config_path()
                if config_path:
                    stop_vpn(config_path)
        except Exception as e:
            logger.warning(f"VPN disconnect on logout failed: {e}")

    def _remove_wazuh_agent(self):
        """Stop and uninstall the Wazuh agent, wiping its enrollment keys.

        The platform ``remove_agent(wipe_keys=True)`` calls take care of:
        stopping the service, deleting the install directory, removing the
        client.keys backup file, and (on macOS) deleting the System Keychain
        entry. Failures are logged but do not block logout — the settings
        namespace will still be cleared so the UI no longer references the
        old enrollment.
        """
        import platform as plat

        try:
            system = plat.system()
            if system == "Darwin":
                from plugins.wazuh.agent.wazuh_functions_darwin import remove_agent
            elif system == "Windows":
                from plugins.wazuh.agent.wazuh_functions_windows import remove_agent
            elif system == "Linux":
                from plugins.wazuh.agent.wazuh_functions_linux import remove_agent
            else:
                logger.info(f"Wazuh removal unsupported on {system}")
                return

            if not remove_agent(wipe_keys=True):
                logger.warning(
                    "Wazuh agent removal reported failure; continuing logout",
                )
        except Exception as e:
            logger.warning(f"Wazuh agent removal on logout failed: {e}")

    def _clear_user_data(self):
        """Remove all user-scoped data, keeping device-scoped settings."""
        import platform as plat

        # Auth identity
        settings.clear_namespace("auth")

        # WireGuard keys — Darwin stores in "wireguard" namespace
        settings.delete("wireguard", "private_key")
        settings.delete("wireguard", "public_key")

        # VPN namespace: config registry, active config, onboarding state,
        # and Windows WireGuard keys (stored under "vpn")
        settings.clear_namespace("vpn")

        # VPN .conf files on disk
        try:
            system = plat.system()
            if system == "Darwin":
                from plugins.vpn.wireguard.vpn_functions_darwin import (
                    get_writable_wireguard_dir,
                )
            elif system == "Windows":
                from plugins.vpn.wireguard.vpn_functions_windows import (
                    get_writable_wireguard_dir,
                )
            else:
                from plugins.vpn.wireguard.vpn_functions_linux import (
                    get_writable_wireguard_dir,
                )
            wg_dir = get_writable_wireguard_dir()
            for conf in glob.glob(os.path.join(wg_dir, "*.conf")):
                try:
                    os.remove(conf)
                except OSError as e:
                    logger.warning(f"Failed to remove VPN config {conf}: {e}")
        except Exception as e:
            logger.warning(f"VPN config cleanup failed: {e}")

        # Chat history and API credentials
        settings.clear_namespace("chat_history")
        settings.delete("chat", "openai_api_key")
        settings.delete("chat", "openai_base_url")

        # Wazuh SIEM enrollment and installation state
        settings.clear_namespace("wazuh")

        # Legacy email file
        email_file_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(
                os.path.realpath(__file__),
            ))),
            "utils",
            "email-settings.txt",
        )
        if os.path.exists(email_file_path):
            try:
                os.remove(email_file_path)
            except Exception as e:
                logger.error(f"Failed to remove email settings: {e}")

    def change_appearance_mode(self, new_appearance_mode: str):
        try:
            customtkinter.set_appearance_mode(new_appearance_mode)
        finally:
            self._apply_theme_refresh()
