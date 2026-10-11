## @file plugins/dashboard/main.py
## @package dashboard_plugin
## @namespace dashboard_plugin
## @class dashboard_plugin::Plugin

"""Dashboard plugin UI.

Header (product, signed-in account, website link), the protection banner, and
three status cards: Endpoint, AI assistant and System. Card values are
collected on a background thread and refreshed while the dashboard is shown.

Author: P3, Peres J. and the Resistine Team
Copyright (c) Resistine 2025
Licensed under the GNU General Public License v2 or later
"""

import importlib
import os
import threading
import webbrowser
from urllib.parse import urlparse

import customtkinter
from customtkinter import ThemeManager
from PIL import Image

from plugins.base_plugin import BasePlugin
from plugins.plugin_manager import PluginManager
from utils import branding, chat_endpoint, system_info
from utils import settings as app_settings
from utils.functions import get_resource_path
from utils.logger import logger

_REFRESH_MS = 30_000
_PENDING = "…"
_NONE = "—"
# Content width (logical px) below which the cards stack in one column.
_STACK_BELOW = 900

_FONT_TITLE = dict(family="Inter", size=26, weight="bold")
_FONT_CARD_TITLE = dict(family="Inter", size=17, weight="bold")
_FONT_LABEL = dict(family="Inter", size=13)
_FONT_VALUE = dict(family="Inter", size=13, weight="bold")
_COLOR_MUTED = ("#6B7280", "#9CA3AF")
_COLOR_LINK = ("#0D5394", "#3a7ebf")
_COLOR_CARD_BG = ("#FFFFFF", "#0F1A2E")
_COLOR_CARD_BORDER = ("#E5E7EB", "#1E2A44")
_COLOR_DIVIDER = ("#E5E7EB", "#1E2A44")

# Status pill colors: (background, text) as (light, dark) pairs.
_PILL = {
    "ok": (("#DCFCE7", "#0A2F1A"), ("#15803D", "#4ADE80")),
    "warn": (("#FEF3C7", "#2D1F05"), ("#B45309", "#FBBF24")),
    "error": (("#FEE2E2", "#3B0D0D"), ("#B91C1C", "#F87171")),
    "neutral": (("#F3F4F6", "#1F2937"), ("#4B5563", "#9CA3AF")),
}

_ENDPOINT_ROWS = ("Service", "Connection", "Agent name", "Group", "Manager", "Install")
_ASSISTANT_ROWS = ("Server", "Model", "Access", "Models", "Latency")
_SYSTEM_ROWS = ("Device", "System", "Kernel", "CPU", "Memory", "Disk",
                "Uptime", "Local IP", "VPN", branding.APP_NAME)


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
        self.status = self.get_status()
        self._cards = []
        self._value_labels = {}
        self._pills = {}
        self._refresh_id = None
        self._collecting = False
        self._resize_after_id = None
        self._resize_handler_id = None

    # -- helpers -------------------------------------------------------

    def _plugins(self):
        if not hasattr(self.app, "plugin_list") or not self.app.plugin_list:
            return PluginManager(self.app).plugins
        return self.app.plugin_list

    def _plugin(self, name):
        return next((p for p in self._plugins() if p.get_name() == name), None)

    def _vpn_ok(self):
        vpn = self._plugin("VPN")
        return bool(vpn and vpn.get_status() == "OK")

    def _widget_scale(self):
        """Physical→logical scale factor (winfo_width() is physical px)."""
        try:
            return customtkinter.ScalingTracker.get_widget_scaling(self.app)
        except Exception:
            return getattr(self.app, "_hidpi_factor", 1.0) or 1.0

    def _columns(self):
        """3 cards per row on wide windows, stacked otherwise."""
        scale = self._widget_scale()
        width = self.app.winfo_width()
        if width <= 1:
            width = int(1344 * scale)
        content_width = width / scale - 250 - 40
        return 1 if content_width < _STACK_BELOW else 3

    def _open(self, plugin):
        try:
            self.app.select_frame_by_name(
                f"frame_{plugin.get_name()}", button=plugin.get_button())
        except Exception:
            plugin.create_main_screen().grid(row=0, column=1, sticky="nsew")

    # -- build ---------------------------------------------------------

    def create_main_screen(self):
        self._stop_refresh()
        self.main_frame = customtkinter.CTkScrollableFrame(
            self.app, corner_radius=0, fg_color="transparent")
        self.main_frame.grid_columnconfigure(0, weight=1)

        self._build_header(self.main_frame).grid(
            row=0, column=0, sticky="ew", padx=20, pady=(16, 12))
        self._build_banner(self.main_frame).grid(
            row=1, column=0, sticky="ew", padx=20, pady=(0, 16))

        self._cards_frame = customtkinter.CTkFrame(
            self.main_frame, fg_color="transparent")
        self._cards_frame.grid(row=2, column=0, sticky="new", padx=20, pady=(0, 20))

        self._value_labels = {}
        self._pills = {}
        endpoint = self._plugin("Endpoint")
        chat = self._plugin("Chat")
        self._cards = [
            self._build_card("endpoint", "Endpoint", endpoint, _ENDPOINT_ROWS),
            self._build_card("assistant", "AI assistant", chat, _ASSISTANT_ROWS),
            self._build_card("system", "System", self, _SYSTEM_ROWS,
                             open_link=False, show_pill=False),
        ]
        self._layout_cards(self._columns())
        self._bind_responsive_resize()
        self._schedule_refresh(0)
        return self.main_frame

    def _build_header(self, parent):
        header = customtkinter.CTkFrame(parent, fg_color="transparent")
        header.grid_columnconfigure(1, weight=1)

        try:
            mark = Image.open(get_resource_path(
                os.path.join("resources", "icons", branding.LOGO_MARK)))
            customtkinter.CTkLabel(
                header, text="",
                image=customtkinter.CTkImage(mark, mark, size=(48, 48)),
            ).grid(row=0, column=0, rowspan=2, padx=(0, 14))
        except OSError as e:
            logger.warning(f"Dashboard logo load failed: {e}")

        customtkinter.CTkLabel(
            header, text=branding.APP_NAME,
            font=customtkinter.CTkFont(**_FONT_TITLE), anchor="w",
        ).grid(row=0, column=1, sticky="sw")

        logged_in = app_settings.get("auth", "logged_in", False)
        email = app_settings.get("auth", "email", "")
        account = customtkinter.CTkLabel(
            header,
            text=(f"Signed in as {email}" if logged_in and email
                  else "Not signed in — sign in"),
            font=customtkinter.CTkFont(family="Inter", size=13),
            text_color=_COLOR_MUTED if logged_in else _COLOR_LINK,
            anchor="w",
        )
        account.grid(row=1, column=1, sticky="nw")
        if not logged_in and hasattr(self.app, "show_login_screen"):
            account.configure(cursor="hand2")
            account.bind("<Button-1>", lambda _e: self._show_login())

        site = customtkinter.CTkLabel(
            header,
            text=f"{urlparse(branding.WEBSITE_URL).netloc} ↗",
            font=customtkinter.CTkFont(family="Inter", size=13, weight="bold"),
            text_color=_COLOR_LINK,
            cursor="hand2",
        )
        site.grid(row=0, column=2, rowspan=2, sticky="e")
        site.bind("<Button-1>", lambda _e: webbrowser.open(branding.WEBSITE_URL))
        return header

    def _show_login(self):
        # Full-window takeover; same path as the Settings "Log In" button.
        try:
            self.app.show_login_screen()
        except Exception as e:
            logger.error(f"Dashboard: could not open login: {e}")

    def _build_banner(self, parent):
        theme = ThemeManager.theme.get("Theme", {})
        if self._vpn_ok():
            bg = theme.get("protection_bg_ok", ["#DCFCE7", "#0A2F1A"])
            fg = theme.get("protection_text_ok", ["#15803D", "#4ADE80"])
            text = "✓  Protected"
        else:
            bg = theme.get("protection_bg_warn", ["#FEF3C7", "#2D1F05"])
            fg = theme.get("protection_text_warn", ["#B45309", "#FBBF24"])
            text = "⚠  Not Protected"
        banner = customtkinter.CTkFrame(parent, fg_color=bg, corner_radius=12, height=48)
        banner.grid_propagate(False)
        customtkinter.CTkLabel(
            banner, text=text, text_color=fg,
            font=customtkinter.CTkFont(family="Inter", size=15, weight="bold"),
        ).place(relx=0.5, rely=0.5, anchor="center")
        return banner

    def _build_card(self, key, title, plugin, rows, open_link=True, show_pill=True):
        card = customtkinter.CTkFrame(
            self._cards_frame, corner_radius=12, border_width=1,
            fg_color=_COLOR_CARD_BG, border_color=_COLOR_CARD_BORDER)
        card.grid_columnconfigure(0, weight=1)

        head = customtkinter.CTkFrame(card, fg_color="transparent")
        head.grid(row=0, column=0, sticky="ew", padx=18, pady=(16, 10))
        head.grid_columnconfigure(1, weight=1)

        icon = None
        if plugin is not None and plugin is not self:
            try:
                icon = plugin.get_icon()
            except Exception:
                icon = None
        customtkinter.CTkLabel(
            head, text=f"  {title}" if icon else title, image=icon, compound="left",
            font=customtkinter.CTkFont(**_FONT_CARD_TITLE), anchor="w",
        ).grid(row=0, column=0, sticky="w")

        if show_pill:
            pill = customtkinter.CTkLabel(
                head, text="", corner_radius=8, height=22,
                font=customtkinter.CTkFont(family="Inter", size=12, weight="bold"))
            pill.grid(row=0, column=2, padx=(8, 0))
            self._pills[key] = pill
            self._set_pill(key, _PENDING, "neutral")

        if open_link and plugin is not None:
            link = customtkinter.CTkLabel(
                head, text="Open", text_color=_COLOR_LINK, cursor="hand2",
                font=customtkinter.CTkFont(family="Inter", size=13, weight="bold"))
            link.grid(row=0, column=3, padx=(12, 0))
            link.bind("<Button-1>", lambda _e, p=plugin: self._open(p))

        customtkinter.CTkFrame(card, height=1, fg_color=_COLOR_DIVIDER).grid(
            row=1, column=0, sticky="ew", padx=18)

        body = customtkinter.CTkFrame(card, fg_color="transparent")
        body.grid(row=2, column=0, sticky="nsew", padx=18, pady=(10, 16))
        body.grid_columnconfigure(1, weight=1)
        for i, name in enumerate(rows):
            customtkinter.CTkLabel(
                body, text=name, text_color=_COLOR_MUTED, anchor="nw",
                font=customtkinter.CTkFont(**_FONT_LABEL),
            ).grid(row=i, column=0, sticky="nw", padx=(0, 18), pady=2)
            value = customtkinter.CTkLabel(
                body, text=_PENDING if plugin is not None else _NONE,
                anchor="nw", justify="left", wraplength=260,
                font=customtkinter.CTkFont(**_FONT_VALUE))
            value.grid(row=i, column=1, sticky="nw", pady=2)
            self._value_labels[(key, name)] = value

        if plugin is None:
            self._set_pill(key, "Not installed", "neutral")
        return card

    def _layout_cards(self, columns):
        self._current_cols = columns
        for i in range(3):
            self._cards_frame.grid_columnconfigure(
                i, weight=1 if i < columns else 0, uniform="cards" if i < columns else "")
        for i, card in enumerate(self._cards):
            card.grid_forget()
            card.grid(row=i // columns, column=i % columns, sticky="nsew",
                      padx=(0 if i % columns == 0 else 8, 0), pady=(0, 12))

    def _set_pill(self, key, text, kind):
        pill = self._pills.get(key)
        if pill is None:
            return
        bg, fg = _PILL[kind]
        try:
            pill.configure(text=f"  {text}  ", fg_color=bg, text_color=fg)
        except Exception:
            pass

    # -- data ----------------------------------------------------------

    def _alive(self):
        try:
            return self.main_frame.winfo_exists()
        except Exception:
            return False

    def _schedule_refresh(self, delay_ms=_REFRESH_MS):
        self._refresh_id = self.app.after(delay_ms, self._refresh)

    def _stop_refresh(self):
        if self._refresh_id is not None:
            try:
                self.app.after_cancel(self._refresh_id)
            except Exception:
                pass
            self._refresh_id = None

    def _refresh(self):
        self._refresh_id = None
        if not self._alive():
            return
        # Skip work while another screen is showing; keep the timer so the
        # cached dashboard is current again shortly after it is re-shown.
        if self.main_frame.winfo_ismapped() and not self._collecting:
            self._collecting = True
            context = self._collect_context()
            threading.Thread(
                target=self._collect, args=(context,), daemon=True).start()
        self._schedule_refresh()

    def _collect_context(self):
        """Values that must be read on the Tk thread."""
        chat = self._plugin("Chat")
        return {
            "has_endpoint": self._plugin("Endpoint") is not None,
            "has_chat": chat is not None,
            "model": getattr(chat, "model", None),
        }

    def _collect(self, context):
        data = {}
        try:
            if context["has_endpoint"]:
                data["endpoint"] = _endpoint_data()
            if context["has_chat"]:
                data["assistant"] = _assistant_data(context["model"])
            data["system"] = _system_data()
        except Exception as e:
            logger.error(f"Dashboard: collecting card data failed: {e}")
        try:
            self.app.after(0, self._apply, data)
        except Exception:
            self._collecting = False

    def _apply(self, data):
        self._collecting = False
        if not self._alive():
            return
        for key, (pill, values) in data.items():
            if pill[0] is not None:
                self._set_pill(key, *pill)
            for name, value in values.items():
                label = self._value_labels.get((key, name))
                if label is not None:
                    try:
                        label.configure(text=value or _NONE)
                    except Exception:
                        pass

    # -- caching / resize ----------------------------------------------

    def screen_signature(self):
        """Rebuild only when the banner, account or theme changes.

        Card values refresh in place, so they are not part of the signature.
        """
        try:
            return (
                "dashboard",
                customtkinter.get_appearance_mode(),
                self._vpn_ok(),
                app_settings.get("auth", "logged_in", False),
                app_settings.get("auth", "email", ""),
            )
        except Exception:
            return None

    def _bind_responsive_resize(self):
        """Re-grid the cards when the window crosses the stacking width."""
        def on_resize():
            self._resize_after_id = None
            if not self._alive():
                return
            columns = self._columns()
            if columns != getattr(self, "_current_cols", None):
                self._layout_cards(columns)

        def debounced(_event=None):
            if self._resize_after_id:
                self.app.after_cancel(self._resize_after_id)
            self._resize_after_id = self.app.after(250, on_resize)

        if self._resize_handler_id:
            try:
                self.app.unbind("<Configure>", self._resize_handler_id)
            except Exception:
                pass
        self._resize_handler_id = self.app.bind("<Configure>", debounced, add="+")

    def destroy(self):
        """Cleanup handler for uninstallation."""
        self._stop_refresh()
        if self._resize_after_id:
            try:
                self.app.after_cancel(self._resize_after_id)
            except Exception:
                pass
        if self._resize_handler_id:
            try:
                self.app.unbind("<Configure>", self._resize_handler_id)
            except Exception:
                pass
        super().destroy()


# -- card data (background thread; no Tk access) ---------------------------


def _endpoint_data():
    """Return ((pill_text, kind), {row: value}) for the Endpoint card."""
    import plugins.wazuh.main as wazuh
    from plugins.wazuh import config

    if not wazuh._platform_supported:
        return ("Unsupported", "neutral"), {}
    status = wazuh.get_agent_status()
    # The platform module wazuh.main imported its agent functions from.
    module = importlib.import_module(wazuh.get_agent_status.__module__)
    if hasattr(module, "get_install_info"):
        info = module.get_install_info()
    else:
        path = {"Darwin": config.WAZUH_INSTALL_DIR,
                "Windows": config.WINDOWS_WAZUH_DIR}.get(wazuh._PLATFORM)
        info = {"path": path if path and os.path.exists(path) else None,
                "system_managed": False}
    install = info["path"]
    if install and info["system_managed"]:
        install = f"{install} (system-managed)"
    kind = {"Running": "ok", "Stopped": "error"}.get(status, "warn")
    return (status, kind), {
        "Service": status,
        # No unprivileged "connected to manager" signal exists (the agent
        # state file is root-owned).
        "Connection": _NONE,
        "Agent name": wazuh.get_agent_name(),
        "Group": wazuh.get_agent_group(),
        "Manager": config.WAZUH_MANAGER,
        "Install": install,
    }


def _assistant_data(model):
    """Return ((pill_text, kind), {row: value}) for the AI assistant card."""
    vpn_on = _vpn_connected()
    try:
        from plugins.wazuh.main import is_agent_running

        agent_on = is_agent_running()
    except Exception:
        agent_on = False
    # Mirrors the chat access gate (VPN connected + endpoint agent running).
    if vpn_on and agent_on:
        access = "Unlocked (VPN + endpoint agent)"
    else:
        missing = [n for n, ok in (("VPN", vpn_on), ("endpoint agent", agent_on)) if not ok]
        access = f"Locked (needs {' + '.join(missing)})"

    if chat_endpoint.get_transport() == chat_endpoint.TRANSPORT_MATRIX:
        return ("Matrix", "neutral"), {
            "Server": chat_endpoint.get_assistant_mxid(),
            "Model": None, "Access": access, "Models": None, "Latency": None,
        }

    base_url = chat_endpoint.get_base_url()
    result = chat_endpoint.probe(
        base_url, app_settings.get_secret("chat", "openai_api_key"))
    parsed = urlparse(base_url)
    return (("Online", "ok") if result["online"] else ("Offline", "error")), {
        "Server": parsed.netloc or base_url,
        "Model": model,
        "Access": access,
        "Models": (f"{result['models']} available"
                   if result["models"] is not None else None),
        "Latency": (f"{result['latency_ms']} ms"
                    if result["latency_ms"] is not None else None),
    }


def _system_data():
    """Return ((pill_text, kind), {row: value}) for the System card."""
    try:
        from utils.updates.version import get_current_version

        version = get_current_version()
    except Exception:
        version = None
    return (None, None), {
        "Device": system_info.device_name(),
        "System": system_info.os_name(),
        "Kernel": system_info.kernel(),
        "CPU": system_info.cpu(),
        "Memory": system_info.format_usage(system_info.memory()),
        "Disk": system_info.format_usage(system_info.disk()),
        "Uptime": system_info.format_uptime(system_info.uptime_seconds()),
        "Local IP": system_info.local_ip(),
        "VPN": "On" if _vpn_connected() else "Off",
        branding.APP_NAME: version,
    }


def _vpn_connected():
    try:
        from plugins.vpn.main import is_vpn_connected

        return bool(is_vpn_connected())
    except Exception:
        return False
