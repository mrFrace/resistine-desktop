## @file plugins/vpn/main.py
## @package vpn_plugin
## @namespace vpn_plugin
## @class vpn_plugin::Plugin
"""
This module contains the main plugin class for the VPN plugin.
The VPN plugin displays VPN information and allows the user to manage VPN tunnels.
Author: Javier Perez and Jacqueline Edoro 
Copyright (c) Resistine 2025
Licensed under the GNU General Public License v2 or later
"""

from plugins.base_plugin import BasePlugin
from utils.logger import logger
import customtkinter
import os
from tkinter import filedialog
import platform
import subprocess
import base64
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives import serialization
# --- Platform Detection (single source of truth) ---
_PLATFORM = platform.system()
IS_MACOS = _PLATFORM == "Darwin"
IS_WINDOWS = _PLATFORM == "Windows"
IS_LINUX = _PLATFORM == "Linux"

# Consolas is more compact and better hinted on Windows than Courier New
_MONO_FONT = "Consolas" if IS_WINDOWS else "Courier New"

# --- Platform Specific Imports ---
if IS_WINDOWS:
    from plugins.vpn.wireguard.vpn_functions_windows import (
        get_writable_wireguard_dir,
        check_wireguard_installed,
        check_service_status,
        start_vpn,
        stop_vpn,
    )
    from plugins.vpn.wireguard.vpn_windows_client import (
        get_status, connect, disconnect, toggle
    )
    wireguard_folder = get_writable_wireguard_dir()

elif IS_LINUX:
    from plugins.vpn.wireguard.vpn_functions_linux import *
    wireguard_folder = get_writable_wireguard_dir()

elif IS_MACOS:
    from plugins.vpn.wireguard.vpn_functions_darwin import *
    wireguard_folder = get_writable_wireguard_dir()

# DNS Configuration - Change this value to update DNS across the application
DNS_SERVER = "10.49.11.10"

# Global cache for interface mapping (e.g., config 'wg0' -> system 'utun3')
_interface_cache = {}
active_client_name = None
my_vpn_status = "Stopped"


def is_vpn_connected():
    """Return True if VPN is currently connected.

    Dev escape hatch (macOS only): when running ``./run.sh`` alongside an
    installed ``.pkg`` whose NetworkExtension already holds the tunnel up,
    this process's internal ``my_vpn_status`` stays ``"Stopped"`` because
    the dev instance never toggled the VPN itself — even though traffic is
    already routing through the system tunnel. Setting
    ``RESISTINE_DEV_VPN_CONNECTED=1`` forces this gate to True so
    VPN-gated features (e.g. the chat access gate, wazuh_overview API
    fetches) work in source mode without the dev instance needing to
    actually drive the tunnel.

    Gated on ``platform.system() == "Darwin"`` so Linux/Windows behavior
    is unchanged — those platforms have different VPN backends and the
    escape hatch is irrelevant there. ``run.sh`` only exports the env
    var on Darwin too, so this is defense in depth.
    """
    if (platform.system() == "Darwin"
            and os.environ.get("RESISTINE_DEV_VPN_CONNECTED") == "1"):
        return True
    return my_vpn_status == "Running"

# --- Config Manager (module-level for use in init) ---
from plugins.vpn.config_manager import VPNConfigManager
_config_manager = VPNConfigManager(wireguard_folder)
_config_manager.migrate_legacy_config()

# --- Initialization Logic ---
def initialize_vpn_status():
    global active_client_name, my_vpn_status, existing_interfaces

    existing_interfaces = []

    # First, check if WireGuard is actually installed
    if not check_wireguard_installed():
        logger.warning("⚠️ WireGuard not installed - VPN features disabled")
        my_vpn_status = "Stopped"
        return

    if IS_MACOS:
        # macOS uses Network Extension — wg show interfaces won't see the tunnel.
        # First verify the extension is actually enabled in Login Items & Extensions.
        # A stale NETunnelProviderManager can make the CLI report a false status.
        if not is_extension_enabled():
            logger.warning("Network extension is not enabled — VPN unavailable")
            my_vpn_status = "Stopped"
        else:
            # Extension is enabled, query actual connection status via CLI
            status = check_service_status("vpn", DNS_SERVER)
            if status == "Running":
                # Use config manager to determine the active config name
                active_name = _config_manager.get_active_config_name()
                if active_name:
                    active_client_name = active_name
                my_vpn_status = "Running"
            else:
                my_vpn_status = "Stopped"
    
    elif IS_WINDOWS:
        try:
            active_name = _config_manager.get_active_config_name()
            if active_name:
                state = check_service_status(active_name)
                if state == "Running":
                    active_client_name = active_name
                    my_vpn_status = "Running"
                else:
                    my_vpn_status = "Stopped"
            else:
                my_vpn_status = "Stopped"
        except Exception as e:
            logger.warning(f"⚠️ Could not determine VPN status on Windows: {e}")
            my_vpn_status = "Stopped"
    elif IS_LINUX:
        try:
            existing_interfaces = os.popen('wg show interfaces').read().split()
        except Exception as e:
            logger.warning(f"⚠️ Could not enumerate WireGuard interfaces: {e}")
            existing_interfaces = []

#? On Linux, we can check the status of each interface to find the active one. On Windows/macOS, we rely on service/extension status and config manager.
    if not IS_MACOS:
        # Check if any known interface is running (Linux/Windows only)
        for interface in existing_interfaces:
            if interface.strip():
                status = check_service_status(interface, DNS_SERVER)
                if status == "Running":
                    active_client_name = interface
                    break

        my_vpn_status = check_service_status(active_client_name, DNS_SERVER) if active_client_name else "Stopped"

    logger.info(f"VPN Status in Init: {my_vpn_status}")

# --- Helper Functions ---


def update_listbox_colors(listbox):
    if customtkinter.get_appearance_mode() == "Dark":
        listbox.config(fg="white", bg="#2e2e2e")
    else:
        listbox.config(fg="black", bg="lightgray")

# --- Run Init ---
initialize_vpn_status()


# --- Main Plugin Class ---

class Plugin(BasePlugin):
    """
    @brief Plugin class for the VPN plugin.
    """

    # The scrollbar auto-hide + content-column centering settle just after the
    # screen is built (the canvas reflows when the scrollbar toggles), which
    # would otherwise be a visible "shift right" after the page appears. Defer
    # the reveal until the layout goes quiescent so the page is shown already
    # settled.
    defer_reveal_until_settled = True

    def __init__(self, app):
        super().__init__(
            id="008",
            version="2025.01.01",
            order=3,
            name="VPN",
            status=None, # Default status
            description="VPN Management",
            supported_systems=["Windows", "Darwin", "Linux"],
            translations={"US": "VPN", "ES": "VPN", "FR": "VPN"},
            icon_light_path=os.path.join(os.path.dirname(os.path.realpath(__file__)), "vpn_light.png"),
            icon_dark_path=os.path.join(os.path.dirname(os.path.realpath(__file__)), "vpn_dark.png"),
        )
        self.app = app
        self.config_dir = wireguard_folder
        self.config_manager = _config_manager
        self.active_interface = None
        self._extension_poll_id = None
        self._windows_poll_id = None
        self._last_extension_state = None
        # Set status dynamically after super().__init__
        self.status = self.get_status()
        # Start background polling so my_vpn_status stays fresh at all times
        # (needed for both the VPN toggle page and the dashboard banner)
        if IS_WINDOWS:
            self.app.after(2000, self._start_windows_service_polling)
        elif IS_MACOS:
            # Request system extension activation after the main loop starts.
            # If the bundled extension is newer than the installed one, macOS
            # prompts for replacement — preventing stale-extension XPC failures.
            self.app.after(1000, self._activate_extension_if_needed)

    def _activate_extension_if_needed(self):
        """Request system extension activation (macOS only).

        Called once via app.after() so the NSRunLoop is running when the
        OSSystemExtensionRequest is submitted.  If the bundled extension
        matches the installed one, sysextd returns immediately (no dialog).
        """
        try:
            vpn_helper.activate_extension()
        except Exception as e:
            logger.warning(f"Extension activation request failed: {e}")

    def check_status(self):
        """Dynamic check of the VPN status."""
        if IS_MACOS and not is_extension_enabled():
            return "Error"
        if my_vpn_status == "Running":
            return "OK"
        elif my_vpn_status == "Connecting":
            return "Info"
        return "Warning"

    @staticmethod
    def validate_wireguard_config(content):
        """Validate that content is a well-formed WireGuard config.

        Checks for required [Interface] and [Peer] sections and their
        mandatory keys.  Returns (True, "") on success or (False, reason)
        on failure.
        """
        MAX_CONFIG_SIZE = 10_240  # 10 KB — more than enough for any config
        if len(content) > MAX_CONFIG_SIZE:
            return False, "File is too large to be a valid WireGuard config"

        lines = content.splitlines()
        sections = {}
        current_section = None
        for line in lines:
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if stripped.startswith("[") and stripped.endswith("]"):
                current_section = stripped[1:-1]
                sections.setdefault(current_section, set())
            elif "=" in stripped and current_section:
                key = stripped.split("=", 1)[0].strip()
                sections[current_section].add(key.lower())

        if "Interface" not in sections:
            return False, "Missing [Interface] section"
        if "Peer" not in sections:
            return False, "Missing [Peer] section"

        iface_keys = sections["Interface"]
        peer_keys = sections["Peer"]

        if "privatekey" not in iface_keys:
            return False, "Missing PrivateKey in [Interface]"
        if "address" not in iface_keys:
            return False, "Missing Address in [Interface]"
        if "publickey" not in peer_keys:
            return False, "Missing PublicKey in [Peer]"
        if "endpoint" not in peer_keys:
            return False, "Missing Endpoint in [Peer]"

        return True, ""

    def import_config(self):
        """Allows the user to import a WireGuard config file alongside existing configs."""
        global my_vpn_status, active_client_name

        file_path = filedialog.askopenfilename(
            title="Select WireGuard Config",
            filetypes=[("WireGuard Config", "*.conf"), ("All Files", "*.*")]
        )

        if not file_path:
            return

        try:
            with open(file_path, 'r') as src:
                content = src.read()

            valid, reason = self.validate_wireguard_config(content)
            if not valid:
                logger.warning(f"Invalid config rejected: {reason}")
                self.app.show_notification(f"Invalid config: {reason}", type="error")
                return

            # Stop VPN if running before switching to imported config
            if my_vpn_status == "Running" and active_client_name:
                #old_config_path = os.path.join(wireguard_folder, f"{active_client_name}.conf")
                #stop_vpn(old_config_path)
                stop_vpn(
                        active_client_name if IS_WINDOWS
                        else os.path.join(wireguard_folder, f"{active_client_name}.conf")
                    )
                my_vpn_status = "Stopped"
                active_client_name = None

            # Import via config manager (keeps existing configs)
            success, config_name = self.config_manager.import_config(file_path, content)
            if not success:
                self.app.show_notification(f"Failed to import: {config_name}", type="error")
                return

            # Set imported config as active
            self.config_manager.set_active_config(config_name)

            logger.info(f"Imported config: {config_name}")
            self.app.show_notification("Configuration imported successfully!", type="success")
            self.update_plugin(self.id)

        except Exception as e:
            logger.error(f"Failed to import config: {e}")
            self.app.show_notification(f"Failed to import config: {e}", type="error")

    def get_selected_conf_file_name(self):
        """Get the active VPN config name from the config manager."""
        global active_client_name

        # If VPN is running, return the running interface name
        if active_client_name and my_vpn_status == "Running":
            return active_client_name

        # Use config manager to get the active config
        return self.config_manager.get_active_config_name()

    def _get_client_public_key(self, private_key_b64):
        """Derive the WireGuard public key from a private key using pure Python."""
        try:
            # Decode the base64 private key
            private_bytes = base64.b64decode(private_key_b64)
            if len(private_bytes) != 32:
                # WireGuard keys are exactly 32 bytes (256 bits)
                return 'N/A'
                
            # Create private key object and get public bytes
            priv = X25519PrivateKey.from_private_bytes(private_bytes)
            pub_bytes = priv.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )
            
            # Re-encode to base64 for display
            return base64.b64encode(pub_bytes).decode('utf-8')
        except Exception as e:
            logger.warning(f"Could not compute client public key: {e}")
            return 'N/A'

    def get_system_info(self, tunnel_name):
        """Generates the system information dictionary for display."""
        global my_vpn_status
        data = self.get_configuration_values(tunnel_name) if tunnel_name else {}

        is_running = my_vpn_status == "Running"

        # Parse Endpoint for display
        endpoint = data.get('endpoint', 'N/A')
        if endpoint != 'N/A' and ':' in endpoint:
            endpoint = endpoint.split(':')[0]  # Just show IP/Host

        # Compute client public key from private key (never expose private key)
        private_key = data.get('private_key', '')
        client_public_key = self._get_client_public_key(private_key) if private_key else 'N/A'

        # DNS from config or module default
        dns = data.get('dns', DNS_SERVER)

        return {
            "Status": "Secured" if is_running else "Unsecured",
            "Config Name": tunnel_name if tunnel_name else "None",
            "System": f"{_PLATFORM} {platform.release()}",
            "Client IP": data.get('client_ip_address', 'N/A'),
            "Client Public Key": client_public_key,
            "Server IP": endpoint,
            "Server Public Key": data.get('public_key', 'N/A'),
            "DNS": dns,
        }

    def create_main_screen(self):
        """Create the main screen for the VPN plugin."""
        self._stop_extension_polling()
        return self.display_toggle_screen()

    def refresh_vpn_state(self):
        """Refresh VPN state from the Windows service."""
        global my_vpn_status, active_client_name

        if not IS_WINDOWS:
            return

        tunnel = self.get_selected_conf_file_name()
        if not tunnel:
            my_vpn_status = "Stopped"
            active_client_name = None
            return

        try:
            status = get_status(tunnel)
            my_vpn_status = status.get("state", "Stopped")
            active_client_name = tunnel if my_vpn_status == "Running" else None
        except Exception as e:
            logger.error(f"Status refresh failed: {e}")
            my_vpn_status = "Stopped"
            active_client_name = None

    def toggle_vpn_connection(self, switch_value):
        """Handles the toggle switch.
        
        Args:
            switch_value: 1 for ON, 0 for OFF
        """
        selected_conf_file = self.get_selected_conf_file_name()

        if not selected_conf_file:
            logger.error("❌ Cannot toggle: No VPN config found in wireguard directory.")
            self.app.show_notification("No VPN configuration found. Please log in or add a config.", type="error")
            # Reset switch to off if no config available
            if hasattr(self, 'vpn_toggle_switch'):
                self.vpn_toggle_switch.deselect()
            return

        # WINDOWS: use IPC service for connect/disconnect
        if IS_WINDOWS:
            # Always get fresh state from service before acting
            current = get_status(selected_conf_file)
            print(f"Current VPN status for '{selected_conf_file}': {current.get('state', 'Unknown')}")
            is_running = current.get("state") == "Running"

            if switch_value == 1 and not is_running:
                config_path = os.path.join(wireguard_folder, f"{selected_conf_file}.conf")
                result = connect(selected_conf_file, config_path=config_path)
                if result.get("status") != "ok" and result.get("state") not in ("Starting", "Running"):
                    logger.error(f"Connect failed: {result.get('message', '')}")
                    self.app.show_notification("Failed to connect VPN", type="error")
            elif switch_value == 0 and is_running:
                result = disconnect(selected_conf_file)
                if result.get("status") != "ok":
                    logger.error(f"Disconnect failed: {result.get('message', '')}")
                    self.app.show_notification("Failed to disconnect VPN", type="error")

            self.refresh_vpn_state()
            self.update_plugin(self.id)

        else:
            # Logic: 1 = ON Request, 0 = OFF Request
            is_running = my_vpn_status == "Running"
            if switch_value == 1 and not is_running:
                # User wants to turn VPN ON and it's currently OFF
                logger.info(f"🔄 Toggle ON: Starting VPN tunnel: {selected_conf_file}")
                self.activate_tunnel(selected_conf_file)

            elif switch_value == 0 and is_running:
                # User wants to turn VPN OFF and it's currently ON
                logger.info(f"🔄 Toggle OFF: Stopping VPN tunnel: {selected_conf_file}")
                self.activate_tunnel(selected_conf_file)

            else:
                # Edge case: Switch state doesn't match VPN state
                logger.warning(f"⚠️ Switch state ({switch_value}) doesn't match VPN state (Running: {is_running}). Refreshing UI...")
                self.update_plugin(self.id)

    def display_toggle_screen(self):
        """Display the redesigned VPN dashboard."""

        selected_conf_file = self.get_selected_conf_file_name()

        self.main_container = customtkinter.CTkFrame(self.app, corner_radius=0, fg_color="transparent")
        # Three-column layout: left-spacer | content | right-spacer
        # Equal-weight spacer columns auto-center the content column when the
        # window is wider than MAX_CONTENT_WIDTH; _do_layout sets col 1's minsize.
        self.main_container.grid_columnconfigure(0, weight=1)              # left spacer
        self.main_container.grid_columnconfigure(1, weight=0, minsize=100) # content (updated in _do_layout)
        self.main_container.grid_columnconfigure(2, weight=1)              # right spacer
        self.main_container.grid_rowconfigure(0, weight=1)

        scroll_frame = customtkinter.CTkScrollableFrame(
            self.main_container, 
            corner_radius=0, 
            fg_color="transparent"
        )
        scroll_frame.grid(row=0, column=1, sticky="nsew", pady=10)
        # Two equal columns — panels sit directly here; no wrapper frame needed
        scroll_frame.grid_columnconfigure(0, weight=1)
        scroll_frame.grid_columnconfigure(1, weight=1)

        global my_vpn_status

        # On Windows, always refresh state from the service
        if IS_WINDOWS:
            self.refresh_vpn_state()

        # On macOS, detect if the extension was disabled after onboarding
        extension_disabled = IS_MACOS and not is_extension_enabled()
        if extension_disabled and my_vpn_status == "Running":
            my_vpn_status = "Stopped"
            active_client_name = None

        is_connected = my_vpn_status == "Running"

        if extension_disabled:
            status_text  = "Extension Disabled"
            status_color = ("#C5221F", "#FF4040")
            mac_major = int(platform.mac_ver()[0].split(".")[0] or "0")
            if mac_major >= 15:
                sub_text = "Enable in System Settings › General › Login Items & Extensions › Network Extensions"
            else:
                sub_text = "Enable in System Settings › Privacy & Security › scroll to Security › click Allow"
            card_bg      = ("#FDEDEC", "#3A1A1A")
            is_enabled   = False
        elif not selected_conf_file:
            status_text  = "No Configuration"
            status_color = ("#666666", "#999999")
            sub_text     = "Please log in or import a VPN configuration to get started"
            card_bg      = ("#F5F5F5", "#1A1A1A")
            is_enabled   = False
        else:
            status_text  = "Connected" if is_connected else "Disconnected"
            status_color = ("#1B7A3E", "#2CC985") if is_connected else ("#C5221F", "#FF4040")
            sub_text     = "All traffic is encrypted and routed securely" if is_connected else "Your internet traffic is not protected"
            card_bg      = ("#E8F5E9", "#1A2E1F") if is_connected else ("#FDEDEC", "#2E1A1A")
            is_enabled   = True


        from customtkinter import ThemeManager
        cr = ThemeManager.theme.get("Theme", {}).get("corner_radius", 12)

        PANEL_BG     = ("#FFFFFF", "#141414")
        PANEL_BORDER = ("#E0E0E0", "#2A2A2A")
        LABEL_COLOR  = ("#888888", "#777777")
        VALUE_COLOR  = ("#111111", "#EEEEEE")
        ACCENT       = "#3A7EBF"

        next_row = 0

        # ── 1. STATUS CARD (spans both columns) ───────────────────────────
        status_card = customtkinter.CTkFrame(
            scroll_frame, corner_radius=cr, fg_color=card_bg, border_width=0
        )
        status_card.grid(row=next_row, column=0, columnspan=2, sticky="ew", pady=(10, 6))
        status_card.grid_columnconfigure(0, weight=1)
        next_row += 1

        text_col = customtkinter.CTkFrame(status_card, fg_color="transparent")
        text_col.grid(row=0, column=0, padx=22, pady=20, sticky="w")

        customtkinter.CTkLabel(
            text_col, text=status_text,
            font=customtkinter.CTkFont(family="Inter", size=28, weight="bold"),
            text_color=status_color
        ).grid(row=0, column=0, sticky="w")

        customtkinter.CTkLabel(
            text_col, text=sub_text,
            font=customtkinter.CTkFont(family="Inter", size=12),
            text_color=("#555555", "#AAAAAA"),
            wraplength=340, justify="left"
        ).grid(row=1, column=0, sticky="w", pady=(4, 0))

        self.vpn_toggle_switch = customtkinter.CTkSwitch(
            status_card, text="",
            command=lambda: self.toggle_vpn_connection(self.vpn_toggle_switch.get()),
            switch_width=56, switch_height=28,
            onvalue=1, offvalue=0,
            state="normal" if is_enabled else "disabled"
        )
        if is_connected and is_enabled:
            self.vpn_toggle_switch.select()
        else:
            self.vpn_toggle_switch.deselect()
        self.vpn_toggle_switch.grid(row=0, column=1, padx=22, pady=20)

        # ── 2. CONFIG SELECTOR (spans both columns) ────────────────────────
        configs = self.config_manager.list_configs()
        if len(configs) > 1:
            sel_frame = customtkinter.CTkFrame(
                scroll_frame, corner_radius=cr,
                fg_color=PANEL_BG, border_width=1, border_color=PANEL_BORDER
            )
            sel_frame.grid(row=next_row, column=0, columnspan=2, sticky="ew", pady=6)
            sel_frame.grid_columnconfigure(1, weight=1)
            next_row += 1

            customtkinter.CTkLabel(
                sel_frame, text="CONFIGURATION",
                font=customtkinter.CTkFont(size=12, weight="bold"),
                text_color=LABEL_COLOR
            ).grid(row=0, column=0, padx=(16, 8), pady=12, sticky="w")

            config_display_names = [c["display_name"] for c in configs]
            active_display = (
                self.config_manager.get_display_name(selected_conf_file)
                if selected_conf_file else (config_display_names[0] if config_display_names else "None")
            )
            self.config_selector = customtkinter.CTkOptionMenu(
                sel_frame, values=config_display_names,
                command=self._on_config_selected, height=34, corner_radius=8
            )
            self.config_selector.set(active_display)
            self.config_selector.grid(row=0, column=1, padx=8, pady=12, sticky="ew")

            if selected_conf_file and not self.config_manager.is_resistine_config(selected_conf_file):
                customtkinter.CTkButton(
                    sel_frame, text="Delete", width=70, height=34,
                    corner_radius=8, fg_color="#C5221F", hover_color="#A01B18",
                    command=lambda: self._delete_config(selected_conf_file)
                ).grid(row=0, column=2, padx=(0, 12), pady=12)

        # ── 3. DETAIL PANELS (only when config is available) ──────────────
        # Track references for the responsive resize handler
        client_panel      = None
        server_panel      = None
        post_panel_widgets = []   # full-width panels after the two-column section
        panel_row         = next_row

        if selected_conf_file:
            data     = self.get_configuration_values(selected_conf_file)
            sys_info = self.get_system_info(selected_conf_file)

            def _section_header(parent, row, title):
                customtkinter.CTkLabel(
                    parent, text=title,
                    font=customtkinter.CTkFont(family="Inter", size=12, weight="bold"),
                    text_color=ACCENT
                ).grid(row=row, column=0, columnspan=2, padx=14, pady=(14, 3), sticky="w")
                customtkinter.CTkFrame(
                    parent, height=1, fg_color=PANEL_BORDER
                ).grid(row=row + 1, column=0, columnspan=2, sticky="ew", padx=14, pady=(0, 8))
                return row + 2

            def _info_row(parent, row, label, value, mono=False, pady=5):
                customtkinter.CTkLabel(
                    parent, text=label,
                    font=customtkinter.CTkFont(size=13),
                    text_color=LABEL_COLOR, anchor="w"
                ).grid(row=row, column=0, padx=(14, 6), pady=pady, sticky="w")
                customtkinter.CTkLabel(
                    parent, text=value,
                    font=customtkinter.CTkFont(
                        family=_MONO_FONT if mono else "Inter",
                        size=13, weight="bold"
                    ),
                    text_color=VALUE_COLOR, anchor="e"
                ).grid(row=row, column=1, padx=(4, 14), pady=pady, sticky="ew")

            # Left — Client panel placed directly in scroll_frame column 0
            client_panel = customtkinter.CTkFrame(  # noqa: tracked for responsive layout
                scroll_frame, corner_radius=cr,
                fg_color=PANEL_BG, border_width=1, border_color=PANEL_BORDER
            )
            client_panel.grid(row=next_row, column=0, sticky="nsew", padx=(0, 4), pady=6)
            client_panel.grid_columnconfigure(0, weight=0)
            client_panel.grid_columnconfigure(1, weight=1, minsize=130)

            r = _section_header(client_panel, 0, "CLIENT")
            _info_row(client_panel, r, "IP Address", data.get('client_ip_address', 'N/A'), mono=True); r += 1
            _info_row(client_panel, r, "DNS",        sys_info.get("DNS", "N/A"),            mono=True); r += 1
            _info_row(client_panel, r, "System",     sys_info.get("System", "N/A"));                    r += 1
            _info_row(client_panel, r, "Status",     sys_info.get("Status", "N/A"), pady=(5, 14));       r += 1

            # Right — Server panel placed directly in scroll_frame column 1, same row
            server_panel = customtkinter.CTkFrame(  # noqa: tracked for responsive layout
                scroll_frame, corner_radius=cr,
                fg_color=PANEL_BG, border_width=1, border_color=PANEL_BORDER
            )
            server_panel.grid(row=next_row, column=1, sticky="nsew", padx=(4, 0), pady=6)
            server_panel.grid_columnconfigure(0, weight=0)
            server_panel.grid_columnconfigure(1, weight=1, minsize=130)
            next_row += 1  # Advance after both panels share this row

            r = _section_header(server_panel, 0, "SERVER / PEER")
            _info_row(server_panel, r, "IP Address",  sys_info.get("Server IP", "N/A"), mono=True); r += 1
            _info_row(server_panel, r, "Protocol",    "WireGuard");                                  r += 1
            _info_row(server_panel, r, "Config Name", sys_info.get("Config Name", "N/A"), pady=(5, 14)); r += 1

            # ── Public Keys (spans both columns) ──────────────────────────
            keys_panel = customtkinter.CTkFrame(
                scroll_frame, corner_radius=cr,
                fg_color=PANEL_BG, border_width=1, border_color=PANEL_BORDER
            )
            keys_panel.grid(row=next_row, column=0, columnspan=2, sticky="ew", pady=6)
            keys_panel.grid_columnconfigure(0, weight=0)
            keys_panel.grid_columnconfigure(1, weight=1, minsize=180)
            post_panel_widgets.append(keys_panel)
            next_row += 1

            kr = _section_header(keys_panel, 0, "PUBLIC KEYS")

            customtkinter.CTkLabel(
                keys_panel, text="Client",
                font=customtkinter.CTkFont(size=13), text_color=LABEL_COLOR, anchor="w"
            ).grid(row=kr, column=0, padx=(14, 10), pady=5, sticky="w")
            customtkinter.CTkLabel(
                keys_panel, text=sys_info.get("Client Public Key", "N/A"),
                font=customtkinter.CTkFont(family=_MONO_FONT, size=13, weight="bold"),
                text_color=VALUE_COLOR, anchor="e", wraplength=420, justify="right"
            ).grid(row=kr, column=1, padx=(4, 14), pady=(5, 14), sticky="ew")
            kr += 1

            customtkinter.CTkLabel(
                keys_panel, text="Server",
                font=customtkinter.CTkFont(size=13), text_color=LABEL_COLOR, anchor="w"
            ).grid(row=kr, column=0, padx=(14, 10), pady=(5, 14), sticky="w")
            customtkinter.CTkLabel(
                keys_panel, text=data.get('public_key', 'N/A'),
                font=customtkinter.CTkFont(family=_MONO_FONT, size=13, weight="bold"),
                text_color=VALUE_COLOR, anchor="e", wraplength=420, justify="right"
            ).grid(row=kr, column=1, padx=(4, 14), pady=(5, 14), sticky="ew")
            kr += 1

            # ── Allowed IPs (spans both columns) ──────────────────────────
            allowed_panel = customtkinter.CTkFrame(
                scroll_frame, corner_radius=cr,
                fg_color=PANEL_BG, border_width=1, border_color=PANEL_BORDER
            )
            allowed_panel.grid(row=next_row, column=0, columnspan=2, sticky="ew", pady=6)
            allowed_panel.grid_columnconfigure(0, weight=0)
            allowed_panel.grid_columnconfigure(1, weight=1, minsize=180)
            post_panel_widgets.append(allowed_panel)
            next_row += 1

            ar = _section_header(allowed_panel, 0, "ALLOWED IPs")
            customtkinter.CTkLabel(
                allowed_panel, text="Routes",
                font=customtkinter.CTkFont(size=13), text_color=LABEL_COLOR, anchor="w"
            ).grid(row=ar, column=0, padx=(14, 10), pady=5, sticky="w")
            customtkinter.CTkLabel(
                allowed_panel, text=data.get('allowed_ips', 'N/A'),
                font=customtkinter.CTkFont(family=_MONO_FONT, size=13, weight="bold"),
                text_color=VALUE_COLOR, anchor="e", wraplength=420, justify="right"
            ).grid(row=ar, column=1, padx=(4, 14), pady=(5, 14), sticky="ew")
            ar += 1

        # ── 4. ACTION BUTTONS (spans both columns) ────────────────────────
        buttons_frame = customtkinter.CTkFrame(scroll_frame, fg_color="transparent")
        buttons_frame.grid(row=next_row, column=0, columnspan=2, pady=(6, 20), sticky="ew")
        buttons_frame.grid_columnconfigure(0, weight=1)
        if selected_conf_file:
            buttons_frame.grid_columnconfigure(1, weight=1)

        customtkinter.CTkButton(
            buttons_frame, text="Import Configuration",
            command=self.import_config,
            fg_color="transparent", border_width=1,
            border_color=("#3A7EBF", "#1F538D"),
            text_color=("#3A7EBF", "#3A7EBF"),
            font=customtkinter.CTkFont(size=13), height=38
        ).grid(row=0, column=0, padx=(0, 4) if selected_conf_file else 0, sticky="ew")

        if selected_conf_file:
            customtkinter.CTkButton(
                buttons_frame, text="View Config",
                command=lambda: self._show_config_dialog(selected_conf_file),
                fg_color="transparent", border_width=1,
                border_color=("#3A7EBF", "#1F538D"),
                text_color=("#3A7EBF", "#3A7EBF"),
                font=customtkinter.CTkFont(size=13), height=38
            ).grid(row=0, column=1, padx=(4, 0), sticky="ew")

        # ── 5. RESPONSIVE LAYOUT + MAX-WIDTH CENTERING ────────────────────
        MAX_CONTENT_WIDTH = 750
        PANEL_BREAKPOINT  = 600   # content px below which panels stack vertically
        _stacked          = [False]
        _resize_job       = [None]

        def _do_layout():
            """Apply centering and responsive layout based on current app/sidebar widths."""
            _resize_job[0] = None

            # Safety check: if plugin updated/destroyed, main_container might be gone
            if not hasattr(self, 'main_container') or not self.main_container.winfo_exists():
                return
            
            # --- Auto-hide Scrollbar Logic ---
            try:
                if hasattr(scroll_frame, "_parent_canvas") and hasattr(scroll_frame, "_scrollbar"):
                    yview = scroll_frame._parent_canvas.yview()
                    
                    # Check if currently hidden (hacky check usually works if grid_remove used)
                    is_mapped = bool(scroll_frame._scrollbar.grid_info())
                    
                    # If content fits entirely (0.0 to 1.0)
                    if yview and (yview[0] <= 0.01 and yview[1] >= 0.99):
                        if is_mapped:
                            # Save grid info to restore later if needed, though grid() usually suffices 
                            # if grid_remove was used. To be safe with CTk internals:
                            scroll_frame._saved_sb_grid = scroll_frame._scrollbar.grid_info()
                            scroll_frame._scrollbar.grid_remove()
                    else:
                        if not is_mapped:
                             # Restore
                             if hasattr(scroll_frame, "_saved_sb_grid") and scroll_frame._saved_sb_grid:
                                 scroll_frame._scrollbar.grid(**scroll_frame._saved_sb_grid)
                             else:
                                 # Default fallback if we somehow didn't save it.
                                 # CTk's vertical CTkScrollableFrame grids the
                                 # scrollbar at row=1, column=1 (row 0 is the
                                 # label row). Using row=0 dropped a default
                                 # height=200 scrollbar into the empty label row,
                                 # creating a 200px gap that pushed the canvas
                                 # down and shrank it.
                                 scroll_frame._scrollbar.grid(row=1, column=1, sticky="ns", pady=0)
            except Exception:
                pass
            # --- End Auto-hide ---
            try:
                if not scroll_frame.winfo_exists():
                    return
            except Exception:
                return

            # Content area = total window width minus the fixed sidebar.
            # Using app.winfo_width() is reliable; main_container.winfo_width()
            # can be stale or wrong depending on when Configure fires.
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
                nav = getattr(self.app, 'navigation_frame', None)
                nav_w = (nav.winfo_width() / _scale) if (nav and nav.winfo_exists()) else 250
                nav_w = max(nav_w, 250)  # sidebar minsize is 250 logical
            except Exception:
                nav_w = 250
            width = app_w - nav_w  # logical
            if width < 10:
                return

            # — Max-width centering via column widths, not padx —
            # Column 1 (content) is set to the desired width.
            # Columns 0 and 2 (spacers, weight=1 each) absorb any surplus equally,
            # which automatically centers the content column in the available area.
            # Windows CTkScrollableFrame scrollbar takes more horizontal space than macOS
            _breathing = 60 if IS_WINDOWS else 40
            if width > MAX_CONTENT_WIDTH + 40:
                col_w = MAX_CONTENT_WIDTH
            else:
                col_w = max(100, width - _breathing)

            # Ensure main_container still exists and is valid
            if not hasattr(self, 'main_container') or not self.main_container.winfo_exists():
                return

            try:
                # grid_columnconfigure(minsize=) wants physical pixels — scale up.
                self.main_container.grid_columnconfigure(1, weight=0, minsize=int(col_w * _scale))
            except Exception:
                return

            # — Responsive panels (only when a config is loaded) —
            if client_panel is None or server_panel is None:
                return

            now_stacked = col_w < PANEL_BREAKPOINT

            if now_stacked == _stacked[0]:
                return   # nothing to change

            _stacked[0] = now_stacked
            n_post       = len(post_panel_widgets)

            if now_stacked:
                client_panel.grid_configure(row=panel_row,     column=0, columnspan=2, sticky="ew", padx=0)
                server_panel.grid_configure(row=panel_row + 1, column=0, columnspan=2, sticky="ew", padx=0)
                for i, panel in enumerate(post_panel_widgets):
                    panel.grid_configure(row=panel_row + 2 + i)
                buttons_frame.grid_configure(row=panel_row + 2 + n_post)
            else:
                client_panel.grid_configure(row=panel_row, column=0, columnspan=1, sticky="nsew", padx=(0, 4))
                server_panel.grid_configure(row=panel_row, column=1, columnspan=1, sticky="nsew", padx=(4, 0))
                for i, panel in enumerate(post_panel_widgets):
                    panel.grid_configure(row=panel_row + 1 + i)
                buttons_frame.grid_configure(row=panel_row + 1 + n_post)

        def _on_resize(event):
            # Debounce: cancel any pending layout job and schedule a fresh one.
            # after_idle runs after all pending events are processed, so winfo_width()
            # will reflect the final settled size rather than an intermediate value.
            if _resize_job[0] is not None:
                try:
                    self.app.after_cancel(_resize_job[0])
                except Exception:
                    pass
            _resize_job[0] = self.app.after_idle(_do_layout)

        self.main_container.bind("<Configure>", _on_resize)
        # Synchronous finalizer: _settle_screen() applies the initial centering
        # before reveal, so the content is correctly placed on first paint
        # instead of shifting ~50 ms later. (<Configure> handles genuine resizes.)
        self.main_container._resistine_finalize = _do_layout

        if IS_MACOS:
            self._start_extension_polling()

        return self.main_container

    def _on_config_selected(self, display_name):
        """Handle config dropdown selection."""
        global my_vpn_status, active_client_name

        configs = self.config_manager.list_configs()
        selected = next((c for c in configs if c["display_name"] == display_name), None)
        if not selected:
            return

        new_config_name = selected["name"]
        current_active = self.config_manager.get_active_config_name()

        if new_config_name == current_active:
            return

        # Stop VPN if running on the old config
        if my_vpn_status == "Running" and active_client_name:
            old_path = os.path.join(wireguard_folder, f"{active_client_name}.conf")
            stop_vpn(old_path if not IS_WINDOWS else active_client_name)
            my_vpn_status = "Stopped"
            active_client_name = None

        self.config_manager.set_active_config(new_config_name)
        self.app.show_notification(f"Switched to {display_name}", type="info")
        self.update_plugin(self.id)

    def _delete_config(self, config_name):
        """Delete a user-imported config."""
        global my_vpn_status, active_client_name

        # Stop VPN if running on this config
        if my_vpn_status == "Running" and active_client_name == config_name:
            config_path = os.path.join(wireguard_folder, f"{config_name}.conf")
            stop_vpn(config_path if not IS_WINDOWS else config_name)
            my_vpn_status = "Stopped"
            active_client_name = None

        success, message = self.config_manager.delete_config(config_name)
        if success:
            self.app.show_notification("Configuration deleted", type="info")
        else:
            self.app.show_notification(f"Failed to delete: {message}", type="error")

        self.update_plugin(self.id)

    def _show_config_dialog(self, tunnel_name):
        """Open a modal dialog showing the config file with a copy button."""
        conf_file_path = os.path.join(wireguard_folder, f"{tunnel_name}.conf")

        if not os.path.exists(conf_file_path):
            self.app.show_notification("Config file not found", type="error")
            return

        with open(conf_file_path, 'r', encoding='utf-8') as f:
            content = f.read()

        dialog = customtkinter.CTkToplevel(self.app)
        dialog.title(f"{tunnel_name}.conf")
        dialog.geometry("520x440")
        dialog.resizable(True, True)
        dialog.grab_set()
        dialog.grid_columnconfigure(0, weight=1)
        dialog.grid_rowconfigure(1, weight=1)

        title_label = customtkinter.CTkLabel(
            dialog,
            text=f"{tunnel_name}.conf",
            font=customtkinter.CTkFont(size=14, weight="bold")
        )
        title_label.grid(row=0, column=0, padx=20, pady=(15, 5), sticky="w")

        textbox = customtkinter.CTkTextbox(
            dialog,
            font=customtkinter.CTkFont(family="Courier", size=12),
            wrap="word",
            state="normal"
        )
        textbox.grid(row=1, column=0, padx=20, pady=5, sticky="nsew")
        textbox.insert("1.0", content)
        textbox.configure(state="disabled")

        def copy_to_clipboard():
            dialog.clipboard_clear()
            dialog.clipboard_append(content)
            copy_btn.configure(text="Copied!")
            dialog.after(2000, lambda: copy_btn.configure(text="Copy to Clipboard"))

        copy_btn = customtkinter.CTkButton(
            dialog,
            text="Copy to Clipboard",
            command=copy_to_clipboard,
            height=36
        )
        copy_btn.grid(row=2, column=0, padx=20, pady=(5, 20), sticky="ew")

    def _start_extension_polling(self):
        """Poll extension status every 5 seconds to detect enable/disable changes.
        macOS only — no-op on other platforms.
        """
        if not IS_MACOS:
            return
        self._stop_extension_polling()
        self._last_extension_state = is_extension_enabled()

        def poll():
            # Stop polling if the VPN page is no longer visible
            if not hasattr(self, 'main_container') or not self.main_container.winfo_exists():
                self._extension_poll_id = None
                return

            # 1. Check Extension State
            current_ext_state = is_extension_enabled()
            if current_ext_state != self._last_extension_state:
                logger.info(f"Extension state changed: {self._last_extension_state} -> {current_ext_state}")
                self._last_extension_state = current_ext_state
                self.update_plugin(self.id)
                return  # update_plugin rebuilds screen -> restarts polling

            # 2. Check Connection Status
            # We also poll the actual tunnel status to detect if it was turned off in System Settings
            global my_vpn_status, active_client_name
            current_status = check_service_status(active_client_name or "vpn", DNS_SERVER)
            if current_status != my_vpn_status:
                # We only care about sync if the app thinks it's Running but system says Stopped
                # Or if it was Stopped but now it's Running (e.g. turned on in Settings)
                # If status is "Connecting", we let the connection logic handle it.
                if my_vpn_status in ["Running", "Stopped"]:
                    logger.info(f"VPN Connection status changed externally: {my_vpn_status} -> {current_status}")
                    my_vpn_status = current_status
                    self.update_plugin(self.id)
                    return

            self._extension_poll_id = self.app.after(5000, poll)

        self._extension_poll_id = self.app.after(5000, poll)

    def _stop_extension_polling(self):
        """Cancel any active extension polling."""
        if self._extension_poll_id:
            self.app.after_cancel(self._extension_poll_id)
            self._extension_poll_id = None

    def _start_windows_service_polling(self):
        """Poll the Windows VPN service every 5 seconds to detect external state changes.

        Mirrors _start_extension_polling for macOS. Detects when the tray,
        another tool, or the service itself changes the VPN state.
        Runs regardless of which page is active so my_vpn_status stays fresh
        for both the VPN page toggle and the dashboard protection banner.
        """
        if not IS_WINDOWS:
            return
        self._stop_windows_service_polling()

        def poll():
            global my_vpn_status, active_client_name
            tunnel = self.get_selected_conf_file_name()
            if not tunnel:
                self._windows_poll_id = self.app.after(5000, poll)
                return

            try:
                result = get_status(tunnel)
                new_state = result.get("state", "Stopped")
            except Exception:
                self._windows_poll_id = self.app.after(5000, poll)
                return

            if new_state != my_vpn_status:
                logger.info(f"VPN state changed externally: {my_vpn_status} -> {new_state}")
                my_vpn_status = new_state
                active_client_name = tunnel if new_state == "Running" else None
                # Rebuild the VPN page if it's currently shown
                self.update_plugin(self.id)
                # Also refresh the dashboard if it's currently shown
                for p in self.app.plugin_list:
                    if p.get_name() == "Dashboard":
                        self.update_plugin(p.id)
                        break

            self._windows_poll_id = self.app.after(5000, poll)

        self._windows_poll_id = self.app.after(5000, poll)

    def _stop_windows_service_polling(self):
        """Cancel any active Windows service polling."""
        if self._windows_poll_id:
            self.app.after_cancel(self._windows_poll_id)
            self._windows_poll_id = None

    def update_plugin(self, plugin_id):
        """Reloads the plugin UI to reflect state changes, but only if it's the active tab."""
        for plugin in self.app.plugin_list:
            if plugin.id == plugin_id:
                # ONLY grid if we are actually currently viewing this scale
                # This prevents "flashing" when status updates happen in the background
                current = getattr(self.app, "current_frame_name", "")
                target = f"frame_{plugin.get_name()}"
                
                if current == target:
                    if hasattr(self, 'main_container'):
                        try: self.main_container.destroy()
                        except: pass
                    plugin.create_main_screen().grid(row=0, column=1, sticky="nsew")
                return    

    def get_configuration_values(self, tunnel_name):
        
        conf_file_path = os.path.join(wireguard_folder, f"{tunnel_name}.conf")
        logger.info(f"Reading configuration from: {conf_file_path}")    
        data = {}

        if os.path.exists(conf_file_path):
            with open(conf_file_path, 'r', encoding='utf-8') as conf_file:
                for line in conf_file:
                    if '=' in line:
                        key, value = line.split('=', 1)
                        key = key.strip().lower()
                        value = value.strip()
                        
                        if key == 'privatekey': data['private_key'] = value
                        elif key == 'address': data['client_ip_address'] = value
                        elif key == 'publickey': data['public_key'] = value
                        elif key == 'dns': data['dns'] = value
                        elif key == 'allowedips': data['allowed_ips'] = value
                        elif key == 'endpoint':
                            data['endpoint'] = value
                            if ':' in value: data['port'] = value.split(':')[-1]
        elif not os.path.exists(wireguard_folder):
            logger.error(f"WireGuard configuration directory does not exist: {wireguard_folder}")
        else:
            logger.error(f"Configuration file not found: {conf_file_path}") 
        return data

    def activate_tunnel(self, tunnel_name):
        """
        Activates/Deactivates VPN tunnel.
        Handles MacOS specifically via helper functions.
        """
        logger.info(f"Toggling VPN tunnel: {tunnel_name}")
        global my_vpn_status, active_client_name
        
        if not tunnel_name:
            logger.error("❌ No tunnel name provided")
            self.app.show_notification("No tunnel name provided", type="error")
            return

        config_path = os.path.join(wireguard_folder, f"{tunnel_name}.conf")

        # --- MacOS Implementation ---
        if IS_MACOS:
            logger.info(f"macOS: Toggling {tunnel_name}")

            if not is_extension_enabled():
                logger.error("Network extension is disabled in System Settings")
                mac_major = int(platform.mac_ver()[0].split(".")[0] or "0")
                if mac_major >= 15:
                    ext_path = "General > Login Items & Extensions > Network Extensions"
                else:
                    ext_path = "Privacy & Security > Security > click Allow"
                self.app.show_notification(
                    f"VPN extension is disabled. Enable it in System Settings > {ext_path}",
                    type="error",
                )
                my_vpn_status = "Stopped"
                active_client_name = None
                self.update_plugin(self.id)
                return

            if my_vpn_status == "Running":
                # STOP
                success = stop_vpn(config_path)
                if success:
                    my_vpn_status = "Stopped"
                    active_client_name = None
                    self.app.show_notification("VPN stopped", type="info")
                else:
                    logger.error("Failed to stop VPN")
                    self.app.show_notification("Failed to stop VPN", type="error")
            else:
                # START
                success = start_vpn(config_path)
                if success:
                    my_vpn_status = "Running"
                    active_client_name = tunnel_name
                    logger.info("✅ VPN started successfully")
                    self.app.show_notification("VPN started successfully", type="info")
                else:
                    logger.error("Failed to start VPN")
                    self.app.show_notification("Failed to start VPN", type="error")
            
            # Refresh UI
            self.update_plugin(self.id)

        # --- Linux Implementation ---
        elif IS_LINUX:
            logger.info(f"Linux: Toggling {tunnel_name}")
            
            if not check_wireguard_installed():
                logger.error("WireGuard tools not found.")
                self.app.show_notification("WireGuard tools not found", type="error")
                return

            if my_vpn_status == "Running":
                # STOP
                success = stop_vpn(config_path)
                if success:
                    my_vpn_status = "Stopped"
                    active_client_name = None
                    self.app.show_notification("VPN stopped", type="info")
                else:
                    logger.error("Failed to stop VPN")
                    self.app.show_notification("Failed to stop VPN", type="error")
            else:
                # START
                success = start_vpn(config_path)
                if success:
                    my_vpn_status = "Running"
                    active_client_name = tunnel_name
                    logger.info("✅ VPN started successfully")
                    self.app.show_notification("VPN started successfully", type="info")
                else:
                    logger.error("Failed to start VPN")
                    self.app.show_notification("Failed to start VPN", type="error")
            
            # Refresh UI
            self.update_plugin(self.id)