## @file plugins/vpn/main.py
## @package vpn_plugin
## @namespace vpn_plugin
## @class vpn_plugin::Plugin
"""VPN plugin (PyQt6) — faithful port of the CustomTkinter VPN screen.

Reproduces the original CTk dashboard 1:1: a status card with a sliding
toggle, a configuration selector (shown only when more than one config
exists) with a Delete button, CLIENT / SERVER detail panels, PUBLIC KEYS
and ALLOWED IPs panels, and the Import / View Config action buttons — all
inside a centered ~750 px content column. The platform connect/disconnect
backends are called, not rewritten; status is refreshed by a re-arming
``app.after(5000, ...)`` poll that runs the blocking status check on a
worker thread.

Author: Javier Perez and Jacqueline Edoro (original); Resistine Team (Qt port)
Copyright (c) Resistine 2025
Licensed under the GNU General Public License v2 or later
"""

from __future__ import annotations

import base64
import os
import platform
import subprocess
import threading

from PyQt6.QtCore import Qt
from PyQt6.QtGui import QGuiApplication
from PyQt6.QtWidgets import (
    QComboBox,
    QDialogButtonBox,
    QFileDialog,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QPlainTextEdit,
    QPushButton,
    QSizePolicy,
    QSpacerItem,
    QVBoxLayout,
    QWidget,
)
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from gui import theme
from gui.qt_widgets import ResponsiveStack, scroll_page
from plugins.base_plugin import BasePlugin
from utils.logger import logger

# --- Platform Detection (single source of truth) ---
_PLATFORM = platform.system()
IS_MACOS = _PLATFORM == "Darwin"
IS_WINDOWS = _PLATFORM == "Windows"
IS_LINUX = _PLATFORM == "Linux"

# Consolas is more compact and better hinted on Windows than Courier New
_MONO_FONT = "Consolas" if IS_WINDOWS else "Courier New"

# --- Platform Specific Imports (guarded so the module imports on any OS) ---
# Only the current platform's backend is loaded at top level; the import is
# wrapped so a missing/erroring platform module never blocks the GUI.
get_writable_wireguard_dir = None
check_wireguard_installed = None
check_service_status = None
start_vpn = None
stop_vpn = None
get_status = None
connect = None
disconnect = None
is_extension_enabled = None
vpn_helper = None

try:
    if IS_WINDOWS:
        from plugins.vpn.wireguard.vpn_functions_windows import (  # noqa: F401
            check_service_status,
            check_wireguard_installed,
            get_writable_wireguard_dir,
            start_vpn,
            stop_vpn,
        )
        from plugins.vpn.wireguard.vpn_windows_client import (  # noqa: F401
            connect,
            disconnect,
            get_status,
        )
    elif IS_LINUX:
        from plugins.vpn.wireguard.vpn_functions_linux import (  # noqa: F401
            check_service_status,
            check_wireguard_installed,
            get_writable_wireguard_dir,
            start_vpn,
            stop_vpn,
        )
    elif IS_MACOS:
        from plugins.vpn.wireguard.vpn_functions_darwin import (  # noqa: F401
            check_service_status,
            check_wireguard_installed,
            get_writable_wireguard_dir,
            is_extension_enabled,
            start_vpn,
            stop_vpn,
            vpn_helper,
        )
except Exception as _imp_err:  # pragma: no cover - depends on host OS
    logger.warning(f"VPN backend import failed on {_PLATFORM}: {_imp_err}")


def _resolve_wireguard_folder() -> str:
    """Resolve the writable WireGuard config dir (guarded)."""
    try:
        if get_writable_wireguard_dir is not None:
            return get_writable_wireguard_dir()
    except Exception as e:
        logger.warning(f"Could not resolve WireGuard dir: {e}")
    # Fallback so the plugin can still build on an unsupported host.
    return os.path.join(os.path.expanduser("~"), ".config", "phoenix", "wireguard")


wireguard_folder = _resolve_wireguard_folder()

# DNS Configuration - used as the connectivity-check target and as the DNS
# shown when a config has none. Override with RESISTINE_DNS_SERVER.
DNS_SERVER = os.environ.get("RESISTINE_DNS_SERVER", "10.49.11.10")

# Module-level state preserved from the original (wazuh imports is_vpn_connected).
active_client_name = None
my_vpn_status = "Stopped"


def _phoenix_signed_in() -> bool:
    """True when signed in with a Phoenix (MAS) account."""
    try:
        from plugins.login import oidc
        return oidc.has_session()
    except Exception:  # noqa: BLE001
        return False


def is_vpn_connected():
    """Return True if VPN is currently connected.

    Dev escape hatch (macOS only): when running from source alongside an
    installed .pkg whose NetworkExtension already holds the tunnel up, this
    process's internal ``my_vpn_status`` stays "Stopped" even though traffic
    routes through the system tunnel. RESISTINE_DEV_VPN_CONNECTED=1 forces
    the gate to True so VPN-gated features work in source mode.
    """
    if (platform.system() == "Darwin"
            and os.environ.get("RESISTINE_DEV_VPN_CONNECTED") == "1"):
        return True
    return my_vpn_status == "Running"


# --- Config Manager (module-level for use in init) ---
from plugins.vpn.config_manager import VPNConfigManager  # noqa: E402

_config_manager = VPNConfigManager(wireguard_folder)
try:
    _config_manager.migrate_legacy_config()
except Exception as e:
    logger.warning(f"Legacy VPN config migration failed: {e}")


def _safe_extension_enabled() -> bool:
    """is_extension_enabled() guarded; True on non-macOS / on error."""
    if not IS_MACOS or is_extension_enabled is None:
        return True
    try:
        return bool(is_extension_enabled())
    except Exception:
        return True


def _list_wg_interfaces() -> list[str]:
    """Return the WireGuard interfaces reported by ``wg show interfaces``.

    Returns [] if wg is not installed, fails (e.g. lacks privileges) or hangs.
    """
    try:
        result = subprocess.run(
            ["wg", "show", "interfaces"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except FileNotFoundError:
        logger.info("WireGuard 'wg' tool not found; assuming no active interfaces")
        return []
    except (subprocess.TimeoutExpired, OSError) as e:
        logger.warning(f"⚠️ Could not enumerate WireGuard interfaces: {e}")
        return []
    if result.returncode != 0:
        logger.warning(
            f"⚠️ 'wg show interfaces' failed ({result.returncode}): "
            f"{(result.stderr or '').strip()}"
        )
        return []
    return result.stdout.split()


def _conf_path(config_name: str) -> str:
    """Path of ``<config_name>.conf`` inside wireguard_folder.

    Raises ValueError for names that could escape the folder.
    """
    return _config_manager.config_path(config_name)


# --- Initialization Logic ---
def initialize_vpn_status():
    global active_client_name, my_vpn_status

    existing_interfaces = []

    # First, check if WireGuard is actually installed
    try:
        installed = check_wireguard_installed() if check_wireguard_installed else False
    except Exception:
        installed = False
    if not installed:
        logger.warning("⚠️ WireGuard not installed - VPN features disabled")
        my_vpn_status = "Stopped"
        return

    if IS_MACOS:
        if not _safe_extension_enabled():
            logger.warning("Network extension is not enabled — VPN unavailable")
            my_vpn_status = "Stopped"
        else:
            try:
                status = check_service_status("vpn", DNS_SERVER)
            except Exception:
                status = "Stopped"
            if status == "Running":
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
        existing_interfaces = _list_wg_interfaces()

    # On Linux/Windows, find the active interface by polling each known one.
    if not IS_MACOS:
        for interface in existing_interfaces:
            if interface.strip():
                try:
                    status = check_service_status(interface, DNS_SERVER)
                except Exception:
                    status = "Stopped"
                if status == "Running":
                    active_client_name = interface
                    break

        if active_client_name:
            try:
                my_vpn_status = check_service_status(active_client_name, DNS_SERVER)
            except Exception:
                my_vpn_status = "Stopped"
        else:
            my_vpn_status = "Stopped"

    logger.info(f"VPN Status in Init: {my_vpn_status}")


try:
    initialize_vpn_status()
except Exception as e:
    logger.warning(f"VPN status initialization failed: {e}")


# --- Theme colour helpers (mirror the original (light, dark) pairs) ---
def _pick(light: str, dark: str) -> str:
    return dark if theme.is_dark() else light


# --- Main Plugin Class ---


class Plugin(BasePlugin):
    """@brief Plugin class for the VPN plugin (PyQt6)."""

    defer_reveal_until_settled = True

    def __init__(self, app):
        super().__init__(
            id="008",
            version="2025.01.01",
            order=3,
            name="VPN",
            status=None,  # Default status
            description="Encrypt your traffic through the Phoenix network.",
            supported_systems=["Windows", "Darwin", "Linux"],
            translations={"US": "VPN", "ES": "VPN", "FR": "VPN"},
            icon_light_path=os.path.join(
                os.path.dirname(os.path.realpath(__file__)), "vpn_light.png"
            ),
            icon_dark_path=os.path.join(
                os.path.dirname(os.path.realpath(__file__)), "vpn_dark.png"
            ),
        )
        self.app = app
        self.config_dir = wireguard_folder
        self.config_manager = _config_manager
        self.active_interface = None
        self.vpn_toggle_switch = None
        self._poll_id = None
        self._toggle_busy = False
        self._last_polled_state = my_vpn_status
        # Set status dynamically after super().__init__
        self.status = self.get_status()

        if IS_MACOS:
            # Request extension activation once the Qt loop is running.
            self.app.after(1000, self._activate_extension_if_needed)
            # Debug-mode convenience: auto-connect the VPN so VPN-gated
            # features (chat) work without a manual toggle.
            # Scheduled after extension activation has had time to settle.
            if os.environ.get("RESISTINE_DEBUG") == "1":
                self.app.after(3000, self._debug_auto_connect)

    def _debug_auto_connect(self):
        """Auto-start the VPN on launch in debug mode (macOS dev flow).

        Skips silently when the tunnel is already up; skips with a log
        line when no config has been imported yet. activate_tunnel()
        itself handles the extension-disabled case with a notification.
        """
        if my_vpn_status == "Running":
            return
        tunnel = self.get_selected_conf_file_name()
        if not tunnel:
            logger.warning(
                "Debug auto-connect skipped: no VPN config found")
            return
        logger.info(f"Debug mode: auto-connecting VPN tunnel {tunnel}")
        self.activate_tunnel(tunnel)

    # ===================================================================
    #  Status
    # ===================================================================
    def _activate_extension_if_needed(self):
        """Request system extension activation (macOS only)."""
        try:
            if vpn_helper is not None:
                vpn_helper.activate_extension()
        except Exception as e:
            logger.warning(f"Extension activation request failed: {e}")

    def check_status(self):
        """Dynamic check of the VPN status from cheap cached state."""
        if IS_MACOS and not _safe_extension_enabled():
            return "Error"
        if my_vpn_status == "Running":
            return "OK"
        if my_vpn_status in ("Connecting", "Starting"):
            return "Info"
        return "Warning"

    def on_theme_changed(self):
        """Rebuild the VPN screen on theme toggle to re-evaluate the _pick() colours."""
        if getattr(self, "app", None):
            self.app.update_plugin(self.id)

    @staticmethod
    def validate_wireguard_config(content):
        """Validate that content is a well-formed WireGuard config.

        Returns (True, "") on success or (False, reason) on failure.
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

    # ===================================================================
    #  Config helpers
    # ===================================================================
    def import_config(self):
        """Import a WireGuard config file alongside existing configs."""
        global my_vpn_status, active_client_name

        file_path, _ = QFileDialog.getOpenFileName(
            None,  # no parent: a movable panel, not a fixed macOS sheet
            "Select WireGuard Config",
            "",
            "WireGuard Config (*.conf);;All Files (*.*)",
        )
        if not file_path:
            return

        try:
            with open(file_path, "r") as src:
                content = src.read()

            valid, reason = self.validate_wireguard_config(content)
            if not valid:
                logger.warning(f"Invalid config rejected: {reason}")
                self.app.show_notification(f"Invalid config: {reason}", type="error")
                return

            # Stop VPN if running before switching to imported config
            if my_vpn_status == "Running" and active_client_name:
                self._safe_stop(active_client_name)
                my_vpn_status = "Stopped"
                active_client_name = None

            success, config_name = self.config_manager.import_config(file_path, content)
            if not success:
                self.app.show_notification(
                    f"Failed to import: {config_name}", type="error"
                )
                return

            self.config_manager.set_active_config(config_name)

            logger.info(f"Imported config: {config_name}")
            self.app.show_notification(
                "Configuration imported successfully!", type="success"
            )
            self.update_plugin(self.id)

        except Exception as e:
            logger.error(f"Failed to import config: {e}")
            self.app.show_notification(f"Failed to import config: {e}", type="error")

    def get_selected_conf_file_name(self):
        """Get the active VPN config name from the config manager."""
        if active_client_name and my_vpn_status == "Running":
            return active_client_name
        try:
            return self.config_manager.get_active_config_name()
        except Exception as e:
            logger.warning(f"Could not resolve active config: {e}")
            return None

    def _get_client_public_key(self, private_key_b64):
        """Derive the WireGuard public key from a private key in pure Python."""
        try:
            private_bytes = base64.b64decode(private_key_b64)
            if len(private_bytes) != 32:
                return "N/A"
            priv = X25519PrivateKey.from_private_bytes(private_bytes)
            pub_bytes = priv.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
            return base64.b64encode(pub_bytes).decode("utf-8")
        except Exception as e:
            logger.warning(f"Could not compute client public key: {e}")
            return "N/A"

    def get_system_info(self, tunnel_name):
        """Generate the system information dictionary for display."""
        data = self.get_configuration_values(tunnel_name) if tunnel_name else {}

        is_running = my_vpn_status == "Running"

        endpoint = data.get("endpoint", "N/A")
        if endpoint != "N/A" and ":" in endpoint:
            endpoint = endpoint.split(":")[0]  # Just show IP/Host

        private_key = data.get("private_key", "")
        client_public_key = (
            self._get_client_public_key(private_key) if private_key else "N/A"
        )

        dns = data.get("dns", DNS_SERVER)

        return {
            "Status": "Secured" if is_running else "Unsecured",
            "Config Name": tunnel_name if tunnel_name else "None",
            "System": f"{_PLATFORM} {platform.release()}",
            "Client IP": data.get("client_ip_address", "N/A"),
            "Client Public Key": client_public_key,
            "Server IP": endpoint,
            "Server Public Key": data.get("public_key", "N/A"),
            "DNS": dns,
        }

    def get_configuration_values(self, tunnel_name):
        try:
            conf_file_path = _conf_path(tunnel_name)
        except ValueError as e:
            logger.error(f"Refusing to read config: {e}")
            return {}
        logger.info(f"Reading configuration from: {conf_file_path}")
        data = {}

        if os.path.exists(conf_file_path):
            with open(conf_file_path, "r", encoding="utf-8") as conf_file:
                for line in conf_file:
                    if "=" in line:
                        key, value = line.split("=", 1)
                        key = key.strip().lower()
                        value = value.strip()
                        if key == "privatekey":
                            data["private_key"] = value
                        elif key == "address":
                            data["client_ip_address"] = value
                        elif key == "publickey":
                            data["public_key"] = value
                        elif key == "dns":
                            data["dns"] = value
                        elif key == "allowedips":
                            data["allowed_ips"] = value
                        elif key == "endpoint":
                            data["endpoint"] = value
                            if ":" in value:
                                data["port"] = value.split(":")[-1]
        elif not os.path.exists(wireguard_folder):
            logger.error(
                f"WireGuard configuration directory does not exist: {wireguard_folder}"
            )
        else:
            logger.error(f"Configuration file not found: {conf_file_path}")
        return data

    # ===================================================================
    #  Main screen
    # ===================================================================
    def create_main_screen(self):
        """Create the main screen for the VPN plugin."""
        return self.display_toggle_screen()

    def display_toggle_screen(self):
        """Display the VPN dashboard (faithful Qt port of the CTk screen)."""
        global my_vpn_status, active_client_name

        selected_conf_file = self.get_selected_conf_file_name()

        # On Windows, refresh state from the service before painting.
        if IS_WINDOWS:
            self.refresh_vpn_state()
            selected_conf_file = self.get_selected_conf_file_name()

        # On macOS, detect if the extension was disabled after onboarding.
        extension_disabled = IS_MACOS and not _safe_extension_enabled()
        if extension_disabled and my_vpn_status == "Running":
            my_vpn_status = "Stopped"
            active_client_name = None

        is_connected = my_vpn_status == "Running"
        self._last_polled_state = my_vpn_status

        # ── Status copy + colours (mirror the original (light, dark) pairs) ──
        if extension_disabled:
            status_text = "Extension Disabled"
            status_color = _pick("#C5221F", "#FF4040")
            try:
                mac_major = int(platform.mac_ver()[0].split(".")[0] or "0")
            except Exception:
                mac_major = 0
            if mac_major >= 15:
                sub_text = (
                    "Enable in System Settings › General › Login Items & "
                    "Extensions › Network Extensions"
                )
            else:
                sub_text = (
                    "Enable in System Settings › Privacy & Security › scroll to "
                    "Security › click Allow"
                )
            card_bg = _pick("#FDEDEC", "#3A1A1A")
            is_enabled = False
        elif not selected_conf_file:
            status_text = "No Configuration"
            status_color = _pick("#666666", "#999999")
            sub_text = "Please log in or import a VPN configuration to get started"
            card_bg = _pick("#F5F5F5", "#1A1A1A")
            is_enabled = False
        else:
            status_text = "Connected" if is_connected else "Disconnected"
            status_color = (
                _pick("#1B7A3E", "#2CC985")
                if is_connected
                else _pick("#C5221F", "#FF4040")
            )
            sub_text = (
                "All traffic is encrypted and routed securely"
                if is_connected
                else "Your internet traffic is not protected"
            )
            card_bg = (
                _pick("#E8F5E9", "#1A2E1F")
                if is_connected
                else _pick("#FDEDEC", "#2E1A1A")
            )
            is_enabled = True

        # ── Content column (two equal columns, centered ~750 px) ──────────
        content = QWidget()
        grid = QGridLayout(content)
        grid.setContentsMargins(0, 10, 0, 20)
        grid.setHorizontalSpacing(8)
        grid.setVerticalSpacing(12)
        grid.setColumnStretch(0, 1)
        grid.setColumnStretch(1, 1)

        # Collected by _section_header for the equal-padding pass below.
        self._panel_spacers = []
        self._panel_grids = []

        row = 0

        # ── 1. STATUS CARD (spans both columns) ───────────────────────────
        status_card = QFrame()
        status_card.setObjectName("Surface")
        status_card.setStyleSheet(
            f"#Surface {{ background-color: {card_bg}; border: none; "
            f"border-radius: 12px; }}"
        )
        # Cap the banner height so leftover page height doesn't inflate it
        # into a sparse slab with the subtitle marooned at the bottom.
        status_card.setMaximumHeight(110)
        sc_lay = QHBoxLayout(status_card)
        sc_lay.setContentsMargins(22, 16, 22, 16)
        sc_lay.setSpacing(12)

        text_col = QVBoxLayout()
        text_col.setSpacing(4)
        title_lbl = QLabel(status_text)
        title_lbl.setStyleSheet(
            f"color: {status_color}; font-size: 28px; font-weight: 700; "
            f"background: transparent;"
        )
        text_col.addWidget(title_lbl)
        sub_lbl = QLabel(sub_text)
        sub_lbl.setWordWrap(True)
        sub_lbl.setMaximumWidth(360)
        sub_lbl.setStyleSheet(
            f"color: {_pick('#555555', '#AAAAAA')}; font-size: 12px; "
            f"background: transparent;"
        )
        text_col.addWidget(sub_lbl)
        sc_lay.addLayout(text_col, 1)

        from plugins.vpn.qt_toggle import ToggleSwitch

        self.vpn_toggle_switch = ToggleSwitch()
        self.vpn_toggle_switch.setEnabled(is_enabled)
        if is_connected and is_enabled:
            self.vpn_toggle_switch.select()
        else:
            self.vpn_toggle_switch.deselect()
        self.vpn_toggle_switch.clicked.connect(self._on_toggle_clicked)
        sc_lay.addWidget(
            self.vpn_toggle_switch, 0, Qt.AlignmentFlag.AlignVCenter
        )

        grid.addWidget(status_card, row, 0, 1, 2)
        row += 1

        # ── 2. CONFIG SELECTOR (spans both columns; only when >1 config) ──
        try:
            configs = self.config_manager.list_configs()
        except Exception:
            configs = []
        if len(configs) > 1:
            sel_card = QFrame()
            sel_card.setObjectName("Surface")
            sel_lay = QHBoxLayout(sel_card)
            sel_lay.setContentsMargins(16, 12, 12, 12)
            sel_lay.setSpacing(8)

            cfg_lbl = QLabel("CONFIGURATION")
            cfg_lbl.setStyleSheet(
                f"color: {_pick('#888888', '#777777')}; font-size: 12px; "
                f"font-weight: 700; background: transparent;"
            )
            sel_lay.addWidget(cfg_lbl)

            config_display_names = [c["display_name"] for c in configs]
            active_display = (
                self.config_manager.get_display_name(selected_conf_file)
                if selected_conf_file
                else (config_display_names[0] if config_display_names else "None")
            )
            self.config_selector = QComboBox()
            self.config_selector.addItems(config_display_names)
            idx = self.config_selector.findText(active_display)
            if idx >= 0:
                self.config_selector.setCurrentIndex(idx)
            self.config_selector.activated.connect(self._on_config_activated)
            sel_lay.addWidget(self.config_selector, 1)

            if selected_conf_file and not self.config_manager.is_resistine_config(
                selected_conf_file
            ):
                del_btn = QPushButton("Delete")
                del_btn.setObjectName("Danger")
                del_btn.setCursor(Qt.CursorShape.PointingHandCursor)
                del_btn.clicked.connect(
                    lambda: self._delete_config(selected_conf_file)
                )
                sel_lay.addWidget(del_btn)

            grid.addWidget(sel_card, row, 0, 1, 2)
            row += 1

        # ── 3. DETAIL PANELS (only when a config is available) ────────────
        if selected_conf_file:
            data = self.get_configuration_values(selected_conf_file)
            sys_info = self.get_system_info(selected_conf_file)

            # Left — CLIENT panel (column 0)
            client_panel, client_grid = self._panel()
            cr = self._section_header(client_panel, client_grid, 0, "CLIENT")
            cr = self._info_row(
                client_grid, cr, "IP Address",
                data.get("client_ip_address", "N/A"), mono=True,
            )
            cr = self._info_row(
                client_grid, cr, "DNS", sys_info.get("DNS", "N/A"), mono=True,
            )
            cr = self._info_row(
                client_grid, cr, "System", sys_info.get("System", "N/A"),
            )
            cr = self._info_row(
                client_grid, cr, "Status", sys_info.get("Status", "N/A"),
            )
            # Right — SERVER / PEER panel
            server_panel, server_grid = self._panel()
            sr = self._section_header(server_panel, server_grid, 0, "SERVER / PEER")
            sr = self._info_row(
                server_grid, sr, "IP Address",
                sys_info.get("Server IP", "N/A"), mono=True,
            )
            sr = self._info_row(server_grid, sr, "Protocol", "WireGuard")
            sr = self._info_row(
                server_grid, sr, "Config Name", sys_info.get("Config Name", "N/A"),
            )
            client_grid.setRowStretch(cr, 1)
            server_grid.setRowStretch(sr, 1)
            # Side-by-side on a wide window; stacked vertically when narrow so
            # neither panel compresses its rows into clipped text
            # ("10.11.128." / "Config Nam").
            grid.addWidget(
                ResponsiveStack(client_panel, server_panel, stretches=(1, 1)),
                row, 0, 1, 2)
            row += 1

            # ── PUBLIC KEYS (spans both columns) ──────────────────────────
            keys_panel, keys_grid = self._panel()
            kr = self._section_header(keys_panel, keys_grid, 0, "PUBLIC KEYS")
            kr = self._info_row(
                keys_grid, kr, "Client",
                sys_info.get("Client Public Key", "N/A"), mono=True, wrap=True,
            )
            kr = self._info_row(
                keys_grid, kr, "Server",
                data.get("public_key", "N/A"), mono=True, wrap=True,
            )
            keys_grid.setRowStretch(kr, 1)
            grid.addWidget(keys_panel, row, 0, 1, 2)
            row += 1

            # ── ALLOWED IPs (spans both columns) ──────────────────────────
            allowed_panel, allowed_grid = self._panel()
            ar = self._section_header(allowed_panel, allowed_grid, 0, "ALLOWED IPs")
            ar = self._info_row(
                allowed_grid, ar, "Routes",
                data.get("allowed_ips", "N/A"), mono=True, wrap=True,
            )
            allowed_grid.setRowStretch(ar, 1)
            grid.addWidget(allowed_panel, row, 0, 1, 2)
            row += 1

        # ── 4. ACTION BUTTONS (spans both columns) ────────────────────────
        buttons_row = QHBoxLayout()
        buttons_row.setSpacing(8)

        import_btn = QPushButton("Import Configuration")
        import_btn.setObjectName("SurfaceBtn")
        import_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        import_btn.setMinimumHeight(38)
        import_btn.clicked.connect(self.import_config)
        buttons_row.addWidget(import_btn, 1)

        if selected_conf_file:
            view_btn = QPushButton("View Config")
            view_btn.setObjectName("SurfaceBtn")
            view_btn.setCursor(Qt.CursorShape.PointingHandCursor)
            view_btn.setMinimumHeight(38)
            view_btn.clicked.connect(
                lambda: self._show_config_dialog(selected_conf_file)
            )
            buttons_row.addWidget(view_btn, 1)

        grid.addLayout(buttons_row, row, 0, 1, 2)
        row += 1

        # Keep the layout top-aligned: a trailing stretch row swallows any
        # leftover viewport height so the panels stay at their natural
        # (compact) heights instead of being inflated to fill the page —
        # tall windows were stretching huge gaps into every panel.
        grid.setRowStretch(row, 1)

        # ── Capped content column ─────────────────────────────────────────
        # Compresses freely at small windows (same 20px edge margins as the
        # Endpoint page, no minimum floor), but stops growing at 700px and
        # centers on wide windows instead of stretching edge-to-edge.
        centered = QWidget()
        outer = QHBoxLayout(centered)
        # CTk-style: centered (pulled off the sidebar) once the window is
        # wide enough for the 700px cap to engage — leftover space splits
        # equally between the side stretches. Below the cap the 50:1 weights
        # collapse the gutters to ~nothing, so a squished window shows the
        # same ~20px margin on BOTH sides (matching the Endpoint page).
        outer.setContentsMargins(20, 10, 20, 10)
        outer.addStretch(1)
        content.setMaximumWidth(700)
        outer.addWidget(content, 50)
        outer.addStretch(1)

        self.main_container = scroll_page(centered)

        # Equalise the panels' title→content padding so the bottom buttons stay
        # flush — recomputed whenever the viewport is resized.
        self._vpn_content = content
        self._vpn_outer_grid = grid
        self._vpn_scroll = self.main_container
        _orig_resize = self.main_container.resizeEvent
        self._rebalance_padding() # unconditional cuz revisiting from theme change doesn't resize
        def _on_resize(event, _o=_orig_resize):
            _o(event)
            self._rebalance_padding() # rebalance on a resize too or it WILL misalign itself

        self.main_container.resizeEvent = _on_resize
        self.app.after(0, self._rebalance_padding)

        # Start the re-arming status poll.
        self._start_polling()

        return self.main_container

    def _rebalance_padding(self):
        """Keep a small, EQUAL title→content padding in every panel.

        Previously this computed large spacer heights so the bottom buttons
        sat flush with the viewport — which read as huge dead gaps between
        each panel's title and its rows. Content now sits directly under the
        titles (matching the original CTk layout); leftover height simply
        stays below the last row of panels.
        """
        spacers = getattr(self, "_panel_spacers", None)
        grids = getattr(self, "_panel_grids", [])
        if not spacers:
            return
        fixed = QSizePolicy.Policy.Fixed
        mini = QSizePolicy.Policy.Minimum
        try:
            for sp in spacers:
                sp.changeSize(0, 8, mini, fixed)
            for g in grids:
                g.invalidate()
            self._vpn_outer_grid.invalidate()
        except (RuntimeError, AttributeError):
            return

    # ---- Panel / row builders (mirror _section_header / _info_row) -------
    def _panel(self) -> tuple[QFrame, QGridLayout]:
        panel = QFrame()
        panel.setObjectName("Surface")
        g = QGridLayout(panel)
        g.setContentsMargins(0, 0, 0, 8)
        g.setHorizontalSpacing(6)
        g.setVerticalSpacing(10)
        g.setColumnStretch(0, 0)
        g.setColumnStretch(1, 1)
        return panel, g

    def _section_header(self, panel, g: QGridLayout, row: int, title: str) -> int:
        hdr = QLabel(title)
        hdr.setStyleSheet(
            f"color: {_pick('#3A7EBF', '#3A7EBF')}; font-size: 12px; "
            f"font-weight: 700; background: transparent;"
        )
        g.addWidget(hdr, row, 0, 1, 2)
        g.setContentsMargins(14, 14, 14, 8)
        div = QFrame()
        div.setFixedHeight(1)
        div.setObjectName("Divider")
        g.addWidget(div, row + 1, 0, 1, 2)
        # Spacer between the title/divider and the content rows. Its height is
        # assigned later by _rebalance_padding() to an EQUAL value across every
        # panel (so all title→content paddings match) chosen so the bottom
        # buttons sit flush with the bottom of the screen. Equal *row stretch*
        # can't do this — it yields equal total panel heights, hence unequal
        # padding — so we compute and set fixed spacer heights instead.
        spacer = QSpacerItem(
            0, 0, QSizePolicy.Policy.Minimum, QSizePolicy.Policy.Fixed)
        g.addItem(spacer, row + 2, 0, 1, 2)
        self._panel_spacers.append(spacer)
        self._panel_grids.append(g)
        return row + 3

    def _info_row(
        self, g: QGridLayout, row: int, label: str, value: str,
        mono: bool = False, wrap: bool = False,
    ) -> int:
        lbl = QLabel(label)
        lbl.setStyleSheet(
            f"color: {_pick('#888888', '#777777')}; font-size: 13px; "
            f"background: transparent;"
        )
        lbl.setAlignment(
            Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter
        )
        g.addWidget(lbl, row, 0)

        val = QLabel(str(value))
        # One family + one weight for every value (mono is intentionally
        # ignored): the Courier-vs-UI-font mix read as inconsistent sizing
        # and boldness across rows.
        _ = mono
        val.setStyleSheet(
            f"color: {_pick('#111111', '#EEEEEE')}; font-size: 13px; "
            f"font-weight: 700; background: transparent;"
        )
        # Always allow wrapping: a non-wrapping QLabel is CLIPPED (no
        # ellipsis) when the two side-by-side panels compress its column on
        # a narrow window — IPs rendered as "10.11.128." and labels as
        # "Config Nam". Wrapped values shrink gracefully instead. Keep the
        # value vertically CENTERED against its label even when it wraps to
        # multiple lines (Public Keys / Routes rows looked misaligned with
        # the label at the bottom and the value at the top).
        val.setWordWrap(True)
        val.setAlignment(
            Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter
        )
        val.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        g.addWidget(val, row, 1)
        return row + 1

    # ===================================================================
    #  Toggle / connect / disconnect (blocking work on a worker thread)
    # ===================================================================
    def _on_toggle_clicked(self):
        """Switch clicked: dispatch connect/disconnect off the GUI thread."""
        if self._toggle_busy:
            return
        switch_value = self.vpn_toggle_switch.get()

        selected_conf_file = self.get_selected_conf_file_name()
        if not selected_conf_file and switch_value and _phoenix_signed_in():
            # Signed in with Phoenix but no config yet (e.g. after signing in
            # again): get this device's config from the API, then connect.
            self._toggle_busy = True
            if self.vpn_toggle_switch is not None:
                self.vpn_toggle_switch.setEnabled(False)
            threading.Thread(
                target=self._provision_then_connect, args=(switch_value,),
                daemon=True,
            ).start()
            return
        if not selected_conf_file:
            logger.error("❌ Cannot toggle: No VPN config found.")
            self.app.show_notification(
                "No VPN configuration found. Please log in or add a config.",
                type="error",
            )
            if self.vpn_toggle_switch is not None:
                self.vpn_toggle_switch.deselect()
            return

        self._toggle_busy = True
        if self.vpn_toggle_switch is not None:
            self.vpn_toggle_switch.setEnabled(False)

        threading.Thread(
            target=self._toggle_worker,
            args=(switch_value, selected_conf_file),
            daemon=True,
        ).start()

    def _provision_then_connect(self, switch_value):
        """Worker: fetch this device's Phoenix VPN config, then connect."""
        from plugins.vpn import provisioning
        try:
            name, _path = provisioning.ensure_vpn_config()
        except provisioning.ProvisioningError as e:
            logger.error(f"VPN provisioning failed: {e}")
            self._toggle_busy = False
            try:
                self.app.after(0, self.app.show_notification, str(e), "error")
                self.app.after(0, self.update_plugin, self.id)
            except Exception:
                pass
            return
        self._toggle_worker(switch_value, name)

    def _toggle_worker(self, switch_value, selected_conf_file):
        """Run the blocking connect/disconnect, then marshal UI back."""
        global my_vpn_status, active_client_name
        try:
            if IS_WINDOWS:
                self._toggle_windows(switch_value, selected_conf_file)
            else:
                self._toggle_posix(switch_value, selected_conf_file)
        except Exception as e:
            logger.error(f"VPN toggle failed: {e}")
            try:
                self.app.after(
                    0, self.app.show_notification, "VPN action failed", "error"
                )
            except Exception:
                pass
        finally:
            self._toggle_busy = False
            try:
                self.app.after(0, self.update_plugin, self.id)
            except Exception:
                pass

    def _toggle_windows(self, switch_value, selected_conf_file):
        global my_vpn_status, active_client_name
        current = get_status(selected_conf_file)
        is_running = current.get("state") == "Running"

        if switch_value == 1 and not is_running:
            try:
                config_path = _conf_path(selected_conf_file)
            except ValueError as e:
                logger.error(f"Refusing to connect: {e}")
                self.app.after(
                    0, self.app.show_notification, "Invalid VPN configuration name", "error"
                )
                return
            result = connect(selected_conf_file, config_path=config_path)
            if result.get("status") != "ok" and result.get("state") not in (
                "Starting", "Running",
            ):
                logger.error(f"Connect failed: {result.get('message', '')}")
                self.app.after(
                    0, self.app.show_notification, "Failed to connect VPN", "error"
                )
        elif switch_value == 0 and is_running:
            result = disconnect(selected_conf_file)
            if result.get("status") != "ok":
                logger.error(f"Disconnect failed: {result.get('message', '')}")
                self.app.after(
                    0, self.app.show_notification,
                    "Failed to disconnect VPN", "error",
                )

        self.refresh_vpn_state()

    def _toggle_posix(self, switch_value, selected_conf_file):
        """macOS / Linux connect/disconnect via start_vpn / stop_vpn (config path)."""
        global my_vpn_status, active_client_name
        is_running = my_vpn_status == "Running"

        if switch_value == 1 and not is_running:
            logger.info(f"🔄 Toggle ON: Starting VPN tunnel: {selected_conf_file}")
            self.activate_tunnel(selected_conf_file)
        elif switch_value == 0 and is_running:
            logger.info(f"🔄 Toggle OFF: Stopping VPN tunnel: {selected_conf_file}")
            self.activate_tunnel(selected_conf_file)
        else:
            logger.warning(
                f"⚠️ Switch state ({switch_value}) doesn't match VPN state "
                f"(Running: {is_running})."
            )

    def activate_tunnel(self, tunnel_name):
        """Activate/deactivate the VPN tunnel (macOS/Linux). Blocking — call on a worker."""
        logger.info(f"Toggling VPN tunnel: {tunnel_name}")
        global my_vpn_status, active_client_name

        if not tunnel_name:
            logger.error("❌ No tunnel name provided")
            self.app.after(
                0, self.app.show_notification, "No tunnel name provided", "error"
            )
            return

        try:
            config_path = _conf_path(tunnel_name)
        except ValueError as e:
            logger.error(f"❌ {e}")
            self.app.after(
                0, self.app.show_notification, "Invalid VPN configuration name", "error"
            )
            return

        if IS_MACOS:
            if not _safe_extension_enabled():
                logger.error("Network extension is disabled in System Settings")
                try:
                    mac_major = int(platform.mac_ver()[0].split(".")[0] or "0")
                except Exception:
                    mac_major = 0
                ext_path = (
                    "General > Login Items & Extensions > Network Extensions"
                    if mac_major >= 15
                    else "Privacy & Security > Security > click Allow"
                )
                self.app.after(
                    0, self.app.show_notification,
                    f"VPN extension is disabled. Enable it in System Settings > "
                    f"{ext_path}", "error",
                )
                my_vpn_status = "Stopped"
                active_client_name = None
                return

        elif IS_LINUX:
            try:
                installed = (
                    check_wireguard_installed() if check_wireguard_installed else False
                )
            except Exception:
                installed = False
            if not installed:
                logger.error("WireGuard tools not found.")
                self.app.after(
                    0, self.app.show_notification,
                    "WireGuard tools not found", "error",
                )
                return

        if my_vpn_status == "Running":
            success = self._safe_stop(tunnel_name, config_path)
            if success:
                my_vpn_status = "Stopped"
                active_client_name = None
                self.app.after(0, self.app.show_notification, "VPN stopped", "info")
            else:
                logger.error("Failed to stop VPN")
                self.app.after(
                    0, self.app.show_notification, "Failed to stop VPN", "error"
                )
        else:
            success = False
            try:
                if start_vpn is not None:
                    success = bool(start_vpn(config_path))
            except Exception as e:
                logger.error(f"start_vpn failed: {e}")
            if success:
                my_vpn_status = "Running"
                active_client_name = tunnel_name
                logger.info("✅ VPN started successfully")
                self.app.after(
                    0, self.app.show_notification,
                    "VPN started successfully", "info",
                )
            else:
                logger.error("Failed to start VPN")
                self.app.after(
                    0, self.app.show_notification, "Failed to start VPN", "error"
                )

    def _safe_stop(self, name, config_path=None):
        """Call stop_vpn with the right argument shape per platform (guarded)."""
        try:
            if stop_vpn is None:
                return False
            if IS_WINDOWS:
                return bool(stop_vpn(name))
            path = config_path or _conf_path(name)
            return bool(stop_vpn(path))
        except Exception as e:
            logger.error(f"stop_vpn failed: {e}")
            return False

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

    # ===================================================================
    #  Config dropdown / delete
    # ===================================================================
    def _on_config_activated(self, _index):
        display_name = self.config_selector.currentText()
        self._on_config_selected(display_name)

    def _on_config_selected(self, display_name):
        """Handle config dropdown selection."""
        global my_vpn_status, active_client_name

        configs = self.config_manager.list_configs()
        selected = next(
            (c for c in configs if c["display_name"] == display_name), None
        )
        if not selected:
            return

        new_config_name = selected["name"]
        current_active = self.config_manager.get_active_config_name()
        if new_config_name == current_active:
            return

        # Stop VPN if running on the old config
        if my_vpn_status == "Running" and active_client_name:
            self._safe_stop(active_client_name)
            my_vpn_status = "Stopped"
            active_client_name = None

        self.config_manager.set_active_config(new_config_name)
        self.app.show_notification(f"Switched to {display_name}", type="info")
        self.update_plugin(self.id)

    def _delete_config(self, config_name):
        """Delete a user-imported config."""
        global my_vpn_status, active_client_name

        if my_vpn_status == "Running" and active_client_name == config_name:
            self._safe_stop(config_name)
            my_vpn_status = "Stopped"
            active_client_name = None

        success, message = self.config_manager.delete_config(config_name)
        if success:
            self.app.show_notification("Configuration deleted", type="info")
        else:
            self.app.show_notification(f"Failed to delete: {message}", type="error")

        self.update_plugin(self.id)

    # ===================================================================
    #  View config dialog
    # ===================================================================
    def _show_config_dialog(self, tunnel_name):
        """Open a modal dialog showing the config file with a copy button."""
        from PyQt6.QtWidgets import QDialog

        try:
            conf_file_path = _conf_path(tunnel_name)
        except ValueError as e:
            logger.error(f"Refusing to show config: {e}")
            self.app.show_notification("Invalid configuration name", type="error")
            return
        if not os.path.exists(conf_file_path):
            self.app.show_notification("Config file not found", type="error")
            return

        with open(conf_file_path, "r", encoding="utf-8") as f:
            content = f.read()

        dialog = QDialog(self.app)
        dialog.setWindowTitle(f"{tunnel_name}.conf")
        dialog.resize(520, 440)
        dialog.setModal(True)
        lay = QVBoxLayout(dialog)
        lay.setContentsMargins(20, 15, 20, 20)
        lay.setSpacing(8)

        title_label = QLabel(f"{tunnel_name}.conf")
        title_label.setStyleSheet("font-size: 14px; font-weight: 700;")
        lay.addWidget(title_label)

        textbox = QPlainTextEdit()
        textbox.setReadOnly(True)
        textbox.setPlainText(content)
        textbox.setStyleSheet(
            f'font-family: "{_MONO_FONT}", monospace; font-size: 12px;'
        )
        lay.addWidget(textbox, 1)

        copy_btn = QPushButton("Copy to Clipboard")
        copy_btn.setMinimumHeight(36)

        def _reset_copy_label():
            # Fires 2s later; the dialog (and this button) may be closed by
            # then, leaving a deleted C++ object — setText would raise.
            try:
                copy_btn.setText("Copy to Clipboard")
            except RuntimeError:
                pass

        def copy_to_clipboard():
            clip = QGuiApplication.clipboard()
            if clip is not None:
                clip.setText(content)
            copy_btn.setText("Copied!")
            self.app.after(2000, _reset_copy_label)

        copy_btn.clicked.connect(copy_to_clipboard)
        lay.addWidget(copy_btn)

        # Esc / close support
        bb = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        bb.rejected.connect(dialog.reject)
        bb.accepted.connect(dialog.accept)
        lay.addWidget(bb)

        dialog.exec()

    # ===================================================================
    #  Status polling (re-arming app.after; worker thread does the blocking work)
    # ===================================================================
    def _start_polling(self):
        """Arm the recurring status poll (single source; re-arms itself)."""
        self._stop_polling()
        self._poll_id = self.app.after(5000, self._poll)

    def _stop_polling(self):
        if self._poll_id is not None:
            try:
                self.app.after_cancel(self._poll_id)
            except Exception:
                pass
            self._poll_id = None

    def _poll(self):
        """GUI thread: dispatch the blocking status check to a worker."""
        # Stop if our screen is no longer the live one.
        if getattr(self.app, "_current_main_screen", None) is not getattr(
            self, "main_container", None
        ):
            self._poll_id = None
            return
        threading.Thread(target=self._poll_worker, daemon=True).start()

    def _poll_worker(self):
        """Worker: run the blocking status check off the GUI thread."""
        new_state = my_vpn_status
        ext_changed = False
        try:
            if IS_MACOS:
                if not _safe_extension_enabled():
                    new_state = "Stopped"
                    ext_changed = True
                else:
                    new_state = check_service_status(
                        active_client_name or "vpn", DNS_SERVER
                    )
            elif IS_WINDOWS:
                tunnel = self.get_selected_conf_file_name()
                if tunnel:
                    result = get_status(tunnel)
                    new_state = result.get("state", "Stopped")
            elif IS_LINUX:
                tunnel = active_client_name or self.get_selected_conf_file_name()
                if tunnel:
                    new_state = check_service_status(tunnel, DNS_SERVER)
        except Exception:
            new_state = my_vpn_status

        try:
            self.app.after(0, self._apply_poll_result, new_state, ext_changed)
        except Exception:
            pass

    def _apply_poll_result(self, new_state, ext_changed):
        """GUI thread: update cached state + toggle; re-arm the poll."""
        global my_vpn_status, active_client_name

        changed = False
        if new_state in ("Running", "Stopped") and new_state != my_vpn_status:
            logger.info(
                f"VPN state changed externally: {my_vpn_status} -> {new_state}"
            )
            my_vpn_status = new_state
            active_client_name = (
                active_client_name if new_state == "Running" else None
            )
            changed = True

        self.status = self.get_status()

        # Keep the live toggle in sync without rebuilding when nothing changed.
        if self.vpn_toggle_switch is not None:
            try:
                if my_vpn_status == "Running":
                    self.vpn_toggle_switch.select()
                else:
                    self.vpn_toggle_switch.deselect()
            except Exception:
                pass

        if changed or ext_changed:
            # Rebuild this screen + the dashboard banner.
            self.update_plugin(self.id)
            return  # update_plugin rebuilds the screen → poll re-armed there

        # Nothing changed — re-arm the poll.
        self._poll_id = self.app.after(5000, self._poll)

    # ===================================================================
    #  Screen lifecycle
    # ===================================================================
    def update_plugin(self, plugin_id):
        """Rebuild the affected plugin's live screen via the host shim."""
        try:
            self.app.update_plugin(plugin_id)
        except Exception as e:
            logger.error(f"update_plugin failed: {e}")

    def destroy(self):
        """Release the recurring poll timer."""
        self._stop_polling()
        self.vpn_toggle_switch = None
