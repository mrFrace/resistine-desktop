"""
VPN Functions for WireGuard on macOS
Author: Jacqueline Edoro
Copyright (c) Resistine 2025
Licensed under the GNU General Public License v2 or later
"""

import json
import os
import re
import subprocess
import sys
from typing import Optional, Tuple

from utils import settings
from utils.logger import logger
from plugins.vpn.wireguard.config_validation import (
    optional_peer_lines,
    validate_config_name,
    validate_server_config,
    validate_wg_field,
)


def _restrict_dir_permissions(path):
    """Ensure the WireGuard config dir is private (0o700).

    makedirs(mode=...) is subject to the umask and does not touch an existing
    directory, so chmod explicitly. Failures are logged, not fatal.
    """
    try:
        if (os.stat(path).st_mode & 0o777) != 0o700:
            os.chmod(path, 0o700)
    except OSError as e:
        logger.warning(f"Could not restrict permissions on {path}: {e}")


def get_writable_wireguard_dir():
    """Get a writable directory for WireGuard configuration files
    
    Uses the App Group container so the sandboxed CLI can access configs.
    Path: ~/Library/Group Containers/group.Resistine.WireguardTest/wireguard/
    """
    # Use App Group container instead of Application Support
    # This allows the sandboxed resistine-vpn-cli to access the configs
    home = os.path.expanduser("~")
    app_group_container = os.path.join(
        home, "Library", "Group Containers", "group.Resistine.WireguardTest"
    )
    wireguard_dir = os.path.join(app_group_container, "wireguard")
    os.makedirs(wireguard_dir, mode=0o700, exist_ok=True)
    _restrict_dir_permissions(wireguard_dir)
    return wireguard_dir


# Cache to map config names to actual utun interfaces (e.g., wg0 → utun6)
_interface_cache = {}


class HelperToolManager:
    """Manages CLI communication with the resistine-vpn-cli tool"""

    def __init__(self):
        self.cli_path = self._find_cli_path()
        self.is_available = self.cli_path is not None
        logger.info(f"🔍 [HELPER] CLI Path: {self.cli_path}")
        logger.info(
            f"🔍 [HELPER] CLI Exists: {self.cli_path and os.path.exists(self.cli_path) if self.cli_path else False}"
        )

    def _find_cli_path(self):
        """Locate resistine-vpn-cli tool in the app bundle"""
        # When frozen (PyInstaller), look relative to the executable
        if getattr(sys, "frozen", False):
            # sys.executable is in Contents/MacOS/Phoenix
            macos_dir = os.path.dirname(sys.executable)
            contents_dir = os.path.dirname(macos_dir)
            
            # CLI is in Contents/MacOS/ — must be here (not Contents/Helpers/)
            # because NSXPCConnection(serviceName:) requires launchd to associate
            # the process with its parent app bundle, which only works for
            # binaries in Contents/MacOS/.
            cli_path = os.path.join(contents_dir, "MacOS", "resistine-vpn-cli")
            if os.path.exists(cli_path):
                return cli_path
            
            # Fallback: old nested path for backwards compatibility
            old_cli_path = os.path.join(
                contents_dir, "Resources", "wireguard-apple.app",
                "Contents", "MacOS", "resistine-vpn-cli"
            )
            if os.path.exists(old_cli_path):
                logger.warning("⚠️ Using legacy CLI path - please rebuild for full VPN support")
                return old_cli_path

        # Development mode: VPN features require the built app bundle
        # Run ./build-installer.sh first, then test from dist/Phoenix.app
        logger.warning("VPN CLI not found - run ./build-installer.sh to build the app")
        return None


# Initialize helper manager
helper = HelperToolManager()

NOT_BUNDLED = ("This build of Phoenix doesn't include the VPN. "
               "Install the signed Phoenix release to use it.")


def vpn_bundled() -> bool:
    """The app carries the VPN helper (signed release builds do; unsigned
    test builds don't, and macOS refuses their extension anyway)."""
    return helper.cli_path is not None


def vpn_unavailable_reason() -> Optional[str]:
    """Why the VPN cannot work in this build/install, or None."""
    if not vpn_bundled():
        return NOT_BUNDLED
    try:
        get_writable_wireguard_dir()
    except PermissionError:
        # The App Group container needs the team-signed app-group entitlement.
        return ("macOS blocked Phoenix from saving its VPN settings. "
                "Reinstall the signed Phoenix release.")
    return None


# Add VPN-specific helper methods
class VPNHelper:
    """VPN-specific operations using the CLI interface"""

    # Keep reference to avoid GC of the delegate
    _activator_ref = None

    @staticmethod
    def activate_extension() -> bool:
        """Activate the System Extension using Main App PyObjC bridge.

        False when no request was sent (no VPN in this build, or an error).
        The request answers asynchronously: see activation_error()."""
        if not vpn_bundled():
            logger.info("🔌 [VPN] No VPN in this build — not requesting the extension")
            return False
        try:
            from .extension_activator import ExtensionActivator, run_activation
            logger.info("🔌 [VPN] Triggering System Extension activation via Main App...")
            
            # Store reference to keep delegate alive
            VPNHelper._activator_ref = run_activation("com.resistine.desktop.network-extension")
            return True
        except ImportError:
            logger.error("❌ [VPN] PyObjC ExtensionActivator not found (ImportError)")
            return False
        except Exception as e:
            logger.error(f"❌ [VPN] Activation error: {e}")
            return False

    @staticmethod
    def activation_error() -> Optional[str]:
        """macOS's refusal of the last activation request, if it refused."""
        return getattr(VPNHelper._activator_ref, "error", None)

    @staticmethod
    def start_vpn(config_path: str) -> Tuple[bool, str]:
        """Start VPN using config file"""
        if not helper.cli_path:
            logger.error("❌ [CLI] Helper CLI not found")
            return (False, "Helper CLI not found")

        # Ensure extension is activated before starting
        VPNHelper.activate_extension()

        try:
            cmd = [helper.cli_path, "start", config_path]
            logger.info(f"🔧 [CLI] Executing: {' '.join(cmd)}")
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30,
            )
            output = result.stdout.strip() or result.stderr.strip()
            logger.info(f"📤 [CLI] Result: returncode={result.returncode}, output='{output}'")
            return (result.returncode == 0, output)
        except subprocess.TimeoutExpired:
            logger.error("⏰ [CLI] Command timed out after 30 seconds")
            return (False, "Command timed out")
        except Exception as e:
            logger.error(f"❌ [CLI] Command error: {e}")
            return (False, str(e))

    @staticmethod
    def stop_vpn(config_path: str = None) -> Tuple[bool, str]:
        """Stop VPN (config_path is ignored - CLI uses 'stop' without arguments)"""
        if not helper.cli_path:
            logger.error("❌ [CLI] Helper CLI not found")
            return (False, "Helper CLI not found")

        try:
            cmd = [helper.cli_path, "stop"]
            logger.info(f"🔧 [CLI] Executing: {' '.join(cmd)}")
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30,
            )
            output = result.stdout.strip() or result.stderr.strip()
            logger.info(f"📤 [CLI] Result: returncode={result.returncode}, output='{output}'")
            return (result.returncode == 0, output)
        except subprocess.TimeoutExpired:
            logger.error("⏰ [CLI] Command timed out after 30 seconds")
            return (False, "Command timed out")
        except Exception as e:
            logger.error(f"❌ [CLI] Command error: {e}")
            return (False, str(e))

    @staticmethod
    def check_status(
        interface_name: str = None, test_ip: Optional[str] = None
    ) -> Tuple[bool, str]:
        """Check VPN status (interface_name is ignored - CLI uses 'status' without arguments)"""
        if not helper.cli_path:
            logger.warning("⚠️ [HELPER] CLI path not available")
            return (False, "Stopped")

        try:
            cmd = [helper.cli_path, "status"]

            logger.info(f"🔍 [HELPER] Running command: {' '.join(cmd)}")
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            output = result.stdout.strip()
            logger.info(
                f"📊 [HELPER] Command result: returncode={result.returncode}, output='{output}'"
            )

            # Status check returns "Connected" or "Disconnected" (or similar variations)
            if "Running" in output or "Connected" in output:
                is_running = True
            else:
                is_running = False
            return (is_running, output)

        except subprocess.TimeoutExpired:
            logger.error("⏰ [HELPER] Command timed out after 30 seconds")
            return (False, "Command timed out")
        except FileNotFoundError:
            logger.error(f"❌ [HELPER] CLI executable not found: {helper.cli_path}")
            return (False, "Helper not available")
        except Exception as e:
            logger.error(f"❌ [HELPER] Command error: {e}")
            return (False, str(e))


vpn_helper = VPNHelper()


def save_wireguard_keys(private_key, public_key):
    """
    Save WireGuard keys.

    Args:
        private_key: WireGuard private key (string)
        public_key: WireGuard public key (string)

    Returns:
        bool: True if successful, False otherwise
    """
    p1 = settings.set_secret("wireguard", "private_key", private_key)
    p2 = settings.set_secret("wireguard", "public_key", public_key)
    return p1 and p2


def get_wireguard_private_key():
    """Get WireGuard private key from Keychain"""
    return settings.get_secret("wireguard", "private_key")


def get_wireguard_public_key():
    """Get WireGuard public key from Keychain"""
    return settings.get_secret("wireguard", "public_key")


def delete_wireguard_keys():
    """
    Delete WireGuard keys from Keychain (for key regeneration)

    Returns:
        bool: True if successful, False otherwise
    """
    d1 = settings.delete("wireguard", "private_key")
    d2 = settings.delete("wireguard", "public_key")
    return d1 and d2


def wireguard_keys_exist():
    """Check if WireGuard keys exist in Keychain"""
    private_key = settings.get_secret("wireguard", "private_key")
    public_key = settings.get_secret("wireguard", "public_key")
    return bool(private_key and public_key)


def generate_wireguard_keys():
    """
    Generate WireGuard public/private key pair using pure Python cryptography.

    Uses X25519 (Curve25519) from the cryptography library, which is the same
    algorithm used by WireGuard. No wg binary required.

    Returns:
        dict: {
            'private_key': str,   # Base64-encoded private key (44 chars)
            'public_key': str     # Base64-encoded public key (44 chars)
        }
        None: If key generation fails
    """
    try:
        import base64
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
        from cryptography.hazmat.primitives import serialization

        private_key_obj = X25519PrivateKey.generate()

        private_bytes = private_key_obj.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        private_key = base64.b64encode(private_bytes).decode("utf-8")

        public_bytes = private_key_obj.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        public_key = base64.b64encode(public_bytes).decode("utf-8")

        return {
            "private_key": private_key,
            "public_key": public_key,
        }

    except Exception as e:
        logger.error(f"❌ Key generation failed: {e}")
        return None


def start_vpn(config_path):
    """Start VPN using the privileged helper"""

    success, output = vpn_helper.start_vpn(config_path)
    if success or "Interface for" in output:
        logger.info(f"✅ VPN started: {output}")

        # Extract and cache the actual utun interface
        config_name = os.path.basename(config_path).replace(".conf", "")
        match = re.search(r"Interface for \S+ is (\S+)", output)
        if match:
            actual_interface = match.group(1)
            _interface_cache[config_name] = actual_interface

        return True
    else:
        logger.error(f"❌ VPN start failed: {output}")
        return False


def stop_vpn(config_path):
    """Stop VPN using the privileged helper"""

    success, output = vpn_helper.stop_vpn(config_path)
    if success or "stopped" in output.lower():
        logger.info(f"✅ VPN stopped: {output}")

        # Clear the cached interface mapping
        config_name = os.path.basename(config_path).replace(".conf", "")
        if config_name in _interface_cache:
            del _interface_cache[config_name]
        logger.info(f"🔍 [CACHE] Cleared mapping for {config_name}")
        return True
    else:
        logger.error(f"❌ VPN stop failed: {output}")
        return False


def check_service_status(interface_name, test_ip=None):
    """Check VPN status using the privileged helper

    Args:
        interface_name: Config name (e.g., 'wg0') or actual interface name (e.g., 'utun10')
        test_ip: Optional IP to ping for connectivity test
    """

    # Map config name to actual utun interface if available
    actual_interface = _interface_cache.get(interface_name, interface_name)

    # If the interface_name is already a utun interface (starts with 'utun'), use it directly
    if interface_name.startswith("utun"):
        actual_interface = interface_name

    logger.info(
        f"🔍 [STATUS] Checking status for interface: {interface_name} -> {actual_interface}"
    )
    try:
        # ✅ Don't pass test_ip to avoid ping tests
        is_running, status = vpn_helper.check_status(actual_interface, None)

        logger.info(
            f"📊 [STATUS] Helper returned: is_running={is_running}, status='{status}'"
        )

        return "Running" if is_running else "Stopped"

    except Exception as e:
        logger.error(f"❌ [STATUS] Exception in check_service_status: {e}")
        import traceback

        logger.error(traceback.format_exc())
        return "Stopped"


def check_wireguard_installed():
    """On macOS, VPN uses Network Extension — wg/wg-quick binaries are not needed."""
    return True


def parse_and_create_vpn_config(vpn_config_json_string, config_name="phoenix"):
    """
    Parse VPN configuration from server response and create WireGuard config file.

    Args:
        vpn_config_json_string: JSON string containing VPN config from server
        config_name: Name for the config file (default: "wg0")

    Returns:
        str: Path to created config file, or None if failed

    Expected JSON structure:
    {
        "Peer": {
            "PublicKey": "...",
            "AllowedIPs": ["10.0.0.0/24"],
            "Endpoint": "vpn.example.com:51820"
        },
        "Interface": {
            "PrivateKey": "",  # Empty, will use from keychain
            "Address": "10.0.0.2",
            "DNS": ["10.0.0.53"]  # Uses DNS_SERVER constant (see top of file)
        }
    }
    """
    try:
        # Parse the VPN config (accepts both dict and JSON string)
        if isinstance(vpn_config_json_string, dict):
            vpn_config = vpn_config_json_string
        else:
            vpn_config = json.loads(vpn_config_json_string)

        # Extract Peer configuration
        peer_config = vpn_config.get("Peer", {})
        server_public_key = peer_config.get("PublicKey", "")
        allowed_ips = peer_config.get("AllowedIPs", [])
        endpoint = peer_config.get("Endpoint", "")

        # Extract Interface configuration
        interface_config = vpn_config.get("Interface", {})
        client_address = interface_config.get("Address", "")
        dns_servers = interface_config.get("DNS", [])

        # Get private key from keychain (local function)
        private_key = get_wireguard_private_key()
        if not private_key:
            logger.error("❌ Error: Private key not found in keychain")
            return None

        # Validate every server-provided value (and the config name, which
        # becomes a file path) before anything is written, so a malicious API
        # response can't inject extra lines such as PostUp into the .conf.
        try:
            validate_config_name(config_name)
            validate_wg_field(private_key, "PrivateKey")
            validate_server_config(
                server_public_key, endpoint, client_address, allowed_ips, dns_servers
            )
            extra_peer_lines = optional_peer_lines(peer_config)
        except ValueError as e:
            logger.error(f"Rejected invalid VPN config from server: {e}")
            return None

        # Convert AllowedIPs array to comma-separated string
        allowed_ips_str = (
            ", ".join(allowed_ips)
            if isinstance(allowed_ips, list)
            else str(allowed_ips)
        )

        # Convert DNS array to comma-separated string
        dns_str = (
            ", ".join(dns_servers)
            if isinstance(dns_servers, list)
            else str(dns_servers)
        )

        # Build WireGuard config content
        config_content = f"""[Interface]
PrivateKey = {private_key}
Address = {client_address}
DNS = {dns_str}

[Peer]
PublicKey = {server_public_key}
AllowedIPs = {allowed_ips_str}
Endpoint = {endpoint}
"""
        if extra_peer_lines:
            config_content += "\n".join(extra_peer_lines) + "\n"

        # Get writable WireGuard directory
        wireguard_dir = get_writable_wireguard_dir()

        # Create config file path
        config_filename = f"{config_name}.conf"
        config_path = os.path.join(wireguard_dir, config_filename)

        # Write config file
        with open(config_path, "w") as config_file:
            config_file.write(config_content)

        # Set strict permissions (600) to avoid "world accessible" warning
        os.chmod(config_path, 0o600)

        logger.info(f"✅ WireGuard config created at: {config_path}")
        logger.info(f"   Server: {endpoint}")
        logger.info(f"   Client IP: {client_address}")
        logger.info(f"   DNS: {dns_str}")

        return config_path

    except json.JSONDecodeError as e:
        logger.error(f"❌ Error parsing VPN config JSON: {e}")
        return None
    except KeyError as e:
        logger.error(f"❌ Error: Missing required field in VPN config: {e}")
        return None
    except Exception as e:
        logger.error(f"❌ Error creating VPN config: {e}")
        import traceback

        logger.error(traceback.format_exc())
        return None


def setup_vpn_keys():
    """
    Generate and save new WireGuard keys for the session.
    Returns the public key if successful, None otherwise.
    """
    try:
        # Step 1: Regenerate fresh keys for this sign-in session
        # Delete old keys (if they exist) to ensure fresh key pair
        logger.info("Regenerating WireGuard keys for new login session")
        delete_wireguard_keys()

        # Generate new key pair
        keys = generate_wireguard_keys()
        if not keys:
            logger.error("❌ Failed to generate keys")
            return None

        # Save both private and public keys to Keychain with iOS-compatible service names
        if not save_wireguard_keys(keys["private_key"], keys["public_key"]):
            logger.error("❌ Failed to save keys securely")
            return None

        # Get public key for API transmission
        public_key = keys["public_key"]

        if not public_key:
            logger.error("❌ Failed to get public key")
            return None

        logger.info(f"✅ WireGuard Public Key Validated: Length={len(public_key)} characters")
        return public_key

    except Exception as e:
        logger.error(f"❌ Error setting up VPN keys: {e}")
        return None


def save_vpn_configuration(vpn_config_json, config_name="phoenix"):
    """
    Parse and save the VPN configuration.
    Returns the path to the saved config file if successful, None otherwise.
    """
    try:
        if not vpn_config_json:
            return None

        logger.info("WireGuard config received from API")

        # Log redacted config for debugging
        try:
            vpn_config = (
                json.loads(vpn_config_json)
                if isinstance(vpn_config_json, str)
                else vpn_config_json
            )
            safe_config = {}
            if "Interface" in vpn_config:
                safe_config["Interface"] = {
                    "Address": vpn_config["Interface"].get("Address", ""),
                    "DNS": vpn_config["Interface"].get("DNS", []),
                    "PrivateKey": (
                        "[REDACTED]"
                        if vpn_config["Interface"].get("PrivateKey")
                        else None
                    ),
                }
            if "Peer" in vpn_config:
                safe_config["Peer"] = {
                    "PublicKey": (
                        "[REDACTED]" if vpn_config["Peer"].get("PublicKey") else None
                    ),
                    "AllowedIPs": vpn_config["Peer"].get("AllowedIPs", []),
                    "Endpoint": vpn_config["Peer"].get("Endpoint", ""),
                }
            logger.debug(f"VPN Config (redacted): {json.dumps(safe_config)}")
        except Exception as e:
            logger.error(f"Error parsing VPN config for logging: {e}")

        # Create config file
        config_path = parse_and_create_vpn_config(vpn_config_json, config_name=config_name)

        if config_path:
            logger.info("✅ VPN configuration saved successfully")
            return config_path
        else:
            logger.error("❌ Failed to create VPN config")
            return None

    except Exception as e:
        logger.error(f"❌ Error creating VPN config: {e}")
        return None


import time as _time

_extension_cache = {"value": None, "timestamp": 0}
_EXTENSION_CACHE_TTL = 2  # seconds


def is_extension_enabled():
    """Check if the Phoenix network extension is enabled in Login Items & Extensions.

    Uses systemextensionsctl to verify the extension is both activated AND enabled.
    A NETunnelProviderManager can exist in preferences even when the extension is
    disabled, so this is the only reliable check.

    Results are cached for 2 seconds to avoid redundant subprocess calls when
    multiple callers check within the same render cycle.

    Returns:
        bool: True if the extension is [activated enabled], False otherwise.
    """
    now = _time.monotonic()
    if now - _extension_cache["timestamp"] < _EXTENSION_CACHE_TTL:
        return _extension_cache["value"]

    try:
        result = subprocess.run(
            ["systemextensionsctl", "list"],
            capture_output=True, text=True, timeout=10,
        )
        output = result.stdout + result.stderr
        enabled = False
        for line in output.splitlines():
            if "com.resistine.desktop.network-extension" in line:
                if "[activated enabled]" in line:
                    enabled = True
                else:
                    logger.info(f"Extension not enabled: {line.strip()}")
                break

        _extension_cache["value"] = enabled
        _extension_cache["timestamp"] = now
        return enabled
    except Exception as e:
        logger.warning(f"Extension status check failed: {e}")
        return False
