"""
VPN Functions for WireGuard on Linux
-------------------------------------
This module contains functions for managing a WireGuard VPN on Linux.
The functions include checking if WireGuard is installed, generating keys,
creating a WireGuard configuration file, starting and stopping the VPN service,
and checking the status of the VPN service.
Author: Petr and the Resistine Team
Copyright (c) Resistine 2025
Licensed under the GNU General Public License v2 or later
"""

import json
import os
import re
import shlex
import shutil
import subprocess
import sys

from gui.dialogs import CTkPasswordDialog
from utils.i18n import get_text
from utils.logger import logger
from plugins.vpn.wireguard.config_validation import (
    is_valid_config_name,
    optional_peer_lines,
    validate_config_name,
    validate_server_config,
    validate_wg_field,
)
from utils.settings import get_config_dir

# Removed standard logging setup

# Keychain Constants
# Legacy plaintext key file (pre-2026.10); migrated to encrypted settings.
KEYS_FILE_PATH = os.path.join(get_config_dir(), "keys.json")

# IPv4/IPv6 addresses and domain names only (used before interpolating DNS
# values into PostUp shell commands).
_SAFE_DNS_TOKEN = re.compile(r"^[A-Za-z0-9.:_-]+$")


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
    """Get a writable directory for WireGuard configuration files"""
    from utils.settings import get_config_dir

    wireguard_dir = os.path.join(get_config_dir(), "wireguard")
    os.makedirs(wireguard_dir, mode=0o700, exist_ok=True)
    _restrict_dir_permissions(wireguard_dir)
    return wireguard_dir


def is_admin():
    """
    Check if the script is running with root privileges.

    :return: True if running as root, False otherwise.
    """
    return os.geteuid() == 0


def run_privileged_command(command_args):
    """Traced entry point; see _run_privileged_command."""
    from utils import http_trace
    http_trace.event("root command (pkexec)", command_args)
    result = _run_privileged_command(command_args)
    http_trace.event("root command result", result if isinstance(result, tuple)
                     else getattr(result, "returncode", result))
    return result


def _run_privileged_command(command_args):
    """
    Run a command with elevated privileges using pkexec or sudo fallback.

    :param command_args: List of command arguments (e.g., ["wg", "show"])
    :return: subprocess.CompletedProcess or None if failed
    """
    if is_admin():
        try:
            return subprocess.run(command_args, check=True, capture_output=True, text=True)
        except subprocess.CalledProcessError as e:
            logger.error(f"Command failed as root (code {e.returncode}): "
                         f"{e.stderr.strip() or e.stdout.strip() or 'No output'}")
        except Exception as e:
            logger.error(f"Error running command as root: {e}")
        return None

    # Try pkexec first (standard GUI way). When pkexec is available it drives
    # the system polkit prompt, which already handles authentication — so we do
    # NOT pop a second, in-app sudo password dialog on top of it.
    if shutil.which("pkexec"):
        try:
            # Resolve absolute path for the command
            # pkexec often fails if the command is not in its minimal PATH (exit code 126)
            executable = shutil.which(command_args[0])
            full_command_args = (
                [executable] + command_args[1:] if executable else command_args
            )

            logger.info(f"Attempting to run with pkexec: {full_command_args}")
            # pkexec runs the command directly, handling the GUI prompt
            return subprocess.run(
                ["pkexec"] + full_command_args,
                check=True,
                capture_output=True,
                text=True,
            )
        except subprocess.CalledProcessError as e:
            # pkexec executed and the privileged command (or the auth prompt)
            # returned non-zero. Authentication was already handled by the
            # system polkit agent, so re-prompting with an in-app sudo dialog
            # would just run the same command again and double-prompt the user.
            # Report the failure instead of falling back.
            error_msg = e.stderr.strip() or e.stdout.strip() or "No output"
            logger.error(
                f"Privileged command failed under pkexec (code {e.returncode}): {error_msg}"
            )
            return None
        except Exception as e:
            # pkexec itself could not be executed (e.g. missing polkit agent).
            # Only in this case do we fall back to the sudo password dialog.
            logger.warning(f"pkexec could not run: {e}. Falling back to sudo.")

    # Fallback to sudo with GUI password prompt (only reached when pkexec is
    # unavailable or failed to execute at all)
    logger.info("Falling back to sudo with themed password prompt")

    dialog = CTkPasswordDialog(
        title=get_text("dialog.password.title"),
        text=get_text("vpn.linux.privileges_required", command=command_args[0]),
    )
    password = dialog.get_input()

    if not password:
        logger.warning("User cancelled password prompt")
        return None

    try:
        # Run sudo with -S to read password from stdin
        return subprocess.run(
            ["sudo", "-S"] + command_args,
            input=password + "\n",
            check=True,
            capture_output=True,
            text=True,
        )
    except subprocess.CalledProcessError as e:
        logger.error(f"sudo failed: {e.stderr}")
        return None
    except Exception as e:
        logger.error(f"sudo error: {e}")
        return None


def run_installer_as_admin(file_path):
    """
    Run an installer file with admin privileges.

    :param file_path: The path to the installer file.
    :return: True if successful, False otherwise.
    """
    try:
        logger.info(f"Running installer as admin: {file_path}...")
        from utils.distro import LinuxDistro
        command = LinuxDistro.get_install_command(["wireguard"])
        
        if not command:
            logger.error("Could not determine package manager to install WireGuard.")
            return False
            
        result = run_privileged_command(command)
        if result and result.returncode == 0:
            logger.info("WireGuard installation command executed.")
            return True
        else:
            logger.info("Failed to install WireGuard.")
            return False
    except Exception as e:
        logger.error(f"Error during installation: {e}")
        return False


def generate_wireguard_keys():
    """
    Generate WireGuard public/private key pair using wg command.

    Returns:
        dict: {
            'private_key': str,
            'public_key': str
        }
        None: If key generation fails
    """
    try:
        private_key = subprocess.check_output(["wg", "genkey"], text=True).strip()
        public_key = subprocess.check_output(
            ["wg", "pubkey"], input=private_key, text=True
        ).strip()

        return {
            "private_key": private_key,
            "public_key": public_key,
        }

    except subprocess.CalledProcessError as e:
        logger.error(f"Key generation command failed: {e}")
        return None
    except Exception as e:
        logger.error(f"Key generation failed: {e}")
        return None


def _settings():
    from utils import settings
    return settings


def _migrate_legacy_keys():
    """Move keys from the old plaintext keys.json into encrypted settings."""
    if not os.path.exists(KEYS_FILE_PATH):
        return
    try:
        with open(KEYS_FILE_PATH, "r") as f:
            keys = json.load(f)
        if keys.get("private_key") and keys.get("public_key"):
            if not _save_secrets(keys["private_key"], keys["public_key"]):
                return  # keep the file rather than lose the key
        os.remove(KEYS_FILE_PATH)
        logger.info("Moved WireGuard keys from keys.json to encrypted settings")
    except Exception as e:
        logger.error(f"Could not migrate legacy WireGuard keys: {e}")


def _save_secrets(private_key, public_key):
    s = _settings()
    return bool(s.set_secret("wireguard", "private_key", private_key)
                and s.set_secret("wireguard", "public_key", public_key))


def get_wireguard_private_key():
    """Retrieve the WireGuard private key (encrypted settings)."""
    try:
        _migrate_legacy_keys()
        return _settings().get_secret("wireguard", "private_key")
    except Exception as e:
        logger.error(f"Error retrieving private key: {e}")
        return None


def get_wireguard_public_key():
    try:
        _migrate_legacy_keys()
        return _settings().get_secret("wireguard", "public_key")
    except Exception as e:
        logger.error(f"Error retrieving public key: {e}")
        return None


def save_wireguard_keys(private_key, public_key):
    """Save the WireGuard keys encrypted (settings secrets, keyring-backed)."""
    try:
        return _save_secrets(private_key, public_key)
    except Exception as e:
        logger.error(f"Error saving keys: {e}")
        return False


def delete_wireguard_keys():
    """Delete the WireGuard keys (and any legacy plaintext keys.json)."""
    try:
        s = _settings()
        s.delete("wireguard", "private_key")
        s.delete("wireguard", "public_key")
        if os.path.exists(KEYS_FILE_PATH):
            os.remove(KEYS_FILE_PATH)
        return True
    except Exception as e:
        logger.error(f"Error deleting keys: {e}")
        return False


def parse_and_create_vpn_config(vpn_config_json_string, config_name="phoenix"):
    """
    Parse VPN configuration from server response and create WireGuard config file.

    Args:
        vpn_config_json_string: JSON string containing VPN config from server
        config_name: Name for the config file (default: "phoenix")

    Returns:
        str: Path to created config file, or None if failed
    """
    try:
        # Accept the config either already parsed (a dict) or as a JSON string,
        # like macOS does. Blindly calling json.loads() on a dict raises
        # TypeError, which silently dropped the config and left the setup
        # wizard reporting "No VPN configuration found".
        if isinstance(vpn_config_json_string, (bytes, bytearray)):
            vpn_config_json_string = vpn_config_json_string.decode("utf-8")
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
            logger.error("Private key not found in keychain")
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

        # Build WireGuard config content. The canonical `DNS =` directive is
        # stored here; host-specific DNS compatibility (resolvconf vs
        # resolvectl) is applied at bring-up time in start_vpn().
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

        # Determine config path using the shared utility
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", ".."))

        wireguard_dir = get_writable_wireguard_dir()

        # Create config file path
        config_filename = f"{config_name}.conf"
        config_path = os.path.join(wireguard_dir, config_filename)

        # Write config file
        with open(config_path, "w") as config_file:
            config_file.write(config_content)

        # Set strict permissions (600) to avoid "world accessible" warning
        os.chmod(config_path, 0o600)

        logger.info(f"WireGuard config created at: {config_path}")

        return config_path

    except json.JSONDecodeError as e:
        logger.error(f"Error parsing VPN config JSON: {e}")
        return None
    except KeyError as e:
        logger.error(f"Error: Missing required field in VPN config: {e}")
        return None
    except Exception as e:
        logger.error(f"Error creating VPN config: {e}")
        return None


def check_service_status(interface_name, test_ip):
    """
    Check the status of the WireGuard VPN service.

    :param interface_name: The name of the WireGuard interface.
    :param test_ip: The IP address to ping for testing connectivity.
    :return: "Running" if the service is up, "Stopped" otherwise.
    """
    try:
        # Check if interface exists and is UP — no sudo needed
        result = subprocess.run(
            ["ip", "link", "show", interface_name],
            check=False,
            capture_output=True,
            text=True,
        )

        if not result or result.returncode != 0 or "UP" not in result.stdout:
            return "Stopped"

        # Optional: Check connectivity
        if test_ip:
            ping_result = subprocess.run(
                ["ping", "-c", "1", "-W", "1", test_ip],
                check=False,
                capture_output=True,
                text=True,
            )
            if ping_result.returncode != 0:
                logger.warning(
                    f"Interface {interface_name} up but ping to {test_ip} failed."
                )

        return "Running"
    except Exception as e:
        logger.error(f"Error checking WireGuard interface {interface_name}: {e}")
        return "Stopped"


def check_wireguard_installed():
    """
    Check if WireGuard is installed on the system.

    :return: True if WireGuard is installed, False otherwise.
    """
    try:
        subprocess.run(["which", "wg"], check=True, capture_output=True, text=True)
    except Exception:
        return False

    try:
        subprocess.run(
            ["which", "wg-quick"], check=True, capture_output=True, text=True
        )
    except Exception:
        return False
    return True


def stop_vpn(config_path):
    """
    Stop the WireGuard VPN service with a specified configuration.

    :param config_path: The path to the WireGuard configuration file.
    :return: True if the service is stopped successfully, False otherwise.
    """
    try:
        iface = os.path.splitext(os.path.basename(config_path))[0]
        if not is_valid_config_name(iface):
            logger.error(f"Refusing to stop VPN: invalid interface name {iface!r}")
            return False
        etc_conf = f"/etc/wireguard/{iface}.conf"
        if _is_nixos():
            # Started from the config in place (see start_vpn): no /etc copy.
            script = f"{shlex.quote(_wg_quick())} down {shlex.quote(config_path)}"
        else:
            # Use interface name so AppArmor-confined wg-quick (Ubuntu) can
            # access the config; clean up the /etc/wireguard copy afterwards.
            script = (
                f"{shlex.quote(_wg_quick())} down {shlex.quote(iface)}; rm -f {shlex.quote(etc_conf)}"
            )
        result = run_privileged_command(["sh", "-c", script])
        return result is not None and result.returncode == 0
    except Exception as e:
        logger.error(f"Failed to stop VPN service: {e}")
        return False


def _wg_quick():
    """Absolute path of wg-quick, resolved in the app's own environment.

    pkexec resets PATH to /usr/sbin:/usr/bin:/sbin:/bin, which holds nothing
    on NixOS (the app's package puts wireguard-tools on its own PATH only),
    so the privileged shell gets the full path. nixpkgs' wg-quick is a
    wrapper that brings its own dependencies (iproute2, procps, ...).
    """
    return shutil.which("wg-quick") or "wg-quick"


def _is_nixos():
    """NixOS: /etc is read-only (managed by the system config)."""
    try:
        with open("/etc/os-release", encoding="utf-8") as f:
            return any(line.strip() in ("ID=nixos", 'ID="nixos"') for line in f)
    except OSError:
        return False


def make_dns_compatible_config(config_path):
    """
    Return a path to a WireGuard config whose DNS handling works on this host.

    wg-quick's `DNS =` directive shells out to `resolvconf`, which isn't present
    on every distro (e.g. Arch without the systemd-resolvconf package). When
    resolvconf is missing, rewrite the `DNS =` line into systemd-resolved
    `resolvectl` PostUp/PostDown hooks — each guarded with `|| true` so a DNS
    failure never tears the tunnel back down — or drop it entirely if neither
    tool exists. When resolvconf is present the config is used unchanged.

    The (possibly rewritten) config is written alongside the original; the
    user's stored config is never modified. Returns the original path if no
    rewrite is needed or on any error.
    """
    try:
        with open(config_path, "r") as config_file:
            lines = config_file.readlines()
    except OSError as e:
        logger.warning(f"Could not read config for DNS compatibility check: {e}")
        return config_path

    def is_dns_line(line):
        stripped = line.strip()
        return stripped.lower().startswith("dns") and "=" in stripped

    dns_values = []
    for line in lines:
        if is_dns_line(line):
            _, _, value = line.strip().partition("=")
            dns_values = [d.strip() for d in value.replace(",", " ").split() if d.strip()]
            break

    # DNS values are interpolated into root PostUp shell commands below; drop
    # anything that is not a plain IP / domain token so a crafted config
    # can't smuggle shell metacharacters in.
    safe_dns = [d for d in dns_values if _SAFE_DNS_TOKEN.fullmatch(d)]
    if len(safe_dns) != len(dns_values):
        logger.warning("Ignoring DNS entries with unexpected characters")
    dns_values = safe_dns

    # No DNS directive, or resolvconf is available -> use config as-is.
    if not dns_values or shutil.which("resolvconf"):
        return config_path

    def resolved_active():
        try:
            return (
                subprocess.run(
                    ["systemctl", "is-active", "--quiet", "systemd-resolved"]
                ).returncode
                == 0
            )
        except Exception:
            return False

    if shutil.which("resolvectl") and resolved_active():
        # systemd-resolved is running: set per-link DNS the clean way.
        dns_list = " ".join(dns_values)
        replacement = [
            f"PostUp = resolvectl dns %i {dns_list} || true\n",
            "PostUp = resolvectl domain %i ~. || true\n",
            "PostDown = resolvectl revert %i || true\n",
        ]
        logger.info("resolvconf not found; using resolvectl for tunnel DNS")
    else:
        # No resolvconf and no active systemd-resolved (e.g. a plain
        # NetworkManager host). Manage /etc/resolv.conf directly for the
        # lifetime of the tunnel: back it up on up, restore it on down. Guarded
        # with `|| true` so a write failure never tears the tunnel down.
        ns_block = "".join(f"nameserver {d}\\n" for d in dns_values)
        backup = "/etc/resolv.conf.wg-%i.bak"
        replacement = [
            f"PostUp = cp -fp /etc/resolv.conf '{backup}' 2>/dev/null || true\n",
            f"PostUp = printf '{ns_block}' > /etc/resolv.conf 2>/dev/null || true\n",
            f"PostDown = mv -f '{backup}' /etc/resolv.conf 2>/dev/null || true\n",
        ]
        logger.info(
            "resolvconf and systemd-resolved unavailable; managing "
            "/etc/resolv.conf directly for tunnel DNS"
        )

    new_lines = []
    for line in lines:
        if is_dns_line(line):
            new_lines.extend(replacement)
        else:
            new_lines.append(line)

    iface = os.path.splitext(os.path.basename(config_path))[0]
    compat_path = os.path.join(
        os.path.dirname(config_path), f".{iface}.compat.conf"
    )
    try:
        with open(compat_path, "w") as compat_file:
            compat_file.writelines(new_lines)
        os.chmod(compat_path, 0o600)
    except OSError as e:
        logger.error(f"Failed to write DNS-compatible config: {e}")
        return config_path

    return compat_path


def start_vpn(config_path):
    """
    Start the WireGuard VPN service with a specified configuration.

    :param config_path: The path to the WireGuard configuration file.
    :return: True if the service is started successfully, False otherwise.
    """
    try:
        iface = os.path.splitext(os.path.basename(config_path))[0]
        if not is_valid_config_name(iface):
            logger.error(f"Refusing to start VPN: invalid interface name {iface!r}")
            return False
        etc_conf = f"/etc/wireguard/{iface}.conf"
        # Adapt DNS handling to whatever this host provides (resolvconf vs
        # resolvectl) so wg-quick doesn't fail on a missing resolvconf.
        src_conf = make_dns_compatible_config(config_path)
        if _is_nixos():
            # /etc is read-only on NixOS: run wg-quick on the user's config
            # (~/.config/phoenix/wireguard/<iface>.conf, 0600) in place. The
            # interface name comes from the file name, so use the stored file
            # (NixOS always has resolvconf, so no DNS-compat copy is needed).
            script = f"{shlex.quote(_wg_quick())} up {shlex.quote(config_path)}"
        else:
            # Copy into /etc/wireguard/ first — Ubuntu's AppArmor profile for
            # wg-quick only permits reading configs from that directory.
            script = (
                f"cp {shlex.quote(src_conf)} {shlex.quote(etc_conf)} && "
                f"chmod 600 {shlex.quote(etc_conf)} && "
                f"{shlex.quote(_wg_quick())} up {shlex.quote(iface)}"
            )
        result = run_privileged_command(["sh", "-c", script])
        return result is not None and result.returncode == 0
    except Exception as e:
        logger.error(f"Failed to start VPN service: {e}")
        return False


def setup_vpn_keys():
    """
    Generate and save new WireGuard keys for the session.
    Returns the public key if successful, None otherwise.
    """
    try:
        # Step 1: Regenerate fresh keys for this sign-in session
        logger.debug("Regenerating WireGuard keys for new login session")
        delete_wireguard_keys()

        # Generate new key pair
        keys = generate_wireguard_keys()
        if not keys:
            logger.error("Failed to generate keys")
            return None

        # Save both private and public keys
        if not save_wireguard_keys(keys["private_key"], keys["public_key"]):
            logger.error("Failed to save keys securely")
            return None

        # Get public key for API transmission
        public_key = keys["public_key"]

        if not public_key:
            logger.error("Failed to get public key")
            return None

        logger.debug(
            f"WireGuard Public Key Validated: Length={len(public_key)} characters"
        )
        return public_key

    except Exception as e:
        logger.error(f"Error setting up VPN keys: {e}")
        return None


def save_vpn_configuration(vpn_config_json, config_name="phoenix"):
    """
    Parse and save the VPN configuration.
    Returns the path to the saved config file if successful, None otherwise.
    """
    try:
        if not vpn_config_json:
            return None

        logger.debug("WireGuard config received from API")

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
            logger.debug(f"Error parsing VPN config for logging: {e}")

        # Create config file
        config_path = parse_and_create_vpn_config(vpn_config_json, config_name=config_name)

        if config_path:
            logger.info("VPN configuration saved successfully")
            return config_path
        else:
            logger.warning("Failed to create VPN config")
            return None

    except Exception as e:
        logger.warning(f"Error creating VPN config: {e}")
        return None
