"""
Windows VPN helper functions — key management, config management,
WireGuard installation checks, and service status wrappers.

This module does NOT manage tunnel connect/disconnect directly.
Use vpn_windows_client.py for all tunnel control.

Authors: Merhawi, Johann Gawron, and the Resistine Team
Copyright (c) Resistine 2025
Licensed under the GNU General Public License v2 or later
"""

from __future__ import annotations

import json
import os
import subprocess

import utils.settings as _settings
from utils.settings import get_config_dir
from utils.logger import logger
from plugins.vpn.wireguard.config_validation import (
    validate_config_name,
    validate_section_entry,
)

# Import client functions so main.py can use check_service_status etc.
# without importing from two places
from plugins.vpn.wireguard.vpn_windows_client import get_status, connect, disconnect


# ----------------------------------------------------------------
# Directory / path helpers
# ----------------------------------------------------------------

def get_writable_wireguard_dir() -> str:
    """Return (and create) the WireGuard config directory."""
    wg_dir = os.path.join(get_config_dir(), "wireguard")
    os.makedirs(wg_dir, exist_ok=True)
    return wg_dir


def get_config_path(tunnel_name: str) -> str:
    """Return the full path to a tunnel's .conf file."""
    return os.path.join(get_writable_wireguard_dir(), f"{tunnel_name}.conf")


# ----------------------------------------------------------------
# WireGuard installation checks
# ----------------------------------------------------------------

def find_wireguard_exe() -> str | None:
    """Find the WireGuard executable. Returns path or None."""
    candidates = [
        r"C:\Program Files\WireGuard\wireguard.exe",
        r"C:\Program Files (x86)\WireGuard\wireguard.exe",
    ]
    for path in candidates:
        if os.path.exists(path):
            return path
    return None


def find_wg_cli() -> str | None:
    """Find the wg.exe CLI tool. Returns path or None."""
    exe = find_wireguard_exe()
    if exe:
        cli = os.path.join(os.path.dirname(exe), "wg.exe")
        if os.path.exists(cli):
            return cli
    return None


def check_wireguard_installed() -> bool:
    """Return True if WireGuard is installed."""
    return find_wireguard_exe() is not None


# ----------------------------------------------------------------
# Service status wrappers (compatibility with main.py)
# ----------------------------------------------------------------

def start_vpn(tunnel_name: str) -> bool:
    """Connect tunnel via service. Returns True on success."""
    result = connect(tunnel_name)
    return result.get("status") == "ok"


def stop_vpn(tunnel_name: str) -> bool:
    """Disconnect tunnel via service. Returns True on success."""
    result = disconnect(tunnel_name)
    return result.get("status") == "ok"


def check_service_status(tunnel_name: str, test_ip: str = None) -> str:
    """Return a status string: 'Running', 'Stopped', etc.

    Args:
        tunnel_name: The tunnel to check.
        test_ip: Ignored on Windows (kept for cross-platform compat).
    """
    if not tunnel_name:
        return "Stopped"
    try:
        result = get_status(tunnel_name)
        return result.get("state", "Stopped")
    except Exception:
        return "Stopped"


# ----------------------------------------------------------------
# Key management
# Private key is stored encrypted via settings.set_secret() which uses
# Fernet encryption backed by the Windows Credential Manager (DPAPI).
# Public key is stored as plaintext since it is not sensitive.
# ----------------------------------------------------------------

def generate_wireguard_keys() -> dict | None:
    """Generate a WireGuard public/private key pair.

    Uses the bundled ``cryptography`` library (X25519/Curve25519), which
    produces standards-compliant WireGuard keys entirely in-process. We avoid
    shelling out to wg.exe: some WireGuard builds ship a wg.exe that fails to
    initialize when launched from a windowless GUI process, raising error
    0xc0000142 and popping a modal "application was unable to start correctly"
    dialog at the user. wg.exe is only tried as a last resort if the
    cryptography library is somehow unavailable.

    Returns dict with 'private_key' and 'public_key', or None on failure.
    """
    keys = _generate_keys_fallback()
    if keys:
        return keys

    # Last resort: only reached if the cryptography library is unavailable.
    wg_cli = find_wg_cli()
    if wg_cli:
        try:
            private_key = subprocess.check_output(
                [wg_cli, "genkey"], text=True,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            ).strip()
            public_key = subprocess.check_output(
                [wg_cli, "pubkey"], input=private_key, text=True,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            ).strip()
            logger.info("WireGuard keys generated via wg.exe")
            return {"private_key": private_key, "public_key": public_key}
        except Exception as e:
            logger.warning(f"wg.exe key generation failed: {e}")

    return None


def _generate_keys_fallback() -> dict | None:
    """Generate a WireGuard key pair using the cryptography library.

    Returns None if the cryptography library is unavailable so the caller can
    fall back to wg.exe — never returns a random (non-matching) public key,
    which would silently break the tunnel.
    """
    try:
        import base64
        import secrets

        try:
            from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
            from cryptography.hazmat.primitives import serialization
        except ImportError:
            logger.warning("cryptography library not available for key generation")
            return None

        private_key_bytes = secrets.token_bytes(32)
        private_key = base64.b64encode(private_key_bytes).decode()

        x25519_private = X25519PrivateKey.from_private_bytes(private_key_bytes)
        public_key_bytes = x25519_private.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        public_key = base64.b64encode(public_key_bytes).decode()
        logger.info("WireGuard keys generated via cryptography library")
        return {"private_key": private_key, "public_key": public_key}

    except Exception as e:
        logger.error(f"Key generation failed: {e}")
        return None


def get_wireguard_private_key() -> str | None:
    """Retrieve the saved WireGuard private key from encrypted settings storage."""
    try:
        return _settings.get_secret("vpn", "private_key")
    except Exception as e:
        logger.error(f"Error retrieving private key: {e}")
        return None


def save_wireguard_keys(private_key: str, public_key: str) -> bool:
    """Save WireGuard keys using encrypted settings storage.

    The private key is encrypted at rest via the system keyring (Windows Credential
    Manager / DPAPI).  The public key is non-sensitive and stored as plaintext.
    """
    try:
        ok1 = _settings.set_secret("vpn", "private_key", private_key)
        ok2 = _settings.set("vpn", "public_key", public_key)
        return bool(ok1 and ok2)
    except Exception as e:
        logger.error(f"Error saving keys: {e}")
        return False


def delete_wireguard_keys() -> bool:
    """Delete the saved WireGuard keys from encrypted settings storage."""
    try:
        _settings.delete("vpn", "private_key")
        _settings.delete("vpn", "public_key")
        return True
    except Exception as e:
        logger.error(f"Error deleting keys: {e}")
        return False


def setup_vpn_keys() -> str | None:
    """Generate and save new WireGuard keys.

    Returns the public key string on success, None on failure.
    """
    try:
        logger.debug("Regenerating WireGuard keys for new login session")
        delete_wireguard_keys()

        keys = generate_wireguard_keys()
        if not keys:
            logger.error("Failed to generate WireGuard keys")
            return None

        if not save_wireguard_keys(keys["private_key"], keys["public_key"]):
            logger.error("Failed to save WireGuard keys")
            return None

        public_key = keys["public_key"]
        logger.debug(f"WireGuard public key ready: length={len(public_key)}")
        return public_key

    except Exception as e:
        logger.error(f"Error setting up VPN keys: {e}")
        return None


# ----------------------------------------------------------------
# Config file management
# ----------------------------------------------------------------

def parse_and_create_vpn_config(
    vpn_config_json_string: str,
    config_name: str = "resistine",
) -> str | None:
    try:
        if not vpn_config_json_string:
            raise ValueError("Empty API response")

        # The server may hand us the config already parsed (a dict) or as a
        # JSON string. macOS handled both; Windows only handled the string, so
        # a dict response blew up on json.loads() and the config was silently
        # dropped — the "No VPN configuration found" the wizard then reports.
        if isinstance(vpn_config_json_string, (bytes, bytearray)):
            vpn_config_json_string = vpn_config_json_string.decode("utf-8")
        if isinstance(vpn_config_json_string, dict):
            vpn_config = vpn_config_json_string
        else:
            vpn_config = json.loads(vpn_config_json_string)

        interface = vpn_config.get("Interface")
        peer = vpn_config.get("Peer")

        if not isinstance(interface, dict) or not isinstance(peer, dict):
            raise ValueError(f"Invalid WireGuard JSON shape: keys={list(vpn_config.keys())}")

        # The config name becomes the .conf path and the tunnel service name.
        validate_config_name(config_name)

        # FIX: If the server response doesn't include PrivateKey (expected —
        # the server only knows the public key), inject it from keys.json now.
        # This ensures the .conf written to disk is always complete so:
        #   1. validate_wireguard_config() passes without error
        #   2. _ensure_system_config() copies a working config to ProgramData
        #   3. The WireGuard tunnel service (running as SYSTEM) can connect
        #      without ever needing to access the user's AppData directly.
        # Check value too — server may send "PrivateKey": "" as a placeholder
        existing_private_key = next(
            (v for k, v in interface.items() if k.lower() == "privatekey"),
            None
        )
        if not existing_private_key:
            private_key = get_wireguard_private_key()

            if not private_key:
                # Fresh install — no key in encrypted storage yet.
                # Generate and save keys now so the config can be completed
                # and the public key is available for future API calls.
                logger.info("No private key in encrypted storage — generating keys for fresh install")
                public_key = setup_vpn_keys()
                if not public_key:
                    logger.error("Failed to generate WireGuard keys on fresh install")
                    return None
                # setup_vpn_keys() returns the public key — re-read the
                # private key from the file it just wrote
                private_key = get_wireguard_private_key()
                if not private_key:
                    logger.error("Keys generated but private key could not be read back")
                    return None

            interface["PrivateKey"] = private_key
            # Remove any empty placeholder the server sent so we don't
            # write duplicate keys with different casing to the conf file
            for k in list(interface.keys()):
                if k.lower() == "privatekey" and k != "PrivateKey":
                    del interface[k]
            logger.info("PrivateKey injected into config from encrypted settings")

        def _conf_value(v):
            """Flatten list values to comma-separated strings for WireGuard conf format."""
            if isinstance(v, list):
                return ", ".join(str(x).strip() for x in v)
            return v

        def _section_lines(section, entries):
            """Validate and render one section. Every key/value comes from the
            server, so reject newline/control-char injection, script hooks
            (PostUp etc.) and malformed values; skip keys that are not part of
            the WireGuard format."""
            out = []
            for k, v in entries.items():
                if v is None or v == "" or v == []:
                    continue
                if not validate_section_entry(section, k, v):
                    logger.warning(f"Ignoring unsupported [{section}] key from server: {k!r}")
                    continue
                out.append(f"{k} = {_conf_value(v)}")
            return out

        # Build WireGuard .conf text
        lines = []
        lines.append("[Interface]")
        lines.extend(_section_lines("Interface", interface))

        lines.append("")  # blank line between sections
        lines.append("[Peer]")
        lines.extend(_section_lines("Peer", peer))

        conf_text = "\n".join(lines).strip() + "\n"

        if not conf_text.strip():
            raise ValueError("Generated WireGuard config is empty")

        config_dir = get_writable_wireguard_dir()
        os.makedirs(config_dir, exist_ok=True)

        config_path = os.path.join(config_dir, f"{config_name}.conf")

        with open(config_path, "w", encoding="utf-8", newline="\n") as f:
            f.write(conf_text)
            f.flush()
            os.fsync(f.fileno())

        logger.info(f"VPN configuration saved to: {os.path.abspath(config_path)}")
        return config_path

    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse VPN config JSON: {e}")
        return None
    except Exception as e:
        logger.error(f"Error creating VPN config: {e}")
        return None


def save_vpn_configuration(
    vpn_config_json: str,
    config_name: str = "resistine",
) -> str | None:
    """Alias for parse_and_create_vpn_config."""
    return parse_and_create_vpn_config(vpn_config_json, config_name)
