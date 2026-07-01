"""
Unified Settings Manager for Resistine Desktop.

This module provides a secure and unified way to manage application settings and secrets.
It uses a hybrid approach:
1. A Master Key is stored securely in the system keyring.
2. Configuration is stored in JSON files (one per namespace).
3. Secrets within JSON files are encrypted using the Master Key.
"""

import json
import os
import platform
from threading import RLock
from typing import Any, Dict, List, Optional

import keyring
from cryptography.fernet import Fernet

from utils.logger import logger

# Removed standard logging logger

# Constants
APP_NAME = "Resistine"
MASTER_KEY_SERVICE = "resistine-master-key"
MASTER_KEY_USERNAME = "master-key"
ENCRYPTED_PREFIX = "ENC:"

# Thread-safe lock for file operations.
# RLock (reentrant) allows the same thread to acquire the lock multiple times,
# which is needed because set() holds the lock while calling _save_json() which
# also acquires it.
_lock = RLock()


def get_config_dir() -> str:
    """Get the configuration directory based on the platform."""
    system = platform.system()
    if system == "Darwin":
        return os.path.expanduser("~/Library/Application Support/Resistine")
    elif system == "Windows":
        return os.path.join(
            os.environ.get("APPDATA", os.path.expanduser("~")), "Resistine"
        )
    else:
        # Linux / WSL — honor XDG_CONFIG_HOME
        return os.path.join(
            os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config"),
            "resistine",
        )


def _get_master_key() -> bytes:
    """
    Retrieve the master key from the system keyring.
    If it doesn't exist, generate one and store it.
    """
    with _lock:
        try:
            key = keyring.get_password(MASTER_KEY_SERVICE, MASTER_KEY_USERNAME)
            if key:
                return key.encode()
        except Exception as e:
            logger.warning(f"Failed to retrieve master key from keyring: {e}")

        # Generate new key if not found or retrieval failed
        logger.info("Generating new master key...")
        new_key = Fernet.generate_key()

        try:
            keyring.set_password(MASTER_KEY_SERVICE, MASTER_KEY_USERNAME, new_key.decode())
            logger.info("Master key saved to keyring.")
        except Exception as e:
            logger.error(f"Failed to save master key to keyring: {e}")
            # Fallback: Save to a protected file if keyring fails
            _save_master_key_fallback(new_key)

        return new_key


def _save_master_key_fallback(key: bytes):
    """Save master key to a file with restricted permissions as a fallback."""
    config_dir = get_config_dir()
    os.makedirs(config_dir, exist_ok=True)
    key_file = os.path.join(config_dir, ".master.key")

    try:
        # Set restricted permissions (read/write only by owner)
        if os.path.exists(key_file):
            os.chmod(key_file, 0o600)

        with open(key_file, "wb") as f:
            f.write(key)
        os.chmod(key_file, 0o600)
        logger.info(f"Master key saved to fallback file: {key_file}")
    except Exception as e:
        logger.critical(f"Failed to save master key fallback: {e}")
        raise RuntimeError("Could not save master key to keyring or file.") from e


def _get_master_key_fallback() -> Optional[bytes]:
    """Try to retrieve master key from fallback file."""
    key_file = os.path.join(get_config_dir(), ".master.key")
    if os.path.exists(key_file):
        try:
            with open(key_file, "rb") as f:
                return f.read()
        except Exception as e:
            logger.error(f"Failed to read fallback master key: {e}")
    return None


def _get_fernet() -> Fernet:
    """Get Fernet instance with the master key."""
    with _lock:
        # Try keyring first
        try:
            key_str = keyring.get_password(MASTER_KEY_SERVICE, MASTER_KEY_USERNAME)
            if key_str:
                return Fernet(key_str.encode())
        except Exception:
            pass

        # Try fallback file
        key_bytes = _get_master_key_fallback()
        if key_bytes:
            return Fernet(key_bytes)

        # If neither exists, _get_master_key() will generate and store one
        return Fernet(_get_master_key())


def _get_file_path(namespace: str) -> str:
    """Get the JSON file path for a namespace."""
    config_dir = get_config_dir()
    os.makedirs(config_dir, exist_ok=True)
    # Ensure secure permissions on the directory
    if platform.system() != "Windows":
        try:
            os.chmod(config_dir, 0o700)
        except OSError:
            pass
    return os.path.join(config_dir, f"{namespace}.json")


def _load_json(namespace: str) -> Dict[str, Any]:
    """Load settings from the JSON file."""
    file_path = _get_file_path(namespace)
    if not os.path.exists(file_path):
        return {}

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        logger.error(f"Failed to load settings from {file_path}: {e}")
        return {}


def _save_json(namespace: str, data: Dict[str, Any]) -> bool:
    """Save settings to the JSON file."""
    file_path = _get_file_path(namespace)
    try:
        with _lock:
            with open(file_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=4, ensure_ascii=False)

            # Ensure secure permissions on the file
            if platform.system() != "Windows":
                os.chmod(file_path, 0o600)
        return True
    except OSError as e:
        logger.error(f"Failed to save settings to {file_path}: {e}")
        return False


# --- Public API ---


def set(namespace: str, key: str, value: Any) -> bool:
    """
    Set a configuration value.

    Args:
        namespace: The plugin or component name (e.g., 'chat', 'core').
        key: The setting key.
        value: The value to store (must be JSON serializable).
    """
    with _lock:
        data = _load_json(namespace)
        data[key] = value
        return _save_json(namespace, data)


def get(namespace: str, key: str, default: Any = None) -> Any:
    """
    Get a configuration value.

    Args:
        namespace: The plugin or component name.
        key: The setting key.
        default: Value to return if key is missing.
    """
    data = _load_json(namespace)
    return data.get(key, default)


def delete(namespace: str, key: str) -> bool:
    """
    Delete a configuration value.
    """
    with _lock:
        data = _load_json(namespace)
        if key in data:
            del data[key]
            return _save_json(namespace, data)
    return True


def set_secret(namespace: str, key: str, value: str) -> bool:
    """
    Encrypt and store a secret value.

    Args:
        namespace: The plugin or component name.
        key: The secret key.
        value: The secret string to encrypt.
    """
    try:
        f = _get_fernet()
        encrypted_value = f.encrypt(value.encode()).decode()
        stored_value = f"{ENCRYPTED_PREFIX}{encrypted_value}"
        return set(namespace, key, stored_value)
    except Exception as e:
        logger.error(f"Failed to encrypt secret for {namespace}.{key}: {e}")
        return False


def get_secret(namespace: str, key: str) -> Optional[str]:
    """
    Retrieve and decrypt a secret value.

    Returns:
        The decrypted secret string, or None if not found or decryption fails.
    """
    stored_value = get(namespace, key)
    if not stored_value or not isinstance(stored_value, str):
        return None

    if not stored_value.startswith(ENCRYPTED_PREFIX):
        logger.warning(f"Value for {namespace}.{key} is not encrypted.")
        return stored_value  # Return as-is if not marked encrypted (legacy support?)

    try:
        encrypted_data = stored_value[len(ENCRYPTED_PREFIX) :]
        f = _get_fernet()
        return f.decrypt(encrypted_data.encode()).decode()
    except Exception as e:
        logger.error(f"Failed to decrypt secret for {namespace}.{key}: {e}")
        return None


def list_keys(namespace: str) -> List[str]:
    """List all keys in a namespace."""
    data = _load_json(namespace)
    return list(data.keys())


def clear_namespace(namespace: str) -> bool:
    """Delete all settings for a namespace (removes the file)."""
    file_path = _get_file_path(namespace)
    if os.path.exists(file_path):
        try:
            os.remove(file_path)
            return True
        except OSError as e:
            logger.error(f"Failed to clear namespace {namespace}: {e}")
            return False
    return True
