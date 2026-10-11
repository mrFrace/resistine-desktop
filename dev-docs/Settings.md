# Unified Settings System

The Unified Settings System (`utils/settings.py`) provides a secure, centralized, and cross-platform way to manage application configuration and sensitive secrets in Resistine.

## Overview

The system uses a **hybrid storage strategy** to balance security and usability:

1.  **Master Key**: A single high-entropy encryption key is generated and stored securely in the system's native keyring (Keychain on macOS, Secret Service/Keyring on Linux, Credential Locker on Windows).
    - _Fallback_: If the system keyring is unavailable, the Master Key is stored in a protected file (`.master.key`) with restricted permissions (`0600`) in the configuration directory.
2.  **Configuration Storage**: Settings are stored in plain JSON files, organized by **namespace** (e.g., `chat.json`, `auth.json`).
3.  **Secret Encryption**: Sensitive values (like API keys or passwords) are encrypted using the Master Key (Fernet symmetric encryption) before being written to the JSON files. They are prefixed with `ENC:` to distinguish them from plain values.

## File Locations

Configuration files are stored in platform-specific directories:

- **macOS**: `~/Library/Application Support/Resistine/`
- **Linux**: `~/.config/resistine/`
- **Windows**: `%APPDATA%\Resistine\`

## API Reference

Import the settings module:

```python
from utils import settings
```

### Basic Operations

#### `get(namespace, key, default=None)`

Retrieve a plain configuration value.

```python
# Get a value with a default
theme = settings.get("ui", "theme", "dark")
```

#### `set(namespace, key, value)`

Save a configuration value. The value must be JSON-serializable.

```python
settings.set("ui", "theme", "light")
settings.set("core", "max_retries", 5)
```

#### `delete(namespace, key)`

Remove a specific setting.

```python
settings.delete("ui", "theme")
```

### Secret Management

#### `set_secret(namespace, key, value)`

Encrypt and save a sensitive string.

```python
settings.set_secret("chat", "openai_api_key", "sk-...")
```

#### `get_secret(namespace, key)`

Retrieve and decrypt a sensitive string. Returns `None` if the key doesn't exist or decryption fails.

```python
api_key = settings.get_secret("chat", "openai_api_key")
```

### Advanced

#### `list_keys(namespace)`

List all keys available in a namespace.

```python
keys = settings.list_keys("auth")
```

#### `clear_namespace(namespace)`

Delete all settings for a namespace (removes the underlying JSON file).

```python
settings.clear_namespace("temp_cache")
```

#### `get_config_dir()`

Get the absolute path to the configuration directory.

```python
config_path = settings.get_config_dir()
```

## Security Considerations

- **Permissions**: The configuration directory is created with `0700` permissions (owner only) on POSIX systems. JSON files are written with `0600` permissions.
- **Encryption**: Secrets are encrypted using `cryptography.fernet` (AES-128 in CBC mode with HMAC).
- **Keyring**: The system prioritizes the OS keyring for Master Key storage, which provides the highest level of security available on the platform.

## Migration

A migration script (`utils/migration.py`) was used to transition from the old `config_manager.py` and `encryption.py` systems. If you encounter missing settings from an older installation, ensure the migration logic covers that specific data source.
