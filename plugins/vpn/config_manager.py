
"""
VPN Configuration Manager for Resistine Desktop.

Manages multiple WireGuard configuration files stored in Resistine's
own hidden config directories (not WireGuard's system folders).
Tracks the active config via the settings system.
"""
import os
import re

from utils import settings as app_settings
from utils.logger import logger

RESISTINE_CONFIG_NAME = "resistine"
SETTINGS_NAMESPACE = "vpn"


class VPNConfigManager:
    """Manages multiple VPN configs and tracks which one is active."""

    def __init__(self, wireguard_folder):
        self.wireguard_folder = wireguard_folder

    def list_configs(self):
        """List all available .conf files.

        Returns a list of dicts sorted with Resistine default first:
        [{"name": "resistine", "display_name": "Phoenix (Default)",
          "source": "api", "path": "/path/to/file.conf"}, ...]
        """
        names = self._list_conf_files()
        registry = app_settings.get(SETTINGS_NAMESPACE, "config_registry", {})

        configs = []
        for name in names:
            entry = registry.get(name, {})
            configs.append({
                "name": name,
                "display_name": self.get_display_name(name),
                "source": entry.get("source", "import"),
                "path": os.path.join(self.wireguard_folder, f"{name}.conf"),
            })

        # Sort: Resistine default first, then alphabetical
        configs.sort(key=lambda c: (0 if c["name"] == RESISTINE_CONFIG_NAME else 1, c["name"]))
        return configs

    def get_active_config_name(self):
        """Get the name of the currently active config.

        Falls back to resistine, then first found config.
        Returns None if no configs exist.
        """
        active = app_settings.get(SETTINGS_NAMESPACE, "active_config")
        if active and os.path.exists(os.path.join(self.wireguard_folder, f"{active}.conf")):
            return active

        # Fallback: try resistine
        if os.path.exists(os.path.join(self.wireguard_folder, f"{RESISTINE_CONFIG_NAME}.conf")):
            self.set_active_config(RESISTINE_CONFIG_NAME)
            return RESISTINE_CONFIG_NAME

        # Fallback: first .conf found
        names = self._list_conf_files()
        if names:
            self.set_active_config(names[0])
            return names[0]

        return None

    def set_active_config(self, config_name):
        """Set the active config by name (without .conf extension)."""
        conf_path = os.path.join(self.wireguard_folder, f"{config_name}.conf")
        if not os.path.exists(conf_path):
            logger.error(f"Cannot set active config: {conf_path} does not exist")
            return False
        app_settings.set(SETTINGS_NAMESPACE, "active_config", config_name)
        return True

    def get_active_config_path(self):
        """Get the full path to the active config file."""
        name = self.get_active_config_name()
        if name:
            return os.path.join(self.wireguard_folder, f"{name}.conf")
        return None

    def import_config(self, source_path, content):
        try:
            if not content or not content.strip():
                raise ValueError("Config content is empty")

            filename = os.path.basename(source_path)
            config_name = self.sanitize_filename(filename)

            dest_path = os.path.join(self.wireguard_folder, f"{config_name}.conf")

            if os.path.exists(dest_path):
                base = config_name
                counter = 2
                while os.path.exists(os.path.join(self.wireguard_folder, f"{config_name}.conf")):
                    config_name = f"{base}_{counter}"
                    counter += 1
                dest_path = os.path.join(self.wireguard_folder, f"{config_name}.conf")

            os.makedirs(self.wireguard_folder, exist_ok=True)

            with open(dest_path, "w", encoding="utf-8") as f:
                f.write(content)

            os.chmod(dest_path, 0o600)

            self.register_config(config_name, source="import")
            logger.info(f"Imported config as: {config_name}")
            return True, config_name

        except Exception as e:
            logger.error(f"Failed to import config: {e}")
            return False, str(e)

    def delete_config(self, config_name):
        """Delete a user-imported config.

        Refuses to delete the Resistine default config.
        Returns (True, "") on success or (False, reason) on failure.
        """
        if config_name == RESISTINE_CONFIG_NAME:
            return False, "Cannot delete the Phoenix default configuration"

        conf_path = os.path.join(self.wireguard_folder, f"{config_name}.conf")
        try:
            if os.path.exists(conf_path):
                os.remove(conf_path)

            # Remove from registry
            registry = app_settings.get(SETTINGS_NAMESPACE, "config_registry", {})
            registry.pop(config_name, None)
            app_settings.set(SETTINGS_NAMESPACE, "config_registry", registry)

            # If deleted config was active, switch to resistine or first available
            active = app_settings.get(SETTINGS_NAMESPACE, "active_config")
            if active == config_name:
                self.get_active_config_name()  # triggers fallback logic to set a new active config

            logger.info(f"Deleted config: {config_name}")
            return True, ""

        except Exception as e:
            logger.error(f"Failed to delete config {config_name}: {e}")
            return False, str(e)

    def register_config(self, config_name, source, display_name=None):
        """Register a config in the settings registry."""
        registry = app_settings.get(SETTINGS_NAMESPACE, "config_registry", {})
        registry[config_name] = {
            "source": source,
            "display_name": display_name or (
                "Phoenix (Default)" if config_name == RESISTINE_CONFIG_NAME else config_name
            ),
        }
        app_settings.set(SETTINGS_NAMESPACE, "config_registry", registry)

    def get_display_name(self, config_name):
        """Get human-readable display name for a config."""
        if config_name == RESISTINE_CONFIG_NAME:
            return "Phoenix (Default)"
        registry = app_settings.get(SETTINGS_NAMESPACE, "config_registry", {})
        entry = registry.get(config_name, {})
        return entry.get("display_name", config_name)

    def is_resistine_config(self, config_name):
        """Check if a config is the Resistine API config."""
        return config_name == RESISTINE_CONFIG_NAME

    def migrate_legacy_config(self):
        """One-time migration: rename wg0.conf to resistine_default.conf."""
        legacy_path = os.path.join(self.wireguard_folder, "wg0.conf")
        new_path = os.path.join(self.wireguard_folder, f"{RESISTINE_CONFIG_NAME}.conf")

        if os.path.exists(legacy_path) and not os.path.exists(new_path):
            os.rename(legacy_path, new_path)
            os.chmod(new_path, 0o600)
            self.register_config(RESISTINE_CONFIG_NAME, source="api")
            self.set_active_config(RESISTINE_CONFIG_NAME)
            logger.info(f"Migrated wg0.conf -> {RESISTINE_CONFIG_NAME}.conf")
            return True
        return False

    def sanitize_filename(self, filename):
        """Sanitize a filename for use as a config name.

        Removes .conf extension, replaces non-alphanumeric chars with underscore,
        prevents collision with resistine.
        """
        name = os.path.splitext(filename)[0]
        name = re.sub(r"[^a-zA-Z0-9_-]", "_", name)
        name = name.strip("_-")
        if not name:
            name = "imported"
        if name == RESISTINE_CONFIG_NAME:
            name = f"{name}_user"
        return name

    def _list_conf_files(self):
        """List all .conf file basenames (without extension) in wireguard_folder."""
        if not os.path.exists(self.wireguard_folder):
            return []
        return sorted([
            os.path.splitext(f)[0]
            for f in os.listdir(self.wireguard_folder)
            if f.endswith(".conf")
        ])

