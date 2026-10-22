# Store Plugin

The official Phoenix Plugin Marketplace.

## Features
- Browse available plugins with detailed descriptions.
- One-click installation to the user's local configuration directory.
- Manage installed plugins with the uninstallation interface.
- View detailed documentation for each plugin via the "Info" button.

## Architecture
Downloaded plugins are stored in the user's home directory (`~/.config/phoenix/plugins`), allowing the application to remain functional even in read-only environments.
