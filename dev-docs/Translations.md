# Resistine I18n System Documentation

## Overview

The Resistine Internationalization (i18n) system provides centralized translation management using JSON files with automatic translation support via OpenAI.


## Quick Start

### Using Translations in Your Code

    from utils.i18n import get_text

    # Simple text retrieval
    print(get_text('main.app_title'))  # "Resistine"

    # With formatting parameters
    error_msg = get_text('main.helper.registration_error', error="Permission denied")
    # "⚠️ Helper registration error: Permission denied"

    # Specify language (falls back to English if not available)
    text = get_text('main.registration.welcome', lang='es')


## File Structure

    utils/
      i18n/
        __init__.py      # Main i18n module (auto-loads translations)
        translate.py     # Auto-translation utility
        en.json          # English translations (default)
        es.json          # Spanish translations
        de.json          # German translations
        ...

    plugins/
      myplugin/
        i18n/
          en.json
          es.json

## Translation Files

### Format: `utils/i18n/en.json`

    {
      "category.key": "Text with {placeholder}",
      "main.app_title": "Resistine",
      "main.registration.welcome": "Welcome to Resistine"
    }

**Naming Convention**: `module.category.specific_key`

Examples:
- `encryption.insecure_backend`
- `main.debug_window.title`
- `main.registration.error.empty`


## Plugin Integration

### Option 1: In-Memory Registration

    # plugins/myplugin/__init__.py
    from utils.i18n import register_plugin_texts

    TEXTS = {
        'en': {
            'status.connected':' "Connected to server",
            'error.timeout': "Connection timeout after {seconds}s"
        },
        'es': {
            'status.connected': "Conectado al servidor",
            'error.timeout': "Tiempo de espera agotado después de {seconds}s"
        }
    }

    def initialize():
        register_plugin_texts('myplugin', TEXTS)
        
    # Use in plugin
    from utils.i18n import get_text
    print(get_text('myplugin.status.connected'))

### Option 2: JSON Files (Recommended)

    # plugins/myplugin/__init__.py
    from utils.i18n import load_plugin_i18n_dir
    from pathlib import Path

    def initialize():
        plugin_dir = Path(__file__).parent
        load_plugin_i18n_dir(plugin_dir, 'myplugin')

Create: `plugins/myplugin/i18n/en.json`:
    {
      "status.connected": "Connected to server",
      "error.timeout": "Connection timeout after {seconds}s"
    }


## Auto-Translation Tool

### Usage

    # List available languages
    python utils/i18n/translate.py --list-languages

    # List missing translations (dry-run)
    python utils/i18n/translate.py --from en --to es --list-missing

    # Auto-translate missing keys from English to Spanish
    python utils/i18n/translate.py --from en --to es

    # Force re-translate all keys
    python utils/i18n/translate.py --from en --to de --force

    # Translate plugin
    python utils/i18n/translate.py --from en --to fr --plugin myplugin

### Supported Languages

English (en), Spanish (es), German (de), French (fr), Italian (it), Portuguese (pt), Russian (ru), Chinese (zh), Japanese (ja), Korean (ko), Arabic (ar), Dutch (nl), Polish (pl), Turkish (tr)

### Requirements

    pip install openai
    export OPENAI_API_KEY="your-api-key"

## API Reference

### `get_text(key, lang=None, **kwargs)`

Retrieve translated text with optional formatting.

**Parameters**:
- `key` (str): Translation key in dot notation
- `lang` (str, optional): Language code (defaults to 'en')
- `**kwargs`: Formatting parameters

**Returns**: Formatted string

**Raises**: `KeyError` if key not found

**Example**:
    get_text('main.helper.registration_error', error="Access denied")


### `register_plugin_texts(plugin_name, texts_dict)`

Register plugin translations programmatically.

**Parameters**:
- `plugin_name` (str): Unique plugin identifier
- `texts_dict` (dict): `{language: {key: text}}`

---

### `load_plugin_i18n_dir(plugin_path, plugin_name)`

Load plugin translations from JSON files.

**Parameters**:
- `plugin_path` (str/Path): Path to plugin directory
- `plugin_name` (str): Unique plugin identifier

---

### `get_available_languages()`

Get list of loaded languages.

**Returns**: List of language codes

---

### `has_text(key, lang=None)`

Check if translation exists.

**Returns**: Boolean

---

### `reload_translations()`

Reload all translation files from disk.


## Best Practices

### 1. **Consistent Naming**
Use hierarchical keys: `module.feature.specific`

✅ Good:

    {
      "dashboard.menu.home": "Home",
      "dashboard.menu.settings": "Settings",
      "dashboard.error.connection": "Connection failed"
    }


❌ Bad:
    {
      "home": "Home",
      "settings_text": "Settings",
      "errConnectionFailed": "Connection failed"
    }

### 2. **Use Placeholders**

    {
      "error.timeout": "Timeout after {seconds}s",
      "user.greeting": "Hello, {name}!"
    }

### 3. **Preserve Formatting**
Newlines (`\n`), special characters, and emojis are supported:

    {
      "helper.message": "Line 1\nLine 2",
      "status.success": "✅ Success!"
    }

### 4. **Keep Translations Short**
UI text should be concise for better UX.

### 5. **Auto-translate, Then Review**
Use the translation tool for first pass, then have native speakers review.


## Migration Guide

### Converting Hardcoded Strings

**Before**:
    print("Key securely stored in system keyring.")
    raise ValueError("No key found in keyring.")

**After**:
    from utils.i18n import get_text

    print(get_text('encryption.key_stored_keyring'))
    raise ValueError(get_text('encryption.no_key_found'))

### Add to en.json:

    {
      "encryption.key_stored_keyring": "Key securely stored in system keyring.",
      "encryption.no_key_found": "No key found in keyring."
    }


## Troubleshooting

### Import Error
    ImportError: cannot import name 'get_text' from 'utils.i18n'

**Solution**: The i18n module is now a package. Import works correctly after restructuring.

### Key Not Found
    KeyError: "Text key 'mykey' not found for language 'en'"

**Solution**: Check that the key exists in `utils/i18n/en.json`. Keys are case-sensitive.

### Translation Not Updating
    from utils.i18n import reload_translations
    reload_translations()  # Force reload from disk

---

## Examples

### Complete Plugin Example

**File**: `plugins/alerts/i18n/en.json`

    {
      "title": "Security Alerts",
      "no_alerts": "No alerts at this time",
      "severity.high": "High",
      "severity.medium": "Medium",
      "severity.low": "Low",
      "alert.detected": "Alert detected at {time  stamp}"
    }

**File**: `plugins/alerts/main.py`

    from utils.i18n import load_plugin_i18n_dir, get_text
    from pathlib import Path

    class Plugin:
        def __init__(self):
            # Load plugin translations
            plugin_dir = Path(__file__).parent
            load_plugin_i18n_dir(plugin_dir, 'alerts')
        
        def show_alert(self, severity, timestamp):
            title = get_text('alerts.title')
            severity_text = get_text(f'alerts.severity.{severity}')
            message = get_text('alerts.alert.detected', timestamp=timestamp)
            
            print(f"{title}: [{severity_text}] {message}")



## Future Enhancements

- [ ] Web UI for translation management
- [ ] Pluralization support
- [ ] Context-aware translations
- [ ] Translation memory/glossary
- [ ] CI/CD integration for translation validation
