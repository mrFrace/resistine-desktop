"""
Internationalization (i18n) module for Phoenix.
Provides centralized text storage and translation support for user-facing messages.

Author: Petr and the Phoenix Team
Copyright (c) Phoenix 2025
Licensed under the GNU General Public License v2 or later
"""

import json
from pathlib import Path
from utils.logger import logger

# Translation storage - loaded from JSON files
TEXTS = {}

# Default language
DEFAULT_LANGUAGE = 'en'


def load_language_files():
    """
    Load all translation JSON files from the utils/i18n/ directory.
    Called automatically on module import.
    """
    i18n_dir = Path(__file__).parent  # This is already in utils/i18n/ directory
    
    if not i18n_dir.exists():
        logger.warning(f"i18n directory not found at {i18n_dir}")
        return
    
    for json_file in i18n_dir.glob('*.json'):
        if json_file.name.startswith('_'):
            continue  # Skip private files like _template.json
        
        lang = json_file.stem  # e.g., 'en', 'es', 'de'
        
        try:
            with open(json_file, 'r', encoding='utf-8') as f:
                TEXTS[lang] = json.load(f)
        except json.JSONDecodeError as e:
            logger.error(f"Error loading {json_file}: {e}")
        except Exception as e:
            logger.error(f"Unexpected error loading {json_file}: {e}")


def register_plugin_texts(plugin_name, texts_dict):
    """
    Register translations for a plugin.
    
    Plugin texts are namespaced with the plugin name to avoid conflicts.
    
    :param plugin_name: Unique plugin identifier
    :param texts_dict: Dictionary of {language: {key: text}}
    
    Example:
        register_plugin_texts('myplugin', {
            'en': {'error.connection': "Connection failed"},
            'es': {'error.connection': "Conexión fallida"}
        })
        # Use as: get_text('myplugin.error.connection')
    """
    for lang, keys in texts_dict.items():
        if lang not in TEXTS:
            TEXTS[lang] = {}
        
        # Prefix all keys with plugin name to avoid conflicts
        for key, text in keys.items():
            TEXTS[lang][f"{plugin_name}.{key}"] = text


def load_plugin_i18n_dir(plugin_path, plugin_name):
    """
    Load plugin translations from a plugin's i18n directory.
    
    :param plugin_path: Absolute path to the plugin directory
    :param plugin_name: Unique plugin identifier (used for namespacing)
    
    Example directory structure:
        plugins/myplugin/
            i18n/
                en.json
                es.json
            __init__.py
    """
    i18n_dir = Path(plugin_path) / 'i18n'
    
    if not i18n_dir.exists():
        return  # Plugin doesn't have translations
    
    for json_file in i18n_dir.glob('*.json'):
        if json_file.name.startswith('_'):
            continue
        
        lang = json_file.stem
        
        try:
            with open(json_file, 'r', encoding='utf-8') as f:
                texts = json.load(f)
            
            # Register with plugin namespace
            register_plugin_texts(plugin_name, {lang: texts})
        except Exception as e:
            logger.error(f"Error loading plugin i18n from {json_file}: {e}")


def get_text(key, lang=None, **kwargs):
    """
    Get a translated text string with optional formatting.
    
    :param key: The text key in dot notation (e.g., 'encryption.insecure_backend')
    :param lang: Language code (defaults to DEFAULT_LANGUAGE)
    :param kwargs: Optional formatting parameters for the text template
    :return: The translated and formatted text string
    :raises KeyError: If the key is not found in the specified language
    """
    if lang is None:
        lang = DEFAULT_LANGUAGE
    
    # Try requested language
    if lang in TEXTS and key in TEXTS[lang]:
        text = TEXTS[lang][key]
        if kwargs:
            return text.format(**kwargs)
        return text
    
    # Fallback to default language if key doesn't exist in requested language
    if lang != DEFAULT_LANGUAGE and DEFAULT_LANGUAGE in TEXTS and key in TEXTS[DEFAULT_LANGUAGE]:
        text = TEXTS[DEFAULT_LANGUAGE][key]
        if kwargs:
            return text.format(**kwargs)
        return text
    
    raise KeyError(f"Text key '{key}' not found for language '{lang}'")


def get_available_languages():
    """
    Get a list of available language codes.
    
    :return: List of available language codes
    """
    return list(TEXTS.keys())


def has_text(key, lang=None):
    """
    Check if a text key exists for the specified language.
    
    :param key: The text key in dot notation
    :param lang: Language code (defaults to DEFAULT_LANGUAGE)
    :return: True if the key exists, False otherwise
    """
    if lang is None:
        lang = DEFAULT_LANGUAGE
    
    return lang in TEXTS and key in TEXTS[lang]


def reload_translations():
    """
    Reload all translation files from disk.
    Useful for development or when translation files are updated at runtime.
    """
    global TEXTS
    TEXTS = {}
    load_language_files()


# Auto-load translation files when module is imported
load_language_files()
