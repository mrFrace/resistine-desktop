#!/usr/bin/env python3
"""
Auto-translation tool for Phoenix i18n system.
Automatically translates missing keys using OpenAI API.

Usage:
    python tools/translate.py --from en --to es
    python tools/translate.py --from en --to de --plugin myplugin
    python tools/translate.py --list-missing --to es

Author: Petr and the Phoenix Team
Copyright (c) Phoenix 2025
Licensed under the GNU General Public License v2 or later
"""

import json
import argparse
from pathlib import Path
import sys
import os

# Add parent directory to path for imports
# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from utils.logger import logger

try:
    from openai import OpenAI
except ImportError:
    logger.error("Error: openai package not installed. Install with: pip install openai")
    sys.exit(1)


def translate_text(text, target_lang, source_lang='en'):
    """
    Translate text using OpenAI API.
    
    :param text: Text to translate
    :param target_lang: Target language code (e.g., 'es', 'de', 'fr')
    :param source_lang: Source language code (default: 'en')
    :return: Translated text
    """
    # Language name mapping
    lang_names = {
        'en': 'English',
        'es': 'Spanish',
        'de': 'German',
        'fr': 'French',
        'it': 'Italian',
        'pt': 'Portuguese',
        'ja': 'Japanese',
        'ko': 'Korean',
        'ar': 'Arabic',
        'tr': 'Turkish',
        'nl': 'Dutch',
        'pl': 'Polish',
        'cs': 'Czech',
        'sk': 'Slovak'
    }
    
    target_name = lang_names.get(target_lang, target_lang)
    
    try:
        client = OpenAI()
        response = client.chat.completions.create(
            model="gpt-4o-mini",  # Using mini for cost effectiveness
            messages=[
                {
                    "role": "system",
                    "content": (
                        f"You are a professional translator. Translate the following text from "
                        f"{source_lang} to {target_name}. "
                        f"IMPORTANT: Preserve all formatting placeholders like {{backend}}, {{key}}, etc. "
                        f"Do not translate placeholder names. Preserve newlines (\\n) exactly as they appear. "
                        f"Only return the translated text, nothing else."
                    )
                },
                {
                    "role": "user",
                    "content": text
                }
            ],
            temperature=0.3,  # Lower temperature for more consistent translations
        )
        
        return response.choices[0].message.content.strip()
    
    except Exception as e:
        logger.error(f"Translation error: {e}")
        return None


def get_missing_keys(source_file, target_file):
    """
    Find keys that exist in source but not in target.
    
    :param source_file: Path to source JSON file
    :param target_file: Path to target JSON file
    :return: Set of missing keys
    """
    with open(source_file, 'r', encoding='utf-8') as f:
        source_data = json.load(f)
    
    if target_file.exists():
        with open(target_file, 'r', encoding='utf-8') as f:
            target_data = json.load(f)
    else:
        target_data = {}
    
    return set(source_data.keys()) - set(target_data.keys()), source_data, target_data


def translate_file(source_lang, target_lang, base_dir, dry_run=False, force=False):
    """
    Translate all missing keys from source language to target language.
    
    :param source_lang: Source language code
    :param target_lang: Target language code
    :param base_dir: Base directory containing language files
    :param dry_run: If True, only show what would be translated
    :param force: If True, retranslate all keys even if they exist
    """
    source_file = base_dir / f"{source_lang}.json"
    target_file = base_dir / f"{target_lang}.json"
    
    if not source_file.exists():
        logger.error(f"Error: Source file {source_file} not found")
        return
    
    missing_keys, source_data, target_data = get_missing_keys(source_file, target_file)
    
    if force:
        missing_keys = set(source_data.keys())
        logger.info(f"Force mode: translating all {len(missing_keys)} keys")
    
    if not missing_keys:
        logger.info(f"✓ No missing translations for {target_lang}")
        return

    logger.info(f"Found {len(missing_keys)} keys to translate from {source_lang} to {target_lang}")

    if dry_run:
        logger.info("\nMissing keys:")
        for key in sorted(missing_keys):
            logger.info(f"  - {key}")
        return
    
    # Translate missing keys
    for i, key in enumerate(sorted(missing_keys), 1):
        source_text = source_data[key]
        logger.info(f"[{i}/{len(missing_keys)}] Translating: {key}")
        
        translated = translate_text(source_text, target_lang, source_lang)
        
        if translated:
            target_data[key] = translated
            logger.info(f"  ✓ {translated[:60]}{'...' if len(translated) > 60 else ''}")
        else:
            logger.error("  ✗ Translation failed")
    
    # Save updated target file
    with open(target_file, 'w', encoding='utf-8') as f:
        json.dump(target_data, f, ensure_ascii=False, indent=2)
    
    logger.info(f"\\n✓ Saved translations to {target_file}")


def list_languages(base_dir):
    """List all available language files."""
    lang_files = list(base_dir.glob('*.json'))
    
    if not lang_files:
        logger.warning(f"No language files found in {base_dir}")
        return
    
    logger.info("Available languages:")
    for lang_file in sorted(lang_files):
        with open(lang_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        logger.info(f"  {lang_file.stem}: {len(data)} keys")


def main():
    parser = argparse.ArgumentParser(
        description="Auto-translate Phoenix i18n files using OpenAI"
    )
    
    parser.add_argument(
        '--from',
        dest='source_lang',
        default='en',
        help='Source language code (default: en)'
    )
    
    parser.add_argument(
        '--to',
        dest='target_lang',
        help='Target language code (e.g., es, de, fr)'
    )
    
    parser.add_argument(
        '--plugin',
        dest='plugin_name',
        help='Plugin name (if translating plugin files)'
    )
    
    parser.add_argument(
        '--list-missing',
        action='store_true',
        help='List missing keys without translating'
    )
    
    parser.add_argument(
        '--list-languages',
        action='store_true',
        help='List all available languages'
    )
    
    parser.add_argument(
        '--force',
        action='store_true',
        help='Retranslate all keys, even if they already exist'
    )
    
    args = parser.parse_args()
    
    # Determine base directory
    if args.plugin_name:
        base_dir = Path(__file__).parent.parent / 'plugins' / args.plugin_name / 'i18n'
    else:
        base_dir = Path(__file__).parent
    
    if not base_dir.exists():
        logger.error(f"Error: Directory {base_dir} does not exist")
        sys.exit(1)
    
    # List languages
    if args.list_languages:
        list_languages(base_dir)
        return
    
    # Validate target language
    if not args.target_lang:
        logger.error("Error: --to <language> is required")
        parser.print_help()
        sys.exit(1)
    
    # Translate
    translate_file(
        args.source_lang,
        args.target_lang,
        base_dir,
        dry_run=args.list_missing,
        force=args.force
    )


if __name__ == '__main__':
    main()
