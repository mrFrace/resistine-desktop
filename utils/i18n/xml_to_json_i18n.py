#!/usr/bin/env python3
"""
Convert Android strings.xml to translations_EN.json

- Reads an Android-style strings.xml file.
- Extracts <string> entries.
- Replaces '_' with '.' in each key.
- Writes a JSON file like: { "app.title": "Super App", ... }

Usage:
    python xml_to_json_i18n.py \
        --input strings.xml \
        --output translations_EN.json

Author: Petr and the Phoenix Team
Copyright (c) Phoenix 2025
Licensed under the GNU General Public License v2 or later
"""

import argparse
import json
import xml.etree.ElementTree as ET
from pathlib import Path


def parse_strings_xml(input_path: Path) -> dict:
    """Parse an Android strings.xml and return a dict of key -> value."""
    tree = ET.parse(input_path)
    root = tree.getroot()

    translations = {}

    for elem in root.findall("string"):
        name = elem.attrib.get("name")
        if not name:
            continue

        # Skip non-translatable if you want; comment out this block if not needed.
        if elem.attrib.get("translatable") == "false":
            continue

        # Replace underscores with dots in the key
        key = name.replace("_", ".")

        # Get all text inside the element (handles simple inline tags if present)
        text_parts = []
        for node in elem.itertext():
            text_parts.append(node)
        value = "".join(text_parts).strip()

        translations[key] = value

    return translations


def main():
    parser = argparse.ArgumentParser(
        description="Extract i18n strings from Android strings.xml into translations_EN.json",
    )
    parser.add_argument(
        "--input",
        "-i",
        type=Path,
        default=Path("strings.xml"),
        help="Path to input strings.xml (default: ./strings.xml)",
    )
    parser.add_argument(
        "--output",
        "-o",
        type=Path,
        default=Path("translations_EN.json"),
        help="Path to output JSON file (default: ./translations_EN.json)",
    )

    args = parser.parse_args()

    if not args.input.exists():
        raise FileNotFoundError(f"Input file not found: {args.input}")

    translations = parse_strings_xml(args.input)

    # Write pretty JSON for easier reviewing / diffing
    with args.output.open("w", encoding="utf-8") as f:
        json.dump(translations, f, ensure_ascii=False, indent=2, sort_keys=True)

    print(f"Wrote {len(translations)} entries to {args.output}")


if __name__ == "__main__":
    main()
