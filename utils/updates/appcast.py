"""
Appcast Feed Parser — fetches and parses the Sparkle appcast XML feed.

The same appcast.xml hosted on GitHub Pages serves all platforms.
macOS items have no sparkle:os attribute (Sparkle convention).
Windows items use sparkle:os="windows", Linux uses sparkle:os="linux".

Author: Resistine Team
Copyright (c) Resistine 2025
Licensed under the GNU General Public License v2 or later
"""
from __future__ import annotations

import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Optional

import requests

from utils.logger import logger
from utils.updates.version import compare_versions

APPCAST_URL = "https://resistine.github.io/appcast.xml"

_SPARKLE_NS = "http://www.andymatuschak.org/xml-namespaces/sparkle"


@dataclass
class AppcastItem:
    """A single release entry from the appcast feed."""
    title: str = ""
    version: str = ""
    release_notes_html: str = ""
    download_url: str = ""
    download_length: int = 0
    signature: str = ""
    os: str = ""


def fetch_appcast(url: str = APPCAST_URL, timeout: int = 15) -> list[AppcastItem]:
    """Download and parse the appcast.xml feed.

    Returns all items (newest first based on document order, which the
    appcast already maintains).  Returns an empty list on network or
    parse errors.
    """
    try:
        resp = requests.get(url, timeout=timeout)
        resp.raise_for_status()
    except Exception as e:
        logger.error(f"[APPCAST] Failed to fetch feed: {e}")
        return []

    try:
        root = ET.fromstring(resp.content)
    except ET.ParseError as e:
        logger.error(f"[APPCAST] Failed to parse XML: {e}")
        return []

    items = []
    for item_el in root.iter("item"):
        ai = AppcastItem()

        title_el = item_el.find("title")
        if title_el is not None and title_el.text:
            ai.title = title_el.text.strip()

        desc_el = item_el.find("description")
        if desc_el is not None and desc_el.text:
            ai.release_notes_html = desc_el.text.strip()

        enc_el = item_el.find("enclosure")
        if enc_el is not None:
            ai.download_url = enc_el.get("url", "")
            ai.signature = enc_el.get(f"{{{_SPARKLE_NS}}}edSignature", "")
            ai.os = enc_el.get(f"{{{_SPARKLE_NS}}}os", "")

            version = enc_el.get(f"{{{_SPARKLE_NS}}}version", "")
            short_version = enc_el.get(
                f"{{{_SPARKLE_NS}}}shortVersionString", ""
            )
            ai.version = short_version or version

            try:
                ai.download_length = int(enc_el.get("length", "0"))
            except (ValueError, TypeError):
                ai.download_length = 0

        items.append(ai)

    logger.info(f"[APPCAST] Parsed {len(items)} items from feed")
    return items


def get_latest_update(
    current_version: str, platform_os: str, url: str = APPCAST_URL
) -> Optional[AppcastItem]:
    """Return the newest appcast item for *platform_os* newer than *current_version*.

    Filters for items where ``os == platform_os`` and returns the first
    (newest) one whose version is greater than *current_version*.
    Returns ``None`` if already up-to-date or on any error.
    """
    items = fetch_appcast(url)
    for item in items:
        if item.os != platform_os:
            continue
        if compare_versions(current_version, item.version) < 0:
            logger.info(
                f"[APPCAST] {platform_os} update available: {item.version} "
                f"(current: {current_version})"
            )
            return item
    return None


def get_latest_linux_update(
    current_version: str, url: str = APPCAST_URL
) -> Optional[AppcastItem]:
    """Return the newest Linux appcast item newer than *current_version*."""
    return get_latest_update(current_version, "linux", url)


def get_latest_windows_update(
    current_version: str, url: str = APPCAST_URL
) -> Optional[AppcastItem]:
    """Return the newest Windows appcast item newer than *current_version*."""
    return get_latest_update(current_version, "windows", url)
