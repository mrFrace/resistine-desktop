"""The Terms of Service and Privacy Policy, and whether this user accepted them.

The two documents are docs/Terms.md and docs/Privacy.md (bundled; the Help
plugin lists them too). The installers show the same text, generated from
them by scripts/build/render_legal.py.

``LEGAL_VERSION`` is the version of the pair. Bump it, together with the
"Version" line at the top of both documents, whenever a change needs the
user's agreement again: sign-in is gated on having accepted *this* version.
"""
from __future__ import annotations

import os
import re
import time

from utils import settings
from utils.functions import get_resource_path

LEGAL_VERSION = "2026-11-20"

TERMS = "terms"
PRIVACY = "privacy"
_FILES = {TERMS: "Terms.md", PRIVACY: "Privacy.md"}
_NS = "legal"
_VERSION_LINE = re.compile(r"^\*\*Version (\d{4}-\d{2}-\d{2})\.", re.M)


def path(doc: str) -> str:
    """Path of a bundled document; ``doc`` is TERMS or PRIVACY."""
    return get_resource_path(os.path.join("docs", _FILES[doc]))


def text(doc: str) -> str:
    with open(path(doc), encoding="utf-8") as f:
        return f.read()


def document_version(doc: str) -> str | None:
    """The version date stated in the document itself."""
    try:
        m = _VERSION_LINE.search(text(doc))
    except OSError:
        return None
    return m.group(1) if m else None


def accepted() -> bool:
    """Whether the current version was accepted on this device."""
    return settings.get(_NS, "accepted_version") == LEGAL_VERSION


def accept() -> None:
    """Record acceptance of the current version (what, and when)."""
    settings.set(_NS, "accepted_version", LEGAL_VERSION)
    settings.set(_NS, "accepted_at", int(time.time()))
