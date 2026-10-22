"""
Version Helper — single source of truth for the current app version.

Frozen (PyInstaller) builds: reads from the bundled VERSION file in _MEIPASS.
Source / dev mode: parses VERSION = '...' from packaging/Resistine.spec.

Author: Resistine Team
Copyright (c) Resistine 2025
Licensed under the GNU General Public License v2 or later
"""

import os
import re
import sys

from utils.logger import logger

_VERSION_RE = re.compile(r"^VERSION\s*=\s*['\"](.+?)['\"]", re.MULTILINE)

# Project root: utils/updates/version.py -> utils/updates -> utils -> project root
_PROJECT_ROOT = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)


def get_project_root() -> str:
    """Return the absolute path to the project root directory."""
    return _PROJECT_ROOT


def get_current_version() -> str:
    """Return the current application version.

    Frozen builds: reads the VERSION file placed by PyInstaller.
    Source / dev: parses VERSION = '...' from packaging/Resistine.spec.
    Returns '0.0.0' if the version cannot be determined.
    """
    # Frozen build — read the bundled VERSION file
    if getattr(sys, "frozen", False):
        meipass = getattr(sys, "_MEIPASS", os.path.dirname(sys.executable))
        version_file = os.path.join(meipass, "VERSION")
        try:
            with open(version_file, "r", encoding="utf-8") as f:
                version = f.read().strip()
            if version:
                return version
        except (OSError, IOError) as e:
            logger.warning(f"[VERSION] Could not read bundled VERSION file: {e}")

    # Source / dev mode — parse from spec
    spec_path = os.path.join(_PROJECT_ROOT, "packaging", "Resistine.spec")
    try:
        with open(spec_path, "r", encoding="utf-8") as f:
            content = f.read()
        match = _VERSION_RE.search(content)
        if match:
            return match.group(1)
    except (OSError, IOError) as e:
        logger.warning(f"[VERSION] Could not read spec file: {e}")
    return "0.0.0"


def compare_versions(current: str, remote: str) -> int:
    """Compare two dot-separated version strings.

    Splits on '.' and compares each segment as an integer.
    Returns -1 if current < remote, 0 if equal, 1 if current > remote.
    """
    def _parts(v):
        try:
            return [int(x) for x in v.split(".")]
        except (ValueError, AttributeError):
            return [0]

    c = _parts(current)
    r = _parts(remote)
    # Pad to equal length
    length = max(len(c), len(r))
    c.extend([0] * (length - len(c)))
    r.extend([0] * (length - len(r)))

    for a, b in zip(c, r):
        if a < b:
            return -1
        if a > b:
            return 1
    return 0
