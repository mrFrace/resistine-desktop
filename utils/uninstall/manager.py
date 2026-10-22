"""
Cross-Platform Uninstall Manager.

Provides a single interface for uninstalling Phoenix on all platforms.
Dispatches to the appropriate backend for platform-specific cleanup.

Architecture:
    utils/uninstall/
    ├── manager.py         ← shared interface (this file)
    ├── darwin.py          ← macOS: full cleanup
    ├── windows.py         ← Windows (stub)
    └── linux.py           ← Linux (stub)

Usage:
    from utils import uninstall

    uninstall.is_available()
    uninstall.run_uninstall(app, progress_callback)

Author: Resistine Team
Copyright (c) Resistine 2025
Licensed under the GNU General Public License v2 or later
"""

import platform

from utils.logger import logger

# ---------------------------------------------------------------------------
# Platform detection
# ---------------------------------------------------------------------------
_PLATFORM = platform.system()

_backend = None

if _PLATFORM == "Darwin":
    from utils.uninstall import darwin as _backend
elif _PLATFORM == "Windows":
    from utils.uninstall import windows as _backend
elif _PLATFORM == "Linux":
    from utils.uninstall import linux as _backend

# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def is_available():
    """Return True if uninstall is supported on this platform."""
    if _backend is None:
        return False
    return _backend.is_available()


def run_uninstall(app, progress_callback=None):
    """Execute the full uninstall sequence.

    Args:
        app: The main App instance.
        progress_callback: Optional callable(step_description: str) for UI updates.

    Returns:
        (bool, str): (success, message)
    """
    if _backend is None:
        return (False, "Uninstall not supported on this platform")
    return _backend.run_uninstall(app, progress_callback)
