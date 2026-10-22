"""
Cross-Platform Uninstall Package.

Usage:
    from utils import uninstall

    uninstall.is_available()
    uninstall.run_uninstall(app, progress_callback)
"""

from utils.uninstall.manager import is_available, run_uninstall

__all__ = ["is_available", "run_uninstall"]
