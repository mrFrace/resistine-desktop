"""
Cross-Platform Auto-Update Package.

Usage:
    from utils import updates

    updates.init(app)
    updates.check_for_updates()
    updates.is_available()
    updates.shutdown()
"""

from utils.updates.manager import check_for_updates, init, is_available, shutdown

__all__ = ["init", "check_for_updates", "is_available", "shutdown"]
