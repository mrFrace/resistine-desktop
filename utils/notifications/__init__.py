"""
Cross-Platform System Notification Package.

Usage:
    from utils import notifications

    notifications.init()
    notifications.send("Title", "Body", urgency="normal")
"""

from utils.notifications.manager import init, send

__all__ = ["init", "send"]
