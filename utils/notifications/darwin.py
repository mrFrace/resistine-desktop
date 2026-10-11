"""macOS system notifications via UNUserNotificationCenter.

Extracted from plugins/antivirus/main.py to be a shared backend.
Uses the modern UserNotifications framework (macOS 10.14+) with an
osascript fallback when authorization hasn't been granted yet.

Author: Resistine Team
Copyright (c) Resistine 2025
Licensed under the GNU General Public License v2 or later
"""

import subprocess
import uuid

from utils.logger import logger

_initialized = False
_authorized = False
_delegate = None  # prevent GC of the ObjC delegate
_THREAT_CATEGORY_ID = "THREAT_DETECTED"


def _make_delegate():
    """Build a UNUserNotificationCenterDelegate that allows foreground banners."""
    import objc
    from UserNotifications import UNUserNotificationCenter  # noqa: F401

    # UNNotificationPresentationOptionBanner | Sound
    _PRESENT_BANNER_SOUND = (1 << 4) | (1 << 1)

    NSObject = objc.lookUpClass("NSObject")

    class _Delegate(NSObject):
        """Delegate that opts in to foreground notification display."""

        def userNotificationCenter_willPresentNotification_withCompletionHandler_(
            self, center, notification, handler,
        ):
            handler(_PRESENT_BANNER_SOUND)

    _Delegate.protocols = [
        objc.protocolNamed("UNUserNotificationCenterDelegate"),
    ]
    return _Delegate.alloc().init()


def _set_auth(granted: bool, err):
    global _authorized  # noqa: PLW0603
    _authorized = granted
    if granted:
        logger.debug("macOS notification authorization granted")
    elif err:
        logger.warning("macOS notification authorization denied: %s", err)
    else:
        logger.debug("macOS notification authorization denied by user")


def init():
    """Request macOS notification authorization (call once at startup).

    Must be called on the main thread — UNUserNotificationCenter
    delegate installation requires it. Safe to call multiple times
    (only the first call has any effect).
    """
    global _initialized, _authorized, _delegate  # noqa: PLW0603
    if _initialized:
        return
    _initialized = True
    try:
        from UserNotifications import UNUserNotificationCenter

        center = UNUserNotificationCenter.currentNotificationCenter()

        # Install delegate so notifications display while app is foreground
        _delegate = _make_delegate()
        center.setDelegate_(_delegate)

        # alert | sound | badge
        center.requestAuthorizationWithOptions_completionHandler_(
            0x1 | 0x2 | 0x4,
            lambda granted, err: _set_auth(granted, err),
        )

        # Register a "threat" category so critical alerts persist as alerts
        from UserNotifications import (
            UNNotificationAction,
            UNNotificationCategory,
        )

        view_action = UNNotificationAction.actionWithIdentifier_title_options_(
            "VIEW", "View in Phoenix", 1 << 2,  # foreground
        )
        threat_category = UNNotificationCategory.categoryWithIdentifier_actions_intentIdentifiers_options_(
            _THREAT_CATEGORY_ID, [view_action], [], 0,
        )
        center.setNotificationCategories_({threat_category})
    except ImportError:
        logger.warning("UserNotifications framework not available (pyobjc missing?)")
    except Exception as e:
        logger.warning("Failed to request notification authorization: %s", e)


def send(title: str, body: str, urgency: str = "normal"):
    """Send a macOS system notification. Never raises.

    Args:
        title: Notification title.
        body: Notification body text.
        urgency: Accepted but unused — macOS has no public urgency API
                 for third-party apps.
    """
    if _authorized:
        try:
            from UserNotifications import (
                UNMutableNotificationContent,
                UNNotificationRequest,
                UNNotificationSound,
                UNUserNotificationCenter,
            )

            center = UNUserNotificationCenter.currentNotificationCenter()
            content = UNMutableNotificationContent.alloc().init()
            content.setTitle_(title)
            content.setBody_(body)
            content.setSound_(UNNotificationSound.defaultSound())
            if urgency == "critical":
                content.setCategoryIdentifier_(_THREAT_CATEGORY_ID)

            request = UNNotificationRequest.requestWithIdentifier_content_trigger_(
                str(uuid.uuid4()), content, None,
            )
            center.addNotificationRequest_withCompletionHandler_(request, None)
            return
        except Exception as e:
            logger.warning("UNUserNotificationCenter send failed, trying osascript: %s", e)

    # Fallback: osascript (works without authorization).
    # Strip newlines and control chars to prevent AppleScript injection.
    safe_body = body.replace("\n", " ").replace("\r", "")
    safe_body = safe_body.replace("\\", "\\\\").replace('"', '\\"')
    safe_title = title.replace("\n", " ").replace("\r", "")
    safe_title = safe_title.replace("\\", "\\\\").replace('"', '\\"')
    script = (
        f'display notification "{safe_body}" '
        f'with title "{safe_title}" sound name "default"'
    )
    try:
        subprocess.Popen(
            ["osascript", "-e", script],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except Exception as e:
        logger.debug("osascript notification fallback failed: %s", e)
