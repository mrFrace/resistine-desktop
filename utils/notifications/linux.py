"""Linux system notifications via the freedesktop.org Desktop Notifications spec.

Primary path: the ``org.freedesktop.Notifications`` D-Bus service, called over
the session bus with jeepney — a pure-Python D-Bus client we already depend on
(keyring/secretstorage pull it in). This is the cross-desktop standard, so it
works on GNOME/KDE/XFCE/Cinnamon/etc. with whatever notification daemon is
running, with no extra binary and no PyGObject. Falls back to the ``notify-send``
CLI if the bus isn't reachable (e.g. no session bus / headless).

Sending runs on a daemon thread because opening the bus and awaiting the reply
blocks briefly; the macOS backend's send is async, so this keeps parity (never
stalls the caller, which is usually the UI thread).

Author: Resistine Team
Copyright (c) Resistine 2025
Licensed under the GNU General Public License v2 or later
"""

import os
import shutil
import subprocess
import threading

from utils.logger import logger

# App urgency level -> freedesktop urgency byte (spec: 0 low, 1 normal, 2 crit).
_URGENCY_BYTE = {"low": 0, "normal": 1, "critical": 2}


def _icon() -> str:
    """Absolute path to the bundled app icon, or a themed-icon name fallback.

    Returns a raw filesystem path (what notify-send's -i expects). The D-Bus
    backend converts this to a file:// URI itself (see _dbus_icon).
    """
    # utils/notifications/linux.py -> repo root is three dirs up.
    root = os.path.dirname(
        os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
    )
    path = os.path.join(root, "resources", "icons", "app_icon.png")
    return path if os.path.isfile(path) else "dialog-warning"


def _dbus_icon(icon: str) -> str:
    """freedesktop app_icon must be a themed-icon NAME or a file:// URI — a
    bare absolute path is non-conforming and GNOME may silently fail to render
    it (the notification is accepted but never bannered). Convert paths."""
    if os.path.isabs(icon):
        try:
            from pathlib import Path
            return Path(icon).as_uri()
        except Exception:
            return icon
    return icon


# A single, long-lived session-bus connection shared by all notifications.
# CRITICAL: gnome-shell ties a notification's "source" to the SENDER's bus
# connection and shows the banner asynchronously *after* it has already
# returned the notification id. If we open a connection, send Notify, and close
# it immediately (as we did originally), our unique bus name vanishes before
# gnome-shell renders the banner — so the notification is created (valid id
# returned) but never displayed. Keeping one connection open for the app's
# lifetime keeps the sender (and thus the source) alive. Access is serialized
# by _conn_lock since jeepney's blocking connection isn't concurrency-safe.
_conn = None
_conn_lock = threading.Lock()


def init():
    """No initialization required on Linux (no authorization step)."""
    return


def _get_connection():
    """Return the shared session-bus connection, opening it on first use."""
    global _conn
    if _conn is None:
        from jeepney.io.blocking import open_dbus_connection
        _conn = open_dbus_connection(bus="SESSION")
    return _conn


def _drop_connection():
    """Close + forget the shared connection (so the next send reopens it)."""
    global _conn
    conn, _conn = _conn, None
    if conn is not None:
        try:
            conn.close()
        except Exception:
            pass


# Click handling: notification id -> callback. The daemon emits
# ActionInvoked(id, "default") when the user clicks a notification that
# offered the "default" action; a listener on its own connection (signals
# are broadcast) runs the callback. NotificationClosed forgets it.
_clicks: dict = {}
_clicks_lock = threading.Lock()
_listener_started = False


def _dispatch_signal(member: str, body) -> None:
    """Handle one org.freedesktop.Notifications signal."""
    if not body:
        return
    with _clicks_lock:
        if member == "ActionInvoked" and len(body) >= 2 and body[1] == "default":
            fn = _clicks.pop(body[0], None)
        elif member == "NotificationClosed":
            _clicks.pop(body[0], None)
            return
        else:
            return
    if fn is not None:
        try:
            fn()
        except Exception as e:  # noqa: BLE001
            logger.warning("Notification click handler failed: %s", e)


def _listen() -> None:
    try:
        from jeepney import MatchRule, message_bus
        from jeepney.io.blocking import Proxy, open_dbus_connection
        from jeepney.low_level import HeaderFields

        conn = open_dbus_connection(bus="SESSION")
        rule = MatchRule(type="signal", interface="org.freedesktop.Notifications",
                         path="/org/freedesktop/Notifications")
        Proxy(message_bus, conn).AddMatch(rule)
        with conn.filter(rule) as queue:
            while True:
                msg = conn.recv_until_filtered(queue)
                _dispatch_signal(msg.header.fields.get(HeaderFields.member), msg.body)
    except Exception as e:  # noqa: BLE001
        logger.debug("Notification click listener stopped: %s", e)


def _ensure_listener() -> None:
    global _listener_started
    with _clicks_lock:
        if _listener_started:
            return
        _listener_started = True
    threading.Thread(target=_listen, name="notification-clicks", daemon=True).start()


def _send_via_dbus(title: str, body: str, urgency_byte: int, icon: str, on_click=None):
    """Try the D-Bus path. Returns None on success, else an error string."""
    try:
        from jeepney import DBusAddress, new_method_call
        from jeepney.low_level import HeaderFields, MessageType
    except Exception as e:
        return f"jeepney unavailable: {e!r}"

    addr = DBusAddress(
        "/org/freedesktop/Notifications",
        bus_name="org.freedesktop.Notifications",
        interface="org.freedesktop.Notifications",
    )
    # Notify(app_name, replaces_id, app_icon, summary, body,
    #        actions, hints, expire_timeout). expire -1 = daemon default;
    #        critical-urgency notifications persist until dismissed.
    msg = new_method_call(
        addr, "Notify", "susssasa{sv}i",
        ("Phoenix", 0, _dbus_icon(icon), title, body,
         ["default", "Open"] if on_click else [],
         # desktop-entry ties the notification to our installed phoenix.desktop
         # (see utils/linux_desktop.py) so GNOME shows "Phoenix" + our icon
         # instead of the window's WM_CLASS-derived name.
         {"urgency": ("y", urgency_byte),
          "desktop-entry": ("s", "phoenix")}, -1),
    )

    last_err = ""
    with _conn_lock:
        # Reuse the persistent connection; if it has died (bus restart, etc.)
        # drop it and reopen once.
        for attempt in (1, 2):
            try:
                reply = _get_connection().send_and_get_reply(msg)
                # Error replies are returned, not raised — check explicitly so
                # a daemon rejection doesn't masquerade as success.
                if reply.header.message_type == MessageType.error:
                    name = reply.header.fields.get(HeaderFields.error_name)
                    return f"daemon error {name}: {reply.body}"
                if on_click and reply.body:
                    with _clicks_lock:
                        _clicks[reply.body[0]] = on_click
                return None
            except Exception as e:
                last_err = f"{type(e).__name__}: {e}"
                _drop_connection()  # force reopen on retry
    return last_err


def _send_via_notify_send(title: str, body: str, urgency: str,
                          icon: str) -> bool:
    if shutil.which("notify-send") is None:
        return False
    try:
        subprocess.Popen(
            ["notify-send", "--app-name=Phoenix",
             f"--urgency={urgency}", "-i", icon, title, body],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return True
    except Exception as e:
        logger.debug("notify-send notification failed: %s", e)
        return False


def send(title: str, body: str, urgency: str = "normal", on_click=None):
    """Send a Linux desktop notification. Never raises.

    Args:
        title: Notification title.
        body: Notification body text.
        urgency: One of "low", "normal", "critical".
        on_click: called (on a background thread) when the user clicks it;
                  D-Bus path only, notify-send can't report clicks.
    """
    urgency_byte = _URGENCY_BYTE.get(urgency, 1)
    icon = _icon()
    if on_click:
        _ensure_listener()

    def _run():
        dbus_err = _send_via_dbus(title, body, urgency_byte, icon, on_click)
        if dbus_err is None:
            return
        if _send_via_notify_send(title, body, urgency, icon):
            logger.debug("Notification delivered via notify-send (D-Bus: %s)",
                         dbus_err)
            return
        # Both paths failed — surface it so a silent miss is diagnosable.
        logger.warning(
            "Desktop notification not delivered — D-Bus failed (%s) and "
            "notify-send is unavailable. Install libnotify-bin or ensure a "
            "notification daemon + session bus are running.",
            dbus_err,
        )

    threading.Thread(target=_run, daemon=True).start()
