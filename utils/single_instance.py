"""One Phoenix per user: a second launch brings the running window forward.

The first launch takes a lock file in the config dir (QLockFile, which clears
locks left by a crashed process) and listens on a per-user local socket. A
later launch can't take the lock, so it asks the running app over that socket
to show its window, then exits.
"""

from __future__ import annotations

import getpass
import os
import re
from typing import Callable, Optional

from PyQt6.QtCore import QLockFile
from PyQt6.QtNetwork import QLocalServer, QLocalSocket

from utils.logger import logger

_SHOW = b"show\n"
_lock: Optional[QLockFile] = None
_server: Optional[QLocalServer] = None


def _name() -> str:
    try:
        user = getpass.getuser()
    except Exception:  # noqa: BLE001 - no user name: fall back to the uid
        user = str(getattr(os, "getuid", lambda: 0)())
    return "phoenix-desktop-" + re.sub(r"[^A-Za-z0-9_.-]", "_", user)


def _lock_path() -> str:
    from utils.settings import get_config_dir

    d = get_config_dir()
    os.makedirs(d, exist_ok=True)
    return os.path.join(d, "phoenix.lock")


def _ask_running_instance_to_show(timeout_ms: int = 3000) -> bool:
    """Tell the running app to show its window. False if none answered."""
    sock = QLocalSocket()
    for _ in range(max(1, timeout_ms // 250)):
        sock.connectToServer(_name())
        if sock.waitForConnected(250):
            sock.write(_SHOW)
            sock.flush()
            sock.waitForBytesWritten(500)
            sock.disconnectFromServer()
            return True
    return False


def acquire() -> bool:
    """True if this is the only Phoenix for this user and should run.

    False means another one is running and has been asked to show itself.
    Errors never stop the app from starting.
    """
    global _lock
    try:
        lock = QLockFile(_lock_path())
        lock.setStaleLockTime(0)  # stale only when its process is gone
        if lock.tryLock(0):
            _lock = lock
            return True
        if _ask_running_instance_to_show():
            return False
        # Locked but nobody listening (still starting, or hung): don't start
        # a second copy on top of it.
        logger.warning("Phoenix is already running but didn't answer")
        return False
    except Exception as e:  # noqa: BLE001
        logger.warning(f"Single-instance check skipped: {e}")
        return True


def listen(on_show: Callable[[], None]) -> None:
    """Call *on_show* (on the GUI thread) whenever another launch asks."""
    global _server
    if _lock is None:
        return
    server = QLocalServer()
    # Holding the lock means any socket by this name is a dead process's.
    QLocalServer.removeServer(_name())
    server.setSocketOptions(QLocalServer.SocketOption.UserAccessOption)
    if not server.listen(_name()):
        logger.warning(f"Single-instance socket unavailable: {server.errorString()}")
        return

    def _accept():
        while server.hasPendingConnections():
            conn = server.nextPendingConnection()
            if conn is None:
                return
            conn.waitForReadyRead(500)
            if conn.readAll().data().startswith(_SHOW.strip()):
                logger.info("Another launch asked to show Phoenix")
                on_show()
            conn.disconnectFromServer()

    server.newConnection.connect(_accept)
    _server = server
