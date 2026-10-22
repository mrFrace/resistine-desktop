"""Cross-platform modal dialogs (PyQt6).

Ports the CustomTkinter dialog helpers used by the platform backends (sudo
password prompts on Linux, helper-approval confirmations on macOS, update
notices). The public names/signatures are unchanged — ``CTkPasswordDialog``,
``ask_yes_no``, ``show_info`` — so the backend modules that import them keep
working verbatim.

Crucially, these are invoked from BACKGROUND THREADS (e.g. while a VPN/Wazuh
operation runs off the GUI thread). Qt widgets may only be touched on the GUI
thread, so every dialog is marshalled onto it via :func:`_run_on_main`, which
blocks the calling worker until the user responds and returns the result.

Author: Resistine Team
Copyright (c) Resistine 2025
Licensed under the GNU General Public License v2 or later
"""

from __future__ import annotations

import threading
from typing import Callable

from PyQt6.QtCore import QCoreApplication, QObject, Qt, QThread, pyqtSignal
from PyQt6.QtWidgets import QApplication, QInputDialog, QLineEdit, QMessageBox


class _Invoker(QObject):
    """Runs a callable on the thread this object lives in (the GUI thread)."""

    _signal = pyqtSignal(object)

    def __init__(self):
        super().__init__()
        self._signal.connect(self._run, Qt.ConnectionType.QueuedConnection)

    def _run(self, fn):
        fn()


_invoker: _Invoker | None = None


def _get_invoker() -> _Invoker | None:
    global _invoker
    app = QCoreApplication.instance()
    if app is None:
        return None
    if _invoker is None:
        _invoker = _Invoker()
        _invoker.moveToThread(app.thread())
    return _invoker


def _run_on_main(fn: Callable):
    """Execute ``fn`` on the GUI thread, blocking the caller for the result."""
    app = QCoreApplication.instance()
    if app is None or QThread.currentThread() == app.thread():
        return fn()
    invoker = _get_invoker()
    if invoker is None:
        return fn()
    box: dict = {}
    done = threading.Event()

    def wrapper():
        try:
            box["value"] = fn()
        except Exception as e:
            box["error"] = e
        finally:
            done.set()

    invoker._signal.emit(wrapper)
    done.wait()
    if "error" in box:
        raise box["error"]
    return box.get("value")


def _active_parent():
    app = QCoreApplication.instance()
    try:
        return QApplication.activeWindow() if app is not None else None
    except Exception:
        return None


def ask_yes_no(master, title: str, message: str,
               callback: Callable[[bool], None]):
    """Safe replacement for messagebox.askyesno (async via callback)."""
    def _do() -> bool:
        result = QMessageBox.question(
            _active_parent(), title, message,
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        return result == QMessageBox.StandardButton.Yes

    answer = _run_on_main(_do)
    if callback:
        callback(bool(answer))


def show_info(master, title: str, message: str):
    """Safe replacement for messagebox.showinfo."""
    _run_on_main(
        lambda: QMessageBox.information(_active_parent(), title, message))


class CTkPasswordDialog:
    """Modal password prompt. Construct, then call :meth:`get_input`.

    The Qt widget is built lazily inside ``get_input`` so construction is safe
    from any thread; only the actual exec() is marshalled to the GUI thread.
    """

    def __init__(self, title: str, text: str, **kwargs):
        self.title = title
        self.text = text
        self.result = None

    def get_input(self):
        def _do():
            value, ok = QInputDialog.getText(
                _active_parent(), self.title, self.text,
                QLineEdit.EchoMode.Password)
            return value if ok else None

        self.result = _run_on_main(_do)
        return self.result
