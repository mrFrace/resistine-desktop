"""Sparkle-style software-update dialog (PyQt6).

Used by the Linux updater (``utils/updates/linux.py``). Public API matches the
original CustomTkinter version: ``UpdateDialog(master, current_version,
new_version, release_notes_html, on_install, on_skip, on_remind_later,
on_restart)`` plus ``cancelled``, ``set_download_progress(fraction, status)``,
``show_restart_prompt()`` and ``show_error(message, on_retry=None)``.

Author: Phoenix Team
Copyright (c) Phoenix 2025
Licensed under the GNU General Public License v2 or later
"""

from __future__ import annotations

from typing import Callable, Optional

from PyQt6.QtWidgets import (
    QDialog,
    QHBoxLayout,
    QLabel,
    QProgressBar,
    QPushButton,
    QTextBrowser,
    QVBoxLayout,
)


class UpdateDialog(QDialog):
    def __init__(self, master=None, current_version="", new_version="",
                 release_notes_html="", on_install: Optional[Callable] = None,
                 on_skip: Optional[Callable] = None,
                 on_remind_later: Optional[Callable] = None,
                 on_restart: Optional[Callable] = None):
        super().__init__()
        self._on_install = on_install
        self._on_skip = on_skip
        self._on_remind_later = on_remind_later
        self._on_restart = on_restart
        self._new_version = new_version
        self.cancelled = False

        self.setWindowTitle("Software Update")
        self.setMinimumWidth(480)
        self.setModal(True)

        self._layout = QVBoxLayout(self)
        self._layout.setContentsMargins(24, 24, 24, 24)
        self._layout.setSpacing(12)

        title = QLabel("A new version of Phoenix is available")
        title.setObjectName("H2")
        self._layout.addWidget(title)
        self._layout.addWidget(QLabel(
            f"Phoenix {new_version} is now available — you have "
            f"{current_version}. Would you like to install it now?"))

        notes = QTextBrowser()
        notes.setOpenExternalLinks(True)
        if release_notes_html:
            notes.setHtml(release_notes_html)
        notes.setMaximumHeight(220)
        self._layout.addWidget(notes)

        self._progress = QProgressBar()
        self._progress.setRange(0, 100)
        self._progress.hide()
        self._layout.addWidget(self._progress)
        self._status = QLabel("")
        self._status.hide()
        self._layout.addWidget(self._status)

        self._buttons = QHBoxLayout()
        self._layout.addLayout(self._buttons)
        self._show_prompt_buttons()

        self.show()

    def _clear_buttons(self):
        while self._buttons.count():
            item = self._buttons.takeAt(0)
            w = item.widget()
            if w is not None:
                w.deleteLater()

    def _show_prompt_buttons(self):
        self._clear_buttons()
        skip = QPushButton("Skip This Version")
        skip.setObjectName("Secondary")
        skip.clicked.connect(self._handle_skip)
        later = QPushButton("Remind Me Later")
        later.setObjectName("Secondary")
        later.clicked.connect(self._handle_later)
        install = QPushButton("Install Update")
        install.clicked.connect(self._handle_install)
        self._buttons.addWidget(skip)
        self._buttons.addStretch(1)
        self._buttons.addWidget(later)
        self._buttons.addWidget(install)

    def _show_downloading(self):
        self._clear_buttons()
        self._progress.show()
        self._progress.setValue(0)
        self._status.show()
        cancel = QPushButton("Cancel")
        cancel.setObjectName("Secondary")
        cancel.clicked.connect(self._handle_cancel)
        self._buttons.addStretch(1)
        self._buttons.addWidget(cancel)

    def _handle_install(self):
        self._show_downloading()
        if self._on_install:
            self._on_install()

    def _handle_skip(self):
        if self._on_skip:
            self._on_skip(self._new_version)
        self.close()

    def _handle_later(self):
        if self._on_remind_later:
            self._on_remind_later()
        self.close()

    def _handle_cancel(self):
        self.cancelled = True
        self.close()

    def set_download_progress(self, fraction: float, status_text: str = ""):
        self._progress.show()
        self._progress.setValue(int(max(0.0, min(1.0, fraction)) * 100))
        if status_text:
            self._status.show()
            self._status.setText(status_text)

    def show_restart_prompt(self):
        self._progress.hide()
        self._status.setText("Update downloaded. Restart to apply.")
        self._status.show()
        self._clear_buttons()
        restart = QPushButton("Restart Now")
        restart.clicked.connect(self._handle_restart)
        self._buttons.addStretch(1)
        self._buttons.addWidget(restart)

    def _handle_restart(self):
        if self._on_restart:
            self._on_restart()
        self.close()

    def show_error(self, message: str, on_retry: Optional[Callable] = None):
        self._progress.hide()
        self._status.setText(message)
        self._status.setStyleSheet("color: #DC2626;")
        self._status.show()
        self._clear_buttons()
        close = QPushButton("Close")
        close.setObjectName("Secondary")
        close.clicked.connect(self.close)
        self._buttons.addStretch(1)
        if on_retry:
            retry = QPushButton("Retry")
            retry.clicked.connect(
                lambda: (self._show_prompt_buttons(), on_retry()))
            self._buttons.addWidget(retry)
        self._buttons.addWidget(close)
