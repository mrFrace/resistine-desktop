# -*- coding: utf-8 -*-
# @file plugins/login/main.py
# @namespace plugins.login.main
# Description: Login plugin (PyQt6) — Phoenix (Matrix / MAS) account sign-in.
# Author: Sherwin and the Resistine Team
# Copyright: Resistine (c) 2025
# Licensed under the GNU General Public License v2 or later

import os
import platform
import threading
import webbrowser

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from plugins.base_plugin import BasePlugin
from plugins.login import oidc
from utils.functions import get_resource_path
from utils.logger import logger

_OK = "#16A34A"
_TITLE = "Sign in with your Phoenix account to get started."


class Plugin(BasePlugin):
    def __init__(self, app):
        super().__init__(
            id="007", version="2025.01.01", order=0, name="Login",
            status=None, description="Sign in with your Phoenix account.",
            supported_systems=["Windows", "Linux", "Mac"],
            translations={"US": "Login", "ES": "Acceso", "FR": "Connexion"},
            icon_light_path=os.path.join(
                os.path.dirname(os.path.realpath(__file__)), "login_light.png"),
            icon_dark_path=os.path.join(
                os.path.dirname(os.path.realpath(__file__)), "login_dark.png"),
        )
        self.app = app
        self._cancel = None  # threading.Event of the running sign-in

    def show(self):
        self.app.setCentralWidget(self.create_main_screen())

    def create_main_screen(self):
        from gui.qt_widgets import pixmap

        page = QWidget()
        outer = QVBoxLayout(page)
        outer.setContentsMargins(40, 20, 40, 16)
        outer.addStretch(1)

        col = QWidget()
        col.setMaximumWidth(440)
        v = QVBoxLayout(col)
        v.setSpacing(18)
        v.setAlignment(Qt.AlignmentFlag.AlignHCenter)

        shield = QLabel()
        shield.setAlignment(Qt.AlignmentFlag.AlignCenter)
        pm = pixmap(get_resource_path(
            os.path.join("resources", "icons", "PhoenixMark.png")), 250)
        if not pm.isNull():
            shield.setPixmap(pm)
        v.addWidget(shield)

        self.title_label = QLabel(_TITLE)
        self.title_label.setWordWrap(True)
        self.title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.title_label.setStyleSheet("font-size: 16px;")
        v.addWidget(self.title_label)

        # Device-code flow: the code the user types at the verification URL.
        self.code_label = QLabel("")
        self.code_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.code_label.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse)
        self.code_label.setStyleSheet(
            "font-size: 30px; font-weight: 700; letter-spacing: 6px;")
        self.code_label.hide()
        v.addWidget(self.code_label)

        self.primary_btn = QPushButton("Sign in with Phoenix")
        self.primary_btn.setFixedWidth(400)
        self.primary_btn.setMinimumHeight(45)
        self.primary_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.primary_btn.clicked.connect(self.start_browser_login)
        v.addWidget(self.primary_btn, 0, Qt.AlignmentFlag.AlignHCenter)

        self.code_btn = QPushButton("Sign in with a code instead")
        self.code_btn.setObjectName("Link")
        self.code_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.code_btn.clicked.connect(self.start_code_login)
        v.addWidget(self.code_btn, 0, Qt.AlignmentFlag.AlignHCenter)

        self.cancel_btn = QPushButton("Cancel")
        self.cancel_btn.setObjectName("Secondary")
        self.cancel_btn.setFixedWidth(400)
        self.cancel_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.cancel_btn.clicked.connect(self.cancel_login)
        self.cancel_btn.hide()
        v.addWidget(self.cancel_btn, 0, Qt.AlignmentFlag.AlignHCenter)

        self.status_label = QLabel("")
        self.status_label.setWordWrap(True)
        self.status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        v.addWidget(self.status_label)

        outer.addWidget(col, 0, Qt.AlignmentFlag.AlignHCenter)
        outer.addStretch(1)

        # Footer: accounts are created by an administrator (MAS registration
        # is off), so link to account management instead of a signup page.
        account = QPushButton("Manage your Phoenix account")
        account.setObjectName("Link")
        account.setCursor(Qt.CursorShape.PointingHandCursor)
        account.clicked.connect(
            lambda: threading.Thread(
                target=lambda: webbrowser.open(oidc.account_url()),
                daemon=True).start())
        outer.addWidget(account, 0, Qt.AlignmentFlag.AlignHCenter)
        terms = QLabel("By signing in you agree to the Terms of Use")
        terms.setAlignment(Qt.AlignmentFlag.AlignCenter)
        terms.setStyleSheet("color: #888888; font-size: 12px;")
        outer.addWidget(terms)

        # Skip (bottom-right).
        skip_row = QHBoxLayout()
        skip_row.addStretch(1)
        skip = QPushButton("Skip")
        skip.setObjectName("Secondary")
        skip.setCursor(Qt.CursorShape.PointingHandCursor)
        skip.clicked.connect(self.skip_login)
        skip_row.addWidget(skip)
        outer.addLayout(skip_row)
        return page

    def update_status(self, message, color="red"):
        self.status_label.setText(message or "")
        self.status_label.setStyleSheet(f"color: {color};")

    # ---- sign-in flows ------------------------------------------------------
    def _set_busy(self, busy: bool):
        self.primary_btn.setVisible(not busy)
        self.code_btn.setVisible(not busy)
        self.cancel_btn.setVisible(busy)
        if not busy:
            self.title_label.setText(_TITLE)
            self.code_label.hide()

    def _run(self, flow):
        """Run ``flow(cancel)`` -> Tokens off the UI thread, then finish."""
        self._cancel = cancel = threading.Event()
        self._set_busy(True)

        def work():
            try:
                tokens = flow(cancel)
                account = oidc.complete_login(tokens)
                self.app.after(0, lambda: self._after_login(account))
            except oidc.Cancelled:
                self.app.after(0, lambda: (self._set_busy(False),
                                           self.update_status("")))
            except Exception as e:  # noqa: BLE001
                logger.error(f"Login failed: {e}")
                msg = str(e) or "Sign-in failed."
                self.app.after(0, lambda: self._login_failed(msg))

        threading.Thread(target=work, daemon=True).start()

    def start_browser_login(self):
        self.update_status("Continue in your browser…", _OK)
        self.title_label.setText(
            "Finish signing in on the page that opened in your browser.")
        self._run(lambda cancel: oidc.login_browser(cancel=cancel))

    def start_code_login(self):
        self.update_status("Requesting a sign-in code…", _OK)

        def show_code(dc):
            def ui():
                self.title_label.setText(
                    f"Open {dc.verification_uri} on any device and enter "
                    f"this code:")
                self.code_label.setText(dc.user_code)
                self.code_label.show()
                self.update_status("Waiting for you to approve the sign-in…",
                                   _OK)
            self.app.after(0, ui)
            if dc.verification_uri_complete:
                webbrowser.open(dc.verification_uri_complete)

        self._run(lambda cancel: oidc.login_device_code(show_code, cancel=cancel))

    def cancel_login(self):
        if self._cancel:
            self._cancel.set()

    def _login_failed(self, message):
        self._set_busy(False)
        self.update_status(message)
        self.app.show_notification(message, type="error")

    def _after_login(self, account):
        self._set_busy(False)
        logger.info("Login successful")
        from utils import settings as app_settings
        app_settings.set("auth", "logged_in", True)

        # Start Wazuh download + ClamAV DB pre-seed while public internet is
        # available (VPN DNS cannot resolve packages.wazuh.com).
        if platform.system() == "Darwin":
            try:
                from plugins.wazuh.agent.installer_service import (
                    ensure_download_started,
                )
                threading.Thread(
                    target=ensure_download_started, daemon=True).start()
            except Exception:
                pass
            try:
                from plugins.antivirus.installer_service import (
                    ensure_db_seed_started,
                )
                threading.Thread(
                    target=ensure_db_seed_started, daemon=True).start()
            except Exception:
                pass

        self.app.show_notification(
            f"Signed in as {account.get('user_id') or 'Phoenix user'}",
            type="info")

        # First login on this machine: run the unified setup wizard instead
        # of dropping the user on the dashboard with everything unconfigured.
        needs_setup = not app_settings.get("setup", "complete", False)
        if needs_setup:
            self._transition_to_setup_wizard()
        else:
            self.app.create_dashboard()

    def skip_login(self):
        self.cancel_login()
        logger.info("User skipped login")
        self.app.show_notification(
            "Login skipped — some features may be unavailable", type="warning")
        self.app.create_dashboard()

    def _transition_to_setup_wizard(self):
        """Transition from login to the unified customer setup wizard.

        The wizard guides the user through every permission/installation
        their OS needs (VPN, antivirus, Full Disk Access, endpoint
        monitoring) behind one flow.
        """
        from plugins.login.setup_wizard import SetupWizardScreen

        def on_setup_complete():
            self.app.create_dashboard()

        self._wizard = SetupWizardScreen(self.app, on_setup_complete)
        self._wizard.show()
