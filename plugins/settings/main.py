## @file plugins/settings/main.py
## @namespace settings_plugin
"""Settings plugin (PyQt6).

A flat page (gui/page_kit.py): a "Settings" header naming the signed-in
account, then sections — Account, AI assistant, Appearance, Updates — and a
last section with the Log in / Log out and Uninstall actions as menu rows.

Author: Peres J. and the Resistine Team
Copyright (c) Resistine 2025
Licensed under the GNU General Public License v2 or later
"""

import glob
import os
import sys

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QComboBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from gui.page_kit import (
    KVList,
    MenuRow,
    Page,
    PageHeader,
    SettingRow,
    muted,
    section_heading,
)
from gui.toggle import ToggleSwitch
from plugins.base_plugin import BasePlugin
from utils import chat_config, settings
from utils.i18n import get_text
from utils.logger import logger

_DIR = os.path.dirname(os.path.realpath(__file__))
_DEFAULT_MATRIX_BOT = "@secagent:phoenix.exposed"


def _t(key, fallback):
    try:
        val = get_text(key)
        return val if val and val != key else fallback
    except Exception:
        return fallback


def _label(key, fallback):
    """A translated row title, minus the trailing colon some strings carry."""
    return _t(key, fallback).rstrip(": ")


class _StatusLine(QLabel):
    """A small muted line for transient status text; hidden while empty so
    it leaves no gap."""

    def __init__(self):
        super().__init__("")
        self.setObjectName("Hint")
        self.setWordWrap(True)
        self.hide()

    def setText(self, text):  # noqa: N802 - Qt override
        super().setText(text)
        self.setVisible(bool(text))


class _NoScrollComboBox(QComboBox):
    """A combo box whose value never changes on mouse-wheel scroll.

    On Windows, rolling the wheel while the cursor is over a QComboBox cycles
    its selection — so scrolling the settings page would silently flip the
    appearance mode between System/Light/Dark. Ignore wheel events so the
    value only changes on click, and let the wheel scroll the page instead.
    (The dropdown popup is a separate widget, so its own scrolling is
    unaffected when it's open.)
    """

    def wheelEvent(self, event):  # noqa: N802 - Qt override
        event.ignore()


class Plugin(BasePlugin):
    """Settings plugin."""

    def __init__(self, app):
        super().__init__(
            id="010", version="2025.01.01", order=1020, name="Settings",
            status=None,
            description="Your account, appearance and updates.",
            supported_systems=["Windows", "Linux", "Mac"],
            translations={"US": "Settings", "ES": "Configuracion",
                          "FR": "Paramètres"},
            icon_light_path=os.path.join(_DIR, "settings_light.png"),
            icon_dark_path=os.path.join(_DIR, "settings_dark.png"),
            uninstall_enabled=False,
        )
        self.app = app

    # ---- A titled page section ---------------------------------------------
    @staticmethod
    def _section(title: str) -> tuple[QWidget, QVBoxLayout]:
        """A section: breathing room, a small uppercase heading, then body."""
        box = QWidget()
        box.setObjectName("Transparent")
        lay = QVBoxLayout(box)
        lay.setContentsMargins(0, 28, 0, 0)
        lay.setSpacing(0)
        lay.addWidget(section_heading(title))
        lay.addSpacing(8)
        return box, lay

    def create_main_screen(self):
        page = Page()
        user_id = settings.get("auth", "user_id", None)
        logged_in = settings.get("auth", "logged_in", False)
        page.add(PageHeader(
            "Settings",
            f"Signed in as {user_id}" if user_id else
            ("Signed in" if logged_in else "Not signed in")))
        page.add(self._profile_card())
        page.add(self._api_card())
        page.add(self._appearance_card())
        page.add(self._updates_card())
        page.add(self._uninstall_card())
        page.stretch()
        return page.widget

    # ---- Account ----------------------------------------------------------
    def _profile_card(self) -> QWidget:
        box, lay = self._section("Account")
        email = settings.get("auth", "email", None)
        user_id = settings.get("auth", "user_id", None)
        rows = []
        if user_id:
            rows.append(("Phoenix account", user_id))
        if email:
            rows.append(("Email", email))
        if rows:
            lay.addWidget(KVList(rows))
        else:
            lay.addWidget(muted("Not signed in"))
        return box

    # ---- AI assistant -----------------------------------------------------
    def _api_card(self) -> QWidget:
        box, lay = self._section("AI assistant")

        # Chat transport: the HTTPS OpenAI-compatible API, or an end-to-end
        # encrypted Matrix DM with the Phoenix assistant bot.
        self.transport_combo = _NoScrollComboBox()
        self.transport_combo.addItem("OpenAI API (HTTPS)", "openai")
        self.transport_combo.addItem("Matrix (end-to-end encrypted)", "matrix")
        current = settings.get("chat", "transport") or "openai"
        self.transport_combo.setCurrentIndex(
            max(0, self.transport_combo.findData(current)))
        lay.addWidget(SettingRow(
            _label("settings.chat.transport", "Chat transport"), "",
            self.transport_combo, stacked=True))

        # The transport-specific rows are shown/hidden as a whole by
        # _sync_transport_fields (the *_label attributes are those rows).
        self.matrix_bot_entry = QLineEdit()
        self.matrix_bot_entry.setPlaceholderText(_DEFAULT_MATRIX_BOT)
        self.matrix_bot_entry.setText(
            settings.get("chat", "matrix_bot") or _DEFAULT_MATRIX_BOT)
        self.matrix_bot_label = SettingRow(
            _label("settings.chat.matrix_bot", "Assistant Matrix ID"), "",
            self.matrix_bot_entry, stacked=True)
        lay.addWidget(self.matrix_bot_label)
        self.matrix_hint = self.matrix_bot_label.hint
        self.transport_combo.currentIndexChanged.connect(
            self._sync_transport_fields)

        self.api_key_entry = QLineEdit()
        self.api_key_entry.setEchoMode(QLineEdit.EchoMode.Password)
        self.api_key_entry.setPlaceholderText(
            _t("settings.apikey.placeholder", "Enter your API key"))
        existing_key = settings.get_secret("chat", "openai_api_key")
        if existing_key:
            self.api_key_entry.setText(existing_key)
        self.api_key_row = SettingRow(
            _label("settings.apikey.label", "OpenAI API Key"), "",
            self.api_key_entry, stacked=True)
        lay.addWidget(self.api_key_row)

        self.api_base_entry = QLineEdit()
        self.api_base_entry.setPlaceholderText(
            _t("settings.apibase.placeholder", "API base URL"))
        self.api_base_entry.setText(chat_config.base_url())
        self.api_base_label = SettingRow(
            _label("settings.apibase.label", "API Base URL"), "",
            self.api_base_entry, stacked=True)
        lay.addWidget(self.api_base_label)

        self.disable_animation_checkbox = ToggleSwitch()
        self.disable_animation_checkbox.setChecked(
            bool(settings.get("chat", "disable_animation", False)))
        self.disable_animation_checkbox.toggled.connect(
            self.save_animation_setting)
        lay.addWidget(SettingRow(
            _label("settings.chat.disable_animation", "Disable typing animation"),
            "Show replies all at once instead of word by word",
            self.disable_animation_checkbox))

        self._sync_transport_fields()

        row = QHBoxLayout()
        row.setContentsMargins(0, 8, 0, 0)
        row.setSpacing(12)
        save = QPushButton(_t("settings.apikey.save", "Save"))
        save.setCursor(Qt.CursorShape.PointingHandCursor)
        save.clicked.connect(self.save_api_key)
        row.addWidget(save)
        self.status_label = QLabel("")
        row.addWidget(self.status_label, 1)
        lay.addLayout(row)
        return box

    # ---- Appearance -------------------------------------------------------
    def _appearance_card(self) -> QWidget:
        box, lay = self._section("Appearance")
        self.appearance_combo = _NoScrollComboBox()
        self.appearance_combo.addItems(["System", "Light", "Dark"])
        self.appearance_combo.setCurrentText(
            settings.get("ui", "appearance_mode", "System"))
        self.appearance_combo.setMinimumWidth(160)
        self.appearance_combo.currentTextChanged.connect(
            self.change_appearance_mode)
        lay.addWidget(SettingRow(
            "Mode", "System follows your computer's light/dark setting",
            self.appearance_combo))
        return box

    # ---- Software Updates -------------------------------------------------
    def _updates_card(self) -> QWidget:
        box, lay = self._section("Updates")
        check = MenuRow("refresh-cw", "Check for updates",
                        f"Current version: {self._get_app_version()}",
                        on_click=self._check_for_updates)
        lay.addWidget(check)
        self.update_status_label = _StatusLine()
        lay.addWidget(self.update_status_label)
        return box

    # ---- Sign in/out + Uninstall ------------------------------------------
    def _uninstall_card(self) -> QWidget:
        box, lay = self._section("Account actions")
        # The row mirrors auth state: logged in -> Log Out, logged out ->
        # Log In.
        if settings.get("auth", "logged_in", False):
            self.logout_button = MenuRow(
                "log-out", "Log Out",
                "Sign out of your Phoenix account on this device",
                on_click=self._handle_logout)
        else:
            self.logout_button = MenuRow(
                "log-in", "Log In", "Sign in with your Phoenix account",
                on_click=self._handle_login)
        lay.addWidget(self.logout_button)
        self.uninstall_button = MenuRow(
            "trash", "Uninstall Phoenix",
            "Permanently remove Phoenix and all associated data from this "
            "computer", on_click=self._handle_uninstall, danger=True)
        lay.addWidget(self.uninstall_button)
        self.uninstall_status_label = _StatusLine()
        lay.addWidget(self.uninstall_status_label)
        return box

    # ===================================================================
    #  Actions
    # ===================================================================
    def _safe_set_text(self, label, text):
        """Set a status label's text, tolerating a torn-down widget.

        These are called from deferred after() callbacks that clear a status
        line seconds later; by then the Settings screen may have been rebuilt
        (theme toggle) or navigated away, leaving a live Python wrapper around
        a deleted C++ QLabel — setText then raises RuntimeError.
        """
        try:
            label.setText(text)
        except RuntimeError:
            pass

    def save_animation_setting(self):
        settings.set("chat", "disable_animation",
                     self.disable_animation_checkbox.isChecked())
        # Apply to an in-flight chat response right away, not just next turn.
        for plugin in getattr(self.app, "plugin_list", []):
            if plugin.get_name() == "Chat" and hasattr(
                    plugin, "apply_animation_setting"):
                try:
                    plugin.apply_animation_setting()
                except Exception:
                    pass
                break

    def _sync_transport_fields(self, *_):
        """Show the Matrix fields only for the Matrix transport."""
        matrix = self.transport_combo.currentData() == "matrix"
        for w in (self.api_key_row, self.api_key_entry, self.api_base_label,
                  self.api_base_entry):
            w.setVisible(not matrix)
        for w in (self.matrix_bot_label, self.matrix_bot_entry, self.matrix_hint):
            w.setVisible(matrix)
        if matrix:
            try:
                from plugins.login import oidc
                signed_in = oidc.has_session()
            except Exception:
                signed_in = False
            self.matrix_hint.setText(
                "Uses your Phoenix account; messages are end-to-end encrypted."
                if signed_in else
                "Sign in with your Phoenix account (Log In below) to use Matrix chat.")

    def save_api_key(self):
        api_key = self.api_key_entry.text().strip()
        api_base = self.api_base_entry.text().strip()
        transport = self.transport_combo.currentData() or "openai"
        bot = self.matrix_bot_entry.text().strip()
        if bot and not (bot.startswith("@") and ":" in bot):
            self.status_label.setText("Matrix ID must look like @name:server")
            self.status_label.setStyleSheet("color: #DC2626;")
            return
        ok_transport = settings.set("chat", "transport", transport)
        ok_bot = settings.set("chat", "matrix_bot",
                              bot if bot and bot != _DEFAULT_MATRIX_BOT else None)
        if transport == "openai" and not api_key and not api_base:
            ok_key = ok_base = True
        else:
            ok_key = (settings.set_secret("chat", "openai_api_key", api_key)
                      if api_key else True)
            ok_base = settings.set("chat", "openai_base_url",
                                   api_base if api_base else None)
        if ok_key and ok_base and ok_transport and ok_bot:
            self.status_label.setText(
                _t("settings.apikey.saved_success", "Saved"))
            self.status_label.setStyleSheet("color: #16A34A;")
            for plugin in getattr(self.app, "plugin_list", []):
                if plugin.get_name() == "Chat" and hasattr(
                        plugin, "reinitialize_client"):
                    plugin.reinitialize_client()
                    break
            self.app.after(
                2500, lambda: self._safe_set_text(self.status_label, ""))
        else:
            self.status_label.setText(
                _t("settings.apikey.saved_error", "Save failed"))
            self.status_label.setStyleSheet("color: #DC2626;")

    def change_appearance_mode(self, new_mode: str):
        settings.set("ui", "appearance_mode", new_mode)
        # Defer the actual restyle by one event-loop tick. This signal fires
        # while the QComboBox popup is still closing; applying an app-wide
        # stylesheet/palette right now re-polishes that still-open popup and
        # makes its little dropdown window flash repeatedly on Windows. Letting
        # the popup fully dismiss first removes the flicker.
        self.app.after(0, lambda: self._apply_appearance_mode(new_mode))

    def _apply_appearance_mode(self, new_mode: str):
        try:
            self.app.set_appearance_mode(new_mode)
        except Exception as e:
            logger.error(f"Theme switch failed: {e}")

    def _check_for_updates(self):
        try:
            from utils import updates
            if not updates.is_available():
                self.update_status_label.setText(
                    "Updates not available in this build")
                self.app.after(
                    5000,
                    lambda: self._safe_set_text(self.update_status_label, ""))
                return
            self.update_status_label.setText("Checking for updates…")
            result = updates.check_for_updates()
            if result == "error":
                self.update_status_label.setText("Update check failed")
            self.app.after(
                4000,
                lambda: self._safe_set_text(self.update_status_label, ""))
        except Exception as e:
            logger.error(f"Update check error: {e}")
            self.update_status_label.setText(f"Error: {e}")

    def _get_app_version(self):
        try:
            if getattr(sys, "frozen", False):
                import plistlib
                contents_dir = os.path.dirname(os.path.dirname(sys.executable))
                plist_path = os.path.join(contents_dir, "Info.plist")
                if os.path.exists(plist_path):
                    with open(plist_path, "rb") as f:
                        info = plistlib.load(f)
                    return info.get("CFBundleShortVersionString", "1.0.0")
        except Exception:
            pass
        try:
            from utils.updates.version import get_current_version
            version = get_current_version()
            if version != "0.0.0":
                return version
        except Exception:
            pass
        return "1.0.0"

    def _handle_uninstall(self):
        confirmed = QMessageBox.question(
            self.app, "Uninstall Phoenix",
            "Are you sure you want to completely uninstall Phoenix?\n\n"
            "This will remove all VPN configurations, application data, and the "
            "application itself.\n\nThis action cannot be undone.",
        ) == QMessageBox.StandardButton.Yes
        if not confirmed:
            return
        self.uninstall_button.setEnabled(False)
        self.uninstall_status_label.setText("Uninstalling…")
        try:
            from utils import uninstall

            def _progress(msg):
                self.uninstall_status_label.setText(msg)

            success, message = uninstall.run_uninstall(
                self.app, progress_callback=_progress)
            if success:
                self.uninstall_status_label.setText("Uninstalled. Closing…")
                if sys.platform == "darwin":
                    # macOS: deferred hard-exit so teardown finishes flushing
                    # (the spawned uninstaller outlives us).
                    import os as _os
                    import threading as _th
                    self.app.close()
                    _th.Timer(0.3, lambda: _os._exit(0)).start()
                else:
                    # Windows/Linux: orderly shutdown so any spawned
                    # uninstaller (Inno's unins000.exe) and WinSparkle
                    # finish cleanly. Quit the Qt loop; main()'s teardown
                    # (updates.shutdown + hard exit) runs after exec()
                    # returns.
                    from PyQt6.QtWidgets import QApplication
                    self.app.close()
                    QApplication.instance().quit()
            else:
                self.uninstall_button.setEnabled(True)
                self.uninstall_status_label.setText(message)
        except Exception as e:
            logger.error(f"Uninstall error: {e}")
            self.uninstall_button.setEnabled(True)
            self.uninstall_status_label.setText(f"Error: {e}")

    def _login_plugin_installed(self) -> bool:
        """True if the Login plugin (id 007) is installed."""
        return any(
            getattr(p, "id", None) == "007"
            for p in getattr(self.app, "plugins", None)
            or getattr(self.app, "plugin_list", [])
            or []
        )

    def _handle_logout(self):
        # Without the Login plugin installed there's no way to sign back in,
        # so refuse the logout up-front rather than stranding the user on a
        # broken bootstrap path.
        if not self._login_plugin_installed():
            self.app.show_notification(
                "Please install the Login plugin from the Store first.",
                type="warning",
            )
            return
        confirmed = QMessageBox.question(
            self.app, "Log Out",
            "Are you sure you want to log out?\n\nThis will sign you out and "
            "remove your VPN configurations, security agent enrollment, chat "
            "history, and account data from this device.\n\nAn administrator "
            "password may be required to fully uninstall the Wazuh agent.",
        ) == QMessageBox.StandardButton.Yes
        if not confirmed:
            return
        self._disconnect_vpn()
        self._remove_wazuh_agent()
        self._revoke_session()
        self._clear_user_data()
        try:
            self.app.show_login()
        except Exception as e:
            logger.error(f"Failed to show login screen: {e}")
            self.app.show_notification(f"Logout failed: {e}", type="error")

    def _handle_login(self):
        """Bring up the full-screen login. No data is cleared — auth namespace
        was already clean (user is logged out / skipped). Guarded the same
        way as logout: if the Login plugin was uninstalled, ask the user to
        reinstall it before continuing.
        """
        if not self._login_plugin_installed():
            self.app.show_notification(
                "Please install the Login plugin from the Store first.",
                type="warning",
            )
            return
        try:
            self.app.show_login()
        except Exception as e:
            logger.error(f"Failed to show login screen: {e}")
            self.app.show_notification(
                f"Could not open sign-in: {e}", type="error")

    # ===================================================================
    #  Logout cleanup helpers (framework-agnostic — kept from CTk version)
    # ===================================================================
    def _disconnect_vpn(self):
        import platform as plat
        try:
            system = plat.system()
            if system == "Darwin":
                from plugins.vpn.config_manager import VPNConfigManager
                from plugins.vpn.wireguard.vpn_functions_darwin import (
                    get_writable_wireguard_dir, stop_vpn,
                )
                mgr = VPNConfigManager(get_writable_wireguard_dir())
                stop_vpn(mgr.get_active_config_path() or "")
            elif system == "Windows":
                from plugins.vpn.wireguard.vpn_windows_client import disconnect
                disconnect("resistine")
            elif system == "Linux":
                from plugins.vpn.config_manager import VPNConfigManager
                from plugins.vpn.wireguard.vpn_functions_linux import (
                    get_writable_wireguard_dir, stop_vpn,
                )
                mgr = VPNConfigManager(get_writable_wireguard_dir())
                path = mgr.get_active_config_path()
                if path:
                    stop_vpn(path)
        except Exception as e:
            logger.warning(f"VPN disconnect on logout failed: {e}")

    def _remove_wazuh_agent(self):
        import platform as plat
        try:
            system = plat.system()
            if system == "Darwin":
                from plugins.wazuh.agent.wazuh_functions_darwin import remove_agent
            elif system == "Windows":
                from plugins.wazuh.agent.wazuh_functions_windows import remove_agent
            elif system == "Linux":
                from plugins.wazuh.agent.wazuh_functions_linux import remove_agent
            else:
                return
            if not remove_agent(wipe_keys=True):
                logger.warning("Wazuh agent removal reported failure")
        except Exception as e:
            logger.warning(f"Wazuh agent removal on logout failed: {e}")

    def _revoke_session(self):
        # End the MAS session too, so the device disappears from the
        # account's session list. Best effort: offline logout still works.
        # First tell the Phoenix API this device signed out, which removes
        # its VPN peer on the server; that call needs the still-valid token.
        try:
            from plugins.login.oidc import has_session, revoke
            if has_session():
                from plugins.vpn.provisioning import release_device
                release_device()
            revoke()
        except Exception as e:
            logger.warning(f"Session revoke on logout failed: {e}")

    def _clear_user_data(self):
        import platform as plat
        settings.clear_namespace("auth")
        settings.delete("wireguard", "private_key")
        settings.delete("wireguard", "public_key")
        settings.clear_namespace("vpn")
        try:
            system = plat.system()
            if system == "Darwin":
                from plugins.vpn.wireguard.vpn_functions_darwin import (
                    get_writable_wireguard_dir,
                )
            elif system == "Windows":
                from plugins.vpn.wireguard.vpn_functions_windows import (
                    get_writable_wireguard_dir,
                )
            else:
                from plugins.vpn.wireguard.vpn_functions_linux import (
                    get_writable_wireguard_dir,
                )
            wg_dir = get_writable_wireguard_dir()
            for conf in glob.glob(os.path.join(wg_dir, "*.conf")):
                try:
                    os.remove(conf)
                except OSError as e:
                    logger.warning(f"Failed to remove VPN config {conf}: {e}")
        except Exception as e:
            logger.warning(f"VPN config cleanup failed: {e}")
        settings.clear_namespace("chat_history")
        settings.delete("chat", "openai_api_key")
        settings.delete("chat", "openai_base_url")
        settings.clear_namespace("wazuh")
