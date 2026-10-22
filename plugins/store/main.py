# @file plugins/store/main.py
"""Store plugin (PyQt6).

Flat page layout (gui/page_kit.py): a "Store" header, then one row per plugin
in a hairline-separated list (icon tile, name + status pill, description) with
the store actions on the right: Info + Install (downloadable / uninstalled) or
Uninstall (installed + uninstall_enabled) with an inline Confirm/Cancel step;
"Installed"/"Core" states have no install/uninstall action.

The full plugin list depends on a NETWORK fetch (get_available_plugins). That
fetch runs on a worker thread and is marshalled back via app.after(0, ...) — the
build never blocks on it. Installed/local rows render immediately and remote-only
ones fold in when they arrive.

Author: Peres J., P3 and the Resistine Team
Copyright (c) Resistine 2025
Licensed under the GNU General Public License v2 or later
"""

from __future__ import annotations

import os
import threading

from PyQt6.QtCore import Qt
from PyQt6.QtGui import QPixmap
from PyQt6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from gui import theme
from gui.page_kit import Page, PageHeader, RowList
from gui.qt_widgets import set_pill
from plugins.base_plugin import BasePlugin

_DIR = os.path.dirname(os.path.realpath(__file__))

# Plugins hidden from the Store (still available in sidebar if installed).
HIDDEN_FROM_STORE = {"001", "004", "009", "010", "100"}  # Dashboard, Store, Help, Settings, Calculator
HIDDEN_NAMES = {"template"}  # Also hide by name for remote-only plugins

# Plugin status -> status pill colour. Store-only states (Uninstalled,
# Available, …) read as neutral info.
_PILL_KIND = {"ok": "ok", "info": "info", "warning": "warning",
              "error": "error", "critical": "error"}


def _action(text: str, kind: str = "link") -> QPushButton:
    """A small, unfilled row action: "link" (accent text), "danger" (red
    text) or "secondary" (outlined)."""
    btn = QPushButton(text)
    btn.setCursor(Qt.CursorShape.PointingHandCursor)
    if kind == "secondary":
        btn.setObjectName("Secondary")
        btn.setStyleSheet("padding: 5px 14px; font-size: 12px;")
    else:
        btn.setObjectName("Link")
        if kind == "danger":
            btn.setStyleSheet(f"color: {theme.badge_colors('error')[1]};")
    return btn


class _StoreRow(QWidget):
    """One plugin: icon tile, name + status pill, description, and the store
    action buttons (injected) on the right."""

    def __init__(self, plugin, inject_buttons):
        super().__init__()
        self.setObjectName("Transparent")
        h = QHBoxLayout(self)
        h.setContentsMargins(0, 12, 0, 12)
        h.setSpacing(14)

        tile = QLabel()
        tile.setObjectName("MenuTile")
        tile.setFixedSize(40, 40)
        tile.setAlignment(Qt.AlignmentFlag.AlignCenter)
        pm = BasePlugin._tint(plugin.get_icon_pixmap(44),
                              theme.color("sidebar_active_text"))
        pm.setDevicePixelRatio(2.0)  # 22 px logical, crisp on HiDPI
        tile.setPixmap(pm)
        h.addWidget(tile, 0, Qt.AlignmentFlag.AlignTop)

        text = QVBoxLayout()
        text.setSpacing(2)
        name_row = QHBoxLayout()
        name_row.setSpacing(10)
        title = QLabel(plugin.get_name())
        title.setObjectName("RowTitle")
        name_row.addWidget(title)
        status = plugin.get_status()
        if status:
            pill = QLabel()
            set_pill(pill, _PILL_KIND.get(str(status).lower(), "info"),
                     str(status).title())
            name_row.addWidget(pill)
        name_row.addStretch(1)
        text.addLayout(name_row)
        desc = QLabel(plugin.get_description())
        desc.setObjectName("Hint")
        desc.setWordWrap(True)
        text.addWidget(desc)
        h.addLayout(text, 1)

        # Injected store action buttons (Info + Install/Uninstall/...).
        self.button_row = QHBoxLayout()
        self.button_row.setSpacing(4)
        h.addLayout(self.button_row)
        inject_buttons(self, plugin)

    def clear_buttons(self) -> None:
        while self.button_row.count():
            item = self.button_row.takeAt(0)
            w = item.widget()
            if w is not None:
                w.deleteLater()


class Plugin(BasePlugin):
    """Store plugin — download and install new plugins."""

    # Kept for source compatibility with the CTk reveal cascade.
    defer_reveal_until_settled = True

    def __init__(self, app):
        super().__init__(
            id="004",
            version="2025.01.01",
            order=1000,
            name="Store",
            status=None,
            description="This plugin allows you to download and install new plugins.",
            supported_systems=["Windows", "Linux", "Mac"],
            translations={"US": "Store", "ES": "Tienda", "FR": "Magasin"},
            icon_light_path=os.path.join(_DIR, "store_light.png"),
            icon_dark_path=os.path.join(_DIR, "store_dark.png"),
            uninstall_enabled=False,
        )
        self.app = app
        # Kept installed (it drives plugin installs) but out of the UI until
        # the plugin catalogue is rebuilt for Phoenix. ui.show_store=true
        # brings it back.
        from utils import settings as app_settings
        self.hidden = not app_settings.get("ui", "show_store", False)
        self.status = self.get_status()
        self.plugin_cards: dict = {}
        self.remote_data_map: dict = {}

    # ===================================================================
    #  Screen
    # ===================================================================
    def create_main_screen(self):
        page = Page()
        header = PageHeader(
            "Store", "Browse and install plugins to extend Phoenix.")
        self.title_label = header.title
        page.add(header)
        page.section("Plugins")

        # Build with whatever remote data we already have (cached from a
        # prior visit, or empty). The remote list is a network fetch, so we
        # NEVER block the build on it — render local plugins now and fold
        # remote-only ones in when they arrive.
        available_remote = getattr(self, "_remote_cache", None)
        plugins = self._build_plugin_list(available_remote or [])
        self._remote_done = available_remote is not None
        self._store_plugins = plugins

        self._list = RowList()
        self.plugin_cards = {}
        for p in plugins:
            self._add_card(p)
        page.add(self._list)
        page.stretch()

        self.main_frame = page.widget

        # On the first visit, fetch the remote plugin list in the background.
        if available_remote is None:
            self._fetch_remote_async()
            self.app.after(2500, self._mark_remote_done)

        return self.main_frame

    def is_screen_ready(self):
        return getattr(self, "_remote_done", True)

    def _mark_remote_done(self):
        self._remote_done = True

    def _add_card(self, plugin) -> None:
        row = _StoreRow(plugin, self._inject_store_buttons)
        self._list.add_row(row)
        self.plugin_cards[plugin.id] = row

    def on_theme_changed(self) -> None:
        """Re-tint row icons and colours on theme toggle.

        Rows bake theme colours in at build time (icon tint, pill and action
        colours), so the cached screen must be rebuilt.
        """
        if getattr(self, "_list", None):
            self._rebuild_grid()

    # ===================================================================
    #  Plugin list composition (NO network I/O — safe on the build path)
    # ===================================================================
    def _build_plugin_list(self, available_remote):
        try:
            manager = self.app.get_plugin_manager()
            installed_plugins = manager.plugins
            all_local_plugins = manager.load_plugins(include_uninstalled=True)
        except Exception:
            installed_plugins = list(getattr(self.app, "plugins", []))
            all_local_plugins = list(installed_plugins)

        installed_ids = {p.id for p in installed_plugins}
        local_ids = {p.id for p in all_local_plugins}

        plugins = list(installed_plugins)
        for lp in all_local_plugins:
            if lp.id not in installed_ids:
                lp.status = "Uninstalled"
                plugins.append(lp)
        for rp in available_remote:
            if rp["id"] not in local_ids:
                plugins.append(RemotePluginWrapper(self.app, rp))

        # Keep remote data for restoration after uninstall.
        self.remote_data_map = {rp["id"]: rp for rp in available_remote}

        plugins = [
            p for p in plugins
            if p.id not in HIDDEN_FROM_STORE
            and getattr(p, "name", "").lower() not in HIDDEN_NAMES
        ]

        # Local/installed first (sorted by name), then remote-only (sorted) — so
        # folding remote in later never reorders the local cards already on
        # screen; the remote cards simply append after them.
        local = sorted(
            (p for p in plugins if not isinstance(p, RemotePluginWrapper)),
            key=lambda x: x.get_name(),
        )
        remote_only = sorted(
            (p for p in plugins if isinstance(p, RemotePluginWrapper)),
            key=lambda x: x.get_name(),
        )
        plugins = local + remote_only

        unique_plugins, seen = [], set()
        for p in plugins:
            if p.id not in seen:
                unique_plugins.append(p)
                seen.add(p.id)
        return unique_plugins

    # ===================================================================
    #  Async remote fetch
    # ===================================================================
    def _fetch_remote_async(self):
        """Fetch the remote plugin list off the GUI thread, then merge it in."""
        def _work():
            try:
                data = self.app.get_plugin_manager().get_available_plugins()
            except Exception:
                data = []
            try:
                self.app.after(0, lambda: self._on_remote_loaded(data))
            except Exception:
                pass

        threading.Thread(target=_work, daemon=True).start()

    def _on_remote_loaded(self, remote):
        """Merge freshly-fetched remote plugins into the Store (GUI thread)."""
        self._remote_done = True
        if not remote:
            return  # don't cache failures; next visit retries
        self._remote_cache = remote

        if not getattr(self, "_list", None):
            return  # screen torn down while fetching

        try:
            new_list = self._build_plugin_list(remote)
        except Exception:
            return
        if [p.id for p in new_list] == [
            p.id for p in getattr(self, "_store_plugins", [])
        ]:
            return  # nothing new to show

        self._store_plugins = new_list
        self._rebuild_grid()

    def _rebuild_grid(self):
        """Tear down and re-add every row from self._store_plugins."""
        if not getattr(self, "_list", None):
            return
        try:
            self._list.clear()
        except RuntimeError:  # list deleted with its page
            self._list = None
            return
        self.plugin_cards = {}
        for p in self._store_plugins:
            self._add_card(p)

    # ===================================================================
    #  Store action buttons (Info + Install/Uninstall + inline confirm)
    # ===================================================================
    def _inject_store_buttons(self, card: _StoreRow, p):
        is_remote = isinstance(p, RemotePluginWrapper)
        is_uninstalled = getattr(p, "status", None) == "Uninstalled"

        def show_normal_buttons():
            card.clear_buttons()

            info = _action("Info")
            info.clicked.connect(
                lambda: self.show_remote_info(p) if is_remote
                else self._show_local_info(p))
            card.button_row.addWidget(info)

            if is_remote or is_uninstalled:
                install = _action("Install", "secondary")
                install.clicked.connect(lambda: self.handle_install(p))
                card.button_row.addWidget(install)
            elif getattr(p, "uninstall_enabled", True):
                uninstall = _action("Uninstall", "danger")
                uninstall.clicked.connect(show_confirm_buttons)
                card.button_row.addWidget(uninstall)

        def show_confirm_buttons():
            card.clear_buttons()
            cancel = _action("Cancel")
            cancel.clicked.connect(show_normal_buttons)
            card.button_row.addWidget(cancel)

            confirm = _action("Confirm uninstall", "danger")
            confirm.clicked.connect(confirm_uninstall)
            card.button_row.addWidget(confirm)

        def confirm_uninstall():
            try:
                result = p.uninstall()
            except Exception as e:
                self.app.show_notification(str(e), type="error")
                show_normal_buttons()
                return

            # plugin.uninstall() -> uninstall_plugin() returns (bool, msg).
            if isinstance(result, tuple):
                success, msg = result
            else:
                success, msg = False, str(result)

            if success:
                self.app.show_notification(msg, type="info")
                new_obj = p
                if p.id in getattr(self, "remote_data_map", {}):
                    try:
                        new_obj = RemotePluginWrapper(
                            self.app, self.remote_data_map[p.id])
                    except Exception:
                        p.status = "Uninstalled"
                        new_obj = p
                else:
                    p.status = "Uninstalled"
                self._replace_card(p.id, new_obj)
                try:
                    self.app.refresh_navigation()
                except Exception:
                    pass
            else:
                self.app.show_notification(msg, type="error")
                show_normal_buttons()

        show_normal_buttons()

    def _replace_card(self, old_plugin_id, new_plugin):
        """Swap one row for a fresh one (e.g. after install/uninstall)."""
        for i, p in enumerate(getattr(self, "_store_plugins", [])):
            if p.id == old_plugin_id:
                self._store_plugins[i] = new_plugin
                break
        self._rebuild_grid()

    # ===================================================================
    #  Install / info
    # ===================================================================
    def handle_install(self, remote_plugin):
        from utils.logger import logger

        def on_success(new_plugin_obj, msg):
            try:
                self.app.refresh_navigation()
            except Exception:
                pass
            self.app.show_notification(msg, type="info")

        try:
            url = getattr(remote_plugin, "url", None)
            if url:
                success, message = (
                    self.app.get_plugin_manager().download_plugin(
                        url, remote_plugin.id, remote_plugin.get_name()))
            elif not isinstance(remote_plugin, RemotePluginWrapper):
                # Local plugin marked uninstalled (files still on disk) —
                # re-enable it instead of downloading.
                success, message = (
                    self.app.get_plugin_manager().reinstall_plugin(
                        remote_plugin.id))
            else:
                self.app.show_notification(
                    f"Cannot install {remote_plugin.get_name()}: "
                    "remote source unknown.", type="error")
                return
        except Exception as e:
            logger.error(f"Store: install failed for "
                         f"{getattr(remote_plugin, 'id', '?')}: {e}")
            self.app.show_notification(f"Install failed: {e}", type="error")
            return

        logger.info(f"Store: Installation result for "
                    f"{remote_plugin.get_name()}: success={success}, "
                    f"msg={message}")
        if success:
            on_success(remote_plugin, message)
        else:
            self.app.show_notification(message, type="error")

    def _show_local_info(self, p):
        try:
            from gui.dialogs import show_info
            show_info(self.app, p.get_name(), p.get_description())
        except Exception:
            self.app.show_notification(p.get_description(), type="info")

    def show_remote_info(self, remote_plugin):
        try:
            from gui.dialogs import show_info
            show_info(self.app, remote_plugin.get_name(),
                      remote_plugin.get_description())
        except Exception:
            self.app.show_notification(
                remote_plugin.get_description(), type="info")


class RemotePluginWrapper:
    """Make a remote plugin dict look like a BasePlugin for the Store row."""

    status_map = BasePlugin.status_map

    def __init__(self, app, data):
        self.app = app
        self.id = data["id"]
        self.name = data["name"]
        self.description = data["description"]
        self.url = data["url"]
        self.order = data.get("order", 99)
        self.status = "Available"
        self.uninstall_enabled = False

    def get_name(self):
        return self.name

    def get_description(self):
        return self.description

    def get_status(self):
        return self.status

    def uninstall(self):
        return False, "Plugin is not installed."

    def get_icon_pixmap(self, size: int = 48) -> QPixmap:
        # Remote plugins use the generic Store icon. icon_light holds the dark
        # glyph and icon_dark the light one, mirroring base_plugin's pairing.
        path = (os.path.join(_DIR, "store_dark.png") if theme.is_dark()
                else os.path.join(_DIR, "store_light.png"))
        if path and os.path.isfile(path):
            # Tint like BasePlugin.get_icon_pixmap() does — without it the
            # raw glyph renders black on the dark background (invisible).
            return BasePlugin._tint(QPixmap(path).scaled(
                size, size,
                Qt.AspectRatioMode.KeepAspectRatio,
                Qt.TransformationMode.SmoothTransformation,
            ))
        return QPixmap()
