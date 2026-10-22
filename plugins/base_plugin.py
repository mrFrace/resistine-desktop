"""BasePlugin — the per-plugin contract (PyQt6).

Same constructor signature as the original CustomTkinter ``BasePlugin`` so the
plugin manager and every plugin's ``super().__init__(...)`` keep working
unchanged; the difference is that icons are ``QIcon``/``QPixmap`` and
``create_main_screen()`` returns a ``QWidget`` instead of a CTk frame.

Author: Resistine Team
Copyright (c) Resistine 2025
Licensed under the GNU General Public License v2 or later
"""

from __future__ import annotations

import os

from PyQt6.QtCore import QSize, Qt
from PyQt6.QtGui import QIcon, QPixmap

from gui import theme


class BasePlugin:
    """Base class for plugins, providing common metadata and helpers."""

    status_map = {
        "ok": "OK",
        "info": "Info",
        "warning": "Warning",
        "error": "Error",
        "critical": "Critical",
    }

    # Kept for source compatibility with the CTk plugins; the Qt shell has no
    # settle/reveal cascade, so this is a no-op flag.
    defer_reveal_until_settled = False

    # Hidden plugins stay installed and loaded but get no sidebar entry or
    # Dashboard card (e.g. the Store).
    hidden = False

    def __init__(self, id, version, order, name, status, description,
                 supported_systems, translations, icon_light_path,
                 icon_dark_path, uninstall_enabled=True):
        self.id = id
        self.version = version
        self.order = order
        self.name = name
        self.status = status
        self.description = description
        self.supported_systems = supported_systems
        self.translations = translations
        self.icon_light = icon_light_path
        self.icon_dark = icon_dark_path
        self.uninstall_enabled = uninstall_enabled
        self.button = None
        self.app = None  # host AppWindow, injected by the manager/shell

    # ---- Screen contract --------------------------------------------------
    def create_main_screen(self):
        """Build and return this plugin's screen (a QWidget)."""
        raise NotImplementedError("Subclasses should implement this method")

    def screen_signature(self):
        """Optional cache key; None disables caching (rebuild every visit)."""
        return None

    def on_screen_shown(self):
        pass

    def is_screen_ready(self):
        return True

    def destroy(self):
        """Release background threads/timers. Override as needed."""
        pass

    # ---- Status -----------------------------------------------------------
    def set_status(self, status):
        self.status = status

    def check_status(self):
        return self.status

    def get_status(self):
        try:
            status = self.check_status()
            if status is None:
                return None
            return self.status_map.get(status.lower(), status)
        except Exception as e:
            from utils.logger import logger
            logger.error(f"Status check failed for plugin {self.name}: {e}")
            return "Warning"

    # ---- Metadata accessors ----------------------------------------------
    def set_id(self, id):
        self.id = id

    def get_id(self):
        return self.id

    def set_name(self, name):
        self.name = name

    def get_name(self):
        return self.name

    def set_translations(self, translations):
        self.translations = translations

    def get_translations(self):
        return self.translations

    def set_description(self, description):
        self.description = description

    def get_description(self):
        return self.description

    def set_supported_systems(self, supported_systems):
        self.supported_systems = supported_systems

    def get_supported_systems(self):
        return self.supported_systems

    def set_button(self, button):
        self.button = button

    def get_button(self):
        return self.button

    # ---- Icons ------------------------------------------------------------
    def _icon_path(self) -> str:
        return self.icon_light if not theme.is_dark() else self.icon_dark

    @staticmethod
    def _tint(pm: QPixmap, color: str | None = None) -> QPixmap:
        """Colorize a monochrome line icon to the theme's primary text colour.

        The shipped *_light.png assets are pale grey and wash out on the
        light card background; tinting keys the strokes to the theme (near-
        black in light mode, white in dark) at any size.
        """
        if pm.isNull():
            return pm
        from PyQt6.QtGui import QColor, QPainter

        from gui import theme
        out = QPixmap(pm.size())
        out.setDevicePixelRatio(pm.devicePixelRatio())
        out.fill(Qt.GlobalColor.transparent)
        p = QPainter(out)
        p.drawPixmap(0, 0, pm)
        p.setCompositionMode(
            QPainter.CompositionMode.CompositionMode_SourceIn)
        p.fillRect(pm.rect(), QColor(color or theme.color("text_primary")))
        p.end()
        return out

    def get_icon(self) -> QIcon:
        path = self._icon_path()
        if path and os.path.isfile(path):
            return QIcon(self._tint(QPixmap(path)))
        return QIcon()

    def get_icon_pixmap(self, size: int = 44) -> QPixmap:
        path = self._icon_path()
        if path and os.path.isfile(path):
            return self._tint(QPixmap(path).scaled(
                QSize(size, size),
                Qt.AspectRatioMode.KeepAspectRatio,
                Qt.TransformationMode.SmoothTransformation,
            ))
        return QPixmap()

    def get_nav_icon(self) -> QIcon:
        """Sidebar icon: text colour normally, accent colour when selected."""
        path = self._icon_path()
        if not (path and os.path.isfile(path)):
            return QIcon()
        from gui import theme
        src = QPixmap(path)
        icon = QIcon()
        icon.addPixmap(self._tint(src, theme.color("text_secondary")),
                       QIcon.Mode.Normal, QIcon.State.Off)
        icon.addPixmap(self._tint(src, theme.color("sidebar_active_text")),
                       QIcon.Mode.Normal, QIcon.State.On)
        icon.addPixmap(self._tint(src, theme.color("text_primary")),
                       QIcon.Mode.Active, QIcon.State.Off)
        icon.addPixmap(self._tint(src, theme.color("sidebar_active_text")),
                       QIcon.Mode.Active, QIcon.State.On)
        return icon

    def get_icon_large(self) -> QIcon:
        return self.get_icon()

    # ---- Uninstall --------------------------------------------------------
    def uninstall(self):
        if not self.uninstall_enabled:
            return "Uninstall is not enabled for this plugin."
        if getattr(self, "app", None):
            return self.app.get_plugin_manager().uninstall_plugin(self)
        return "Application instance not found; cannot uninstall."
