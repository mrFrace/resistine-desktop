"""BasePlugin — the per-plugin contract (PyQt6).

Same constructor signature as the original CustomTkinter ``BasePlugin`` so the
plugin manager and every plugin's ``super().__init__(...)`` keep working
unchanged; the difference is that icons are ``QIcon``/``QPixmap`` and
``create_main_screen()`` returns a ``QWidget`` instead of a CTk frame.

Author: Phoenix Team
Copyright (c) Phoenix 2025
Licensed under the GNU General Public License v2 or later
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass

from PyQt6.QtCore import QSize, Qt
from PyQt6.QtGui import QIcon, QPixmap

from gui import theme

# Status kinds. "off" is nothing to report (VPN not connected by choice, a
# feature this platform does not have): no glow. "unknown" is the app not
# knowing (not checked yet, a check that failed, data older than the plugin
# says it should be): amber glow, never green and never red.
OK, WARNING, ERROR, OFF, UNKNOWN = "ok", "warning", "error", "off", "unknown"
_KINDS = {OK, WARNING, ERROR, OFF, UNKNOWN}
# Status kind -> the legacy get_status() string the Dashboard and Store read.
_LEGACY = {OK: "OK", WARNING: "Warning", ERROR: "Error", OFF: None, UNKNOWN: "Unknown"}


@dataclass(frozen=True)
class Status:
    """What a plugin knows about itself: ``kind`` (one of OK, WARNING, ERROR,
    OFF, UNKNOWN), a short ``reason`` for the rail caption ("not installed",
    "checked 3 h ago") and ``at``, when that fact was established (epoch
    seconds; None = just now)."""

    kind: str
    reason: str = ""
    at: float | None = None

    @property
    def label(self) -> str | None:
        """The legacy ``get_status()`` string ("OK", "Warning", ...)."""
        return _LEGACY.get(self.kind, "Unknown")


def _age(seconds: float) -> str:
    if seconds < 3600:
        return f"{int(seconds // 60)} min"
    if seconds < 86400:
        return f"{int(seconds // 3600)} h"
    return f"{int(seconds // 86400)} d"


def _status_text(key: str, **fmt) -> str:
    from utils.i18n import get_text
    return get_text(f"status.{key}", **fmt)


class BasePlugin:
    """Base class for plugins, providing common metadata and helpers."""

    # Hidden plugins stay installed and loaded but get no sidebar entry or
    # Dashboard card (e.g. the Store).
    hidden = False

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

    # An OK whose ``Status.at`` is older than this (seconds) is reported as
    # unknown: the plugin's own check cadence. None = never ages.
    status_fresh_for: float | None = None

    def check_status(self):
        """A ``Status``, a legacy string ("OK", "Warning", ...) or None (off)."""
        return self.status

    def recheck(self) -> bool:
        """Measure again now, on demand (the shell's "Check now" after a
        long unknown). Plugins that cache their status override this and
        refresh the cache on their own threads. False: nothing to do."""
        return False

    def status_info(self) -> Status:
        """``check_status()`` as a ``Status``, aged: a failed check and an
        OK past ``status_fresh_for`` are unknown, not a warning and not
        a stale green."""
        try:
            raw = self.check_status()
        except Exception as e:
            from utils.logger import logger
            logger.error(f"Status check failed for plugin {self.name}: {e}")
            return Status(UNKNOWN, _status_text("check_failed"))
        if raw is None:
            return Status(OFF)
        if isinstance(raw, Status):
            st = raw
        elif isinstance(raw, str):
            kind = raw.lower()
            if kind == "info":
                kind = OFF
            st = Status(kind) if kind in _KINDS else Status(UNKNOWN, raw)
        else:
            return Status(UNKNOWN)
        if st.kind == OK and st.at is not None and self.status_fresh_for is not None:
            age = time.time() - st.at
            if age > self.status_fresh_for:
                return Status(UNKNOWN, _status_text("stale", age=_age(age)), at=st.at)
        return st

    def get_status(self):
        """Legacy string status: "OK", "Warning", "Error", "Unknown", or None
        (nothing to report). Unmapped strings pass through."""
        try:
            raw = self.check_status()
        except Exception as e:
            from utils.logger import logger
            logger.error(f"Status check failed for plugin {self.name}: {e}")
            return "Unknown"
        if raw is None:
            return None
        if isinstance(raw, Status):
            return raw.label
        return self.status_map.get(raw.lower(), raw)

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
