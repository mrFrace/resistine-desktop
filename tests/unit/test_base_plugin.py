"""
Unit tests for plugins/base_plugin.py — BasePlugin.

The PyQt6 port uses QIcon/QPixmap for icons; icon tests run against a real
QApplication (QT_QPA_PLATFORM=offscreen).

Covers:
- Initialization and attribute storage
- get_status / check_status normalization
- Exception in check_status returns "Warning"
- Status map coverage (ok, info, warning, error, critical)
- create_main_screen raises NotImplementedError
- destroy is a no-op
- uninstall — enabled / disabled / no app reference
- Getters/setters
- Icons: theme-dependent path selection, tinting, missing-file fallbacks
"""
import os

import pytest
from unittest.mock import MagicMock

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")


# ---------------------------------------------------------------------------
# Minimal concrete subclass for testing
# ---------------------------------------------------------------------------
class ConcretePlugin:
    """Lazy import wrapper — avoids importing BasePlugin at collection time."""

    _instance = None

    @classmethod
    def make(cls, **kwargs):
        from plugins.base_plugin import BasePlugin

        class _Concrete(BasePlugin):
            def create_main_screen(self):
                return MagicMock()

        defaults = dict(
            id="test_001",
            version="2025.01.01",
            order=1,
            name="Test Plugin",
            status="OK",
            description="A test plugin",
            supported_systems=["Darwin", "Windows", "Linux"],
            translations={"US": "Test Plugin"},
            icon_light_path="/fake/light.png",
            icon_dark_path="/fake/dark.png",
            uninstall_enabled=True,
        )
        defaults.update(kwargs)
        return _Concrete(**defaults)


@pytest.fixture()
def plugin():
    return ConcretePlugin.make()


# ===========================================================================
# Initialization
# ===========================================================================
@pytest.mark.unit
class TestInit:
    def test_id_stored(self, plugin):
        assert plugin.id == "test_001"

    def test_version_stored(self, plugin):
        assert plugin.version == "2025.01.01"

    def test_name_stored(self, plugin):
        assert plugin.name == "Test Plugin"

    def test_status_stored(self, plugin):
        assert plugin.status == "OK"

    def test_description_stored(self, plugin):
        assert plugin.description == "A test plugin"

    def test_supported_systems_stored(self, plugin):
        assert "Darwin" in plugin.supported_systems

    def test_translations_stored(self, plugin):
        assert plugin.translations["US"] == "Test Plugin"

    def test_uninstall_enabled_defaults_true(self, plugin):
        assert plugin.uninstall_enabled is True

    def test_button_initially_none(self, plugin):
        assert plugin.button is None

    def test_app_initially_none(self, plugin):
        assert plugin.app is None


# ===========================================================================
# get_status / check_status
# ===========================================================================
@pytest.mark.unit
class TestGetStatus:
    @pytest.mark.parametrize("raw,expected", [
        ("ok", "OK"),
        ("OK", "OK"),
        ("info", "Info"),
        ("Info", "Info"),
        ("warning", "Warning"),
        ("Warning", "Warning"),
        ("error", "Error"),
        ("Error", "Error"),
        ("critical", "Critical"),
        ("Critical", "Critical"),
    ])
    def test_status_normalization(self, raw, expected):
        p = ConcretePlugin.make(status=raw)
        assert p.get_status() == expected

    def test_unknown_status_returned_as_is(self):
        p = ConcretePlugin.make(status="CustomStatus")
        assert p.get_status() == "CustomStatus"

    def test_none_status_returns_none(self):
        p = ConcretePlugin.make(status=None)
        assert p.get_status() is None

    def test_exception_in_check_status_returns_warning(self, plugin):
        def _crash():
            raise RuntimeError("status check failed")
        plugin.check_status = _crash
        assert plugin.get_status() == "Warning"


# ===========================================================================
# create_main_screen
# ===========================================================================
@pytest.mark.unit
def test_create_main_screen_raises_not_implemented():
    from plugins.base_plugin import BasePlugin
    p = BasePlugin(
        "id", "1", 1, "n", "ok", "d", ["Linux"], {}, None, None
    )
    with pytest.raises(NotImplementedError):
        p.create_main_screen()


# ===========================================================================
# destroy
# ===========================================================================
@pytest.mark.unit
def test_destroy_is_noop(plugin):
    plugin.destroy()  # Should not raise


# ===========================================================================
# uninstall
# ===========================================================================
@pytest.mark.unit
class TestUninstall:
    def test_uninstall_disabled_returns_message(self):
        p = ConcretePlugin.make(uninstall_enabled=False)
        result = p.uninstall()
        assert "not enabled" in result

    def test_uninstall_without_app_returns_message(self, plugin):
        plugin.app = None
        result = plugin.uninstall()
        assert "Application instance" in result or "not found" in result

    def test_uninstall_with_app_delegates_to_manager(self, plugin):
        mock_mgr = MagicMock()
        mock_mgr.uninstall_plugin.return_value = "uninstalled"
        mock_app = MagicMock()
        mock_app.get_plugin_manager.return_value = mock_mgr
        plugin.app = mock_app
        result = plugin.uninstall()
        mock_mgr.uninstall_plugin.assert_called_once_with(plugin)
        assert result == "uninstalled"


# ===========================================================================
# Getters / setters
# ===========================================================================
@pytest.mark.unit
class TestGettersSetters:
    def test_set_get_id(self, plugin):
        plugin.set_id("new_id")
        assert plugin.get_id() == "new_id"

    def test_set_get_name(self, plugin):
        plugin.set_name("New Name")
        assert plugin.get_name() == "New Name"

    def test_set_get_status(self, plugin):
        plugin.set_status("Error")
        assert plugin.status == "Error"

    def test_set_get_description(self, plugin):
        plugin.set_description("New desc")
        assert plugin.get_description() == "New desc"

    def test_set_get_translations(self, plugin):
        plugin.set_translations({"US": "Updated"})
        assert plugin.get_translations()["US"] == "Updated"

    def test_set_get_button(self, plugin):
        btn = MagicMock()
        plugin.set_button(btn)
        assert plugin.get_button() is btn

    def test_set_get_supported_systems(self, plugin):
        plugin.set_supported_systems(["Windows"])
        assert plugin.get_supported_systems() == ["Windows"]


# ===========================================================================
# Status map / class defaults
# ===========================================================================
@pytest.mark.unit
def test_status_map_completeness():
    from plugins.base_plugin import BasePlugin
    expected_keys = {"ok", "info", "warning", "error", "critical"}
    assert expected_keys == set(BasePlugin.status_map.keys())


@pytest.mark.unit
def test_class_defaults():
    from plugins.base_plugin import BasePlugin
    assert BasePlugin.hidden is False
    assert BasePlugin.defer_reveal_until_settled is False


@pytest.mark.unit
def test_screen_contract_defaults(plugin):
    assert plugin.screen_signature() is None
    assert plugin.is_screen_ready() is True
    assert plugin.on_screen_shown() is None


# ===========================================================================
# Icons (real QApplication, offscreen)
# ===========================================================================
@pytest.fixture(scope="module")
def qapp():
    from PyQt6.QtWidgets import QApplication
    return QApplication.instance() or QApplication([])


@pytest.fixture()
def theme_mode():
    """Allow tests to switch theme mode; restore afterwards."""
    from gui import theme
    original = theme.get_mode()
    yield theme.set_mode
    theme.set_mode(original)


@pytest.fixture()
def icon_files(tmp_path, qapp):
    """Write two opaque 32x32 PNGs (red=light, blue=dark) to disk."""
    from PyQt6.QtGui import QColor, QPixmap

    paths = {}
    for name, col in (("light", "#FF0000"), ("dark", "#0000FF")):
        pm = QPixmap(32, 32)
        pm.fill(QColor(col))
        path = tmp_path / f"icon_{name}.png"
        assert pm.save(str(path), "PNG")
        paths[name] = str(path)
    return paths


@pytest.mark.unit
class TestIcons:
    def test_icon_path_follows_theme(self, theme_mode):
        p = ConcretePlugin.make()
        theme_mode("Light")
        assert p._icon_path() == "/fake/light.png"
        theme_mode("Dark")
        assert p._icon_path() == "/fake/dark.png"

    def test_missing_file_returns_null_icon(self, qapp):
        p = ConcretePlugin.make()  # /fake/*.png do not exist
        assert p.get_icon().isNull()
        assert p.get_nav_icon().isNull()
        assert p.get_icon_large().isNull()
        assert p.get_icon_pixmap().isNull()

    def test_none_path_returns_null_icon(self, qapp):
        p = ConcretePlugin.make(icon_light_path=None, icon_dark_path=None)
        assert p.get_icon().isNull()
        assert p.get_icon_pixmap(20).isNull()

    def test_get_icon_pixmap_scaled_to_size(self, icon_files, theme_mode):
        theme_mode("Light")
        p = ConcretePlugin.make(icon_light_path=icon_files["light"],
                                icon_dark_path=icon_files["dark"])
        pm = p.get_icon_pixmap(16)
        assert not pm.isNull()
        assert (pm.width(), pm.height()) == (16, 16)
        # Default size is 44
        assert p.get_icon_pixmap().width() == 44

    @pytest.mark.parametrize("mode", ["Light", "Dark"])
    def test_icon_tinted_to_text_primary(self, icon_files, theme_mode, mode):
        from PyQt6.QtGui import QColor

        from gui import theme
        theme_mode(mode)
        p = ConcretePlugin.make(icon_light_path=icon_files["light"],
                                icon_dark_path=icon_files["dark"])
        img = p.get_icon_pixmap(32).toImage()
        assert img.pixelColor(8, 8).name().lower() == \
            QColor(theme.color("text_primary")).name().lower()

    def test_get_icon_non_null_for_existing_file(self, icon_files, qapp):
        p = ConcretePlugin.make(icon_light_path=icon_files["light"],
                                icon_dark_path=icon_files["dark"])
        icon = p.get_icon()
        assert not icon.isNull()
        assert not p.get_icon_large().isNull()

    def test_tint_preserves_transparency(self, qapp):
        from PyQt6.QtCore import Qt
        from PyQt6.QtGui import QColor, QPixmap

        from plugins.base_plugin import BasePlugin
        src = QPixmap(10, 10)
        src.fill(Qt.GlobalColor.transparent)
        out = BasePlugin._tint(src, "#00FF00").toImage()
        assert out.pixelColor(5, 5).alpha() == 0

        src.fill(QColor("#FF0000"))
        out = BasePlugin._tint(src, "#00FF00").toImage()
        assert out.pixelColor(5, 5).name().lower() == "#00ff00"

    def test_tint_null_pixmap_returned_unchanged(self, qapp):
        from PyQt6.QtGui import QPixmap

        from plugins.base_plugin import BasePlugin
        assert BasePlugin._tint(QPixmap()).isNull()

    def test_nav_icon_uses_active_color_when_checked(self, icon_files,
                                                     theme_mode):
        from PyQt6.QtCore import QSize
        from PyQt6.QtGui import QColor, QIcon

        from gui import theme
        theme_mode("Light")
        p = ConcretePlugin.make(icon_light_path=icon_files["light"],
                                icon_dark_path=icon_files["dark"])
        icon = p.get_nav_icon()
        assert not icon.isNull()

        def px(mode, state):
            img = icon.pixmap(QSize(32, 32), mode, state).toImage()
            return img.pixelColor(8, 8).name().lower()

        def c(name):
            return QColor(theme.color(name)).name().lower()

        assert px(QIcon.Mode.Normal, QIcon.State.Off) == c("text_secondary")
        assert px(QIcon.Mode.Normal, QIcon.State.On) == \
            c("sidebar_active_text")
        assert px(QIcon.Mode.Active, QIcon.State.Off) == c("text_primary")
