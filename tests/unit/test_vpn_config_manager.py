"""
Unit tests for plugins/vpn/config_manager.py — VPNConfigManager.

Covers:
- list_configs — empty, single, multiple, sort order (default first)
- get_active_config_name — explicit, fallback to default, fallback to first
- set_active_config — valid / invalid path
- get_active_config_path
- import_config — sanitize name, dedup on collision, write to disk, permissions
- delete_config — normal, refuses default config, handles missing file
- sanitize_filename — edge cases
- register_config / get_display_name
- migrate_legacy_config
"""
import os
import platform
import stat
import pytest

from plugins.vpn.config_manager import VPNConfigManager, RESISTINE_CONFIG_NAME


# ---------------------------------------------------------------------------
# Fixture helpers
# ---------------------------------------------------------------------------
@pytest.fixture()
def mgr(wireguard_dir, isolated_settings):
    return VPNConfigManager(str(wireguard_dir))


@pytest.fixture()
def mgr_with_default(mgr, write_conf):
    write_conf(RESISTINE_CONFIG_NAME)
    mgr.register_config(RESISTINE_CONFIG_NAME, source="api")
    return mgr


# ===========================================================================
# list_configs
# ===========================================================================
@pytest.mark.unit
class TestListConfigs:
    def test_empty_folder_returns_empty(self, mgr):
        assert mgr.list_configs() == []

    def test_single_default_config(self, mgr_with_default):
        configs = mgr_with_default.list_configs()
        assert len(configs) == 1
        assert configs[0]["name"] == RESISTINE_CONFIG_NAME

    def test_resistine_sorted_first(self, mgr, write_conf, isolated_settings):
        write_conf("zzz_user")
        write_conf(RESISTINE_CONFIG_NAME)
        write_conf("aaa_user")
        configs = mgr.list_configs()
        assert configs[0]["name"] == RESISTINE_CONFIG_NAME

    def test_user_configs_sorted_alphabetically(self, mgr, write_conf):
        write_conf("charlie")
        write_conf("alpha")
        write_conf("bravo")
        configs = mgr.list_configs()
        user_names = [c["name"] for c in configs]
        assert user_names == sorted(user_names)

    def test_config_entry_has_expected_keys(self, mgr_with_default):
        entry = mgr_with_default.list_configs()[0]
        for key in ("name", "display_name", "source", "path"):
            assert key in entry

    def test_path_points_to_conf_file(self, mgr_with_default):
        entry = mgr_with_default.list_configs()[0]
        assert entry["path"].endswith(".conf")
        assert os.path.exists(entry["path"])

    def test_nonconf_files_excluded(self, mgr, wireguard_dir):
        (wireguard_dir / "note.txt").write_text("not a config")
        (wireguard_dir / "README.md").write_text("docs")
        assert mgr.list_configs() == []


# ===========================================================================
# get_active_config_name
# ===========================================================================
@pytest.mark.unit
class TestGetActiveConfigName:
    def test_returns_none_when_no_configs(self, mgr):
        assert mgr.get_active_config_name() is None

    def test_returns_explicit_active(self, mgr, write_conf, isolated_settings):
        write_conf("my_vpn")
        isolated_settings.set("vpn", "active_config", "my_vpn")
        assert mgr.get_active_config_name() == "my_vpn"

    def test_falls_back_to_resistine(self, mgr, write_conf, isolated_settings):
        write_conf(RESISTINE_CONFIG_NAME)
        # No active_config set in settings
        assert mgr.get_active_config_name() == RESISTINE_CONFIG_NAME

    def test_falls_back_to_first_conf(self, mgr, write_conf, isolated_settings):
        write_conf("only_one")
        assert mgr.get_active_config_name() == "only_one"

    def test_ignores_stale_active_config(self, mgr, write_conf, isolated_settings):
        """If the saved active config file no longer exists, fall back."""
        write_conf(RESISTINE_CONFIG_NAME)
        isolated_settings.set("vpn", "active_config", "deleted_config")
        # deleted_config.conf doesn't exist → should fall back to resistine
        assert mgr.get_active_config_name() == RESISTINE_CONFIG_NAME


# ===========================================================================
# set_active_config
# ===========================================================================
@pytest.mark.unit
class TestSetActiveConfig:
    def test_set_valid_config(self, mgr, write_conf, isolated_settings):
        write_conf("my_vpn")
        result = mgr.set_active_config("my_vpn")
        assert result is True
        assert isolated_settings.get("vpn", "active_config") == "my_vpn"

    def test_set_nonexistent_config_returns_false(self, mgr):
        result = mgr.set_active_config("ghost_config")
        assert result is False

    def test_set_resistine(self, mgr, write_conf):
        write_conf(RESISTINE_CONFIG_NAME)
        result = mgr.set_active_config(RESISTINE_CONFIG_NAME)
        assert result is True


# ===========================================================================
# get_active_config_path
# ===========================================================================
@pytest.mark.unit
class TestGetActiveConfigPath:
    def test_returns_full_path(self, mgr, write_conf, isolated_settings):
        write_conf(RESISTINE_CONFIG_NAME)
        isolated_settings.set("vpn", "active_config", RESISTINE_CONFIG_NAME)
        path = mgr.get_active_config_path()
        assert path is not None
        assert path.endswith(f"{RESISTINE_CONFIG_NAME}.conf")

    def test_returns_none_when_no_configs(self, mgr):
        assert mgr.get_active_config_path() is None


# ===========================================================================
# import_config
# ===========================================================================
@pytest.mark.unit
class TestImportConfig:
    def test_imports_valid_config(self, mgr, sample_wireguard_conf, wireguard_dir):
        ok, name = mgr.import_config("my_tunnel.conf", sample_wireguard_conf)
        assert ok is True
        assert (wireguard_dir / f"{name}.conf").exists()

    def test_sanitizes_filename_spaces(self, mgr, sample_wireguard_conf, wireguard_dir):
        ok, name = mgr.import_config("my tunnel config.conf", sample_wireguard_conf)
        assert ok is True
        assert " " not in name

    def test_sanitizes_filename_special_chars(self, mgr, sample_wireguard_conf, wireguard_dir):
        ok, name = mgr.import_config("my@#tunnel!.conf", sample_wireguard_conf)
        assert ok is True
        assert "@" not in name
        assert "#" not in name
        assert "!" not in name

    def test_dedup_on_name_collision(self, mgr, sample_wireguard_conf, wireguard_dir):
        mgr.import_config("tunnel.conf", sample_wireguard_conf)
        ok, name2 = mgr.import_config("tunnel.conf", sample_wireguard_conf)
        assert ok is True
        assert name2 != "tunnel"  # should have counter suffix

    def test_rejects_empty_content(self, mgr):
        ok, msg = mgr.import_config("tunnel.conf", "")
        assert ok is False

    def test_rejects_whitespace_only_content(self, mgr):
        ok, msg = mgr.import_config("tunnel.conf", "   \n\t  ")
        assert ok is False

    def test_cannot_import_as_resistine(self, mgr, sample_wireguard_conf):
        """Importing with the reserved name must be suffixed."""
        ok, name = mgr.import_config(f"{RESISTINE_CONFIG_NAME}.conf", sample_wireguard_conf)
        assert ok is True
        assert name != RESISTINE_CONFIG_NAME

    @pytest.mark.skipif(platform.system() == "Windows", reason="POSIX-only")
    def test_imported_file_permissions_600(self, mgr, sample_wireguard_conf, wireguard_dir):
        ok, name = mgr.import_config("tunnel.conf", sample_wireguard_conf)
        conf_path = wireguard_dir / f"{name}.conf"
        mode = oct(stat.S_IMODE(os.stat(str(conf_path)).st_mode))
        assert mode == oct(0o600)

    def test_registers_in_registry(self, mgr, sample_wireguard_conf, isolated_settings):
        ok, name = mgr.import_config("tunnel.conf", sample_wireguard_conf)
        registry = isolated_settings.get("vpn", "config_registry", {})
        assert name in registry
        assert registry[name]["source"] == "import"


# ===========================================================================
# delete_config
# ===========================================================================
@pytest.mark.unit
class TestDeleteConfig:
    def test_delete_user_config(self, mgr, write_conf, wireguard_dir):
        write_conf("user_tunnel")
        ok, msg = mgr.delete_config("user_tunnel")
        assert ok is True
        assert not (wireguard_dir / "user_tunnel.conf").exists()

    def test_delete_nonexistent_returns_true(self, mgr):
        ok, msg = mgr.delete_config("ghost")
        assert ok is True

    def test_refuses_to_delete_resistine(self, mgr, write_conf):
        write_conf(RESISTINE_CONFIG_NAME)
        ok, msg = mgr.delete_config(RESISTINE_CONFIG_NAME)
        assert ok is False
        assert "Cannot delete" in msg

    def test_removes_from_registry(self, mgr, write_conf, isolated_settings, sample_wireguard_conf):
        ok, name = mgr.import_config("tunnel.conf", sample_wireguard_conf)
        mgr.delete_config(name)
        registry = isolated_settings.get("vpn", "config_registry", {})
        assert name not in registry

    def test_switches_active_config_on_delete(self, mgr, write_conf, isolated_settings):
        write_conf(RESISTINE_CONFIG_NAME)
        write_conf("secondary")
        mgr.set_active_config("secondary")
        mgr.delete_config("secondary")
        # Active config should switch away from the deleted one
        active = isolated_settings.get("vpn", "active_config")
        assert active != "secondary"


# ===========================================================================
# sanitize_filename
# ===========================================================================
@pytest.mark.unit
class TestSanitizeFilename:
    def test_strips_conf_extension(self, mgr):
        assert mgr.sanitize_filename("tunnel.conf") == "tunnel"

    def test_replaces_special_chars(self, mgr):
        result = mgr.sanitize_filename("my@tunnel!.conf")
        assert "@" not in result
        assert "!" not in result

    def test_strips_leading_underscores(self, mgr):
        result = mgr.sanitize_filename("___tunnel.conf")
        assert not result.startswith("_")

    def test_empty_name_becomes_imported(self, mgr):
        result = mgr.sanitize_filename("@@@.conf")
        assert result == "imported"

    def test_resistine_name_gets_user_suffix(self, mgr):
        result = mgr.sanitize_filename(f"{RESISTINE_CONFIG_NAME}.conf")
        assert result == f"{RESISTINE_CONFIG_NAME}_user"

    def test_allows_hyphens(self, mgr):
        result = mgr.sanitize_filename("my-tunnel.conf")
        assert "-" in result

    def test_allows_underscores(self, mgr):
        result = mgr.sanitize_filename("my_tunnel.conf")
        assert "_" in result


# ===========================================================================
# migrate_legacy_config
# ===========================================================================
@pytest.mark.unit
class TestMigrateLegacyConfig:
    def test_renames_wg0_to_default(self, mgr, wireguard_dir):
        (wireguard_dir / "wg0.conf").write_text("[Interface]\n[Peer]\n")
        result = mgr.migrate_legacy_config()
        assert result is True
        assert (wireguard_dir / f"{RESISTINE_CONFIG_NAME}.conf").exists()
        assert not (wireguard_dir / "wg0.conf").exists()

    def test_skips_if_no_legacy_config(self, mgr, wireguard_dir):
        result = mgr.migrate_legacy_config()
        assert result is False

    def test_skips_if_default_already_exists(self, mgr, wireguard_dir):
        (wireguard_dir / "wg0.conf").write_text("[Interface]\n")
        (wireguard_dir / f"{RESISTINE_CONFIG_NAME}.conf").write_text("[Interface]\n")
        result = mgr.migrate_legacy_config()
        assert result is False
        # Original wg0 should still exist
        assert (wireguard_dir / "wg0.conf").exists()

    @pytest.mark.skipif(platform.system() == "Windows", reason="POSIX-only")
    def test_migrated_file_permissions_600(self, mgr, wireguard_dir):
        (wireguard_dir / "wg0.conf").write_text("[Interface]\n[Peer]\n")
        mgr.migrate_legacy_config()
        conf = wireguard_dir / f"{RESISTINE_CONFIG_NAME}.conf"
        mode = oct(stat.S_IMODE(os.stat(str(conf)).st_mode))
        assert mode == oct(0o600)


# ===========================================================================
# get_display_name
# ===========================================================================
@pytest.mark.unit
class TestGetDisplayName:
    def test_default_config_display_name(self, mgr):
        assert mgr.get_display_name(RESISTINE_CONFIG_NAME) == "Phoenix (Default)"

    def test_registered_config_display_name(self, mgr, isolated_settings):
        mgr.register_config("mycfg", source="import", display_name="My Config")
        assert mgr.get_display_name("mycfg") == "My Config"

    def test_unregistered_config_uses_name(self, mgr):
        assert mgr.get_display_name("unknown_cfg") == "unknown_cfg"
