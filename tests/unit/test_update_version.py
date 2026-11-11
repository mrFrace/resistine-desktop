"""Build IDs: tell builds of one VERSION apart."""

import sys

import pytest

from utils.updates import version


@pytest.fixture
def frozen(tmp_path, monkeypatch):
    """A frozen app whose bundle (_MEIPASS) is tmp_path."""
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "_MEIPASS", str(tmp_path), raising=False)
    (tmp_path / "VERSION").write_text("2026.07.20-rc\n")
    return tmp_path


@pytest.mark.unit
class TestBuildId:
    def test_frozen_build_reads_bundled_file(self, frozen):
        (frozen / "BUILD").write_text("202610221405\n")
        assert version.get_build() == "202610221405"
        assert version.get_display_version() == "2026.07.20-rc (build 202610221405)"

    def test_frozen_build_from_before_build_ids(self, frozen):
        assert version.get_build() == ""
        assert version.get_display_version() == "2026.07.20-rc"

    def test_source_run_has_no_build(self, monkeypatch):
        monkeypatch.setattr(sys, "frozen", False, raising=False)
        assert version.get_build() == ""
        assert version.get_display_version() == version.get_current_version()


@pytest.mark.unit
class TestCompareVersions:
    """A pre-release suffix on one segment must not zero out the whole
    version (that made every remote version look newer — a downgrade
    enabler)."""

    def test_rc_segment_still_beats_older_remote(self):
        assert version.compare_versions("2026.07.20-rc", "2026.07.19") == 1

    def test_rc_segment_still_loses_to_newer_remote(self):
        assert version.compare_versions("2026.07.20-rc", "2026.07.21") == -1

    def test_rc_suffix_ignored_when_numbers_equal(self):
        assert version.compare_versions("2026.07.20-rc", "2026.07.20") == 0

    def test_plain_versions_compare_normally(self):
        assert version.compare_versions("1.2.3", "1.2.4") == -1
        assert version.compare_versions("1.3", "1.2.9") == 1
        assert version.compare_versions("1.2", "1.2.0") == 0

    def test_unparseable_segment_counts_as_zero_not_whole_version(self):
        # Only the odd segment degrades, not the rest of the version.
        assert version.compare_versions("2026.x.5", "2026.0.5") == 0
        assert version.compare_versions("2026.x.5", "2025.99.99") == 1

    def test_non_string_inputs_do_not_crash(self):
        assert version.compare_versions(None, "1.0") == -1
        assert version.compare_versions("1.0", None) == 1
