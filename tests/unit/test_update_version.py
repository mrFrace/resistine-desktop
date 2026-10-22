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
