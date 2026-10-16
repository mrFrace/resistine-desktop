"""remove_legacy_bundle: drop the pre-rename Resistine.app next to Phoenix.app."""

import plistlib

import pytest

from utils import functions


def _bundle(path, bundle_id):
    (path / "Contents" / "MacOS").mkdir(parents=True)
    with open(path / "Contents" / "Info.plist", "wb") as f:
        plistlib.dump({"CFBundleIdentifier": bundle_id}, f)
    return path


@pytest.fixture
def apps(tmp_path, monkeypatch):
    monkeypatch.setattr(functions.sys, "platform", "darwin")
    new = _bundle(tmp_path / "Phoenix.app", "com.resistine.desktop")
    monkeypatch.setattr(functions, "_get_bundle_path", lambda: str(new))
    monkeypatch.setattr(functions, "LEGACY_BUNDLE", str(tmp_path / "Resistine.app"))
    return tmp_path


def test_removes_old_bundle_with_our_id(apps):
    old = _bundle(apps / "Resistine.app", "com.resistine.desktop")
    assert functions.remove_legacy_bundle() is True
    assert not old.exists()


def test_keeps_a_foreign_bundle(apps):
    old = _bundle(apps / "Resistine.app", "com.example.other")
    assert functions.remove_legacy_bundle() is False
    assert old.exists()


def test_never_removes_the_running_bundle(apps, monkeypatch):
    old = _bundle(apps / "Resistine.app", "com.resistine.desktop")
    monkeypatch.setattr(functions, "_get_bundle_path", lambda: str(old))
    assert functions.remove_legacy_bundle() is False
    assert old.exists()
