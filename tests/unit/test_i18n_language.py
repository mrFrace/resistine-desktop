"""The active UI language (utils/i18n set_language/get_language) and the
English fallback for a key a locale lacks."""

import json
import os
import re

import pytest

from utils import i18n

_REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_PH = re.compile(r"\{[a-z_]+\}")


@pytest.fixture(autouse=True)
def _english_again():
    yield
    i18n.set_language(i18n.DEFAULT_LANGUAGE)


@pytest.mark.unit
def test_set_language_switches_get_text_and_falls_back_to_english():
    assert i18n.get_language() == "en"
    i18n.set_language("cs-CZ")
    assert i18n.get_language() == "cs-CZ"
    assert i18n.get_text("devices.title") == "Zařízení"
    # A key only English has must not raise in another language.
    only_en = next(k for k in i18n.TEXTS["en"] if k not in i18n.TEXTS["cs-CZ"])
    assert i18n.get_text(only_en) == i18n.TEXTS["en"][only_en]
    i18n.set_language("xx-XX")  # unknown: back to English, no exception
    assert i18n.get_language() == "en"
    i18n.set_language(None)
    assert i18n.get_language() == "en"


@pytest.mark.unit
def test_every_locale_has_a_name_and_every_name_a_locale():
    codes = set(i18n.get_available_languages())
    assert set(i18n.LANGUAGE_NAMES) <= codes, set(i18n.LANGUAGE_NAMES) - codes
    assert all(os.path.exists(os.path.join(_REPO, f"utils/i18n/{c}.json")) for c in i18n.LANGUAGE_NAMES)


@pytest.mark.unit
@pytest.mark.parametrize("loc", sorted(set(i18n.LANGUAGE_NAMES) - {"en"}))
def test_devices_strings_are_translated_with_matching_placeholders(loc):
    en = json.load(open(os.path.join(_REPO, "utils/i18n/en.json"), encoding="utf-8"))
    cat = json.load(open(os.path.join(_REPO, f"utils/i18n/{loc}.json"), encoding="utf-8"))
    missing = [k for k in en if k.startswith("devices.") and k not in cat]
    assert not missing, missing[:5]
    for k, v in en.items():
        if k.startswith("devices.") and k in cat:
            assert set(_PH.findall(cat[k])) == set(_PH.findall(v)), (loc, k)
            assert "resistine" not in cat[k].lower(), (loc, k)
