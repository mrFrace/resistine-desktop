"""VPN "View config" sub-view (replaces the old popup dialog)."""

import os
from unittest.mock import MagicMock, patch

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtWidgets import QApplication, QLabel  # noqa: E402

from gui.page_kit import KVList, MenuRow, SlideStack  # noqa: E402

CONF = """[Interface]
PrivateKey = cHJpdmF0ZQ==
Address = 10.42.20.10/32
# a comment
DNS = 10.42.20.1

[Peer]
PublicKey = cHVibGlj
PresharedKey = cHNr
Endpoint = vpn.example:987
"""


@pytest.fixture(scope="module")
def qapp():
    return QApplication.instance() or QApplication([])


@pytest.fixture()
def vpn(qapp):
    from plugins.vpn.main import Plugin
    p = Plugin.__new__(Plugin)  # skip __init__ (probes the system VPN)
    p.app = MagicMock()
    return p


def _values(widget):
    return {kv_key: lbl.text()
            for kv in widget.findChildren(KVList)
            for kv_key, lbl in kv.values.items()}


@pytest.mark.unit
class TestConfigView:
    def test_parse_conf(self, vpn):
        sections = vpn._parse_conf(CONF)
        assert [name for name, _ in sections] == ["Interface", "Peer"]
        assert sections[0][1] == [("PrivateKey", "cHJpdmF0ZQ=="),
                                  ("Address", "10.42.20.10/32"),
                                  ("DNS", "10.42.20.1")]

    def test_secrets_hidden_until_revealed(self, vpn):
        view = vpn._build_config_view("phoenix", CONF)
        vals = _values(view)
        assert "cHJpdmF0ZQ==" not in vals.values()
        assert "cHNr" not in vals.values()
        assert vals["Address"] == "10.42.20.10/32"
        assert vals["PublicKey"] == "cHVibGlj"  # public, shown
        vpn._config_reveal.setChecked(True)
        vals = _values(view)
        assert vals["PrivateKey"] == "cHJpdmF0ZQ=="
        assert vals["PresharedKey"] == "cHNr"
        vpn._config_reveal.setChecked(False)
        assert _values(view)["PrivateKey"].startswith("•")

    def test_copy_puts_whole_file_on_clipboard(self, vpn):
        view = vpn._build_config_view("phoenix", CONF)  # keep a ref
        clip = MagicMock()
        with patch("plugins.vpn.main.QGuiApplication.clipboard",
                   return_value=clip):
            vpn._config_copy.clicked.emit()
        clip.setText.assert_called_once_with(CONF)
        assert vpn._config_copy._hint.text() == "Copied"
        del view

    def test_show_and_hide_slide(self, vpn, tmp_path):
        conf = tmp_path / "phoenix.conf"
        conf.write_text(CONF, encoding="utf-8")
        main = QLabel("main")
        vpn._views = SlideStack(fit_height=False)
        vpn._views.addWidget(main)
        vpn._main_view = main
        vpn._config_view = None
        with patch("plugins.vpn.main._conf_path", return_value=str(conf)):
            vpn._show_config_view("phoenix")
        vpn._views._anim.setCurrentTime(SlideStack.DURATION_MS)
        assert vpn._views.currentWidget() is vpn._config_view
        assert any(r.text() == "Copy to clipboard"
                   for r in vpn._config_view.findChildren(MenuRow))
        vpn._hide_config_view()
        vpn._views._anim.setCurrentTime(SlideStack.DURATION_MS)
        assert vpn._views.currentWidget() is main

    def test_missing_file_notifies(self, vpn, tmp_path):
        vpn._views = SlideStack(fit_height=False)
        with patch("plugins.vpn.main._conf_path",
                   return_value=str(tmp_path / "nope.conf")):
            vpn._show_config_view("nope")
        vpn.app.show_notification.assert_called_once()
