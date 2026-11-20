"""Terms of Service and Privacy Policy: one text, shown before install on every
platform and agreed to before sign-in.

docs/Terms.md and docs/Privacy.md are the source. The installers show
renderings of them that are committed (a build must not depend on a
generator having run), so the first thing pinned here is that those
renderings are current.
"""
import importlib.util
import os
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from utils import legal

REPO = Path(__file__).resolve().parents[2]


def _render_legal():
    spec = importlib.util.spec_from_file_location(
        "render_legal", REPO / "scripts" / "build" / "render_legal.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _read(rel):
    return (REPO / rel).read_bytes().decode("utf-8")


@pytest.mark.unit
class TestDocuments:
    @pytest.mark.parametrize("doc", [legal.TERMS, legal.PRIVACY])
    def test_document_states_the_version_the_app_gates_on(self, doc):
        """Changing the text without bumping LEGAL_VERSION (or the reverse)
        means people are asked to accept something other than what they see."""
        assert legal.document_version(doc) == legal.LEGAL_VERSION

    def test_each_names_who_is_responsible_and_how_to_reach_them(self):
        for doc in (legal.TERMS, legal.PRIVACY):
            text = legal.text(doc)
            assert "Drakes Software Solutions LLC" in text
            assert "info@phoenix.exposed" in text

    def test_terms_leave_the_gpl_rights_alone(self):
        terms = legal.text(legal.TERMS)
        assert "GNU General Public License" in terms
        assert "Nothing in these terms limits the rights the GPL gives you" in terms

    def test_they_reach_the_bundle_and_the_help_viewer(self):
        """docs/ is bundled as data and Help lists every .md in it."""
        assert "(_src('docs'), 'docs')" in _read("packaging/Phoenix.spec")
        for doc in (legal.TERMS, legal.PRIVACY):
            assert os.path.dirname(legal.path(doc)).endswith("docs")
            assert os.path.exists(legal.path(doc))


@pytest.mark.unit
class TestInstallers:
    def test_committed_renderings_are_current(self):
        stale = [str(p.relative_to(REPO)) for p, content in _render_legal().render().items()
                 if not p.exists() or p.read_bytes().decode("utf-8") != content]
        assert not stale, f"run scripts/build/render_legal.py: {stale}"

    @pytest.mark.parametrize("rel", [
        "packaging/pkg-resources/license.html",
        "packaging/windows/InstallAgreement.txt",
        "packaging/linux/AGREEMENT.txt",
    ])
    def test_every_rendering_carries_both_documents_and_the_gpl(self, rel):
        text = _read(rel)
        for needle in ("Terms of Service", "Privacy Policy", legal.LEGAL_VERSION,
                       "13. Indemnity", "9. Children", "GNU General Public License"):
            assert needle.lower() in text.lower(), (rel, needle)

    def test_macos_installer_shows_it_on_the_licence_pane(self):
        assert '<license file="license.html" mime-type="text/html"/>' in _read(
            "scripts/build/build-distribution.sh")

    def test_windows_installer_shows_it_on_the_licence_page(self):
        iss = _read("packaging/windows/PhoenixInstaller.iss")
        assert "LicenseFile=InstallAgreement.txt" in iss
        raw = (REPO / "packaging/windows/InstallAgreement.txt").read_bytes()
        assert raw.isascii()  # Inno shows the bytes as they are
        assert b"\r\n" in raw and b"\n" not in raw.replace(b"\r\n", b"")

    def test_linux_packages_ship_and_announce_it(self):
        build = _read("scripts/build/build-linux-packages.sh")
        for name in ("AGREEMENT.txt", "Terms.md", "Privacy.md"):
            assert f"$root/usr/share/doc/phoenix/{name}" in build
        assert "%doc /usr/share/doc/phoenix" in _read("packaging/linux/phoenix.spec.in")
        for rel in ("packaging/linux/postinst", "packaging/linux/phoenix.spec.in",
                    "packaging/linux/repo/phoenix.install"):
            assert "/usr/share/doc/phoenix/AGREEMENT.txt" in _read(rel), rel

    def test_linux_build_snippet_has_no_single_quote(self):
        """The staging commands run inside one single-quoted `sh -c` string."""
        build = _read("scripts/build/build-linux-packages.sh")
        start = build.index("# Terms of Service and Privacy Policy")
        end = build.index("Privacy.md $root/usr/share/doc/phoenix/Privacy.md")
        assert "'" not in build[start:end]


@pytest.mark.unit
class TestAcceptance:
    def test_recorded_per_version(self, isolated_settings, monkeypatch):
        assert legal.accepted() is False
        legal.accept()
        assert legal.accepted() is True
        assert isolated_settings.get("legal", "accepted_version") == legal.LEGAL_VERSION
        assert isinstance(isolated_settings.get("legal", "accepted_at"), int)
        monkeypatch.setattr(legal, "LEGAL_VERSION", "2099-01-01")
        assert legal.accepted() is False  # a new version asks again

    def test_sign_out_forgets_it(self, isolated_settings, monkeypatch):
        """The next person to sign in on the device agrees for themselves."""
        from plugins.settings.main import Plugin

        legal.accept()
        monkeypatch.setattr("plugins.vpn.config_manager.VPNConfigManager", MagicMock(), raising=False)
        Plugin._clear_user_data(MagicMock())
        assert legal.accepted() is False


@pytest.fixture(scope="module")
def qapp():
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    from PyQt6.QtWidgets import QApplication
    return QApplication.instance() or QApplication(sys.argv[:1])


@pytest.mark.unit
class TestSignInScreen:
    def _screen(self, monkeypatch):
        from plugins.login import main as login_main

        plugin = login_main.Plugin(MagicMock())
        started = []
        monkeypatch.setattr(plugin, "_run", lambda flow: started.append(flow))
        self._keep = plugin.create_main_screen()
        return plugin, started

    def test_sign_in_is_not_offered_until_the_box_is_ticked(self, qapp, isolated_settings, monkeypatch):
        plugin, started = self._screen(monkeypatch)
        assert not plugin.agree_box.isChecked()
        assert not plugin.primary_btn.isEnabled() and not plugin.code_btn.isEnabled()

        plugin.start_browser_login()  # even if called directly
        plugin.start_code_login()
        assert started == [] and legal.accepted() is False

        plugin.agree_box.setChecked(True)
        assert plugin.primary_btn.isEnabled() and plugin.code_btn.isEnabled()
        assert legal.accepted() is False  # ticking alone records nothing

        plugin.start_browser_login()
        assert len(started) == 1 and legal.accepted() is True

    def test_unticking_withdraws_the_offer(self, qapp, isolated_settings, monkeypatch):
        plugin, _ = self._screen(monkeypatch)
        plugin.agree_box.setChecked(True)
        plugin.agree_box.setChecked(False)
        assert not plugin.primary_btn.isEnabled()

    def test_already_accepted_version_is_pre_ticked(self, qapp, isolated_settings, monkeypatch):
        legal.accept()
        plugin, started = self._screen(monkeypatch)
        assert plugin.agree_box.isChecked() and plugin.primary_btn.isEnabled()

    @pytest.mark.parametrize("doc,heading", [
        (legal.TERMS, "Phoenix Terms of Service"), (legal.PRIVACY, "Phoenix Privacy Policy")])
    def test_both_documents_open_in_place(self, qapp, isolated_settings, monkeypatch, doc, heading):
        plugin, _ = self._screen(monkeypatch)
        plugin._show_legal(doc)
        assert plugin._views.currentIndex() == 1
        assert heading in plugin.legal_browser.toPlainText()

    def test_links_between_the_documents_stay_in_the_reader(self, qapp, isolated_settings, monkeypatch):
        plugin, _ = self._screen(monkeypatch)
        plugin._show_legal(legal.TERMS)
        plugin._follow_legal_link("Privacy.md")
        assert "Phoenix Privacy Policy" in plugin.legal_browser.toPlainText()
        plugin._follow_legal_link("file:///etc/passwd")  # anything else local: ignored
        assert "Phoenix Privacy Policy" in plugin.legal_browser.toPlainText()
