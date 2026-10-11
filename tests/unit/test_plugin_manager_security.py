"""
Security tests for plugins/plugin_manager.py (ported from drake/repo-cleaning
commits 92fa9e6 and 3d4491f).

Covers:
- SHA-256 verification of downloaded plugin archives (explicit and from metadata)
- redirect handling: allow_redirects=False, only trusted HTTPS redirects followed
- verify=True / timeouts on metadata fetch and downloads
- zip-slip guard ('..' entries, absolute paths)

No test touches the network: requests.get is always patched.
"""
import hashlib
import io
import os
import zipfile
from unittest.mock import MagicMock, patch

import pytest


def _make_zip(files: dict) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, content in files.items():
            zf.writestr(name, content)
    return buf.getvalue()


def _ok(content: bytes):
    resp = MagicMock()
    resp.status_code = 200
    resp.content = content
    resp.headers = {}
    resp.raise_for_status.return_value = None
    return resp


def _redirect(location: str, code: int = 302):
    resp = MagicMock()
    resp.status_code = code
    resp.content = b""
    resp.headers = {"Location": location}
    return resp


@pytest.fixture()
def mgr(tmp_path, monkeypatch):
    monkeypatch.setattr("plugins.plugin_manager.get_config_dir", lambda: str(tmp_path))
    with patch("plugins.plugin_manager.PluginManager.load_plugins", return_value=[]):
        from plugins.plugin_manager import PluginManager

        manager = PluginManager(MagicMock(spec=[]))
    manager.state_file = str(tmp_path / "plugin_state.json")
    return manager


def _download(mgr, responses, url="https://example.com/p.zip", **kwargs):
    """Run download_plugin with requests.get returning ``responses`` in order."""
    with patch("plugins.plugin_manager.requests.get", side_effect=list(responses)) as get, \
         patch.object(mgr, "load_plugins", return_value=[]):
        result = mgr.download_plugin(url, **kwargs)
    return result, get


# ===========================================================================
# SHA-256 verification
# ===========================================================================
@pytest.mark.unit
@pytest.mark.security
class TestHashVerification:
    def test_matching_explicit_hash_installs(self, mgr):
        data = _make_zip({"main.py": "# ok\n"})
        (ok, _), _ = _download(
            mgr, [_ok(data)], plugin_id="p1",
            expected_sha256=hashlib.sha256(data).hexdigest().upper(),
        )
        assert ok is True
        assert os.path.exists(os.path.join(mgr.user_plugins_path, "p1", "main.py"))

    def test_mismatched_explicit_hash_rejects_and_writes_nothing(self, mgr):
        data = _make_zip({"main.py": "# evil\n"})
        (ok, msg), _ = _download(mgr, [_ok(data)], plugin_id="p1", expected_sha256="0" * 64)
        assert ok is False
        assert "integrity" in msg.lower()
        assert not os.path.exists(os.path.join(mgr.user_plugins_path, "p1"))

    def test_hash_from_metadata_is_enforced(self, mgr):
        url = "https://example.com/calc.zip"
        meta = MagicMock()
        meta.raise_for_status.return_value = None
        meta.json.return_value = {"plugins": [{"id": "100", "url": url, "sha256": "f" * 64}]}
        with patch("plugins.plugin_manager.requests.get", return_value=meta):
            mgr.get_available_plugins()

        (ok, msg), _ = _download(mgr, [_ok(_make_zip({"main.py": "x"}))], url=url, plugin_id="100")
        assert ok is False
        assert "integrity" in msg.lower()

    def test_hash_from_metadata_matches_by_id(self, mgr):
        data = _make_zip({"main.py": "x"})
        mgr._remember_published_hashes(
            [{"id": "100", "url": "https://other/x.zip", "sha256": hashlib.sha256(data).hexdigest()}]
        )
        (ok, _), _ = _download(mgr, [_ok(data)], plugin_id="100")
        assert ok is True

    def test_no_hash_available_installs_unverified(self, mgr):
        """Drake's semantics: verification is applied only when a hash exists."""
        (ok, _), _ = _download(mgr, [_ok(_make_zip({"main.py": "x"}))], plugin_id="p2")
        assert ok is True


# ===========================================================================
# Request hardening / redirects
# ===========================================================================
@pytest.mark.unit
@pytest.mark.security
class TestRequestHardening:
    def test_metadata_fetch_uses_timeout_and_verify(self, mgr):
        meta = MagicMock()
        meta.raise_for_status.return_value = None
        meta.json.return_value = {"plugins": []}
        with patch("plugins.plugin_manager.requests.get", return_value=meta) as get:
            mgr.get_available_plugins()
        kwargs = get.call_args.kwargs
        assert kwargs["verify"] is True
        assert kwargs["timeout"] and kwargs["timeout"] > 0

    def test_download_disables_auto_redirects(self, mgr):
        (ok, _), get = _download(mgr, [_ok(_make_zip({"main.py": "x"}))], plugin_id="p")
        assert ok is True
        kwargs = get.call_args.kwargs
        assert kwargs["allow_redirects"] is False
        assert kwargs["verify"] is True
        assert kwargs["timeout"] and kwargs["timeout"] > 0

    def test_github_release_redirect_is_followed(self, mgr):
        asset = "https://release-assets.githubusercontent.com/github-production-release-asset/1/abc"
        (ok, _), get = _download(
            mgr,
            [_redirect(asset), _ok(_make_zip({"main.py": "x"}))],
            url="https://github.com/Resistine/Resistine-Desktop-Plugins/releases/download/v/calc.zip",
            plugin_id="calc",
        )
        assert ok is True
        assert get.call_args_list[1].args[0] == asset
        assert all(c.kwargs["allow_redirects"] is False for c in get.call_args_list)

    @pytest.mark.parametrize(
        "location",
        [
            "https://evil.example.net/p.zip",
            "http://objects.githubusercontent.com/p.zip",  # downgrade to HTTP
            "https://githubusercontent.com.evil.net/p.zip",
        ],
    )
    def test_untrusted_redirect_is_refused(self, mgr, location):
        (ok, msg), get = _download(
            mgr, [_redirect(location)],
            url="https://github.com/o/r/releases/download/v/p.zip", plugin_id="p",
        )
        assert ok is False
        assert "redirect" in msg.lower()
        assert get.call_count == 1

    def test_redirect_loop_is_bounded(self, mgr):
        loop = [_redirect("https://example.com/again.zip")] * 20
        (ok, _), get = _download(mgr, loop, plugin_id="p")
        assert ok is False
        assert get.call_count == mgr.MAX_DOWNLOAD_REDIRECTS + 1


# ===========================================================================
# Zip-slip guard
# ===========================================================================
@pytest.mark.unit
@pytest.mark.security
class TestZipSlip:
    @pytest.mark.parametrize(
        "evil_name",
        ["../escape.py", "sub/../../escape.py", "/tmp/abs_escape.py", "..\\escape.py"],
    )
    def test_traversal_entries_rejected(self, mgr, tmp_path, evil_name):
        data = _make_zip({"main.py": "x", evil_name: "pwned"})
        (ok, msg), _ = _download(mgr, [_ok(data)], plugin_id="p")
        assert ok is False
        assert "zip slip" in msg.lower()
        assert not (tmp_path / "escape.py").exists()
        assert not (tmp_path / "plugins" / "escape.py").exists()
        assert not os.path.exists(os.path.join(mgr.user_plugins_path, "p", "main.py"))

    def test_nested_traversal_rejected(self, mgr, tmp_path):
        # Every entry under '..' would be treated as a "nested" single-root zip.
        data = _make_zip({"../evil/main.py": "x"})
        (ok, _), _ = _download(mgr, [_ok(data)], plugin_id="p")
        assert ok is False
        assert not (tmp_path / "evil").exists()

    def test_benign_dotted_names_allowed(self, mgr):
        data = _make_zip({"main.py": "x", "assets/..hidden..png": "y", "./config.json": "{}"})
        (ok, _), _ = _download(mgr, [_ok(data)], plugin_id="p")
        assert ok is True
