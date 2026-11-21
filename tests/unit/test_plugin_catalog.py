"""
The Store's plugin catalog is trusted only with a pinned-key signature
(plugins/plugin_catalog.py, PluginManager.get_available_plugins).

No test touches the network: requests.get is always patched.
"""
import base64
import hashlib
import json
from unittest.mock import MagicMock, patch

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from plugins import plugin_catalog as pc
from plugins.wazuh.agent import phoenix_packages as pp

KEY_ID = bytes.fromhex("0102030405060708")
URL = "https://example.com/optional_plugins.json"
ENTRY = {"id": "100", "name": "Calc", "url": "https://example.com/calc.zip",
         "sha256": "f" * 64}


def keypair(key_id=KEY_ID):
    sk = Ed25519PrivateKey.generate()
    pub = base64.b64encode(b"Ed" + key_id + sk.public_key().public_bytes_raw()).decode()
    return sk, pub


def sign(sk, data: bytes, trusted: str, key_id=KEY_ID) -> str:
    sig = sk.sign(hashlib.blake2b(data, digest_size=64).digest())
    glob = sk.sign(sig + trusted.encode())
    return (
        "untrusted comment: test\n"
        + base64.b64encode(b"ED" + key_id + sig).decode() + "\n"
        + f"trusted comment: {trusted}\n"
        + base64.b64encode(glob).decode() + "\n"
    )


def catalog(serial=10, plugins=None) -> bytes:
    return json.dumps(
        {"serial": serial, "plugins": [ENTRY] if plugins is None else plugins}
    ).encode()


def response(body: bytes, status=200):
    resp = MagicMock()
    resp.status_code = status
    resp.iter_content = lambda chunk_size=8192: iter(
        [body[i:i + chunk_size] for i in range(0, len(body), chunk_size)] or [b""]
    )
    resp.raise_for_status.return_value = None
    return resp


def serve(data: bytes, signature):
    """A requests.get that serves the catalog and its signature by URL."""
    def get(url, **kwargs):
        if url.endswith(pc.SIGNATURE_SUFFIX):
            if signature is None:
                r = response(b"", 404)
                import requests
                r.raise_for_status.side_effect = requests.HTTPError("404")
                return r
            return response(signature.encode())
        return response(data)
    return get


@pytest.fixture
def key():
    sk, pub = keypair()
    with patch.object(pc, "public_keys", lambda: (pub,)):
        yield sk


@pytest.fixture
def mgr(tmp_path, monkeypatch):
    monkeypatch.setattr("plugins.plugin_manager.get_config_dir", lambda: str(tmp_path))
    with patch("plugins.plugin_manager.PluginManager.load_plugins", return_value=[]):
        from plugins.plugin_manager import PluginManager

        manager = PluginManager(MagicMock(spec=[]))
    manager.OPTIONAL_PLUGINS_URL = URL
    return manager


def fetch(mgr, data, signature):
    with patch("plugins.plugin_manager.requests.get", side_effect=serve(data, signature)) as get:
        return mgr.get_available_plugins(), get


# ===========================================================================
# plugin_catalog.parse
# ===========================================================================
@pytest.mark.unit
@pytest.mark.security
class TestParse:
    def test_signed_catalog_is_read(self, key):
        data = catalog()
        assert pc.parse(data, sign(key, data, "phoenix-plugins 10")) == (10, [ENTRY])

    def test_backup_key_is_accepted(self):
        sk, pub = keypair(bytes.fromhex("1112131415161718"))
        _, main = keypair()
        data = catalog()
        sig = sign(sk, data, "phoenix-plugins 10", bytes.fromhex("1112131415161718"))
        assert pc.parse(data, sig, (main, pub))[0] == 10

    def test_pinned_keys_are_the_release_keys(self):
        assert pc.public_keys() == pp.desktop_public_keys()

    @pytest.mark.parametrize("signature", ["", "untrusted comment: x\n", "not a signature"])
    def test_missing_or_malformed_signature(self, key, signature):
        with pytest.raises(pc.CatalogError):
            pc.parse(catalog(), signature)

    def test_unknown_key(self, key):
        other, _ = keypair(bytes.fromhex("aaaaaaaaaaaaaaaa"))
        data = catalog()
        sig = sign(other, data, "phoenix-plugins 10", bytes.fromhex("aaaaaaaaaaaaaaaa"))
        with pytest.raises(pc.CatalogError, match="unknown key"):
            pc.parse(data, sig)

    def test_forged_signature_under_the_pinned_key_id(self, key):
        other, _ = keypair()
        data = catalog()
        with pytest.raises(pc.CatalogError):
            pc.parse(data, sign(other, data, "phoenix-plugins 10"))

    def test_edited_catalog(self, key):
        sig = sign(key, catalog(), "phoenix-plugins 10")
        evil = catalog(plugins=[dict(ENTRY, url="https://evil.example/x.zip")])
        with pytest.raises(pc.CatalogError):
            pc.parse(evil, sig)

    @pytest.mark.parametrize("trusted", [
        "phoenix-desktop 1.0-10 2099-01-01",   # a release signature
        "phoenix-agent windows 5.0.0-1-10",
        "phoenix-plugins 9",                   # another catalog's
        "phoenix-plugins",
    ])
    def test_signature_made_for_something_else(self, key, trusted):
        data = catalog()
        with pytest.raises(pc.CatalogError, match="not for this"):
            pc.parse(data, sign(key, data, trusted))

    @pytest.mark.parametrize("data", [
        b"not json", b"[]", b'{"plugins": []}', b'{"serial": 1}',
        b'{"serial": "1", "plugins": []}', b'{"serial": true, "plugins": []}',
        b'{"serial": 0, "plugins": []}', b'{"serial": 1, "plugins": {}}',
    ])
    def test_malformed_catalog(self, key, data):
        with pytest.raises(pc.CatalogError):
            pc.parse(data, sign(key, data, "phoenix-plugins 1"))

    def test_non_object_entries_are_dropped(self, key):
        data = catalog(plugins=[ENTRY, "x", 3])
        assert pc.parse(data, sign(key, data, "phoenix-plugins 10"))[1] == [ENTRY]


# ===========================================================================
# PluginManager.get_available_plugins
# ===========================================================================
@pytest.mark.unit
@pytest.mark.security
class TestFetch:
    def test_signed_catalog_supplies_the_hashes(self, mgr, key):
        data = catalog()
        plugins, get = fetch(mgr, data, sign(key, data, "phoenix-plugins 10"))
        assert plugins == [ENTRY]
        assert mgr._published_hashes == {ENTRY["url"]: "f" * 64, "100": "f" * 64}
        assert [c.args[0] for c in get.call_args_list] == [URL, URL + ".minisig"]
        for call in get.call_args_list:
            assert call.kwargs["verify"] is True
            assert call.kwargs["allow_redirects"] is False
            assert call.kwargs["timeout"] > 0

    def test_no_signature_file(self, mgr, key):
        plugins, _ = fetch(mgr, catalog(), None)
        assert plugins == []
        assert mgr._published_hashes == {}

    def test_bad_signature_supplies_nothing(self, mgr, key):
        other, _ = keypair()
        data = catalog()
        plugins, _ = fetch(mgr, data, sign(other, data, "phoenix-plugins 10"))
        assert plugins == []
        assert mgr._published_hashes == {}

    def test_unverified_catalog_cannot_install(self, mgr, key):
        """The hash a download is checked against comes from a verified
        catalog only: without one the install is refused."""
        fetch(mgr, catalog(), "untrusted comment: x\n")
        with patch("plugins.plugin_manager.requests.get") as get:
            ok, msg = mgr.download_plugin(ENTRY["url"], plugin_id="100")
        assert ok is False and "integrity" in msg.lower()
        get.assert_not_called()

    def test_older_catalog_is_refused(self, mgr, key):
        new, old = catalog(serial=20, plugins=[]), catalog(serial=10)
        assert fetch(mgr, new, sign(key, new, "phoenix-plugins 20"))[0] == []
        plugins, _ = fetch(mgr, old, sign(key, old, "phoenix-plugins 10"))
        assert plugins == []
        assert mgr._published_hashes == {}

    def test_same_catalog_again_is_fine(self, mgr, key):
        data = catalog()
        sig = sign(key, data, "phoenix-plugins 10")
        fetch(mgr, data, sig)
        assert fetch(mgr, data, sig)[0] == [ENTRY]

    def test_newer_catalog_replaces_the_hashes(self, mgr, key):
        data = catalog()
        fetch(mgr, data, sign(key, data, "phoenix-plugins 10"))
        newer = catalog(serial=11, plugins=[dict(ENTRY, id="200", url="https://example.com/b.zip")])
        fetch(mgr, newer, sign(key, newer, "phoenix-plugins 11"))
        assert set(mgr._published_hashes) == {"200", "https://example.com/b.zip"}

    def test_failed_fetch_keeps_verified_hashes(self, mgr, key):
        data = catalog()
        fetch(mgr, data, sign(key, data, "phoenix-plugins 10"))
        assert fetch(mgr, catalog(serial=11), None)[0] == []
        assert "100" in mgr._published_hashes

    @pytest.mark.parametrize("url", [
        "http://example.com/optional_plugins.json", "file:///tmp/optional_plugins.json",
    ])
    def test_non_https_catalog_is_not_fetched(self, mgr, key, url):
        mgr.OPTIONAL_PLUGINS_URL = url
        data = catalog()
        plugins, get = fetch(mgr, data, sign(key, data, "phoenix-plugins 10"))
        assert plugins == []
        get.assert_not_called()

    def test_oversized_catalog(self, mgr, key):
        data = catalog(plugins=[dict(ENTRY, name="x" * (pc.MAX_CATALOG + 1))])
        assert fetch(mgr, data, sign(key, data, "phoenix-plugins 10"))[0] == []

    def test_redirect_is_not_followed(self, mgr, key):
        with patch("plugins.plugin_manager.requests.get",
                   return_value=response(b"", 302)) as get:
            assert mgr.get_available_plugins() == []
        assert get.call_count == 1
