"""
Unit tests for plugins/wazuh/agent/phoenix_packages.py.

- verify_minisign: both signature algorithms, every way a signature can be wrong
- parse_manifest: the signed trusted comment pins platform and directory
- download: verified rename into place, 401 refresh, size/hash mismatches
- verify_cached / remove_cached: offline re-check of a kept package
- platform_key: which machines have a package

Signatures are made with a throwaway Ed25519 key in minisign's format; one test
checks the real manifest briareosai served for build 458 against the pinned key.
No network: the HTTP session and the OIDC token are mocked.
"""
import base64
import hashlib
import json
import os
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from plugins.wazuh.agent import phoenix_packages as pp

FIXTURES = Path(__file__).parent.parent / "fixtures" / "phoenix_packages"
KEY_ID = bytes.fromhex("0102030405060708")


def _keypair(key_id=KEY_ID):
    sk = Ed25519PrivateKey.generate()
    pub = base64.b64encode(b"Ed" + key_id + sk.public_key().public_bytes_raw()).decode()
    return sk, pub


def _sign(sk, data: bytes, trusted: str, alg=b"ED", key_id=KEY_ID) -> str:
    msg = hashlib.blake2b(data, digest_size=64).digest() if alg == b"ED" else data
    sig = sk.sign(msg)
    glob = sk.sign(sig + trusted.encode())
    return (
        "untrusted comment: test\n"
        + base64.b64encode(alg + key_id + sig).decode() + "\n"
        + f"trusted comment: {trusted}\n"
        + base64.b64encode(glob).decode() + "\n"
    )


def _manifest(payload: bytes, plat="windows", build=500, **over):
    d = f"5.0.0-1-{build}"
    m = {"product": "phoenix-agent", "platform": plat, "version": "5.0.0-1",
         "build": build, "dir": d, "file": "phoenix-agent-5.0.0-1.msi",
         "sha512": hashlib.sha512(payload).hexdigest(), "size": len(payload),
         "published": "2026-10-15T00:00:00Z"}
    m.update(over)
    return json.dumps(m).encode(), m["dir"]


@pytest.fixture
def key():
    sk, pub = _keypair()
    with patch.object(pp, "MINISIGN_PUBLIC_KEY", pub):
        yield sk, pub


# ===========================================================================
# verify_minisign
# ===========================================================================
@pytest.mark.unit
@pytest.mark.security
class TestVerifyMinisign:
    @pytest.mark.parametrize("alg", [b"ED", b"Ed"])
    def test_valid_returns_trusted_comment(self, key, alg):
        sk, pub = key
        sig = _sign(sk, b"hello", "phoenix-agent windows x-1", alg=alg)
        assert pp.verify_minisign(b"hello", sig, pub) == "phoenix-agent windows x-1"

    def test_tampered_data(self, key):
        sk, pub = key
        sig = _sign(sk, b"hello", "c")
        with pytest.raises(pp.PackageError, match="not valid"):
            pp.verify_minisign(b"hellO", sig, pub)

    def test_tampered_trusted_comment(self, key):
        sk, pub = key
        sig = _sign(sk, b"hello", "phoenix-agent windows a-1")
        sig = sig.replace("windows a-1", "macos-arm64 a-1")
        with pytest.raises(pp.PackageError, match="not valid"):
            pp.verify_minisign(b"hello", sig, pub)

    def test_other_key_same_id(self, key):
        _, pub = key
        other, _ = _keypair()
        with pytest.raises(pp.PackageError, match="not valid"):
            pp.verify_minisign(b"hello", _sign(other, b"hello", "c"), pub)

    def test_other_key_id(self, key):
        sk, pub = key
        sig = _sign(sk, b"hello", "c", key_id=bytes(8))
        with pytest.raises(pp.PackageError, match="unknown key"):
            pp.verify_minisign(b"hello", sig, pub)

    @pytest.mark.parametrize("sig", [
        "", "garbage", "untrusted comment: x\n!!!\ntrusted comment: c\nAAAA\n",
        "untrusted comment: x\nAAAA\ntrusted comment: c\nAAAA\n",
    ])
    def test_malformed(self, key, sig):
        with pytest.raises(pp.PackageError):
            pp.verify_minisign(b"hello", sig, key[1])

    def test_unknown_algorithm(self, key):
        sk, pub = key
        with pytest.raises(pp.PackageError, match="algorithm"):
            pp.verify_minisign(b"hello", _sign(sk, b"hello", "c", alg=b"XX"), pub)


# ===========================================================================
# parse_manifest
# ===========================================================================
@pytest.mark.unit
@pytest.mark.security
class TestParseManifest:
    def test_real_manifest_from_briareosai(self):
        data = (FIXTURES / "manifest.json").read_bytes()
        sig = (FIXTURES / "manifest.json.minisig").read_text()
        m = pp.parse_manifest(data, sig, "windows")
        assert (m.dir, m.build, m.size) == ("5.0.0-1-458", 458, 39043008)
        with pytest.raises(pp.PackageError):
            pp.parse_manifest(data, sig, "macos-arm64")

    def test_valid(self, key):
        sk, _ = key
        data, d = _manifest(b"pkg")
        m = pp.parse_manifest(data, _sign(sk, data, f"phoenix-agent windows {d}"), "windows")
        assert m.file == "phoenix-agent-5.0.0-1.msi" and m.raw == data

    def test_signed_for_another_dir(self, key):
        sk, _ = key
        data, _ = _manifest(b"pkg")
        with pytest.raises(pp.PackageError, match="another platform"):
            pp.parse_manifest(data, _sign(sk, data, "phoenix-agent windows 5.0.0-1-1"), "windows")

    @pytest.mark.parametrize("over", [
        {"product": "other"}, {"platform": "linux-amd64"}, {"dir": "../x-1"},
        {"file": "../evil.msi"}, {"file": "a b.msi"}, {"sha512": "00"},
        {"size": 0}, {"size": "1"}, {"build": "500"}, {"build": True},
    ])
    def test_bad_fields(self, key, over):
        sk, _ = key
        data, d = _manifest(b"pkg", **over)
        d = over.get("dir", d)
        with pytest.raises(pp.PackageError):
            pp.parse_manifest(data, _sign(sk, data, f"phoenix-agent windows {d}"), "windows")

    def test_not_json(self, key):
        sk, _ = key
        with pytest.raises(pp.PackageError, match="JSON"):
            pp.parse_manifest(b"{", _sign(sk, b"{", "c"), "windows")


# ===========================================================================
# download / verify_cached
# ===========================================================================
class _Resp:
    def __init__(self, status=200, body=b""):
        self.status_code = status
        self._body = body

    def iter_content(self, n):
        for i in range(0, len(self._body), n or 1):
            yield self._body[i:i + n]

    def close(self):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def _server(sk, payload, plat="windows", served=None, first_status=None):
    data, d = _manifest(payload, plat=plat)
    sig = _sign(sk, data, f"phoenix-agent {plat} {d}")
    base = f"{pp.PACKAGES_URL}/{plat}"
    files = {
        f"{base}/current/manifest.json": data,
        f"{base}/current/manifest.json.minisig": sig.encode(),
        f"{base}/{d}/phoenix-agent-5.0.0-1.msi": payload if served is None else served,
    }
    calls = []

    def get(url, **kw):
        calls.append((url, kw["headers"]["Authorization"]))
        if first_status and len(calls) == 1:
            return _Resp(first_status)
        return _Resp(200, files[url]) if url in files else _Resp(404)

    http = MagicMock()
    http.get.side_effect = get
    return http, calls


@pytest.fixture
def oidc():
    with patch("plugins.login.oidc.refresh", return_value="tok1") as refresh, \
            patch("plugins.login.oidc._session") as session:
        yield refresh, session


@pytest.mark.unit
@pytest.mark.security
class TestDownload:
    def test_success_then_cached_recheck(self, key, oidc, tmp_path):
        sk, _ = key
        http, calls = _server(sk, b"x" * 3000)
        oidc[1].return_value = http
        path, m = pp.download(str(tmp_path), plat="windows")
        assert Path(path).read_bytes() == b"x" * 3000
        assert all(auth == "Bearer tok1" for _, auth in calls)
        assert not list(tmp_path.glob("*.part"))
        assert pp.verify_cached(path, "windows") == m
        assert pp.verify_cached(path, "macos-arm64") is None

        Path(path).write_bytes(b"y" * 3000)
        assert pp.verify_cached(path, "windows") is None
        pp.remove_cached(path)
        assert list(tmp_path.iterdir()) == []

    def test_existing_good_file_is_not_downloaded_again(self, key, oidc, tmp_path):
        sk, _ = key
        http, calls = _server(sk, b"x" * 10)
        oidc[1].return_value = http
        pp.download(str(tmp_path), plat="windows", filename="a.msi")
        pp.download(str(tmp_path), plat="windows", filename="a.msi")
        assert sum(u.endswith(".msi") for u, _ in calls) == 1

    def test_hash_mismatch_leaves_nothing(self, key, oidc, tmp_path):
        sk, _ = key
        http, _ = _server(sk, b"x" * 10, served=b"y" * 10)
        oidc[1].return_value = http
        with pytest.raises(pp.PackageError, match="does not match"):
            pp.download(str(tmp_path), plat="windows")
        assert list(tmp_path.iterdir()) == []

    def test_oversized_download_is_cut_off(self, key, oidc, tmp_path):
        sk, _ = key
        http, _ = _server(sk, b"x" * 10, served=b"x" * 5000)
        oidc[1].return_value = http
        with pytest.raises(pp.PackageError, match="larger"):
            pp.download(str(tmp_path), plat="windows")
        assert list(tmp_path.iterdir()) == []

    def test_401_refreshes_token_once(self, key, oidc, tmp_path):
        sk, _ = key
        http, calls = _server(sk, b"x" * 10, first_status=401)
        oidc[1].return_value = http
        oidc[0].side_effect = ["tok1", "tok2"]
        pp.download(str(tmp_path), plat="windows")
        assert calls[0][1] == "Bearer tok1"
        assert all(auth == "Bearer tok2" for _, auth in calls[1:])
        oidc[0].assert_called_with(force=True)

    def test_not_signed_in(self, oidc, tmp_path):
        oidc[0].return_value = None
        with pytest.raises(pp.PackageError, match="Sign in"):
            pp.download(str(tmp_path), plat="windows")

    def test_bad_signature_downloads_nothing(self, key, oidc, tmp_path):
        other, _ = _keypair()
        http, calls = _server(other, b"x" * 10)
        oidc[1].return_value = http
        with pytest.raises(pp.PackageError):
            pp.download(str(tmp_path), plat="windows")
        assert not any(u.endswith(".msi") for u, _ in calls)

    def test_download_or_none_reports(self, oidc, tmp_path):
        oidc[0].return_value = None
        seen = []
        assert pp.download_or_none(str(tmp_path), seen.append) is None
        assert seen and "Sign in" in seen[-1]


# ===========================================================================
# platform_key
# ===========================================================================
@pytest.mark.unit
class TestPlatformKey:
    @pytest.mark.parametrize("system,machine,expected", [
        ("Windows", "AMD64", "windows"),
        ("Windows", "ARM64", "windows"),
        ("Darwin", "arm64", "macos-arm64"),
        ("Darwin", "x86_64", None),
        ("Linux", "x86_64", "linux-amd64"),
        ("Linux", "aarch64", None),
    ])
    def test_mapping(self, system, machine, expected):
        with patch.object(pp.platform, "system", return_value=system), \
                patch.object(pp.platform, "machine", return_value=machine):
            assert pp.platform_key() == expected

    def test_env_override(self):
        with patch.dict(os.environ, {"PHOENIX_PACKAGES_URL": "https://x/p/"}):
            assert pp.manifest_url("windows") == "https://x/p/windows/current/manifest.json"
