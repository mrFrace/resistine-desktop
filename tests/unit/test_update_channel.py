"""Desktop updates over the signed channel.

- parse_desktop_manifest: desktop key only, trusted comment pins dir + expiry,
  every field checked, a release without this OS's package
- channel.check: which install it applies to, rollback protection, staleness

Signatures are made with throwaway Ed25519 keys in minisign's format. No
network: the HTTP session and the OIDC token are mocked.
"""
import base64
import datetime
import hashlib
import json
import sys
from unittest.mock import MagicMock, patch

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from plugins.wazuh.agent import phoenix_packages as pp
from utils.updates import channel

DESKTOP_ID = bytes.fromhex("1112131415161718")
AGENT_ID = bytes.fromhex("0102030405060708")


def _keypair(key_id):
    sk = Ed25519PrivateKey.generate()
    return sk, base64.b64encode(b"Ed" + key_id + sk.public_key().public_bytes_raw()).decode()


def _sign(sk, data: bytes, trusted: str, key_id=DESKTOP_ID) -> str:
    sig = sk.sign(hashlib.blake2b(data, digest_size=64).digest())
    return ("untrusted comment: test\n"
            + base64.b64encode(b"ED" + key_id + sig).decode() + "\n"
            + f"trusted comment: {trusted}\n"
            + base64.b64encode(sk.sign(sig + trusted.encode())).decode() + "\n")


def _release(build=202610221204, expires="2027-01-20", oses=("windows", "linux-deb"), **over):
    d = f"2026.07.20-rc-{build}"
    files = {os_: {"file": f"phoenix-{os_}-{build}.bin",
                   "sha512": hashlib.sha512(os_.encode()).hexdigest(), "size": 100}
             for os_ in oses}
    m = {"product": "phoenix-desktop", "version": "2026.07.20-rc", "build": build,
         "dir": d, "expires": expires, "published": "2026-10-22T12:00:00Z", "files": files}
    m.update(over)
    return json.dumps(m).encode(), d


@pytest.fixture
def keys():
    """(desktop secret key, agent secret key), with both public keys pinned."""
    dsk, dpub = _keypair(DESKTOP_ID)
    ask, apub = _keypair(AGENT_ID)
    with patch.object(pp, "DESKTOP_MINISIGN_PUBLIC_KEY", dpub), \
            patch.object(pp, "MINISIGN_PUBLIC_KEY", apub):
        yield dsk, ask


def _signed(sk, build=202610221204, expires="2027-01-20", key_id=DESKTOP_ID, **kw):
    data, d = _release(build, expires, **kw)
    return data, _sign(sk, data, f"phoenix-desktop {d} {expires}", key_id)


# ===========================================================================
# parse_desktop_manifest
# ===========================================================================
@pytest.mark.unit
@pytest.mark.security
class TestParseDesktopManifest:
    def test_valid_picks_this_os(self, keys):
        data, sig = _signed(keys[0])
        m = pp.parse_desktop_manifest(data, sig, "linux-deb")
        assert (m.product, m.build, m.file, m.expires) == (
            "phoenix-desktop", 202610221204, "phoenix-linux-deb-202610221204.bin", "2027-01-20")

    def test_release_without_this_os(self, keys):
        data, sig = _signed(keys[0], oses=("windows",))
        assert pp.parse_desktop_manifest(data, sig, "linux-rpm") is None

    def test_agent_key_cannot_sign_desktop_releases(self, keys):
        data, sig = _signed(keys[1], key_id=AGENT_ID)
        with pytest.raises(pp.PackageError, match="unknown key"):
            pp.parse_desktop_manifest(data, sig, "windows")

    def test_desktop_key_cannot_sign_agent_packages(self, keys):
        agent = json.dumps({"product": "phoenix-agent", "platform": "windows",
                            "version": "5", "build": 1, "dir": "5-1", "file": "a.msi",
                            "sha512": "0" * 128, "size": 1}).encode()
        sig = _sign(keys[0], agent, "phoenix-agent windows 5-1")
        with pytest.raises(pp.PackageError, match="unknown key"):
            pp.parse_manifest(agent, sig, "windows")

    @pytest.mark.parametrize("comment", [
        "phoenix-desktop 2026.07.20-rc-202610221204 2099-01-01",  # expiry pushed out
        "phoenix-desktop 2026.07.20-rc-202610221300 2027-01-20",  # another build
        "phoenix-agent desktop 2026.07.20-rc-202610221204",
    ])
    def test_trusted_comment_must_match(self, keys, comment):
        data, _ = _release()
        with pytest.raises(pp.PackageError, match="another build"):
            pp.parse_desktop_manifest(data, _sign(keys[0], data, comment), "windows")

    @pytest.mark.parametrize("over", [
        {"product": "phoenix-agent"},
        {"build": "202610221204"},
        {"dir": "2026.07.20-rc-1"},           # dir doesn't end in the build
        {"expires": "soon"},
        {"files": {}},
        {"files": {"plan9": {"file": "x", "sha512": "0" * 128, "size": 1}}},
        {"files": {"windows": {"file": "../x", "sha512": "0" * 128, "size": 1}}},
        {"files": {"windows": {"file": "x", "sha512": "short", "size": 1}}},
        {"files": {"windows": {"file": "x", "sha512": "0" * 128, "size": 0}}},
    ])
    def test_bad_fields(self, keys, over):
        data, d = _release(**over)
        exp = over.get("expires", "2027-01-20")
        sig = _sign(keys[0], data, f"phoenix-desktop {d} {exp}")
        with pytest.raises(pp.PackageError, match="malformed"):
            pp.parse_desktop_manifest(data, sig, "windows")


# ===========================================================================
# channel.check
# ===========================================================================
class _Resp:
    def __init__(self, status=200, body=b""):
        self.status_code, self._body = status, body

    def iter_content(self, n):
        yield self._body

    def close(self):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def _http(data, sig):
    base = f"{pp.PACKAGES_URL}/desktop/current"
    files = {f"{base}/manifest.json": data, f"{base}/manifest.json.minisig": sig.encode()}
    http = MagicMock()
    http.get.side_effect = lambda url, **kw: _Resp(200, files[url]) if url in files else _Resp(404)
    return http


@pytest.fixture
def install(monkeypatch):
    """A frozen .deb install running build 202610221204, no update state yet."""
    state = {}
    monkeypatch.setattr(channel, "os_key", lambda: "linux-deb")
    monkeypatch.setattr(channel, "get_build", lambda: "202610221204")
    monkeypatch.setattr(channel.settings, "get", lambda ns, k, d=None: state.get(k, d))
    monkeypatch.setattr(channel.settings, "set", lambda ns, k, v: state.__setitem__(k, v))
    return state


TODAY = datetime.date(2026, 10, 22)


@pytest.mark.unit
@pytest.mark.security
class TestCheck:
    def test_newer_release_is_available(self, keys, install):
        data, sig = _signed(keys[0], build=202610221500)
        c = channel.check(_http(data, sig), ["tok"], today=TODAY)
        assert c.available and c.latest.build == 202610221500 and not c.stale
        assert install["highest_build"] == 202610221500

    def test_same_build_is_not_an_update(self, keys, install):
        data, sig = _signed(keys[0])
        assert not channel.check(_http(data, sig), ["tok"], today=TODAY).available

    def test_older_than_running_is_just_no_update(self, keys, install):
        data, sig = _signed(keys[0], build=202610220000)
        assert not channel.check(_http(data, sig), ["tok"], today=TODAY).available

    def test_rollback_below_highest_seen_is_refused(self, keys, install):
        install["highest_build"] = 202610230000
        data, sig = _signed(keys[0], build=202610221500)
        with pytest.raises(pp.PackageError, match="older Phoenix release"):
            channel.check(_http(data, sig), ["tok"], today=TODAY)

    def test_expired_release_is_stale(self, keys, install):
        data, sig = _signed(keys[0], build=202610221500, expires="2026-10-01")
        assert channel.check(_http(data, sig), ["tok"], today=TODAY).stale

    def test_tampered_manifest_is_refused(self, keys, install):
        data, sig = _signed(keys[0], build=202610221500)
        with pytest.raises(pp.PackageError, match="not valid"):
            channel.check(_http(data.replace(b"100", b"999"), sig), ["tok"], today=TODAY)
        assert "highest_build" not in install

    def test_release_without_this_os(self, keys, install):
        data, sig = _signed(keys[0], build=202610221500, oses=("windows",))
        c = channel.check(_http(data, sig), ["tok"], today=TODAY)
        assert c.latest is None and not c.available

    def test_not_from_the_channel(self, monkeypatch):
        monkeypatch.setattr(channel, "os_key", lambda: None)
        assert channel.check() is None


@pytest.mark.unit
class TestOsKey:
    def test_source_run(self, monkeypatch):
        monkeypatch.setattr(sys, "frozen", False, raising=False)
        assert channel.os_key() is None

    @pytest.mark.parametrize("owner,expected", [
        ("dpkg-query", "linux-deb"), ("rpm", "linux-rpm"), ("pacman", "linux-arch"), (None, None)])
    def test_linux_package_owner(self, monkeypatch, owner, expected):
        monkeypatch.setattr(sys, "frozen", True, raising=False)
        monkeypatch.setattr(sys, "platform", "linux")
        monkeypatch.setattr(channel.shutil, "which", lambda t: f"/usr/bin/{t}")
        monkeypatch.setattr(channel.subprocess, "run",
                            lambda cmd, **kw: MagicMock(returncode=0 if cmd[0] == owner else 1))
        assert channel.os_key() == expected
