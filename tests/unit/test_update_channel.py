"""Desktop updates over the signed channel.

- parse_desktop_manifest: desktop key only, trusted comment pins dir + expiry,
  every field checked, a release without this OS's package
- channel.check: which install it applies to, rollback protection, staleness
- installer: the download must match the signed manifest, and only that file,
  unchanged, is started; the Windows signer check

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
from utils.updates import channel, installer

DESKTOP_ID = bytes.fromhex("1112131415161718")
BACKUP_ID = bytes.fromhex("2122232425262728")
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

    def test_backup_key_signs_a_release(self, keys):
        bsk, bpub = _keypair(BACKUP_ID)
        data, sig = _signed(bsk, key_id=BACKUP_ID)
        with pytest.raises(pp.PackageError, match="unknown key"):  # not pinned yet
            pp.parse_desktop_manifest(data, sig, "windows")
        with patch.object(pp, "DESKTOP_MINISIGN_BACKUP_PUBLIC_KEYS", (bpub,)):
            assert pp.parse_desktop_manifest(data, sig, "windows").build == 202610221204
            # the release key still works next to it
            data, sig = _signed(keys[0])
            assert pp.parse_desktop_manifest(data, sig, "windows") is not None

    def test_backup_key_id_with_another_keys_signature_is_refused(self, keys):
        _, bpub = _keypair(BACKUP_ID)
        data, sig = _signed(keys[0], key_id=BACKUP_ID)  # release key, backup's id
        with patch.object(pp, "DESKTOP_MINISIGN_BACKUP_PUBLIC_KEYS", (bpub,)):
            with pytest.raises(pp.PackageError, match="not valid"):
                pp.parse_desktop_manifest(data, sig, "windows")

    def test_backup_key_cannot_sign_agent_packages(self, keys):
        bsk, bpub = _keypair(BACKUP_ID)
        agent = json.dumps({"product": "phoenix-agent", "platform": "windows",
                            "version": "5", "build": 1, "dir": "5-1", "file": "a.msi",
                            "sha512": "0" * 128, "size": 1}).encode()
        sig = _sign(bsk, agent, "phoenix-agent windows 5-1", BACKUP_ID)
        with patch.object(pp, "DESKTOP_MINISIGN_BACKUP_PUBLIC_KEYS", (bpub,)):
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


def test_pinned_desktop_keys_are_well_formed_and_distinct():
    """The keys really compiled in: minisign Ed25519 keys, each with its own
    key id (a release is matched to its key by id), none of them the agent's."""
    keys = pp.desktop_public_keys()
    raw = [base64.b64decode(k, validate=True) for k in keys]
    assert keys[0] == pp.DESKTOP_MINISIGN_PUBLIC_KEY
    assert all(len(r) == 42 and r[:2] == b"Ed" for r in raw)
    ids = [r[2:10] for r in raw]
    assert len(set(ids)) == len(ids)
    assert base64.b64decode(pp.MINISIGN_PUBLIC_KEY)[2:10] not in ids


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


# ===========================================================================
# installer: download + launch
# ===========================================================================
PAYLOAD = b"MZ" + b"phoenix setup " * 500


def _offer(sk, os_key="windows", name="Phoenix-Setup-1.0-202610221500.exe",
           payload=PAYLOAD, build=202610221500):
    """A verified release for ``os_key`` whose package is ``payload``."""
    data, d = _release(build)
    m = json.loads(data)
    m["files"] = {os_key: {"file": name, "sha512": hashlib.sha512(payload).hexdigest(),
                           "size": len(payload)}}
    data = json.dumps(m).encode()
    manifest = pp.parse_desktop_manifest(data, _sign(sk, data, f"phoenix-desktop {d} 2027-01-20"),
                                         os_key)
    return channel.UpdateCheck(os_key, 202610221204, manifest, stale=False)


def _store(offer, served):
    url = f"{pp.PACKAGES_URL}/desktop/{offer.latest.dir}/{offer.latest.file}"
    http = MagicMock()
    http.get.side_effect = lambda u, **kw: _Resp(200, served) if u == url else _Resp(404)
    return http


@pytest.fixture
def updates_dir(tmp_path, monkeypatch):
    """The config dir is a temp dir; the store is reached with a mocked token."""
    monkeypatch.setattr(installer.settings, "get_config_dir", lambda: str(tmp_path))
    with patch("plugins.login.oidc.refresh", return_value="tok"):
        yield tmp_path / "updates"


def _download(offer, served):
    with patch("plugins.login.oidc._session", return_value=_store(offer, served)):
        return installer.download(offer)


@pytest.mark.unit
@pytest.mark.security
class TestInstallerDownload:
    def test_matching_file_lands_in_a_fresh_private_directory(self, keys, updates_dir):
        offer = _offer(keys[0])
        path = _download(offer, PAYLOAD)
        assert open(path, "rb").read() == PAYLOAD
        parent = updates_dir / path.split("/")[-2]
        assert parent.parent == updates_dir and parent.name.startswith("release-")
        if sys.platform != "win32":
            assert parent.stat().st_mode & 0o077 == 0

    def test_swapped_file_is_refused_and_removed(self, keys, updates_dir):
        offer = _offer(keys[0])
        evil = b"E" * len(PAYLOAD)  # same size, other content
        with pytest.raises(pp.PackageError, match="does not match its signed manifest"):
            _download(offer, evil)
        assert list(updates_dir.iterdir()) == []

    def test_longer_file_is_cut_off(self, keys, updates_dir):
        offer = _offer(keys[0])
        with pytest.raises(pp.PackageError, match="larger than its manifest"):
            _download(offer, PAYLOAD + b"x")
        assert list(updates_dir.iterdir()) == []

    def test_truncated_file_is_refused(self, keys, updates_dir):
        offer = _offer(keys[0])
        with pytest.raises(pp.PackageError, match="does not match"):
            _download(offer, PAYLOAD[:-1])

    def test_earlier_downloads_are_cleared(self, keys, updates_dir):
        offer = _offer(keys[0])
        first = _download(offer, PAYLOAD)
        second = _download(offer, PAYLOAD)
        assert first != second and not pp.verify_file(first, offer.latest)

    def test_nothing_to_download(self, keys, updates_dir):
        same = _offer(keys[0], build=202610221204)
        with pytest.raises(pp.PackageError, match="no update"):
            installer.download(same)

    def test_linux_is_left_to_the_package_manager(self, keys, updates_dir):
        assert not installer.supported("linux-deb") and not installer.supported(None)
        with pytest.raises(pp.PackageError, match="no update"):
            installer.download(_offer(keys[0], os_key="linux-deb", name="phoenix.deb"))

    def test_wrong_kind_of_file_is_not_fetched(self, keys, updates_dir):
        offer = _offer(keys[0], name="Phoenix-Setup.bat")
        with pytest.raises(pp.PackageError, match="not a Phoenix installer"):
            installer.download(offer)

    def test_agent_manifest_cannot_be_downloaded_as_desktop(self, keys, tmp_path):
        m = pp.Manifest("windows", "1", 1, "1-1", "a.exe", "0" * 128, 10)
        with pytest.raises(pp.PackageError, match="not a Phoenix Desktop release"):
            pp.download_desktop(m, str(tmp_path), token_box=["t"], http=MagicMock())


@pytest.fixture
def started(monkeypatch):
    """Record what would be started instead of starting it."""
    calls = []
    monkeypatch.setattr(installer.os, "startfile",
                        lambda *a: calls.append(("startfile", *a)), raising=False)
    monkeypatch.setattr(installer.subprocess, "Popen",
                        lambda cmd, **kw: calls.append(("popen", *cmd)))
    monkeypatch.setattr(installer, "_held", lambda path: installer.contextlib.nullcontext())
    return calls


@pytest.mark.unit
@pytest.mark.security
class TestInstallerLaunch:
    def test_windows_installer_starts_silently(self, keys, updates_dir, started):
        offer = _offer(keys[0])
        path = _download(offer, PAYLOAD)
        installer.launch(path, offer.latest)
        assert started == [("startfile", path, "open", "/SILENT /SUPPRESSMSGBOXES /NORESTART")]

    def test_macos_image_is_opened(self, keys, updates_dir, started):
        offer = _offer(keys[0], os_key="macos-arm64", name="Phoenix-1.0.dmg")
        path = _download(offer, PAYLOAD)
        installer.launch(path, offer.latest)
        assert started == [("popen", "/usr/bin/open", path)]

    def test_file_changed_after_download_is_not_started(self, keys, updates_dir, started):
        offer = _offer(keys[0])
        path = _download(offer, PAYLOAD)
        with open(path, "r+b") as f:
            f.write(b"EVIL")
        with pytest.raises(pp.PackageError, match="changed after it was verified"):
            installer.launch(path, offer.latest)
        assert started == []

    def test_file_outside_the_updates_directory_is_not_started(self, keys, updates_dir,
                                                               started, tmp_path):
        offer = _offer(keys[0])
        other = tmp_path / "elsewhere" / "x"
        other.mkdir(parents=True)
        path = other / offer.latest.file
        path.write_bytes(PAYLOAD)
        with pytest.raises(pp.PackageError, match="not a Phoenix installer"):
            installer.launch(str(path), offer.latest)
        assert started == []

    def test_symlink_is_not_started(self, keys, updates_dir, started, tmp_path):
        offer = _offer(keys[0])
        path = _download(offer, PAYLOAD)
        real = tmp_path / "real.exe"
        real.write_bytes(PAYLOAD)
        import os
        os.unlink(path)
        os.symlink(real, path)
        with pytest.raises(pp.PackageError):
            installer.launch(path, offer.latest)
        assert started == []

    def test_unsigned_installer_is_refused_once_a_publisher_is_pinned(
            self, keys, updates_dir, started, monkeypatch):
        offer = _offer(keys[0])
        path = _download(offer, PAYLOAD)
        monkeypatch.setattr(installer, "WINDOWS_PUBLISHER", "Phoenix s.r.o.")
        monkeypatch.setattr(installer, "_windows_signer", lambda p: ("NotSigned", ""))
        with pytest.raises(pp.PackageError, match="not signed by Phoenix"):
            installer.launch(path, offer.latest)
        assert started == []


@pytest.mark.unit
@pytest.mark.security
class TestWindowsSigner:
    @pytest.mark.parametrize("status,subject,ok", [
        ("Valid", "CN=Phoenix s.r.o., O=Phoenix s.r.o., C=CZ", True),
        ("Valid", 'CN="Phoenix, Inc.", O=Phoenix', False),
        ("Valid", "CN=Someone Else, O=Phoenix s.r.o.", False),
        ("Valid", "O=Phoenix s.r.o., OU=CN=Phoenix s.r.o.", False),
        ("HashMismatch", "CN=Phoenix s.r.o.", False),
        ("UnknownError", "CN=Phoenix s.r.o.", False),  # untrusted root
        ("NotSigned", "", False),
        ("", "", False),  # PowerShell did not run
    ])
    def test_only_a_valid_signature_by_the_publisher_passes(self, monkeypatch, status,
                                                            subject, ok):
        monkeypatch.setattr(installer, "WINDOWS_PUBLISHER", "Phoenix s.r.o.")
        monkeypatch.setattr(installer, "_windows_signer", lambda p: (status, subject))
        if ok:
            installer.check_windows_signer("x.exe")
        else:
            with pytest.raises(pp.PackageError, match="not signed by Phoenix"):
                installer.check_windows_signer("x.exe")

    def test_quoted_common_name(self):
        assert installer._common_name('O=X, CN="Phoenix, Inc.", C=US') == "Phoenix, Inc."

    def test_no_publisher_pinned_means_no_check(self, monkeypatch):
        monkeypatch.setattr(installer, "WINDOWS_PUBLISHER", "")
        monkeypatch.setattr(installer, "_windows_signer",
                            lambda p: pytest.fail("signer looked up"))
        installer.check_windows_signer("x.exe")
