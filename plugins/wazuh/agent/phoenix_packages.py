"""Phoenix agent packages: signed downloads for signed-in users.

The same store also carries Phoenix Desktop's own releases (platform
"desktop", see parse_desktop_manifest and utils/updates/channel.py): one
manifest per build listing every OS's package, signed with a separate desktop
key, so neither key can stand in for the other.

The agent packages are built by Resistine-Server-install CI and served at
https://auth.phoenix.exposed/packages/<platform>/current/ to anyone holding a
MAS access token (matrix repo, modules/services/phoenix-packages.nix):

  manifest.json          {"product", "platform", "version", "build", "dir",
                          "file", "sha512", "size", "published"}
  manifest.json.minisig  minisign signature; its signed trusted comment is
                         "phoenix-agent <platform> <dir>"
  <file>                 the package

The token only keeps the builds to our users. Integrity comes from the
manifest signature, checked here against the pinned public key below, and the
package's sha512 and size from that manifest. Nothing is installed from a
download that fails any check.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import platform
import re
from dataclasses import dataclass, field
from typing import Callable, Optional

from utils.logger import logger

PACKAGES_URL = "https://auth.phoenix.exposed/packages"

# Resistine-Server-install certs/phoenix-packages-minisign.pub (key id
# 0EB5393A52A7533F). Its secret half is the protected MINISIGN_KEY CI variable.
MINISIGN_PUBLIC_KEY = "RWQ/U6dSOjm1DsQR44jVW5YMhrPoSvAdCYphPZJWrKqrGwMFbP2d3aPc"

# packaging/phoenix-desktop-minisign.pub (key id BEA7ECA1B610B3A0): signs
# Phoenix Desktop releases. Its secret half is password-protected on the
# release machine (scripts/build/publish-desktop.sh).
DESKTOP_MINISIGN_PUBLIC_KEY = "RWSgsxC2oeynvutf13Lmgaqf29dX8MAKKtaEV21w4HEfsB3wXq71XjFT"

AGENT, DESKTOP = "phoenix-agent", "phoenix-desktop"
DESKTOP_PLATFORM = "desktop"  # the store's directory for desktop releases
# OS keys of a desktop release manifest's "files".
DESKTOP_OS_KEYS = ("windows", "linux-deb", "linux-rpm", "linux-arch", "macos-arm64")

_TIMEOUT = 30           # seconds per socket operation
_MAX_MANIFEST = 64 * 1024
_MAX_PACKAGE = 512 * 1024 * 1024
_CHUNK = 1024 * 1024

_DIR_RE = re.compile(r"^[0-9A-Za-z.+~-]+-[0-9]+$")
_FILE_RE = re.compile(r"^[0-9A-Za-z._+~-]+$")
_SHA512_RE = re.compile(r"^[0-9a-f]{128}$")
_DATE_RE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}$")


class PackageError(Exception):
    """A Phoenix package could not be fetched or failed verification.

    ``str(e)`` is safe to show to the user.
    """


@dataclass(frozen=True)
class Manifest:
    platform: str
    version: str
    build: int
    dir: str
    file: str
    sha512: str
    size: int
    raw: bytes = field(default=b"", repr=False)       # manifest.json as signed
    signature: str = field(default="", repr=False)  # manifest.json.minisig
    product: str = AGENT
    expires: str = ""  # desktop releases: YYYY-MM-DD after which the feed is stale


def packages_url() -> str:
    """Base URL of the package store (PHOENIX_PACKAGES_URL overrides it)."""
    return (os.environ.get("PHOENIX_PACKAGES_URL") or PACKAGES_URL).rstrip("/")


def platform_key() -> Optional[str]:
    """This machine's package platform, or None when none is built for it."""
    system, machine = platform.system(), platform.machine().lower()
    if system == "Windows":
        return "windows"  # the MSI is x86 and runs on x64 and arm64 Windows
    if system == "Darwin" and machine == "arm64":
        return "macos-arm64"
    if system == "Linux" and machine in ("x86_64", "amd64"):
        return "linux-amd64"
    return None


def manifest_url(plat: Optional[str] = None) -> Optional[str]:
    """URL of this platform's current manifest, or None when unsupported."""
    plat = plat or platform_key()
    return f"{packages_url()}/{plat}/current/manifest.json" if plat else None


# --------------------------------------------------------------------------
# minisign verification
# --------------------------------------------------------------------------


def _b64(text: str, length: int, what: str) -> bytes:
    try:
        raw = base64.b64decode(text.strip(), validate=True)
    except ValueError as e:
        raise PackageError(f"Malformed {what}.") from e
    if len(raw) != length:
        raise PackageError(f"Malformed {what}.")
    return raw


def verify_minisign(data: bytes, signature: str, public_key: Optional[str] = None) -> str:
    """Verify a minisign signature of ``data``; return its trusted comment.

    Supports both the prehashed (``ED``, BLAKE2b-512, minisign's default) and
    the legacy (``Ed``) signature algorithms. Raises PackageError on any
    mismatch.
    """
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    pk = _b64(public_key or MINISIGN_PUBLIC_KEY, 42, "public key")
    if pk[:2] != b"Ed":
        raise PackageError("Unsupported public key algorithm.")
    key_id, key = pk[2:10], Ed25519PublicKey.from_public_bytes(pk[10:])

    lines = signature.splitlines()
    if len(lines) < 4 or not lines[0].startswith("untrusted comment:") \
            or not lines[2].startswith("trusted comment: "):
        raise PackageError("Malformed package signature.")
    sig = _b64(lines[1], 74, "package signature")
    alg, sig_key_id, sig_bytes = sig[:2], sig[2:10], sig[10:]
    if sig_key_id != key_id:
        raise PackageError("The package is signed with an unknown key.")
    if alg == b"ED":
        message = hashlib.blake2b(data, digest_size=64).digest()
    elif alg == b"Ed":
        message = data
    else:
        raise PackageError("Unsupported signature algorithm.")
    trusted_comment = lines[2][len("trusted comment: "):]
    global_sig = _b64(lines[3], 64, "package signature")
    try:
        key.verify(sig_bytes, message)
        key.verify(global_sig, sig_bytes + trusted_comment.encode())
    except InvalidSignature as e:
        raise PackageError("The package signature is not valid.") from e
    return trusted_comment


def parse_manifest(data: bytes, signature: str, plat: str,
                   public_key: Optional[str] = None) -> Manifest:
    """Check the signature and the fields of a manifest for ``plat``."""
    trusted_comment = verify_minisign(data, signature, public_key)
    try:
        m = json.loads(data)
    except ValueError as e:
        raise PackageError("The package manifest is not valid JSON.") from e
    if not isinstance(m, dict):
        raise PackageError("The package manifest is malformed.")
    d = m.get("dir")
    ok = (m.get("product") == "phoenix-agent" and m.get("platform") == plat
          and isinstance(d, str) and _DIR_RE.match(d)
          and isinstance(m.get("version"), str)
          and isinstance(m.get("build"), int) and not isinstance(m.get("build"), bool)
          and isinstance(m.get("file"), str) and _FILE_RE.match(m["file"])
          and isinstance(m.get("sha512"), str) and _SHA512_RE.match(m["sha512"])
          and isinstance(m.get("size"), int) and 0 < m["size"] <= _MAX_PACKAGE)
    if not ok:
        raise PackageError("The package manifest is malformed.")
    # The trusted comment is signed: a valid signature for another platform
    # or build can't be passed off as this one.
    if trusted_comment != f"phoenix-agent {plat} {d}":
        raise PackageError("The package was signed for another platform or version.")
    return Manifest(platform=plat, version=m["version"], build=m["build"], dir=d,
                    file=m["file"], sha512=m["sha512"], size=m["size"],
                    raw=data, signature=signature)


def parse_desktop_manifest(data: bytes, signature: str, os_key: str,
                           public_key: Optional[str] = None) -> Optional[Manifest]:
    """Check a desktop release manifest; return the package for ``os_key``.

    Verified against the desktop key, never the agent one. Returns None when
    the (valid) release has no package for this OS; raises PackageError when
    anything is wrong.
    """
    trusted_comment = verify_minisign(data, signature,
                                      public_key or DESKTOP_MINISIGN_PUBLIC_KEY)
    try:
        m = json.loads(data)
    except ValueError as e:
        raise PackageError("The update manifest is not valid JSON.") from e
    if not isinstance(m, dict):
        raise PackageError("The update manifest is malformed.")
    d, build, files = m.get("dir"), m.get("build"), m.get("files")
    ok = (m.get("product") == DESKTOP
          and isinstance(d, str) and _DIR_RE.match(d)
          and isinstance(build, int) and not isinstance(build, bool)
          and d.endswith(f"-{build}")
          and isinstance(m.get("version"), str)
          and isinstance(m.get("expires"), str) and _DATE_RE.match(m["expires"])
          and isinstance(files, dict) and files
          and all(k in DESKTOP_OS_KEYS and isinstance(v, dict)
                  and isinstance(v.get("file"), str) and _FILE_RE.match(v["file"])
                  and isinstance(v.get("sha512"), str) and _SHA512_RE.match(v["sha512"])
                  and isinstance(v.get("size"), int) and 0 < v["size"] <= _MAX_PACKAGE
                  for k, v in files.items()))
    if not ok:
        raise PackageError("The update manifest is malformed.")
    # The trusted comment is signed: it pins the directory (so the build) and
    # the expiry, so neither can be changed without the key.
    if trusted_comment != f"{DESKTOP} {d} {m['expires']}":
        raise PackageError("The update was signed for another build.")
    entry = files.get(os_key)
    if entry is None:
        return None
    return Manifest(platform=os_key, version=m["version"], build=build, dir=d,
                    file=entry["file"], sha512=entry["sha512"], size=entry["size"],
                    raw=data, signature=signature, product=DESKTOP,
                    expires=m["expires"])


# --------------------------------------------------------------------------
# Download
# --------------------------------------------------------------------------


def _get(http, url: str, token_box: list, **kwargs):
    """GET with the MAS token; refresh it once on 401."""
    from plugins.login import oidc

    for attempt in (1, 2):
        try:
            r = http.get(url, timeout=_TIMEOUT, verify=True, allow_redirects=False,
                         headers={"Authorization": f"Bearer {token_box[0]}"}, **kwargs)
        except Exception as e:  # noqa: BLE001
            raise PackageError(
                "Couldn't reach the Phoenix package server. "
                "Check your internet connection and try again.") from e
        if r.status_code == 401 and attempt == 1:
            r.close()
            try:
                token = oidc.refresh(force=True)
            except oidc.OIDCError as e:
                raise PackageError(f"Couldn't reach the sign-in server: {e}") from e
            if not token:
                raise PackageError("Your Phoenix session ended. Sign in again.")
            token_box[0] = token
            continue
        if r.status_code != 200:
            r.close()
            raise PackageError(f"The Phoenix package server answered HTTP {r.status_code}.")
        return r
    raise PackageError("Your Phoenix session ended. Sign in again.")


def _read_small(r, limit: int) -> bytes:
    body = b""
    for chunk in r.iter_content(8192):
        body += chunk
        if len(body) > limit:
            raise PackageError("The package server sent an oversized manifest.")
    return body


def _fetch_current(plat: str, http, token_box: Optional[list],
                   signed_out: str) -> tuple[bytes, str]:
    """Download ``plat``'s current manifest.json and its signature, unverified."""
    from plugins.login import oidc

    if token_box is None:
        try:
            token = oidc.refresh()
        except oidc.OIDCError as e:
            raise PackageError(f"Couldn't reach the sign-in server: {e}") from e
        if not token:
            raise PackageError(signed_out)
        token_box = [token]
    http = http or oidc._session()
    base = f"{packages_url()}/{plat}/current"
    with _get(http, f"{base}/manifest.json", token_box, stream=True) as r:
        data = _read_small(r, _MAX_MANIFEST)
    with _get(http, f"{base}/manifest.json.minisig", token_box, stream=True) as r:
        sig = _read_small(r, 4096).decode("utf-8", "replace")
    return data, sig


def fetch_manifest(plat: str, http=None, token_box: Optional[list] = None) -> Manifest:
    """Download and verify the current agent manifest for ``plat``."""
    data, sig = _fetch_current(plat, http, token_box,
                               "Sign in to Phoenix to download the agent.")
    return parse_manifest(data, sig, plat)


def fetch_desktop_manifest(os_key: str, http=None,
                           token_box: Optional[list] = None) -> Optional[Manifest]:
    """Download and verify the current desktop release; its ``os_key`` package
    (None when the release has none for this OS)."""
    data, sig = _fetch_current(DESKTOP_PLATFORM, http, token_box,
                               "Sign in to Phoenix to check for updates.")
    return parse_desktop_manifest(data, sig, os_key)


def verify_file(path: str, manifest: Manifest) -> bool:
    """True when the file at ``path`` is exactly the manifest's package."""
    try:
        if os.path.islink(path) or os.path.getsize(path) != manifest.size:
            return False
        h = hashlib.sha512()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(_CHUNK), b""):
                h.update(chunk)
        return h.hexdigest() == manifest.sha512
    except OSError:
        return False


def _manifest_paths(pkg_path: str) -> tuple[str, str]:
    return pkg_path + ".manifest.json", pkg_path + ".manifest.json.minisig"


def verify_cached(pkg_path: str, plat: Optional[str] = None) -> Optional[Manifest]:
    """Re-check a package kept by download(): its signed manifest, saved next
    to it, must verify against the pinned key and match the file. Returns the
    manifest, or None. Works offline."""
    plat = plat or platform_key()
    m_path, s_path = _manifest_paths(pkg_path)
    try:
        with open(m_path, "rb") as f:
            data = f.read(_MAX_MANIFEST + 1)
        with open(s_path, encoding="utf-8", errors="replace") as f:
            sig = f.read(4096)
        if not plat or len(data) > _MAX_MANIFEST:
            return None
        manifest = parse_manifest(data, sig, plat)
    except (OSError, PackageError) as e:
        logger.warning(f"[PKG] cached {pkg_path} not usable: {e}")
        return None
    return manifest if verify_file(pkg_path, manifest) else None


def remove_cached(pkg_path: str) -> None:
    """Delete a package kept by download() and its saved manifest."""
    for p in (pkg_path, *_manifest_paths(pkg_path)):
        _unlink(p)


def download(dest_dir: str, progress_callback: Optional[Callable[[str], None]] = None,
             plat: Optional[str] = None, filename: Optional[str] = None) -> tuple[str, Manifest]:
    """Download this platform's current agent package into ``dest_dir``.

    The file is written under a temporary name and renamed into place only
    after its size and sha512 match the signed manifest, which is saved next
    to it for verify_cached(). Returns the path and the manifest; raises
    PackageError otherwise.
    """
    from plugins.login import oidc

    plat = plat or platform_key()
    if not plat:
        raise PackageError(
            f"No Phoenix agent is built for {platform.system()} {platform.machine()}.")
    try:
        token = oidc.refresh()
    except oidc.OIDCError as e:
        raise PackageError(f"Couldn't reach the sign-in server: {e}") from e
    if not token:
        raise PackageError("Sign in to Phoenix to download the agent.")
    token_box = [token]
    http = oidc._session()

    if progress_callback:
        progress_callback("Checking the latest Phoenix agent...")
    manifest = fetch_manifest(plat, http, token_box)

    os.makedirs(dest_dir, exist_ok=True)
    final = os.path.join(dest_dir, filename or manifest.file)
    if verify_file(final, manifest):
        logger.info(f"[PKG] {final} already matches {plat} {manifest.dir}")
        _save_manifest(final, manifest)
        return final, manifest

    if progress_callback:
        progress_callback(f"Downloading Phoenix agent {manifest.version}...")
    url = f"{packages_url()}/{plat}/{manifest.dir}/{manifest.file}"
    logger.info(f"[PKG] Downloading {url}")
    part = final + ".part"
    h, size = hashlib.sha512(), 0
    try:
        with _get(http, url, token_box, stream=True) as r, open(part, "wb") as out:
            for chunk in r.iter_content(_CHUNK):
                size += len(chunk)
                if size > manifest.size:
                    raise PackageError("The downloaded package is larger than its manifest says.")
                h.update(chunk)
                out.write(chunk)
        if size != manifest.size or h.hexdigest() != manifest.sha512:
            raise PackageError("The downloaded package does not match its signed manifest.")
        os.replace(part, final)
    except PackageError:
        _unlink(part)
        raise
    except Exception as e:  # noqa: BLE001
        _unlink(part)
        raise PackageError(
            "The Phoenix agent download was interrupted. Try again.") from e
    _save_manifest(final, manifest)
    logger.info(f"[PKG] Verified {final} ({plat} {manifest.dir}, {size} bytes)")
    return final, manifest


def download_or_none(dest_dir: str, progress_callback: Optional[Callable[[str], None]] = None,
                     filename: Optional[str] = None, plat: Optional[str] = None) -> Optional[str]:
    """download() for the platform installers: the verified path, or None
    after logging the reason and showing it through ``progress_callback``."""
    try:
        path, _ = download(dest_dir, progress_callback, plat=plat, filename=filename)
        return path
    except PackageError as e:
        logger.error(f"[PKG] {e}")
        if progress_callback:
            progress_callback(str(e))
        return None


def _save_manifest(pkg_path: str, manifest: Manifest) -> None:
    m_path, s_path = _manifest_paths(pkg_path)
    with open(m_path, "wb") as f:
        f.write(manifest.raw)
    with open(s_path, "w", encoding="utf-8") as f:
        f.write(manifest.signature)


def _unlink(path: str) -> None:
    try:
        os.unlink(path)
    except OSError:
        pass

