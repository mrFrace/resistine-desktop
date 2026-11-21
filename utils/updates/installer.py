"""Download a Phoenix Desktop release from the signed channel and start it.

channel.check() says which file the current release is for this install; this
module fetches that file from the package store, where it must match the size
and sha512 in the signed manifest, and hands it to the OS: the Windows
installer is started, the macOS disk image is opened. Linux installs are
updated by the system's package manager from the signed Phoenix repository
and never come through here.

Nothing a server or a middleman sends is run unless it is the exact file the
release key signed for:
- the download lands in a fresh directory only this user can write, under a
  name taken from the (allowlisted) manifest;
- the file is hashed again immediately before it is started, and on Windows
  it is held open without write or delete sharing from before that check
  until the installer is running, so it cannot be swapped in between;
- on Windows, once WINDOWS_PUBLISHER is set, the file must also carry a valid
  Authenticode signature by that publisher: a second check with a different
  key, made by the OS.
"""

from __future__ import annotations

import contextlib
import os
import shutil
import subprocess
import sys
import tempfile
from typing import TYPE_CHECKING, Callable, Optional

from utils import settings
from utils.logger import logger

if TYPE_CHECKING:
    from plugins.wazuh.agent.phoenix_packages import Manifest
    from utils.updates.channel import UpdateCheck

# Common name of the Authenticode certificate Windows releases are signed
# with (scripts/build/build-windows-installer.ps1). Empty until releases are
# signed: then the signer is not checked. Set it only in a build that is
# itself signed, and never clear it afterwards: every later installer must
# carry this publisher or copies with this value refuse it.
WINDOWS_PUBLISHER = ""

# What each OS key's package must be called; anything else is not started.
_SUFFIX = {"windows": ".exe", "macos-arm64": ".dmg"}

# Inno Setup: progress window only, no questions (the user already asked for
# the update), never reboot. Setup closes the running app and starts the new
# one (packaging/windows/PhoenixInstaller.iss: CloseApplications, [Run]).
_WINDOWS_ARGS = "/SILENT /SUPPRESSMSGBOXES /NORESTART"


def supported(os_key: Optional[str]) -> bool:
    """True when this install's updates are downloaded by the app."""
    return os_key in _SUFFIX


def _error(message: str) -> Exception:
    from plugins.wazuh.agent.phoenix_packages import PackageError
    return PackageError(message)


def _updates_dir() -> str:
    return os.path.join(settings.get_config_dir(), "updates")


def download(result: UpdateCheck,
             progress: Optional[Callable[[int, int], None]] = None) -> str:
    """Fetch the release ``result`` (a channel.check() answer) offers; the
    path of the verified file. Raises PackageError (message safe to show)."""
    from plugins.wazuh.agent import phoenix_packages as pp

    manifest = result.latest
    if not result.available or manifest is None or not supported(result.os_key):
        raise _error("There is no update to download.")
    if not manifest.file.lower().endswith(_SUFFIX[result.os_key]):
        raise _error("The update is not a Phoenix installer for this system.")
    base = _updates_dir()
    # Earlier downloads: an installer that already ran, or one never started.
    shutil.rmtree(base, ignore_errors=True)
    os.makedirs(base, mode=0o700, exist_ok=True)
    dest = tempfile.mkdtemp(prefix="release-", dir=base)
    try:
        return pp.download_desktop(manifest, dest, progress)
    except BaseException:
        shutil.rmtree(dest, ignore_errors=True)
        raise


@contextlib.contextmanager
def _held(path: str):
    """Keep ``path`` open so nobody can write, replace or delete it (Windows;
    elsewhere the directory's permissions do that)."""
    if sys.platform != "win32":
        yield
        return
    import ctypes
    from ctypes import wintypes

    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                                wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD,
                                wintypes.HANDLE]
    k32.CreateFileW.restype = wintypes.HANDLE
    k32.CloseHandle.argtypes = [wintypes.HANDLE]
    generic_read, share_read, open_existing, normal = 0x80000000, 0x1, 3, 0x80
    handle = k32.CreateFileW(path, generic_read, share_read, None, open_existing,
                             normal, None)
    if handle is None or handle == ctypes.c_void_p(-1).value:
        raise _error("The downloaded update could not be opened.")
    try:
        yield
    finally:
        k32.CloseHandle(handle)


def _windows_signer(path: str) -> tuple[str, str]:
    """(status, subject) of ``path``'s Authenticode signature, as Windows
    judges it: status is "Valid" only for an intact file whose certificate
    chains to a trusted root."""
    script = ("$s = Get-AuthenticodeSignature -LiteralPath $env:PHOENIX_UPDATE_FILE; "
              "Write-Output ([string]$s.Status); "
              "if ($s.SignerCertificate) { Write-Output $s.SignerCertificate.Subject }")
    try:
        r = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
            capture_output=True, text=True, timeout=120,
            env={**os.environ, "PHOENIX_UPDATE_FILE": path},
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    except (OSError, subprocess.SubprocessError) as e:
        logger.warning(f"[UPDATE] signature check could not run: {e}")
        return "", ""
    lines = [ln.strip() for ln in r.stdout.splitlines() if ln.strip()]
    return (lines[0] if lines else ""), (lines[1] if len(lines) > 1 else "")


def _split_subject(subject: str) -> list[str]:
    parts, cur, quoted = [], "", False
    for ch in subject:
        if ch == '"':
            quoted = not quoted
        if ch == "," and not quoted:
            parts.append(cur)
            cur = ""
        else:
            cur += ch
    parts.append(cur)
    return parts


def _common_name(subject: str) -> str:
    """The CN of an X.500 subject as PowerShell prints it ('CN=Phoenix, O=…';
    a value holding a comma is quoted)."""
    for part in _split_subject(subject):
        key, _, value = part.partition("=")
        if key.strip().upper() == "CN":
            value = value.strip()
            if len(value) >= 2 and value[0] == value[-1] == '"':
                value = value[1:-1].replace('""', '"')
            return value
    return ""


def check_windows_signer(path: str) -> None:
    """Raise PackageError unless ``path`` is validly signed by
    WINDOWS_PUBLISHER. Does nothing while no publisher is pinned."""
    if not WINDOWS_PUBLISHER:
        logger.info("[UPDATE] no Windows publisher pinned; signer not checked")
        return
    status, subject = _windows_signer(path)
    if status != "Valid" or _common_name(subject) != WINDOWS_PUBLISHER:
        logger.error(f"[UPDATE] refused {path}: signature {status or 'unreadable'}, "
                     f"signer {subject or 'none'}")
        raise _error("The update is not signed by Phoenix. It was not started.")


def launch(path: str, manifest: Manifest) -> None:
    """Start the downloaded installer after checking once more that it is the
    file the release names. Raises PackageError when it is not, or when the
    OS refuses to start it."""
    from plugins.wazuh.agent import phoenix_packages as pp

    suffix = _SUFFIX.get(manifest.platform)
    inside = os.path.dirname(os.path.dirname(os.path.realpath(path)))
    if (suffix is None or not path.lower().endswith(suffix)
            or inside != os.path.realpath(_updates_dir())):
        raise _error("The update is not a Phoenix installer for this system.")
    with _held(path):
        if not pp.verify_file(path, manifest):
            raise _error("The downloaded update changed after it was verified. "
                         "It was not started.")
        try:
            if manifest.platform == "windows":
                check_windows_signer(path)
                # ShellExecute, not CreateProcess: Setup asks for elevation.
                os.startfile(path, "open", _WINDOWS_ARGS)
            else:
                subprocess.Popen(["/usr/bin/open", path])
        except OSError as e:
            raise _error(f"The update could not be started: {e}") from e
    logger.info(f"[UPDATE] started {path} ({manifest.dir})")
