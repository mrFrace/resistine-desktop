"""Phoenix Desktop updates over the signed package channel.

Each build is published (scripts/build/publish-desktop.sh) to
https://auth.phoenix.exposed/packages/desktop/current/ as ONE manifest listing
every OS's package, signed with the desktop minisign key and checked here
against the key pinned in plugins/wazuh/agent/phoenix_packages.py. This module
only answers "is there a newer build for this install, and which file is it";
downloading and installing it is the platform backends' job.

Guarantees beyond the signature:
- Rollback protection: a release below the highest build this machine has
  ever seen signed is refused (one below the running build alone is just "no
  update": a newer build may have been installed by hand). To roll back a bad
  release, publish the older code under a new build ID.
- Staleness: every release carries a signed expiry. Past it the check still
  works but reports ``stale``: something may be holding back newer releases
  (a frozen mirror or cache), or nothing was published for months.
"""

from __future__ import annotations

import datetime
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass
from typing import TYPE_CHECKING, Optional

from utils import settings
from utils.logger import logger
from utils.updates.version import get_build

if TYPE_CHECKING:
    from plugins.wazuh.agent.phoenix_packages import Manifest

_NS = "updates"


@dataclass(frozen=True)
class UpdateCheck:
    os_key: str
    current_build: int
    latest: Optional[Manifest]  # this OS's package in the current release
    stale: bool

    @property
    def available(self) -> bool:
        return self.latest is not None and self.latest.build > self.current_build


def _linux_os_key(exe: str) -> Optional[str]:
    """Which package manager owns this install: linux-deb / -rpm / -arch."""
    for tool, args, key in (
        ("dpkg-query", ["-S", exe], "linux-deb"),
        ("rpm", ["-qf", exe], "linux-rpm"),
        ("pacman", ["-Qo", exe], "linux-arch"),
    ):
        if not shutil.which(tool):
            continue
        try:
            r = subprocess.run([tool, *args], capture_output=True, timeout=10)
        except (OSError, subprocess.SubprocessError):
            continue
        if r.returncode == 0:
            return key
    return None


def os_key() -> Optional[str]:
    """This install's key in a release's "files", or None when it can't be
    updated from the channel (a source run, NixOS, an unpackaged copy)."""
    if not getattr(sys, "frozen", False):
        return None
    if sys.platform == "win32":
        return "windows"
    if sys.platform == "darwin":
        return "macos-arm64" if os.uname().machine == "arm64" else None
    if sys.platform.startswith("linux"):
        return _linux_os_key(os.path.realpath(sys.executable))
    return None


def _highest_seen() -> int:
    try:
        return int(settings.get(_NS, "highest_build", 0) or 0)
    except (TypeError, ValueError):
        return 0


def check(http=None, token_box: Optional[list] = None,
          today: Optional[datetime.date] = None) -> Optional[UpdateCheck]:
    """Ask the channel for the current release.

    Returns None when this install isn't updated from the channel. Raises
    phoenix_packages.PackageError (message safe to show) when the release
    can't be fetched or verified, or would be a rollback.
    """
    from plugins.wazuh.agent import phoenix_packages as pp

    key = os_key()
    build = get_build()
    if key is None or not build.isdigit():
        return None
    current = int(build)
    latest = pp.fetch_desktop_manifest(key, http, token_box)
    if latest is None:
        logger.info(f"[UPDATE] the current release has no {key} package")
        return UpdateCheck(key, current, None, stale=False)

    highest = _highest_seen()
    if latest.build < highest:
        logger.warning(f"[UPDATE] refused {latest.dir}: build {latest.build} is below "
                       f"{highest}, already seen signed")
        raise pp.PackageError(
            "The update server offered an older Phoenix release than one it "
            "published before. It was not used.")
    if latest.build > highest:
        settings.set(_NS, "highest_build", latest.build)

    today = today or datetime.datetime.now(datetime.timezone.utc).date()
    stale = latest.expires < today.isoformat()
    if stale:
        logger.warning(f"[UPDATE] release {latest.dir} expired on {latest.expires}")
    logger.info(f"[UPDATE] {key}: running {current}, current release {latest.build}")
    return UpdateCheck(key, current, latest, stale)
