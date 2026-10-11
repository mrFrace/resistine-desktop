"""Linux desktop integration: self-install a freedesktop ``.desktop`` entry.

Without an installed application entry, GNOME (and most desktops) identify the
running window only by its WM_CLASS — which for a bare Tkinter app is "Tk" — so
the dock tile and notifications show "Tk" + a generic icon. We don't ship a
system package for the common "download and run from source" case, so the app
installs a per-user entry itself on startup (idempotent), giving GNOME a real
name + icon to associate via ``StartupWMClass`` (which matches the WM_CLASS set
in main.py) and the notification ``desktop-entry`` hint.

This is intentionally self-contained (writes to ~/.local/share/applications) so
it works for an ad-hoc source checkout as well as a packaged build.

Author: Resistine Team
Copyright (c) Resistine 2025
Licensed under the GNU General Public License v2 or later
"""

import os
import subprocess
import sys

from utils.logger import logger

# Basename (without .desktop). Must match main.py's className and the
# notification desktop-entry hint so GNOME ties them all to this one entry.
DESKTOP_ID = "resistine"


def _repo_root() -> str:
    # utils/linux_desktop.py -> repo root is two dirs up.
    return os.path.dirname(os.path.dirname(os.path.realpath(__file__)))


def _exec_command() -> str:
    """Best-effort command to relaunch the app (used for the dock Exec=)."""
    if getattr(sys, "frozen", False):  # PyInstaller build
        return f'"{sys.executable}"'
    main_py = os.path.join(_repo_root(), "main.py")
    return f'"{sys.executable}" "{main_py}"'


def _icon() -> str:
    """Absolute path to the app icon (Icon= accepts an absolute path)."""
    return os.path.join(_repo_root(), "resources", "icons", "app_icon.png")


def _desktop_contents() -> str:
    return (
        "[Desktop Entry]\n"
        "Type=Application\n"
        "Name=Phoenix\n"
        "Comment=Phoenix Security Desktop\n"
        f"Exec={_exec_command()}\n"
        f"Icon={_icon()}\n"
        "Terminal=false\n"
        "Categories=Security;System;Utility;\n"
        # Ties the running window (WM_CLASS from main.py's className) to this
        # entry so the dock shows the right name/icon. Tk reports both the
        # instance and (capitalized) class form; list both to be robust.
        f"StartupWMClass={DESKTOP_ID}\n"
    )


def ensure_desktop_entry():
    """Create/refresh ~/.local/share/applications/<DESKTOP_ID>.desktop.

    Idempotent: only rewrites when the contents change, and never raises.
    """
    if not sys.platform.startswith("linux"):
        return
    try:
        data_home = os.environ.get("XDG_DATA_HOME") or os.path.join(
            os.path.expanduser("~"), ".local", "share"
        )
        apps_dir = os.path.join(data_home, "applications")
        os.makedirs(apps_dir, exist_ok=True)
        path = os.path.join(apps_dir, f"{DESKTOP_ID}.desktop")

        desired = _desktop_contents()
        try:
            with open(path, encoding="utf-8") as f:
                if f.read() == desired:
                    return  # unchanged — nothing to do
        except FileNotFoundError:
            pass

        with open(path, "w", encoding="utf-8") as f:
            f.write(desired)
        try:
            os.chmod(path, 0o644)
        except OSError:
            pass
        logger.info("Installed desktop entry: %s", path)

        # Refresh the desktop database so GNOME picks it up (non-blocking,
        # best-effort — not all systems have the tool).
        try:
            import shutil
            if shutil.which("update-desktop-database"):
                subprocess.Popen(
                    ["update-desktop-database", apps_dir],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
        except Exception:
            pass
    except Exception as e:
        logger.debug("Could not install desktop entry: %s", e)
