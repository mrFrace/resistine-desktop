from __future__ import annotations

import os
import shutil
import subprocess
import sys


def is_running_from_dmg() -> bool:
    """Return True if the app is running from a mounted DMG volume."""
    if sys.platform != "darwin":
        return False
    app_path = _get_bundle_path()
    if not app_path:
        return False
    # Mounted DMGs appear under /Volumes/
    return app_path.startswith("/Volumes/")


def _get_bundle_path() -> str or None:
    """Return the .app bundle path, or None if not running as a bundle."""
    if not getattr(sys, "frozen", False):
        return None
    # sys.executable is e.g. /Volumes/Phoenix Installer/Resistine.app/Contents/MacOS/Resistine
    path = os.path.realpath(sys.executable)
    while path != "/":
        if path.endswith(".app"):
            return path
        path = os.path.dirname(path)
    return None


def move_to_applications() -> bool:
    """Copy the running .app bundle to /Applications and relaunch from there.

    Returns True if the move succeeded (caller should exit).
    Returns False if the move failed (caller should show an error or continue).
    """
    src = _get_bundle_path()
    if not src:
        return False
    app_name = os.path.basename(src)  # e.g. "Resistine.app"
    dest = os.path.join("/Applications", app_name)

    try:
        # Try unprivileged copy first; fall back to osascript for admin auth
        if not _copy_app_bundle(src, dest):
            return False

        # Relaunch from /Applications
        executable = os.path.join(
            dest, "Contents", "MacOS", os.path.splitext(app_name)[0]
        )
        if not os.path.exists(executable):
            return False
        subprocess.Popen([executable])
        return True
    except (OSError, shutil.Error):
        return False


def _copy_app_bundle(src: str, dest: str) -> bool:
    """Copy .app bundle to dest, requesting admin privileges if needed."""
    # Try without elevation first
    try:
        if os.path.exists(dest):
            shutil.rmtree(dest)
        shutil.copytree(src, dest, symlinks=True)
        return True
    except PermissionError:
        pass

    # Elevated fallback via osascript (prompts the user for password)
    script = (
        f'do shell script "rm -rf \\"{dest}\\" '
        f'&& cp -pR \\"{src}\\" \\"{dest}\\"" '
        f"with administrator privileges"
    )
    result = subprocess.run(
        ["osascript", "-e", script],
        capture_output=True, timeout=120,
    )
    return result.returncode == 0


def is_running_in_ide():
    """
    Check if the application is running within an IDE (VS Code, PyCharm, etc.)
    or if a debugger is attached.

    :return: True if running in an IDE or debugger, False otherwise.
    """
    # 1. Check for Cursor (Check before VS Code as Cursor is based on VS Code)
    if (
        os.environ.get("TERM_PROGRAM") == "Cursor"
        or "CURSOR_VERSION" in os.environ
        or "CURSOR_PID" in os.environ
    ):
        return "Cursor"

    # 2. Check for VS Code
    if (
        os.environ.get("TERM_PROGRAM") == "vscode"
        or "VSCODE_PID" in os.environ
        or "VSCODE_CWD" in os.environ
    ):
        return "VSCode"

    # 3. Check for PyCharm / JetBrains
    if "PYCHARM_HOSTED" in os.environ or "JETBRAINS_IDE" in os.environ:
        return "JetBrains"

    # 4. Check for general debugger attachment
    if sys.gettrace() is not None:
        return "Debugger"

    return None


def get_resource_path(relative_path: str) -> str:
    """
    Get absolute path to resource, works for both dev and PyInstaller bundled app.

    When running from source, returns path relative to the project root.
    When running from a PyInstaller bundle, returns path relative to the
    temporary extraction directory (sys._MEIPASS).
    """
    if hasattr(sys, '_MEIPASS'):
        # Running in PyInstaller bundle
        return os.path.join(sys._MEIPASS, relative_path)
    else:
        # Running from source - assume we are in utils/ and the root is one level up
        # However, for consistency with main.py, let's make it smarter or relative to the actual project root.
        # If we invoke it from anywhere, we want the project root.
        # Let's use the directory of this file as a reference.
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        return os.path.join(root, relative_path)
