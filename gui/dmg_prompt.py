"""Pre-GUI prompt shown when the app is launched from a mounted DMG volume.

Uses native macOS dialogs (osascript) so it works before any Tk/CTk
initialization — no window manager state to clean up on exit.
"""
from __future__ import annotations

import subprocess
import sys

from utils.logger import logger


def _osascript_dialog(title: str, message: str, buttons: list[str],
                      default: str) -> str | None:
    """Show a native macOS dialog via osascript. Returns the button text."""
    btn_list = ", ".join(f'"{b}"' for b in buttons)
    script = (
        f'display dialog "{message}" '
        f'with title "{title}" '
        f"buttons {{{btn_list}}} "
        f'default button "{default}" '
        f"with icon caution"
    )
    try:
        result = subprocess.run(
            ["osascript", "-e", script],
            capture_output=True, text=True, timeout=120,
        )
        # Output looks like: "button returned:Move to Applications"
        if result.returncode == 0 and "button returned:" in result.stdout:
            return result.stdout.split("button returned:")[1].strip()
    except (subprocess.TimeoutExpired, OSError):
        pass
    return None


def prompt_move_to_applications() -> str:
    """Show the DMG relocation prompt. Returns one of: 'moved', 'quit', 'continue'."""
    from utils.functions import move_to_applications

    choice = _osascript_dialog(
        title="Phoenix",
        message=(
            "Phoenix is running from the installer disk image.\n\n"
            "To use all features (background services, auto-updates), "
            "it must be in your Applications folder.\n\n"
            "Move it now?"
        ),
        buttons=["Quit", "Move to Applications"],
        default="Move to Applications",
    )

    if choice == "Move to Applications":
        ok = move_to_applications()
        if ok:
            logger.info("App moved to /Applications and relaunched.")
            return "moved"
        # Move failed — tell the user to do it manually
        _osascript_dialog(
            title="Phoenix",
            message=(
                "Could not move automatically.\n\n"
                "Please drag Resistine.app to your Applications "
                "folder and relaunch from there."
            ),
            buttons=["OK"],
            default="OK",
        )
        return "quit"

    # User clicked Quit (or closed the dialog)
    return "quit"
