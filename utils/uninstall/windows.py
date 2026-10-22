"""
Windows Uninstaller Backend.

Launches the installed Inno Setup uninstaller (unins*.exe) with elevation.
The app UI can call this backend and then terminate itself.
"""

import ctypes
import os
import sys

from utils.logger import logger

_INNO_UNINSTALL_KEYS = (
    r"Software\Microsoft\Windows\CurrentVersion\Uninstall\ResistineDesktop_is1",
    r"Software\Microsoft\Windows\CurrentVersion\Uninstall\Resistine",
)
_APP_KEY = r"Software\Resistine"


def _progress(progress_callback, msg):
    logger.info(f"[UNINSTALL-WIN] {msg}")
    if progress_callback:
        try:
            progress_callback(msg)
        except Exception:
            pass


def _split_uninstall_command(command):
    command = (command or "").strip()
    if not command:
        return ("", "")

    if command[0] == '"':
        end = command.find('"', 1)
        if end == -1:
            return (command.strip('"'), "")
        return (command[1:end], command[end + 1 :].strip())

    parts = command.split(" ", 1)
    if len(parts) == 1:
        return (parts[0], "")
    return (parts[0], parts[1].strip())


def _iter_registry_views(winreg):
    views = [0]
    if hasattr(winreg, "KEY_WOW64_64KEY"):
        views.append(winreg.KEY_WOW64_64KEY)
    if hasattr(winreg, "KEY_WOW64_32KEY"):
        views.append(winreg.KEY_WOW64_32KEY)
    return views


def _query_reg_string(winreg, root, subkey, value_name):
    for view in _iter_registry_views(winreg):
        try:
            with winreg.OpenKey(root, subkey, 0, winreg.KEY_READ | view) as key:
                value, _ = winreg.QueryValueEx(key, value_name)
                if isinstance(value, str) and value.strip():
                    return value.strip()
        except OSError:
            continue
    return None


def _candidate_uninstaller_paths():
    seen = set()
    candidates = []

    def add(path):
        if not path:
            return
        p = os.path.abspath(path)
        key = p.lower()
        if key in seen:
            return
        seen.add(key)
        candidates.append(p)

    if getattr(sys, "frozen", False):
        exe_dir = os.path.dirname(sys.executable)
        add(os.path.join(exe_dir, "unins000.exe"))
        add(os.path.join(exe_dir, "Uninstall.exe"))

    try:
        import winreg
    except Exception:
        return candidates

    roots = [winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER]

    for root in roots:
        install_dir = _query_reg_string(winreg, root, _APP_KEY, "InstallDir")
        if install_dir:
            add(os.path.join(install_dir, "unins000.exe"))
            add(os.path.join(install_dir, "Uninstall.exe"))

    for root in roots:
        for subkey in _INNO_UNINSTALL_KEYS:
            uninstall_cmd = _query_reg_string(winreg, root, subkey, "UninstallString")
            if uninstall_cmd:
                exe_path, _ = _split_uninstall_command(uninstall_cmd)
                add(exe_path)

            install_location = _query_reg_string(winreg, root, subkey, "InstallLocation")
            if install_location:
                add(os.path.join(install_location, "unins000.exe"))
                add(os.path.join(install_location, "Uninstall.exe"))

    return candidates


def _find_uninstaller_command():
    try:
        import winreg
    except Exception:
        return ("", "")

    roots = [winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER]
    for root in roots:
        for subkey in _INNO_UNINSTALL_KEYS:
            uninstall_cmd = _query_reg_string(winreg, root, subkey, "UninstallString")
            if uninstall_cmd:
                exe_path, args = _split_uninstall_command(uninstall_cmd)
                if exe_path and os.path.exists(exe_path):
                    return (exe_path, args)

    for candidate in _candidate_uninstaller_paths():
        if os.path.exists(candidate):
            return (candidate, "")

    return ("", "")


def is_available():
    """Return True if uninstall is available on this machine."""
    exe_path, _ = _find_uninstaller_command()
    return bool(exe_path and os.path.exists(exe_path))


def run_uninstall(app, progress_callback=None):
    """Launch the Windows uninstaller with UAC elevation."""
    _progress(progress_callback, "Locating uninstaller...")

    exe_path, args = _find_uninstaller_command()
    if not exe_path:
        logger.error("[UNINSTALL-WIN] Could not find uninstaller executable")
        return (
            False,
            "Could not find the installed Windows uninstaller (unins000.exe).",
        )

    _progress(progress_callback, "Launching uninstaller...")
    show_normal = 1
    rc = ctypes.windll.shell32.ShellExecuteW(
        None,
        "runas",
        exe_path,
        args if args else None,
        os.path.dirname(exe_path),
        show_normal,
    )

    # Per ShellExecute contract, values <= 32 indicate failure.
    if rc <= 32:
        logger.error(
            "[UNINSTALL-WIN] Failed to launch uninstaller via ShellExecuteW. "
            f"code={rc}, exe={exe_path}, args={args!r}"
        )
        return (
            False,
            "Failed to launch the Windows uninstaller. "
            "Please run 'Uninstall Phoenix' from the Start Menu as Administrator.",
        )

    logger.info(
        "[UNINSTALL-WIN] Uninstaller launched successfully. "
        f"exe={exe_path}, args={args!r}, rc={rc}"
    )
    return (
        True,
        "Windows uninstaller started. Complete the uninstall steps in the setup window.",
    )
