"""Windows UAC elevation helpers.

Provides is_admin() and run_privileged() for any module that needs to
run PowerShell commands with administrator privileges on Windows.

Author: Phoenix Team
Copyright (c) Phoenix 2025
Licensed under the GNU General Public License v2 or later
"""
from __future__ import annotations

import ctypes
import os
import subprocess
import tempfile

from utils.logger import logger

_NO_WINDOW = 0x08000000  # CREATE_NO_WINDOW


def is_admin() -> bool:
    """Return True if the current process has admin privileges."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def run_privileged(command: str, timeout: int = 300) -> tuple[bool, str]:
    """Run a PowerShell command with admin privileges.

    If already admin, runs directly. Otherwise elevates via
    Start-Process -Verb RunAs with a temp script for I/O.
    Returns (success, output).
    """
    ps_cmd = [
        "powershell", "-NoProfile", "-ExecutionPolicy", "Bypass",
        "-Command", command,
    ]

    if is_admin():
        try:
            result = subprocess.run(
                ps_cmd, capture_output=True, text=True, timeout=timeout,
                creationflags=_NO_WINDOW,
            )
            output = result.stdout.strip() or result.stderr.strip()
            logger.info(
                f"run_privileged: rc={result.returncode} output={output!r}",
            )
            return (result.returncode == 0, output)
        except subprocess.TimeoutExpired:
            return (False, "Command timed out")
        except Exception as exc:
            return (False, str(exc))

    # Not admin: write script to temp file and elevate
    script_path = ""
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".ps1", delete=False, encoding="utf-8",
        ) as f:
            result_file = f.name + ".result"
            f.write(
                f"try {{\n{command}\n"
                f"'SUCCESS' | Out-File -FilePath '{result_file}'"
                f" -Encoding utf8\n}}\n"
                f"catch {{ $_.Exception.Message | Out-File"
                f" -FilePath '{result_file}' -Encoding utf8 }}\n",
            )
            script_path = f.name

        elevate_cmd = (
            f"Start-Process powershell -Verb RunAs -Wait"
            f" -WindowStyle Hidden"
            f" -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass',"
            f"'-NonInteractive','-File','{script_path}'"
        )
        subprocess.run(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass",
             "-Command", elevate_cmd],
            capture_output=True, text=True, timeout=timeout,
            creationflags=_NO_WINDOW,
        )

        if os.path.exists(result_file):
            with open(result_file, encoding="utf-8") as rf:
                output = rf.read().strip()
            os.unlink(result_file)
            return ("SUCCESS" in output, output)

        return (False, "No result from elevated process")
    except subprocess.TimeoutExpired:
        return (False, "Command timed out")
    except Exception as exc:
        return (False, str(exc))
    finally:
        try:
            if script_path:
                os.unlink(script_path)
        except Exception:
            pass
