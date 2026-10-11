"""Host facts for the dashboard System card.

Stdlib only (no psutil dependency). Every getter returns None when the value
is unavailable, and some shell out, so call them off the Tk thread.
"""

from __future__ import annotations

import os
import platform
import shutil
import socket
import subprocess
import time

_SYSTEM = platform.system()


def _run(cmd: list[str]) -> str | None:
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        return out.stdout.strip() if out.returncode == 0 else None
    except Exception:
        return None


def device_name() -> str:
    return socket.gethostname()


def os_name() -> str | None:
    if _SYSTEM == "Linux":
        try:
            with open("/etc/os-release", encoding="utf-8") as f:
                for line in f:
                    if line.startswith("PRETTY_NAME="):
                        return line.split("=", 1)[1].strip().strip('"')
        except OSError:
            pass
        return "Linux"
    if _SYSTEM == "Darwin":
        return f"macOS {platform.mac_ver()[0]}".strip()
    if _SYSTEM == "Windows":
        release = platform.release()
        try:
            # Windows 11 still reports release "10"; build 22000+ is 11.
            if int(platform.version().split(".")[2]) >= 22000:
                release = "11"
        except (IndexError, ValueError):
            pass
        return f"Windows {release}"
    return _SYSTEM or None


def kernel() -> str:
    return f"{platform.release()} ({platform.machine()})"


def cpu() -> str | None:
    model = None
    if _SYSTEM == "Linux":
        try:
            with open("/proc/cpuinfo", encoding="utf-8") as f:
                for line in f:
                    if line.startswith("model name"):
                        model = line.split(":", 1)[1].strip()
                        break
        except OSError:
            pass
    elif _SYSTEM == "Darwin":
        model = _run(["sysctl", "-n", "machdep.cpu.brand_string"])
    elif _SYSTEM == "Windows":
        try:
            import winreg

            with winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"HARDWARE\DESCRIPTION\System\CentralProcessor\0",
            ) as key:
                model = winreg.QueryValueEx(key, "ProcessorNameString")[0].strip()
        except Exception:
            pass
    model = model or platform.processor() or None
    threads = os.cpu_count()
    if model and threads:
        return f"{model} · {threads} threads"
    return model


def memory() -> tuple[int, int] | None:
    """Return (used_bytes, total_bytes)."""
    if _SYSTEM == "Linux":
        try:
            info = {}
            with open("/proc/meminfo", encoding="utf-8") as f:
                for line in f:
                    key, value = line.split(":", 1)
                    info[key] = int(value.split()[0]) * 1024
            total = info["MemTotal"]
            return total - info["MemAvailable"], total
        except (OSError, KeyError, ValueError):
            return None
    if _SYSTEM == "Darwin":
        total = _run(["sysctl", "-n", "hw.memsize"])
        vm = _run(["vm_stat"])
        if not total or not vm:
            return None
        try:
            page = int(vm.split("page size of")[1].split()[0])
            pages = {}
            for line in vm.splitlines()[1:]:
                key, value = line.split(":", 1)
                pages[key.strip()] = int(value.strip().rstrip("."))
            free = (pages.get("Pages free", 0) + pages.get("Pages inactive", 0)
                    + pages.get("Pages speculative", 0)) * page
            return int(total) - free, int(total)
        except (IndexError, ValueError):
            return None
    if _SYSTEM == "Windows":
        try:
            import ctypes

            class _MemStatus(ctypes.Structure):
                _fields_ = [
                    ("dwLength", ctypes.c_ulong),
                    ("dwMemoryLoad", ctypes.c_ulong),
                    ("ullTotalPhys", ctypes.c_ulonglong),
                    ("ullAvailPhys", ctypes.c_ulonglong),
                    ("ullTotalPageFile", ctypes.c_ulonglong),
                    ("ullAvailPageFile", ctypes.c_ulonglong),
                    ("ullTotalVirtual", ctypes.c_ulonglong),
                    ("ullAvailVirtual", ctypes.c_ulonglong),
                    ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
                ]

            status = _MemStatus()
            status.dwLength = ctypes.sizeof(_MemStatus)
            ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status))
            return status.ullTotalPhys - status.ullAvailPhys, status.ullTotalPhys
        except Exception:
            return None
    return None


def disk() -> tuple[int, int] | None:
    """Return (used_bytes, total_bytes) for the volume holding the home dir."""
    try:
        usage = shutil.disk_usage(os.path.expanduser("~"))
        return usage.used, usage.total
    except OSError:
        return None


def uptime_seconds() -> float | None:
    if _SYSTEM == "Linux":
        try:
            with open("/proc/uptime", encoding="utf-8") as f:
                return float(f.read().split()[0])
        except (OSError, ValueError):
            return None
    if _SYSTEM == "Darwin":
        out = _run(["sysctl", "-n", "kern.boottime"])  # "{ sec = 1700000000, usec = 0 } ..."
        try:
            return time.time() - int(out.split("sec =")[1].split(",")[0])
        except (AttributeError, IndexError, ValueError):
            return None
    if _SYSTEM == "Windows":
        try:
            import ctypes

            return ctypes.windll.kernel32.GetTickCount64() / 1000
        except Exception:
            return None
    return None


def local_ip() -> str | None:
    """Address of the interface that routes outward. Sends no packets."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("10.255.255.255", 1))
            return s.getsockname()[0]
    except OSError:
        return None


def format_bytes(n: int) -> str:
    value = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if value < 1024 or unit == "TB":
            return f"{value:.0f} {unit}" if unit in ("B", "KB") else f"{value:.1f} {unit}"
        value /= 1024
    return f"{value:.1f} TB"


def format_usage(pair: tuple[int, int] | None) -> str | None:
    if not pair or not pair[1]:
        return None
    used, total = pair
    return f"{format_bytes(used)} / {format_bytes(total)} ({used * 100 // total}%)"


def format_uptime(seconds: float | None) -> str | None:
    if seconds is None:
        return None
    minutes = int(seconds // 60)
    days, minutes = divmod(minutes, 1440)
    hours, minutes = divmod(minutes, 60)
    if days:
        return f"{days}d {hours}h"
    if hours:
        return f"{hours}h {minutes}m"
    return f"{minutes}m"
