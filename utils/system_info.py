"""Host facts for the Dashboard (stdlib only, no psutil).

Every probe is best effort: a value that cannot be read is ``None`` and the
UI shows a dash. Some probes shell out (macOS ``sysctl``), so call
:func:`collect` off the UI thread.
"""

from __future__ import annotations

import os
import platform
import shutil
import socket
import subprocess
import time
from typing import Optional


def _run(*argv: str) -> Optional[str]:
    try:
        out = subprocess.run(  # nosec B603 - fixed argv, no shell
            list(argv), capture_output=True, text=True, timeout=3)
        return out.stdout.strip() if out.returncode == 0 else None
    except Exception:
        return None


def os_name() -> str:
    system = platform.system()
    if system == "Linux":
        try:
            with open("/etc/os-release", encoding="utf-8") as f:
                for line in f:
                    if line.startswith("PRETTY_NAME="):
                        return line.split("=", 1)[1].strip().strip('"')
        except OSError:
            pass
    elif system == "Darwin":
        ver = platform.mac_ver()[0]
        return f"macOS {ver}" if ver else "macOS"
    elif system == "Windows":
        return f"Windows {platform.release()} ({platform.version()})"
    return f"{system} {platform.release()}"


def cpu_model() -> Optional[str]:
    system = platform.system()
    if system == "Linux":
        try:
            with open("/proc/cpuinfo", encoding="utf-8") as f:
                for line in f:
                    if line.lower().startswith(("model name", "hardware")):
                        return line.split(":", 1)[1].strip()
        except OSError:
            pass
    elif system == "Darwin":
        return _run("sysctl", "-n", "machdep.cpu.brand_string")
    return platform.processor() or None


def memory() -> tuple[Optional[int], Optional[int]]:
    """(used, total) bytes."""
    system = platform.system()
    try:
        if system == "Linux":
            info = {}
            with open("/proc/meminfo", encoding="utf-8") as f:
                for line in f:
                    key, val = line.split(":", 1)
                    info[key] = int(val.split()[0]) * 1024
            total = info.get("MemTotal")
            avail = info.get("MemAvailable", info.get("MemFree"))
            return (total - avail if total and avail is not None else None), total
        if system == "Darwin":
            total = int(_run("sysctl", "-n", "hw.memsize") or 0) or None
            vm = _run("vm_stat") or ""
            page = 4096
            free = 0
            for line in vm.splitlines():
                if "page size of" in line:
                    page = int(line.split("page size of")[1].split()[0])
                elif line.startswith(("Pages free", "Pages inactive", "Pages speculative")):
                    free += int(line.split(":")[1].strip().rstrip("."))
            return (total - free * page if total else None), total
        if system == "Windows":
            import ctypes

            class _MemStatus(ctypes.Structure):
                _fields_ = [("dwLength", ctypes.c_ulong), ("dwMemoryLoad", ctypes.c_ulong),
                            ("ullTotalPhys", ctypes.c_ulonglong), ("ullAvailPhys", ctypes.c_ulonglong),
                            ("ullTotalPageFile", ctypes.c_ulonglong), ("ullAvailPageFile", ctypes.c_ulonglong),
                            ("ullTotalVirtual", ctypes.c_ulonglong), ("ullAvailVirtual", ctypes.c_ulonglong),
                            ("ullAvailExtendedVirtual", ctypes.c_ulonglong)]
            st = _MemStatus()
            st.dwLength = ctypes.sizeof(_MemStatus)
            ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(st))
            return st.ullTotalPhys - st.ullAvailPhys, st.ullTotalPhys
    except Exception:
        pass
    return None, None


def disk() -> tuple[Optional[int], Optional[int]]:
    """(used, total) bytes of the volume holding the home directory."""
    try:
        du = shutil.disk_usage(os.path.expanduser("~"))
        return du.used, du.total
    except OSError:
        return None, None


def uptime_seconds() -> Optional[float]:
    system = platform.system()
    try:
        if system == "Linux":
            with open("/proc/uptime", encoding="utf-8") as f:
                return float(f.read().split()[0])
        if system == "Darwin":
            out = _run("sysctl", "-n", "kern.boottime") or ""
            # "{ sec = 1700000000, usec = 0 } ..."
            sec = int(out.split("sec =")[1].split(",")[0])
            return time.time() - sec
        if system == "Windows":
            import ctypes
            return ctypes.windll.kernel32.GetTickCount64() / 1000.0
    except Exception:
        pass
    return None


def local_ip() -> Optional[str]:
    """Address of the interface used for outbound traffic (no packet sent)."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("1.1.1.1", 80))
            return s.getsockname()[0]
    except OSError:
        return None


def human_bytes(n: Optional[int]) -> str:
    if n is None:
        return "—"
    size = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024 or unit == "TB":
            return f"{size:.0f} {unit}" if unit in ("B", "KB") else f"{size:.1f} {unit}"
        size /= 1024
    return "—"


def human_duration(seconds: Optional[float]) -> str:
    if seconds is None:
        return "—"
    minutes = int(seconds // 60)
    days, minutes = divmod(minutes, 1440)
    hours, minutes = divmod(minutes, 60)
    if days:
        return f"{days}d {hours}h"
    if hours:
        return f"{hours}h {minutes}m"
    return f"{minutes}m"


def _usage(used: Optional[int], total: Optional[int]) -> str:
    if not total:
        return "—"
    if used is None:
        return human_bytes(total)
    return f"{human_bytes(used)} / {human_bytes(total)} ({used * 100 // total}%)"


def collect() -> dict[str, str]:
    """Ordered label -> display value."""
    cpu = cpu_model()
    cores = os.cpu_count()
    return {
        "Device": socket.gethostname().split(".")[0],
        "System": os_name(),
        "Kernel": f"{platform.release()} ({platform.machine()})",
        "CPU": f"{cpu or platform.machine()}" + (f" · {cores} threads" if cores else ""),
        "Memory": _usage(*memory()),
        "Disk": _usage(*disk()),
        "Uptime": human_duration(uptime_seconds()),
        "Local IP": local_ip() or "—",
    }
