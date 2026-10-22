"""
Linux Distribution Utilities.

Provides a unified interface for detecting Linux distributions,
handling package managers, and init systems.
"""
import platform
import subprocess
import shutil
import os
from typing import Optional, List

class LinuxDistro:
    """Helper class for Linux distribution identification."""
    
    @staticmethod
    def get_info() -> dict:
        """Get OS release information."""
        try:
            return platform.freedesktop_os_release()
        except Exception:
            # Fallback for older Python or missing etc/os-release
            info = {"ID": "unknown", "ID_LIKE": ""}
            if os.path.exists("/etc/os-release"):
                with open("/etc/os-release") as f:
                    for line in f:
                        if "=" in line:
                            k, v = line.rstrip().split("=", 1)
                            info[k.strip()] = v.strip().strip('"')
            
            # Legacy fallbacks if ID is still missing
            if info.get("ID", "unknown") == "unknown":
                if os.path.exists("/etc/debian_version"):
                    info["ID"] = "debian"
                elif os.path.exists("/etc/redhat-release"):
                    with open("/etc/redhat-release") as f:
                        content = f.read().lower()
                        if "centos" in content:
                            info["ID"] = "centos"
                        elif "red hat" in content or "rhel" in content:
                            info["ID"] = "rhel"
                        else:
                            info["ID"] = "fedora" # Generic RPM fallback
            return info

    @classmethod
    def id(cls) -> str:
        return cls.get_info().get("ID", "unknown").lower()

    @classmethod
    def version(cls) -> str:
        """Get the OS version string."""
        info = cls.get_info()
        version = info.get("VERSION_ID", "")
        if not version:
            # Fallback for legacy systems
            if os.path.exists("/etc/debian_version"):
                with open("/etc/debian_version") as f:
                    version = f.read().strip()
            elif os.path.exists("/etc/redhat-release"):
                with open("/etc/redhat-release") as f:
                    # e.g. "CentOS release 6.10 (Final)"
                    parts = f.read().split()
                    for i, part in enumerate(parts):
                        if part == "release":
                            version = parts[i+1]
                            break
        return version

    @classmethod
    def major_version(cls) -> int:
        """Get the major OS version as an integer."""
        v = cls.version()
        if not v:
            return 0
        try:
            return int(v.split(".")[0])
        except (ValueError, IndexError):
            return 0

    @classmethod
    def id_like(cls) -> List[str]:
        like = cls.get_info().get("ID_LIKE", "")
        return [i.strip().lower() for i in like.split()]

    @classmethod
    def is_debian_like(cls) -> bool:
        return cls.id() in ["debian", "ubuntu", "kali", "linuxmint"] or "debian" in cls.id_like()

    @classmethod
    def is_arch_like(cls) -> bool:
        return cls.id() == "arch" or "arch" in cls.id_like()

    @classmethod
    def is_fedora_like(cls) -> bool:
        return cls.id() in ["fedora", "centos", "rhel"] or "fedora" in cls.id_like() or "rhel" in cls.id_like()

    @classmethod
    def is_suse_like(cls) -> bool:
        return (
            cls.id() in ["opensuse", "opensuse-leap", "opensuse-tumbleweed", "sles", "sled"]
            or "suse" in cls.id_like()
            or "opensuse" in cls.id_like()
        )

    @classmethod
    def get_package_manager(cls) -> Optional[str]:
        """Detect the available package manager."""
        for pm in ["apt", "pacman", "dnf", "zypper", "yum", "apk", "emerge"]:
            if shutil.which(pm):
                return pm
        return None

    @classmethod
    def get_install_command(cls, packages: List[str]) -> Optional[List[str]]:
        """Get the install command for the current distro."""
        pm = cls.get_package_manager()
        if not pm:
            return None
        
        if pm == "apt":
            return ["apt", "install", "-y"] + packages
        elif pm == "pacman":
            return ["pacman", "-S", "--noconfirm"] + packages
        elif pm in ["dnf", "yum"]:
            return [pm, "install", "-y"] + packages
        elif pm == "zypper":
            return ["zypper", "install", "-y"] + packages
        elif pm == "apk":
            return ["apk", "add"] + packages
        elif pm == "emerge":
            return ["emerge", "--ask=n"] + packages
        
        return None

    @staticmethod
    def is_systemd() -> bool:
        """Check if the system is using systemd."""
        return shutil.which("systemctl") is not None and os.path.exists("/run/systemd/system")
