"""ClamAV platform module — Linux.

Binary discovery via PATH, systemd daemon management (clamav-daemon /
clamd@scan, clamav-freshclam, clamav-clamonacc) via pkexec/sudo, and
distro-aware package installation driven by /etc/os-release parsing.

See clamav_platform_darwin.py for the macOS reference.

Author: Phoenix Team
Copyright (c) Phoenix 2025
Licensed under the GNU General Public License v2 or later
"""
from __future__ import annotations

import os
import platform
import shutil
import subprocess
import time

from utils.logger import logger


# ── Distro detection (local; avoids depending on utils.distro) ───

def _os_release() -> dict[str, str]:
    """Parse /etc/os-release; return empty dict on failure."""
    try:
        return platform.freedesktop_os_release()
    except (OSError, AttributeError):
        pass
    info: dict[str, str] = {}
    try:
        with open("/etc/os-release") as f:
            for line in f:
                if "=" not in line:
                    continue
                k, v = line.rstrip().split("=", 1)
                info[k.strip()] = v.strip().strip('"')
    except OSError:
        pass
    return info


def _distro_id() -> str:
    return _os_release().get("ID", "").lower()


def _distro_id_like() -> set[str]:
    like = _os_release().get("ID_LIKE", "")
    return {tok.strip().lower() for tok in like.split() if tok.strip()}


def _is_debian_like() -> bool:
    return (
        _distro_id() in {"debian", "ubuntu", "kali", "linuxmint", "zorin", "pop"}
        or "debian" in _distro_id_like()
    )


def _is_fedora_like() -> bool:
    return (
        _distro_id() in {"fedora", "rhel", "centos", "rocky", "almalinux"}
        or _distro_id_like() & {"fedora", "rhel"}
    )


def _is_arch_like() -> bool:
    return _distro_id() == "arch" or "arch" in _distro_id_like()


def _is_nixos() -> bool:
    return _distro_id() == "nixos"


# NixOS builds /etc and the systemd units from the system configuration:
# the app can't install packages, write clamd.conf or `systemctl enable`.
_NIXOS_HINT = (
    "On NixOS the ClamAV services come from your system configuration. Add "
    "services.clamav.daemon.enable = true; services.clamav.updater.enable = true; "
    "(and services.clamav.clamonacc.enable = true; for real-time protection), "
    "run nixos-rebuild switch, then try again."
)


def _has_systemd() -> bool:
    return (
        shutil.which("systemctl") is not None
        and os.path.exists("/run/systemd/system")
    )


def _install_command(packages: list[str]) -> list[str] | None:
    """Return the install command for the first package manager found on PATH."""
    for pm, prefix in (
        ("apt", ["env", "DEBIAN_FRONTEND=noninteractive", "apt", "install", "-y"]),
        ("dnf", ["dnf", "install", "-y"]),
        ("yum", ["yum", "install", "-y"]),
        ("pacman", ["pacman", "-S", "--noconfirm"]),
        ("zypper", ["zypper", "install", "-y"]),
        ("apk", ["apk", "add"]),
    ):
        if shutil.which(pm):
            return prefix + packages
    return None


# ── Probed system paths ──────────────────────────────────

_SYSTEM_DB_DIR_CANDIDATES = [
    "/var/lib/clamav",        # Debian, Ubuntu, Arch, openSUSE
    "/var/lib/clamd/scan",    # Fedora, RHEL, CentOS (clamd@scan)
]

_SYSTEM_SOCKET_CANDIDATES = [
    "/run/clamav/clamd.ctl",
    "/var/run/clamav/clamd.ctl",
    "/run/clamd.scan/clamd.sock",
    "/var/run/clamd.scan/clamd.sock",
    "/var/lib/clamav/clamd.sock",
]

_SYSTEM_CONF_CANDIDATES = [
    "/etc/clamav/clamd.conf",   # Debian/Ubuntu/Arch
    "/etc/clamd.d/scan.conf",   # Fedora/RHEL
]


# ── Privileged execution (pkexec → sudo) ─────────────────


def _run_privileged(command: list[str], timeout: int = 300) -> tuple[bool, str]:
    """Run *command* as root via pkexec, falling back to sudo+password dialog.

    Returns ``(success, combined_output)``.
    """
    if os.geteuid() == 0:
        try:
            result = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            return False, "Command timed out."
        except Exception as exc:
            return False, str(exc)
        if result.returncode == 0:
            return True, (result.stdout or "").strip()
        return False, (result.stderr or result.stdout or "").strip() or (
            f"exited with code {result.returncode}"
        )

    if shutil.which("pkexec"):
        try:
            executable = shutil.which(command[0]) or command[0]
            full_cmd = ["pkexec", executable, *command[1:]]
            logger.info(f"ClamAV: pkexec — {full_cmd}")
            result = subprocess.run(
                full_cmd, capture_output=True, text=True, timeout=timeout,
            )
            if result.returncode == 0:
                return True, (result.stdout or "").strip()
            err = (result.stderr or result.stdout or "").strip()
            logger.warning(
                f"ClamAV: pkexec failed (code {result.returncode}): {err}. "
                "Falling back to sudo.",
            )
        except FileNotFoundError:
            logger.warning("ClamAV: pkexec not found, falling back to sudo")
        except subprocess.TimeoutExpired:
            return False, "pkexec timed out."
        except Exception as exc:  # pragma: no cover — defensive
            logger.warning(f"ClamAV: pkexec error: {exc}")

    try:
        from gui.dialogs import CTkPasswordDialog
    except ImportError:
        return False, "GUI password dialog unavailable."

    dialog = CTkPasswordDialog(
        title="Authentication Required",
        text="Enter password to configure antivirus protection:",
    )
    password = dialog.get_input()
    if not password:
        return False, "User cancelled password prompt."

    try:
        result = subprocess.run(
            ["sudo", "-S", "-p", "", *command],
            input=password + "\n",
            capture_output=True, text=True, timeout=timeout,
        )
        if result.returncode == 0:
            return True, (result.stdout or "").strip()
        return False, (result.stderr or result.stdout or "").strip() or (
            f"sudo exited with code {result.returncode}"
        )
    except subprocess.TimeoutExpired:
        return False, "Command timed out."
    except Exception as exc:
        return False, str(exc)


# ── Distro-specific service / package mapping ────────────


def _service_names() -> tuple[str, str, str]:
    """Return (clamd_service, freshclam_service, clamonacc_service)."""
    if _is_fedora_like():
        return ("clamd@scan", "clamav-freshclam", "clamav-clamonacc")
    # Debian/Ubuntu, Arch, openSUSE, and most others use these names.
    return ("clamav-daemon", "clamav-freshclam", "clamav-clamonacc")


def _packages_to_install() -> tuple[list[str], list[str]]:
    """Return ``(required, optional)`` ClamAV package lists for this distro.

    Required packages must all be available or the install fails.
    Optional packages (clamonacc on distros that haven't packaged it,
    for example) are installed in a separate transaction so a missing
    one doesn't abort the whole setup.

    Fedora/RHEL/CentOS naming differs from Debian:
        clamav          → clamscan
        clamd           → clamd binary + /usr/lib/systemd/system/clamd@.service
        clamav-update   → freshclam
        clamav-clamonacc → clamonacc (Fedora 42+; missing on older releases)
    """
    if _is_fedora_like():
        return ["clamav", "clamd", "clamav-update"], ["clamav-clamonacc"]
    if _is_arch_like():
        return ["clamav"], []
    # Debian / Ubuntu / derivatives.
    return (
        ["clamav", "clamav-daemon", "clamav-freshclam"],
        ["clamav-clamonacc"],
    )


def _systemctl_is_active(service: str) -> bool:
    try:
        r = subprocess.run(
            ["systemctl", "is-active", service],
            capture_output=True, text=True, timeout=5,
        )
        return r.stdout.strip() == "active"
    except Exception:
        return False


def _systemctl_has_unit(service: str) -> bool:
    """Return True if systemd knows about *service*."""
    try:
        r = subprocess.run(
            ["systemctl", "cat", service],
            capture_output=True, text=True, timeout=5,
        )
        return r.returncode == 0
    except Exception:
        return False


# ── Platform interface ────────────────────────────────────


def system_db_dir() -> str | None:
    """Return system DB dir path if it exists, else None."""
    for path in _SYSTEM_DB_DIR_CANDIDATES:
        if os.path.isdir(path):
            return path
    return None


def system_db_dir_writable() -> str | None:
    """Return system DB dir if writable by the current user, else None.

    Normally the ``clamav`` system user owns the DB dir, so this returns
    None for non-root users — freshclam is run via systemd as that user.
    """
    d = system_db_dir()
    if d and os.access(d, os.W_OK):
        return d
    return None


def system_clamd_socket_path() -> str:
    """Return the system-level clamd socket path."""
    for path in _SYSTEM_SOCKET_CANDIDATES:
        if os.path.exists(path):
            return path
    return _SYSTEM_SOCKET_CANDIDATES[0]


def system_clamd_conf_path() -> str:
    """Return the system-level clamd.conf location."""
    for path in _SYSTEM_CONF_CANDIDATES:
        if os.path.exists(path):
            return path
    # Fall back to the distro-appropriate default even if not yet written.
    if _is_fedora_like():
        return "/etc/clamd.d/scan.conf"
    return "/etc/clamav/clamd.conf"


def find_binary(name: str) -> str | None:
    """Find a ClamAV binary on Linux via PATH lookup."""
    return shutil.which(name)


def find_certs_dir() -> str | None:
    """Locate the CVD signing-cert directory (the one holding clamav.crt).

    ClamAV >= 1.4 verifies *detached CVD signatures* against a dedicated root
    CA cert, which is a different thing from the system TLS CA bundle handled
    by clamav_env(). Returning None here made clamav_common.run_freshclam()
    bail out before ever invoking freshclam — on every Linux distro, not just
    ones with an unusual layout.

    Distro packages ship the cert at <prefix>/share/clamav/certs, so derive
    the prefix from the resolved binary rather than hardcoding /usr. That also
    covers non-FHS prefixes (Nix store, /usr/local, custom builds), where the
    path is not knowable ahead of time.
    """
    candidates: list[str] = []

    # freshclam's own env override wins, if the user set one.
    env_dir = os.environ.get("CVD_CERTS_DIR")
    if env_dir:
        candidates.append(env_dir)

    binary = find_binary("freshclam") or find_binary("clamd")
    if binary:
        prefix = os.path.dirname(os.path.dirname(os.path.realpath(binary)))
        candidates.append(os.path.join(prefix, "share", "clamav", "certs"))

    candidates += [
        "/usr/share/clamav/certs",
        "/usr/local/share/clamav/certs",
        "/var/lib/clamav/certs",
    ]

    for directory in candidates:
        if os.path.isfile(os.path.join(directory, "clamav.crt")):
            return directory

    return None


def clamav_env() -> dict[str, str]:
    """Return env dict for ClamAV on Linux.

    Ensures SSL_CERT_FILE is set so user-level freshclam (used for dev
    scans before system daemons are installed) can verify TLS.
    """
    env = dict(os.environ)
    if "SSL_CERT_FILE" not in env:
        for ca in (
            "/etc/ssl/certs/ca-certificates.crt",   # Debian/Ubuntu/Arch
            "/etc/pki/tls/certs/ca-bundle.crt",     # RHEL/Fedora
            "/etc/ssl/cert.pem",                     # fallback
        ):
            if os.path.isfile(ca):
                env["SSL_CERT_FILE"] = ca
                break
    return env


def is_app_bundle() -> bool:
    """Map the macOS app-bundle concept to 'system-wide daemon install'.

    Returns True when systemd is available — activate_system_daemons()
    will install the distro package if clamd isn't present yet. This
    makes the Start Protection UI path work the same as on macOS.
    """
    return _has_systemd()


def daemons_approved() -> bool:
    """Linux has no Login Items equivalent — approval is implicit."""
    return True


def has_full_disk_access() -> bool:
    """Linux has no FDA equivalent — the clamav system user has access."""
    return True


def open_fda_settings():
    """No-op on Linux — no Full Disk Access equivalent."""
    logger.info(
        "Antivirus: Linux has no Full Disk Access equivalent. "
        "The 'clamav' system user reads files on behalf of the daemon.",
    )


def open_login_items_settings():
    """No-op on Linux — services are managed by systemd."""
    clamd_svc, _fresh, _onacc = _service_names()
    logger.info(
        f"Antivirus: manage the service via 'systemctl enable {clamd_svc}'.",
    )


def ensure_daemons_registered():
    """No-op on Linux — systemd units are registered by the distro package."""
    logger.debug(
        "Antivirus: systemd handles daemon registration on Linux "
        "(done by the distro package).",
    )


def is_clamonacc_running() -> bool:
    """Check if clamonacc is running (by process name)."""
    try:
        r = subprocess.run(
            ["pgrep", "-x", "clamonacc"],
            capture_output=True, timeout=5,
        )
        return r.returncode == 0
    except Exception:
        return False


def system_clamd_running() -> bool:
    """Return True if the system clamd service is up.

    We deliberately do NOT rely on ``_ping_socket`` here.  On Fedora
    the stock SELinux targeted policy forbids ordinary user domains
    (``user_t``/``staff_t``/``xdm_t``) from connecting to a
    ``clamd_var_run_t`` socket, so a direct probe from the Phoenix UI
    process would always fail even when the daemon is healthy and
    clamonacc (running as ``clamscan``) is happily connected.  The
    authoritative signal is systemd's view of the unit plus the
    presence of the Unix socket the service was configured to create.
    """
    clamd_svc, _fresh, _onacc = _service_names()
    if not _systemctl_is_active(clamd_svc):
        return False
    sock = system_clamd_socket_path()
    return bool(sock) and os.path.exists(sock)


# ── System daemon activation ─────────────────────────────


def _install_packages_if_missing() -> tuple[bool, str]:
    """Install ClamAV packages via the distro package manager.

    No-op if ``clamd`` is already on PATH. Returns (success, message).

    Runs the required and optional installs together under one admin
    prompt: required first, then optional in a ``|| true`` trailer so a
    missing clamonacc package on older distros doesn't abort setup.
    """
    if shutil.which("clamd"):
        return True, "ClamAV already installed."

    required, optional = _packages_to_install()

    required_cmd = _install_command(required)
    if not required_cmd:
        return False, (
            "No supported package manager found. Install ClamAV "
            f"manually ({', '.join(required)}) and try again."
        )

    parts: list[str] = []
    # Refresh the package index on Debian-likes so the install doesn't
    # fail on a stale apt cache.  Repair any interrupted dpkg transactions
    # first — apt will refuse to run if triggers are left in a broken state.
    if _is_debian_like():
        parts.append("dpkg --configure -a || true")
        parts.append("dpkg --triggers-only -a || true")
        parts.append("apt-get update")
    parts.append(" ".join(_shell_quote(c) for c in required_cmd))

    if optional:
        optional_cmd = _install_command(optional)
        if optional_cmd:
            parts.append(
                "(" + " ".join(_shell_quote(c) for c in optional_cmd)
                + " || true)",
            )

    script = " && ".join(parts)
    ok, out = _run_privileged(["sh", "-c", script])

    if not ok:
        return False, out or "Package installation failed."

    if not shutil.which("clamd"):
        return False, (
            "Package install completed but clamd is still missing. "
            "Check your package manager logs."
        )
    return True, "ClamAV packages installed."


def _shell_quote(s: str) -> str:
    """Quote *s* for POSIX shell."""
    import shlex
    return shlex.quote(s)


def _prepare_config_script() -> str:
    """Shell snippet that normalises the distro-stock ClamAV configs.

    Two fixups are applied so clamd can actually start after a fresh
    package install:

      1. Comment out the lone ``Example`` stanza that Fedora (and older
         Debian) ship at the top of clamd.conf / freshclam.conf — clamd
         refuses to run with it in place.

      2. Make sure a ``LocalSocket`` line is active in clamd's config.
         Fedora's stock scan.conf leaves ``LocalSocket`` commented, so
         clamd exits with ``Please define server type (local and/or
         TCP)`` on first start. We append the distro-correct socket
         path only if no uncommented ``LocalSocket`` is already
         present, so this is idempotent and non-destructive.

    Both steps are safe to re-run on every invocation.
    """
    cmds: list[str] = []

    # (1) Drop the stock 'Example' stanza wherever it appears.
    example_targets = [
        "/etc/clamav/clamd.conf",
        "/etc/clamav/freshclam.conf",
        "/etc/clamd.d/scan.conf",
        "/etc/freshclam.conf",
    ]
    for t in example_targets:
        q = _shell_quote(t)
        cmds.append(
            f"if [ -f {q} ]; then sed -i 's/^Example$/#Example/' {q}; fi",
        )

    # (2) Ensure LocalSocket AND LocalSocketMode are defined in clamd's
    # config. Each tuple is (config_path, socket_path) — the socket_path
    # matches what the distro's systemd unit expects (RuntimeDirectory=)
    # and what system_clamd_socket_path() probes for.
    #
    # LocalSocketMode 0666 is important: when unset, clamd creates the
    # socket using the service's umask (0022 on Fedora), yielding mode
    # 0644 — which lets only the owning "clamscan" user connect.  The
    # Phoenix UI polls the socket as the regular desktop user, so
    # without 0666 we'd get EACCES and the status card would
    # permanently read "Protection Offline" even though clamd is
    # running.
    socket_targets = [
        ("/etc/clamd.d/scan.conf", "/run/clamd.scan/clamd.sock"),
        ("/etc/clamav/clamd.conf", "/run/clamav/clamd.ctl"),
    ]
    for conf, sock in socket_targets:
        cq = _shell_quote(conf)
        append_sock = _shell_quote(f"LocalSocket {sock}")
        append_mode = _shell_quote("LocalSocketMode 0666")
        cmds.append(
            f"if [ -f {cq} ]; then "
            f"grep -qE '^[[:space:]]*LocalSocket[[:space:]]' {cq} "
            f"|| echo {append_sock} >> {cq}; "
            f"grep -qE '^[[:space:]]*LocalSocketMode[[:space:]]' {cq} "
            f"|| echo {append_mode} >> {cq}; "
            f"fi",
        )

    # (3) Loosen /run/clamd.scan mode on Fedora via an ExecStartPost chmod.
    #
    # The Fedora clamd@.service unit does NOT declare ``RuntimeDirectory=``
    # — it just runs clamd, which creates /run/clamd.scan itself when it
    # drops to the ``User`` declared in scan.conf (clamscan:virusgroup)
    # with mode 0710.  Because the unit has no RuntimeDirectory=, a
    # ``RuntimeDirectoryMode=0755`` drop-in is metadata with nothing to
    # attach to — systemd merges it but never applies it.
    #
    # The reliable fix is to chmod the directory after clamd has
    # created it. A short bash wait-loop handles the (rare) race where
    # ExecStartPost fires before clamd finishes its initial setup.
    if _is_fedora_like():
        drop_in_dir = "/etc/systemd/system/clamd@scan.service.d"
        drop_in_path = f"{drop_in_dir}/resistine.conf"
        drop_in_body = (
            "[Service]\n"
            "# Installed by Resistine: Fedora's clamd@.service has no\n"
            "# RuntimeDirectory= entry, so RuntimeDirectoryMode= is\n"
            "# ignored. clamd itself creates /run/clamd.scan with mode\n"
            "# 0710 — blocking non-clamscan users from even stat'ing\n"
            "# the socket inside. Chmod the dir once clamd has it open.\n"
            "ExecStartPost=/usr/bin/bash -c 'for i in $(seq 1 20); do "
            "[ -d /run/clamd.scan ] && break; sleep 0.25; done; "
            "/usr/bin/chmod 0755 /run/clamd.scan'\n"
        )
        cmds.append(
            f"mkdir -p {_shell_quote(drop_in_dir)} && "
            f"printf '%s' {_shell_quote(drop_in_body)} "
            f"> {_shell_quote(drop_in_path)}",
        )

    return "; ".join(cmds)


def activate_system_daemons() -> tuple[bool, str]:
    """Install (if missing) and start system-level ClamAV daemons.

    Flow:
      1. Install distro packages if clamd isn't already on PATH.
      2. Comment out any 'Example' stanzas left in stock configs.
      3. Enable + start freshclam (populates DB) and clamd.
      4. Enable + start clamav-clamonacc if the unit exists.
      5. Wait for clamd to become responsive via the Unix socket.
    """
    if not _has_systemd():
        return False, (
            "systemd is not available. Start clamd manually for your "
            "init system (OpenRC, runit, etc.)."
        )

    clamd_svc, fresh_svc, onacc_svc = _service_names()

    if _is_nixos():
        # Units exist only when services.clamav is enabled; then just start
        # them (enabling is the system config's job).
        if not _systemctl_has_unit(clamd_svc):
            return False, _NIXOS_HINT
        script = (
            f"systemctl start {fresh_svc} 2>/dev/null || true; "
            f"systemctl start {clamd_svc}; "
            f"systemctl start {onacc_svc} 2>/dev/null || true"
        )
    else:
        installed_ok, install_msg = _install_packages_if_missing()
        if not installed_ok:
            return False, install_msg

        prep = _prepare_config_script()
        # Freshclam first so the DB exists before clamd loads. clamonacc is
        # best-effort (not all distros package it yet).  We use ``enable`` +
        # ``restart`` (instead of ``enable --now``) so that re-running Start
        # Protection picks up any config changes we just wrote in `prep` —
        # e.g. the newly-added LocalSocketMode line.  ``restart`` is
        # idempotent: it starts the service if it's stopped, and bounces it
        # if it's running.
        script = (
            f"{prep}; "
            f"systemctl daemon-reload; "
            f"systemctl enable {fresh_svc} 2>/dev/null || true; "
            f"systemctl restart {fresh_svc} 2>/dev/null || true; "
            f"systemctl enable {clamd_svc}; "
            f"systemctl restart {clamd_svc}; "
            f"systemctl enable {onacc_svc} 2>/dev/null || true; "
            f"systemctl restart {onacc_svc} 2>/dev/null || true"
        )
    ok, out = _run_privileged(["sh", "-c", script], timeout=600)
    if not ok:
        return False, out or "Failed to enable ClamAV services."

    # Wait for clamd to respond on its socket (signature load takes a while).
    sock = system_clamd_socket_path()
    from plugins.antivirus.clamav_common import _ping_socket

    for _ in range(120):  # up to 60 seconds
        time.sleep(0.5)
        if _ping_socket(sock):
            logger.info("ClamAV: system clamd is running")
            # Give clamonacc a few seconds to stabilise once clamd answers.
            for _w in range(20):
                if is_clamonacc_running():
                    logger.info("ClamAV: clamonacc is running")
                    break
                time.sleep(0.5)
            else:
                logger.warning(
                    "ClamAV: clamonacc not running after activation — "
                    "real-time protection may not be available on this distro.",
                )
            return True, "Protection activated."

    if _systemctl_is_active(clamd_svc):
        logger.info("ClamAV: clamd active but still loading signatures")
        return True, "Protection starting — signatures loading in background."

    return False, (
        f"clamd did not start. Check 'journalctl -u {clamd_svc}' for details."
    )


def build_deactivate_script() -> str:
    """Build the privileged shell that stops+disables the ClamAV daemons.

    Returns "" when systemd isn't available.  Split out from
    deactivate_system_daemons so the app uninstaller can batch these commands
    into a single privilege-escalation prompt.
    """
    if not _has_systemd():
        return ""
    clamd_svc, fresh_svc, onacc_svc = _service_names()
    return (
        f"systemctl disable --now {onacc_svc} 2>/dev/null || true; "
        f"systemctl disable --now {clamd_svc} 2>/dev/null || true; "
        f"systemctl disable --now {fresh_svc} 2>/dev/null || true"
    )


def is_any_service_active() -> bool:
    """Return True if any of our ClamAV services is currently active."""
    try:
        return any(_systemctl_is_active(s) for s in _service_names())
    except Exception:
        return False


def deactivate_system_daemons() -> tuple[bool, str]:
    """Stop and disable system-level ClamAV daemons.

    Leaves the distro packages installed so re-activation is fast.
    """
    if not _has_systemd():
        return False, "systemd is not available."

    script = build_deactivate_script()
    ok, out = _run_privileged(["sh", "-c", script], timeout=60)
    if ok:
        return True, "Protection deactivated."
    return False, out or "Failed to stop ClamAV services."
