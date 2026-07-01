"""ClamAV backend — thin facade re-exporting shared + platform functions.

All logic lives in clamav_common.py (shared) and clamav_platform_*.py
(platform-specific). This module re-exports everything so existing
call-sites (``clamav.scan_path()``, ``clamav.start_clamd()``, etc.)
continue to work unchanged.

Author: Resistine Team
Copyright (c) Resistine 2025
Licensed under the GNU General Public License v2 or later
"""

import platform

# ── Shared (platform-agnostic) functions ──────────────────
from plugins.antivirus.clamav_common import (  # noqa: F401
    _CLAMAV_DATA_DIR,
    _CLAMD_CONF,
    _CLAMD_PID,
    _CLAMD_SOCKET,
    _DB_DIR,
    _EXCLUSIONS_FILE,
    _FRESHCLAM_CONF,
    _LOG_DIR,
    _PARALLEL_WORKERS,
    _QUARANTINE_DIR,
    _RUN_DIR,
    _SKIP_DIRS,
    _WHITELIST_FILE,
    _active_clamd_socket,
    _clamd_pid_alive,
    _contscan_socket,
    _ensure_dirs,
    _format_duration,
    _get_platform,
    _ping_socket,
    _scan_dir_socket,
    _scan_file_socket,
    _walk_files,
    _write_clamd_conf,
    _write_freshclam_conf,
    add_excluded_extension,
    add_excluded_extensions,
    add_to_whitelist,
    delete_quarantined,
    engine_name,
    ensure_config,
    get_binaries,
    get_db_info,
    get_realtime_status,
    get_scan_exclusions,
    get_whitelist,
    has_database,
    is_available,
    is_clamd_running,
    is_clamav_installed,
    is_path_whitelisted,
    list_quarantined,
    quarantine_file,
    remove_excluded_extension,
    remove_from_whitelist,
    restore_quarantined,
    run_freshclam,
    scan_path,
    set_max_file_size,
    set_scan_exclusions,
    start_clamd,
    stop_clamd,
)

# ── Platform-specific functions ───────────────────────────
_system = platform.system()

if _system == "Darwin":
    from plugins.antivirus.clamav_platform_darwin import (  # noqa: F401
        _DAEMON_PLISTS,
        _LEGACY_PLIST_PATHS,
        _SYSTEM_CLAMAV_DIR,
        _SYSTEM_CLAMD_CONF,
        _SYSTEM_CLAMD_SOCKET,
        _SYSTEM_DB_DIR,
        _SYSTEM_FRESHCLAM_CONF,
        _SYSTEM_LOG_DIR,
        _SYSTEM_RUN_DIR,
        activate_system_daemons,
        clamav_env,
        daemons_approved,
        deactivate_system_daemons,
        ensure_daemons_registered,
        find_binary,
        find_certs_dir,
        has_full_disk_access,
        is_app_bundle,
        is_clamonacc_running,
        open_fda_settings,
        open_login_items_settings,
        refresh_system_configs,
        set_freshclam_daemon_enabled,
        system_clamd_conf_path,
        system_clamd_socket_path,
        system_db_dir,
        system_db_dir_writable,
    )

elif _system == "Linux":
    from plugins.antivirus.clamav_platform_linux import (  # noqa: F401
        activate_system_daemons,
        clamav_env,
        daemons_approved,
        deactivate_system_daemons,
        ensure_daemons_registered,
        find_binary,
        find_certs_dir,
        has_full_disk_access,
        is_app_bundle,
        is_clamonacc_running,
        open_fda_settings,
        open_login_items_settings,
        system_clamd_conf_path,
        system_clamd_socket_path,
        system_db_dir,
        system_db_dir_writable,
    )

elif _system == "Windows":
    # Defender overrides: shadow the equivalent ClamAV symbols imported
    # from clamav_common above so plugins.antivirus.clamav.* dispatches to
    # Defender on Windows.
    # Quarantine functions (list_quarantined, restore_quarantined,
    # delete_quarantined, quarantine_file) are intentionally NOT overridden —
    # the clamav_common versions use the local quarantine directory, which is
    # correct since we scan with -DisableRemediation.
    from plugins.antivirus.defender_windows import (  # noqa: F401
        activate_system_daemons,
        clamav_env,
        daemons_approved,
        deactivate_system_daemons,
        engine_name,
        ensure_daemons_registered,
        find_binary,
        find_certs_dir,
        get_db_info,
        get_realtime_status,
        get_recent_threats,
        has_database,
        has_full_disk_access,
        is_app_bundle,
        is_available,
        is_clamav_installed,
        is_clamd_running,
        is_clamonacc_running,
        open_fda_settings,
        open_login_items_settings,
        refresh_system_configs,
        run_freshclam,
        scan_path,
        start_clamd,
        stop_clamd,
        system_clamd_conf_path,
        system_clamd_socket_path,
        system_db_dir,
        system_db_dir_writable,
    )

