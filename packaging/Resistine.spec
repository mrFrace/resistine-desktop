# -*- mode: python ; coding: utf-8 -*-
"""
PyInstaller spec file for Phoenix Desktop Application
This bundles the Python PyQt6 UI with all dependencies
Swift components (CLI, XPC, Network Extension) are added by build script
"""

import os
import sys
from PyInstaller.utils.hooks import (
    collect_all, collect_data_files, collect_dynamic_libs, collect_submodules)

block_cipher = None
IS_MACOS = sys.platform == "darwin"
IS_WINDOWS = sys.platform == "win32"

# Application metadata
# Bundle / executable file name (Phoenix.app, Phoenix.exe). The bundle ID,
# app group and service names keep the old name: they are tied to the Apple
# signing profiles and to state on installed machines, and users never see them.
APP_NAME = 'Phoenix'
DISPLAY_NAME = 'Phoenix'
BUNDLE_ID = 'com.resistine.desktop'
VERSION = '2026.07.20-rc'
# Build ID: tells builds of one VERSION apart (package versions, file names,
# the version line in the app). UTC minutes, so every rebuild sorts after the
# one before. The build scripts set PHOENIX_BUILD so that every package made
# in one run carries the same ID.
import datetime as _dt
BUILD = os.environ.get('PHOENIX_BUILD') or _dt.datetime.now(_dt.timezone.utc).strftime('%Y%m%d%H%M')
if not BUILD.isdigit():
    raise SystemExit(f"PHOENIX_BUILD must be digits (UTC YYYYMMDDHHMM), not {BUILD!r}")

# Paths — project root is one level up from packaging/
_spec_dir = os.path.dirname(os.path.abspath(SPEC))
base_path = os.path.dirname(_spec_dir)

def _src(relpath):
    """Resolve a project-relative path to an absolute path."""
    return os.path.join(base_path, relpath)

# Write a VERSION file so the frozen app can read its own version at runtime.
# Use a temp path so we don't pollute the project root.
import tempfile as _tmpmod
_version_file = os.path.join(_tmpmod.gettempdir(), 'VERSION')
with open(_version_file, 'w') as _vf:
    _vf.write(VERSION)
_build_file = os.path.join(_tmpmod.gettempdir(), 'BUILD')
with open(_build_file, 'w') as _bf:
    _bf.write(BUILD)

# Collect data files
datas = [
    (_version_file, '.'),
    (_build_file, '.'),
    (_src('resources'), 'resources'),
    (_src('plugins'), 'plugins'),
    (_src('gui'), 'gui'),
    (_src('utils'), 'utils'),
    (_src('docs'), 'docs'),
    (_src('scripts/wazuh-postinstall-darwin.sh'), 'scripts'),
    (_src('scripts/clamav-postinstall-darwin.sh'), 'scripts'),
]

# Hidden imports (modules not auto-detected)
hiddenimports = [
    'PIL',
    'cryptography',
    'keyring',
    'keyring.backends',
    'httpx',
    'ssl',
    '_ssl',
    'certifi',
    'requests',
    'urllib3',
    'idna',
    'openai',
    'markdown',
    'loguru',
    # OpenTelemetry (logger.py imports these; PyInstaller can't trace the submodules)
    # Only the HTTP OTLP exporter is used — the grpc exporter (grpcio, ~18MB) is
    # intentionally NOT bundled (see excludes below).
    'opentelemetry',
    'opentelemetry._logs',
    'opentelemetry.exporter.otlp.proto.http._log_exporter',
    'opentelemetry.sdk._logs',
    'opentelemetry.sdk._logs.export',
    'opentelemetry.sdk.resources',
    'opentelemetry.trace',
]

# Chat over Matrix. plugins/ ships as data, so PyInstaller never sees the chat
# plugin's `from nio import ...`; without this the bundle has no nio and
# matrix_transport.available() is False ("lacks Matrix encryption support").
# nio.crypto picks its E2EE backend at import time (vodozemac, a Rust
# extension), so collect both packages whole.
hiddenimports += collect_submodules('nio')
_vodozemac_datas, _vodozemac_binaries, _vodozemac_hidden = collect_all('vodozemac')
datas += _vodozemac_datas
hiddenimports += _vodozemac_hidden + [
    'peewee', 'cachetools', 'atomicwrites', 'unpaddedbase64', 'jsonschema']

if IS_MACOS:
    hiddenimports.extend([
        'keyring.backends.macOS',
        'pyobjc',
        'Foundation',
        'ServiceManagement',
        'AppKit',
        'Cocoa',
        'objc',
    ])

if sys.platform.startswith('linux'):
    hiddenimports.extend([
        'keyring.backends.SecretService', 'secretstorage',
        'jeepney', 'jeepney.io.blocking',
        'cairocffi', 'cffi'])
if IS_WINDOWS:
    hiddenimports.extend([
        'keyring.backends.Windows', 'win32ctypes',
        'win32ctypes.pywin32', 'pystray._win32'])

# Analysis
a = Analysis(
    [_src('main.py')],
    pathex=[base_path],
    binaries=_vodozemac_binaries + (
        [(_src('frameworks/WinSparkle/WinSparkle.dll'), '.')] if IS_WINDOWS else []),
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        'matplotlib',
        'numpy',
        'pandas',
        'scipy',
        'pytest',
        'setuptools',
        # OTLP grpc exporter path — only the HTTP exporter is used. grpcio ships
        # an ~18MB compiled cygrpc extension; keep it out of the bundle.
        'grpc',
        'grpcio',
        # Dead CustomTkinter-era GUI deps, removed in the PyQt6 migration.
        'customtkinter',
        'tkinterweb',
        'html2text',
        # The app is fully PyQt6 — the tkinter runtime (Tcl/Tk, ~4.6MB) is dead.
        'tkinter',
        '_tkinter',
        'tkinter.ttk',
        # Unused Qt module — no QtPdf usage anywhere in the app.
        'PyQt6.QtPdf',
        'PyQt6.QtPdfWidgets',
    ],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

# ── Strip dead weight PyInstaller auto-scooped into the bundle ──────────────
# PyInstaller's binary/data scanner over-collects: on Windows it grabs the
# Swift-for-Windows runtime off the build machine's PATH (the app has no Swift
# component there — the Swift VPN CLI is macOS-only and added separately by the
# build script), and every platform pulls Qt's PDF module, its ~40-language
# translation catalogs (we ship our own i18n in utils/i18n), and Pillow's AVIF
# codec (images go through webp/cairosvg). None of it runs. Filter it out.

def _basename(dest):
    return dest.replace('\\', '/').rsplit('/', 1)[-1].lower()

def _is_dead_binary(dest):
    name = _basename(dest)
    path = dest.replace('\\', '/').lower()
    # Pillow AVIF codec (~7.6MB) — unused.
    if '_avif' in name:
        return True
    # Qt PDF viewer module — unused.
    if 'qtpdf' in name or 'qt6pdf' in name:
        return True
    # tkinter runtime — the app is fully PyQt6. Match the _tkinter extension,
    # the Tcl/Tk framework binaries (basename 'tcl'/'tk'), and libtcl*/libtk*.
    if name.startswith('_tkinter') or name.startswith('libtcl') or name.startswith('libtk'):
        return True
    if name in {'tcl', 'tk'} or path.rsplit('/', 2)[0].endswith(('tcl.framework', 'tk.framework')):
        return True
    # Swift-for-Windows runtime — false positive from the build toolchain on PATH.
    if IS_WINDOWS and name.endswith('.dll'):
        if name.startswith('swift'):
            return True
        if name in {
            'foundation.dll', 'foundationnetworking.dll', 'foundationxml.dll',
            '_foundationicu.dll', 'blocksruntime.dll', 'dispatch.dll',
        }:
            return True
    return False

def _is_dead_data(dest):
    path = dest.replace('\\', '/').lower()
    # Qt's bundled UI translations (~6.5MB) — the app ships its own i18n.
    if 'qt6/translations' in path:
        return True
    # Tcl/Tk runtime data — the app is PyQt6; nothing imports tkinter anymore.
    if path.startswith('tcl/') or path.startswith('tk/') or '/tcl8' in path or '/tk8' in path:
        return True
    return False

_bin_before, _data_before = len(a.binaries), len(a.datas)
a.binaries = [e for e in a.binaries if not _is_dead_binary(e[0])]
a.datas = [e for e in a.datas if not _is_dead_data(e[0])]
print(f"[spec] stripped {_bin_before - len(a.binaries)} dead binaries, "
      f"{_data_before - len(a.datas)} dead data files")

# Remove duplicate files
pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

# Create executable
exe_kwargs = dict(
    exclude_binaries=True,
    name=APP_NAME,
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,  # No console window
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,  # Use native architecture (arm64 on Apple Silicon, x86_64 on Intel)
    codesign_identity=None,
)
if IS_MACOS:
    exe_kwargs['entitlements_file'] = _src(os.path.join('packaging', 'Resistine.entitlements'))
if IS_WINDOWS:
    exe_kwargs['icon'] = _src(os.path.join('resources', 'icons', 'icon.ico'))
if IS_WINDOWS:
    exe_kwargs['manifest'] = _src(os.path.join('packaging', 'windows', 'Resistine.exe.manifest'))

exe = EXE(
    pyz,
    a.scripts,
    [],
    **exe_kwargs,
)

# Collect all files
coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name=APP_NAME,
)

if IS_MACOS:
    # Create .app bundle only on macOS. Windows/Linux use the COLLECT folder as output.
    app = BUNDLE(
        coll,
        name=f'{APP_NAME}.app',
        icon=_src('resources/icons/icon_mac.icns'),
        bundle_identifier=BUNDLE_ID,
        version=VERSION,
        info_plist={
            # Basic app info
            'CFBundleName': DISPLAY_NAME,
            'CFBundleDisplayName': DISPLAY_NAME,
            'CFBundleExecutable': APP_NAME,
            'CFBundleIdentifier': BUNDLE_ID,
            'CFBundleVersion': VERSION,
            'CFBundleShortVersionString': VERSION,
            'CFBundleInfoDictionaryVersion': '6.0',
            'CFBundlePackageType': 'APPL',
            'CFBundleSignature': '????',

            # UI settings
            'NSHighResolutionCapable': True,
            'NSRequiresAquaSystemAppearance': False,
            'LSMinimumSystemVersion': '13.0',
            'NSUserNotificationAlertStyle': 'alert',

            # Permissions (will be expanded with actual entitlements)
            'NSNetworkClient': True,
            'NSSystemAdministrationUsageDescription': 'Phoenix needs admin access to manage VPN connections.',

            # XPC Services (will be populated by build script)
            'NSXPCServices': ['ResistineVPNXPC'],

            # Helper registration for privileged operations
            'SMPrivilegedExecutables': {
                'com.resistine.vpn.xpc': 'identifier "com.resistine.vpn.xpc" and anchor apple generic and certificate leaf[subject.CN] = "Resistine" and certificate 1[field.1.2.840.113635.100.6.2.1] /* exists */'
            },

            # URL schemes (if needed for OAuth, deep links, etc.)
            'CFBundleURLTypes': [
                {
                    'CFBundleURLName': BUNDLE_ID,
                    'CFBundleURLSchemes': ['resistine'],
                }
            ],

            # Document types (if you want to open .conf files)
            'CFBundleDocumentTypes': [
                {
                    'CFBundleTypeName': 'WireGuard Configuration',
                    'CFBundleTypeRole': 'Editor',
                    'LSItemContentTypes': ['com.resistine.wireguard-config'],
                    'LSHandlerRank': 'Owner',
                }
            ],

            # Export type for .conf files
            'UTExportedTypeDeclarations': [
                {
                    'UTTypeIdentifier': 'com.resistine.wireguard-config',
                    'UTTypeConformsTo': ['public.data', 'public.content'],
                    'UTTypeDescription': 'WireGuard Configuration File',
                    'UTTypeTagSpecification': {
                        'public.filename-extension': ['conf'],
                        'public.mime-type': 'text/plain',
                    }
                }
            ],

            # Sparkle Auto-Update
            'SUFeedURL': 'https://resistine.github.io/appcast.xml',
            'SUPublicEDKey': '2eiUHVoMgl+qqhEWO8iix5SUcRAKfkWYESh9F7jG6ls=',
            'SUEnableAutomaticChecks': True,
            'SUScheduledCheckInterval': 14400,  # 4 hours (base; Python scheduler adds jitter)
        },
    )
