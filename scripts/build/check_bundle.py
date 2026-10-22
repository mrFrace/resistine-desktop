"""Fail the build if the PyInstaller bundle lacks modules the app needs.

plugins/ ships as data files, so PyInstaller never traces what plugins import;
packaging/Resistine.spec lists those packages by hand. This catches a package
that went missing anyway (a dropped hidden import, a failed pip install), the
way Matrix chat once shipped without matrix-nio and so without E2EE.

Usage: python scripts/build/check_bundle.py dist/Phoenix
"""

import sys
from pathlib import Path

from PyInstaller.archive.readers import CArchiveReader

# Modules that must be in the bundle's PYZ archive.
REQUIRED_MODULES = [
    "nio",
    "nio.crypto",  # Matrix E2EE; sets ENCRYPTION_ENABLED from vodozemac
    "vodozemac",
    "peewee",  # nio's E2EE key store
]

# Compiled extensions that must be next to it: (package dir, why).
REQUIRED_EXTENSIONS = [("vodozemac", "Matrix E2EE crypto (Rust)")]


def main(bundle: Path) -> int:
    exe = next(
        (p for p in (bundle / "Phoenix", bundle / "Phoenix.exe") if p.is_file()), None
    )
    if exe is None:
        print(f"check_bundle: no Phoenix executable in {bundle}", file=sys.stderr)
        return 1
    toc = CArchiveReader(str(exe)).open_embedded_archive("PYZ.pyz").toc
    missing = [m for m in REQUIRED_MODULES if m not in toc]

    internal = bundle / "_internal"
    for pkg, why in REQUIRED_EXTENSIONS:
        exts = [p for p in (internal / pkg).glob("*") if p.suffix in (".so", ".pyd")]
        if not exts:
            missing.append(f"{pkg} extension ({why})")

    if missing:
        print(f"check_bundle: {exe} is missing: {', '.join(missing)}", file=sys.stderr)
        return 1
    print(
        f"check_bundle: {exe} OK ({len(REQUIRED_MODULES)} modules, {len(REQUIRED_EXTENSIONS)} extensions)"
    )
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    sys.exit(main(Path(sys.argv[1])))
