"""Keep an optional dependency that cannot load from taking a required one down.

matrix-nio imports jsonschema, and jsonschema imports a handful of optional
"format" packages whenever they are installed, guarding each import against
ImportError only. ``rfc3987_syntax`` parses a grammar file at import; in a
frozen build that shipped the module without the file it raised
FileNotFoundError, which escaped that guard and aborted ``import nio`` — so
Matrix chat and the SIEM alerts listener were dead on every start.

The build bundles the file (packaging/Resistine.spec). This is the second line:
whatever such a package fails with, turn it into the ImportError its importer
already knows how to skip.
"""
from __future__ import annotations

import importlib
import sys

from utils.logger import logger

# Packages jsonschema treats as optional and that do real work at import.
OPTIONAL_FORMAT_PACKAGES = ("rfc3987_syntax",)

_checked = False


def block_unloadable(names=OPTIONAL_FORMAT_PACKAGES, *, force: bool = False) -> list:
    """Try each optional package once; hide the ones that cannot be imported.

    A hidden package has ``sys.modules[name] = None``, which makes every later
    ``import name`` raise ImportError. Returns the names that were hidden.
    Idempotent and cheap: call it before importing anything that pulls in
    jsonschema.
    """
    global _checked
    if _checked and not force:
        return []
    _checked = True
    hidden = []
    for name in names:
        if sys.modules.get(name) is not None:
            continue  # already imported fine
        try:
            importlib.import_module(name)
        except ImportError:
            continue  # not installed: its importer skips it by itself
        except Exception as e:  # noqa: BLE001 - any other failure must not escape
            for loaded in [m for m in sys.modules if m == name or m.startswith(name + ".")]:
                del sys.modules[loaded]
            sys.modules[name] = None
            hidden.append(name)
            logger.warning(
                f"Optional package {name} cannot load ({type(e).__name__}: {e}); "
                "continuing without it")
    return hidden
