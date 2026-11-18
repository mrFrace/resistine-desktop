"""The frozen app must ship the data files its imports read at import time.

PyInstaller bundles modules, not the files next to them. matrix-nio imports
jsonschema, which imports a set of optional "format" packages whenever they
happen to be installed, guarding only against ImportError. One of them parses
a grammar file at import: missing from the bundle, it raised
FileNotFoundError out of ``import nio`` and Matrix chat and SIEM alerts were
dead on every start of the built app, while everything worked from source.
"""
import importlib
import inspect
import os
import re
from pathlib import Path

import pytest

SPEC = (Path(__file__).resolve().parents[2] / "packaging" / "Phoenix.spec").read_text()
_CODE = (".py", ".pyc", ".pyi", ".so", ".pyd", ".typed")


def _optional_format_modules():
    fmt = pytest.importorskip("jsonschema._format")
    names = re.findall(r"^\s+(?:import|from) ([A-Za-z0-9_]+)", inspect.getsource(fmt), re.M)
    return sorted(set(names) - {"jsonschema", "contextlib"})


@pytest.mark.unit
def test_format_packages_with_data_files_are_collected():
    missing = []
    for name in _optional_format_modules():
        try:
            module = importlib.import_module(name)
        except ImportError:
            continue  # not installed: jsonschema skips that format
        pkg_dir = os.path.dirname(getattr(module, "__file__", "") or "")
        if os.path.basename(pkg_dir) != name:
            continue  # single-file module, nothing next to it
        data = [f for f in os.listdir(pkg_dir)
                if os.path.isfile(os.path.join(pkg_dir, f)) and not f.endswith(_CODE)]
        if data and f"collect_data_files('{name}')" not in SPEC:
            missing.append(f"{name}: {data}")
    assert not missing, (
        "installed packages jsonschema imports carry data files the spec "
        f"does not bundle: {missing}"
    )
