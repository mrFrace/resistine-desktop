"""Every bundled plugin has its own id: the plugin manager keeps only the
first plugin of an id, so a collision silently drops a whole page (Devices
and Alerts both had 013 after a merge)."""

import ast
import pathlib

import pytest

PLUGINS = pathlib.Path(__file__).resolve().parents[2] / "plugins"


def _plugin_id(path: pathlib.Path):
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.keyword) and node.arg == "id" and isinstance(node.value, ast.Constant):
            return node.value.value
    return None


@pytest.mark.unit
def test_bundled_plugin_ids_are_unique():
    ids = {}
    for main in sorted(PLUGINS.glob("*/main.py")):
        pid = _plugin_id(main)
        if pid is not None:
            ids.setdefault(pid, []).append(main.parent.name)
    assert len(ids) >= 10
    assert {pid: names for pid, names in ids.items() if len(names) > 1} == {}
