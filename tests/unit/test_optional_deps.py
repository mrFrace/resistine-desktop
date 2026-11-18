"""An optional package that fails to import must not break its importer.

jsonschema skips its optional format packages on ImportError only. One of
them raised FileNotFoundError in the macOS build (a data file was not
bundled), which aborted ``import nio``: no Matrix chat, no SIEM alerts.
"""
import importlib.abc
import importlib.machinery
import sys

import pytest

from utils import optional_deps

NAME = "px_optional_dep_under_test"


class _Finder(importlib.abc.MetaPathFinder, importlib.abc.Loader):
    def __init__(self, error):
        self.error = error

    def find_spec(self, name, path, target=None):
        if name == NAME:
            return importlib.machinery.ModuleSpec(name, self)

    def create_module(self, spec):
        return None

    def exec_module(self, module):
        if self.error:
            raise self.error


@pytest.fixture
def finder():
    def install(error):
        f = _Finder(error)
        sys.meta_path.insert(0, f)
        installed.append(f)
    installed = []
    yield install
    for f in installed:
        sys.meta_path.remove(f)
    sys.modules.pop(NAME, None)


@pytest.mark.unit
class TestBlockUnloadable:
    def test_failing_package_becomes_an_import_error(self, finder):
        finder(FileNotFoundError(2, "No such file or directory", "grammar.lark"))
        with pytest.raises(FileNotFoundError):
            __import__(NAME)  # what the importer hit before the guard

        assert optional_deps.block_unloadable((NAME,), force=True) == [NAME]
        with pytest.raises(ImportError):
            __import__(NAME)  # what `with suppress(ImportError)` can skip

    def test_working_package_is_left_alone(self, finder):
        finder(None)
        assert optional_deps.block_unloadable((NAME,), force=True) == []
        assert sys.modules[NAME] is not None

    def test_missing_package_is_left_alone(self):
        assert optional_deps.block_unloadable(("px_not_installed_anywhere",), force=True) == []
        assert "px_not_installed_anywhere" not in sys.modules

    def test_matrix_transport_runs_the_guard_before_using_nio(self):
        import inspect
        from plugins.chat import matrix_transport

        src = inspect.getsource(matrix_transport)
        assert src.index("optional_deps.block_unloadable()") < src.index("from nio")

    def test_the_package_that_broke_the_build_is_covered(self):
        assert "rfc3987_syntax" in optional_deps.OPTIONAL_FORMAT_PACKAGES
