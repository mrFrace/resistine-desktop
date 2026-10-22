"""One Phoenix per user (utils/single_instance.py)."""

import pytest


@pytest.fixture(scope="module")
def qapp():
    from PyQt6.QtWidgets import QApplication
    return QApplication.instance() or QApplication([])


@pytest.fixture
def si(tmp_path, monkeypatch, qapp):
    from utils import settings, single_instance

    monkeypatch.setattr(settings, "get_config_dir", lambda: str(tmp_path))
    monkeypatch.setattr(single_instance, "_name", lambda: f"phoenix-test-{tmp_path.name}")
    monkeypatch.setattr(single_instance, "_lock", None)
    monkeypatch.setattr(single_instance, "_server", None)
    yield single_instance
    if single_instance._server is not None:
        single_instance._server.close()
    if single_instance._lock is not None:
        single_instance._lock.unlock()


def test_first_launch_runs(si):
    assert si.acquire() is True


def test_second_launch_is_refused_and_asks_the_first(si, monkeypatch):
    assert si.acquire() is True
    si.listen(lambda: None)
    first = si._lock
    monkeypatch.setattr(si, "_lock", None)  # a fresh launch holds no lock
    assert si.acquire() is False
    monkeypatch.setattr(si, "_lock", first)


def test_errors_never_block_start(si, monkeypatch):
    def boom():
        raise OSError("read-only config dir")

    monkeypatch.setattr(si, "_lock_path", boom)
    assert si.acquire() is True
