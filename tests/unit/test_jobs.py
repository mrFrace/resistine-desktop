"""Jobs with short codes (utils/jobs.py)."""

import json
import os
import stat

import pytest

from utils import jobs

pytestmark = pytest.mark.unit


@pytest.fixture(autouse=True)
def fresh(isolated_settings):
    jobs._reset_for_tests()
    yield
    jobs._reset_for_tests()


def test_start_finish_and_persist():
    seen = []
    jobs.subscribe(seen.append)
    job = jobs.start("antivirus_scan", "Antivirus scan", "files")
    assert jobs.CODE_RE.fullmatch(job["code"]) and job["status"] == "running"
    assert jobs.find(job["code"])["title"] == "Antivirus scan"
    done = jobs.finish(job["code"], ok=True, summary="0 threats in 1,234 files")
    assert done["status"] == "done" and done["ended_at"] >= done["started_at"]
    assert [j["status"] for j in seen] == ["running", "done"]
    assert jobs.finish("PX-ZZZZ") is None
    path = jobs._path()
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    with open(path, encoding="utf-8") as fh:
        assert json.load(fh)["jobs"][0]["code"] == job["code"]
    jobs._reset_for_tests()  # reload from disk
    assert jobs.recent()[0]["summary"] == "0 threats in 1,234 files"


def test_a_job_left_running_by_a_crash_is_failed_on_reload():
    job = jobs.start("vpn", "VPN connect")
    jobs._reset_for_tests()
    again = jobs.find(job["code"])
    assert again["status"] == "failed" and "closed" in again["summary"]


def test_recent_is_newest_first_and_capped():
    for i in range(jobs.MAX_JOBS + 5):
        jobs.start("x", f"job {i}")
    recent = jobs.recent(limit=3)
    assert [j["title"] for j in recent] == ["job 54", "job 53", "job 52"]
    assert len(jobs.recent(limit=1000)) == jobs.MAX_JOBS


def test_codes_in_text():
    assert jobs.codes_in("what happened in PX-4K7Q and px-4k7q and PX-4K7Q?") == ["PX-4K7Q"]
    assert jobs.codes_in("PX-4K7QX PX-10IO PX-AB") == []
    assert jobs.codes_in("") == [] and jobs.codes_in(None) == []
    assert all(c not in "IO01" for c in jobs.ALPHABET)


def test_describe_and_context(monkeypatch):
    job = jobs.start("antivirus_scan", "Antivirus scan", "files")
    now = job["started_at"] + 200
    assert jobs.describe(job, now) == "Antivirus scan (files) · running since 3 min ago"
    jobs.finish(job["code"], ok=False, summary="Scan\x1b cancelled\n early")
    job = jobs.find(job["code"])
    assert jobs.describe(job, job["ended_at"] + 7200) == \
        "Antivirus scan (files) · failed 2 h ago · Scan cancelled early"
    ctx = jobs.context_for([job["code"], "PX-ZZZZ"], now=job["ended_at"])
    assert ctx.splitlines()[0].startswith(f"[Phoenix job {job['code']}: Antivirus scan (files) · failed just now")
    assert ctx.splitlines()[1] == "[Phoenix job PX-ZZZZ: no such job on this machine]"
    assert jobs.context_for([]) == ""


def test_summaries_are_capped_and_printable():
    job = jobs.start("k" * 100, "t" * 100, "d" * 200)
    assert len(job["kind"]) == 40 and len(job["title"]) == 80 and len(job["detail"]) == 120
    done = jobs.finish(job["code"], summary="x" * 1000)
    assert len(done["summary"]) == jobs._SUMMARY_MAX and done["summary"].endswith("…")
