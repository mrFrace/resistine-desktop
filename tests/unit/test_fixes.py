"""The fix queue (utils/fixes.py): this machine only, dependencies first,
one job per fix, a failure skips only what depended on it."""

import pytest

from utils import fixes, jobs

pytestmark = pytest.mark.unit


@pytest.fixture(autouse=True)
def fresh(isolated_settings):
    jobs._reset_for_tests()
    yield
    jobs._reset_for_tests()


def fix(id_, plugin="Endpoint", host="drake-laptop", **kw):
    return fixes.Fix(id_, plugin, f"Do {id_}", "because", host=host, **kw)


def test_gate_keeps_this_machine_only():
    mine, other, nohost = fix("a"), fix("b", host="francispc"), fix("c", host="")
    out = fixes.gate([mine, other, nohost, "junk"], {"DRAKE-laptop", "drake-laptop.local"})
    assert out == [mine]
    assert fixes.gate([mine], set()) == []


def test_plan_puts_prerequisites_first_and_tolerates_missing_ones():
    start, reconnect = fix("agent_start"), fix("agent_reconnect", after=("agent_start",))
    av = fix("av_signatures", plugin="Antivirus")
    assert [f.id for f in fixes.plan([reconnect, av, start])] == ["agent_start", "agent_reconnect", "av_signatures"]
    assert [f.id for f in fixes.plan([reconnect, av])] == ["agent_reconnect", "av_signatures"]
    loop_a, loop_b = fix("x", after=("y",)), fix("y", after=("x",))
    assert len(fixes.plan([loop_a, loop_b, loop_a])) == 2
    assert fixes.admin_prompts([fix("p", needs_admin=True), av]) == 1


def test_run_is_sequential_with_a_job_each_and_skips_dependants_of_a_failure():
    start = fix("agent_start", needs_admin=True, undo={"label": "Stop", "plugin": "Endpoint", "action": "agent_stop", "arg": ""})
    reconnect = fix("agent_reconnect", after=("agent_start",))
    av = fix("av_signatures", plugin="Antivirus")
    order, states = [], []

    def run_one(f):
        order.append(f.id)
        if f.id == "agent_start":
            return False, "the agent did not start"
        if f.id == "av_signatures":
            raise RuntimeError("freshclam missing")
        return True, ""

    results = fixes.run([reconnect, av, start], run_one, lambda f, st, text: states.append((f.id, st, text)))
    assert order == ["agent_start", "av_signatures"]  # reconnect never tried
    assert results["Endpoint:agent_start"] == (fixes.FAILED, "the agent did not start")
    assert results["Endpoint:agent_reconnect"] == (fixes.SKIPPED, "needs you: agent_start did not succeed")
    assert results["Antivirus:av_signatures"] == (fixes.FAILED, "RuntimeError: freshclam missing")
    assert states[0] == ("agent_start", fixes.RUNNING, "")
    recent = jobs.recent()
    assert [j["title"] for j in recent] == ["Do av_signatures", "Do agent_start"]
    assert recent[1]["status"] == "failed" and recent[1]["undo"]["action"] == "agent_stop"
    assert recent[1]["detail"] == "Endpoint"


def test_run_success_path():
    done = fixes.run([fix("a"), fix("b", after=("a",))], lambda f: (True, "ok"))
    assert done == {"Endpoint:a": (fixes.DONE, "ok"), "Endpoint:b": (fixes.DONE, "ok")}
    assert all(j["status"] == "done" for j in jobs.recent())
