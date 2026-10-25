"""Continuous Red-hunt: repeats are dropped, the hunt yields to the worker, the heartbeat says what is going on."""
from pathlib import Path

from wreckless import swarm as swarm_mod
from wreckless.agents import red
from wreckless.config import Settings
from wreckless.swarm import Swarm


def _sw(tmp_path):
    return Swarm(Settings(use_llm=False), tmp_path)


def _found(sw, title, file="victim/vector_sql.py"):
    return sw.queue.enqueue("red-hunt", title, payload={"file": file})


def test_the_same_flaw_worded_differently_is_a_repeat(tmp_path):
    sw = _sw(tmp_path)
    _found(sw, "eval() on database values in vector_sql")
    same = red.Proposal(Path("x"), "llm", "eval on database values in vector_sql", "victim/vector_sql.py")
    assert sw._duplicate(same) == "eval() on database values in vector_sql"
    looser = red.Proposal(Path("x"), "llm", "Code injection through SQL results", "victim/vector_sql.py")
    assert sw._duplicate(looser) is None            # same file but not the same finding, below 0.5
    other = red.Proposal(Path("x"), "llm", "pal chain denylist misses __import__", "victim/pal_chain.py")
    assert sw._duplicate(other) is None


def test_hunt_pass_drops_a_repeat_and_queues_a_new_flaw(tmp_path, monkeypatch):
    sw = _sw(tmp_path)
    _found(sw, "eval() on database values in vector_sql")
    seen = []

    def fake_hunt(wt, enclave, d, s, known=None):
        seen.append(known)
        (d / "repro_exploit.py").write_text("print(1)")
        title = ["eval on database values in vector_sql", "pal chain denylist misses __import__"][len(seen) - 1]
        return red.Proposal(d / "repro_exploit.py", "llm", title, "victim/x.py")
    monkeypatch.setattr(red, "hunt", fake_hunt)
    monkeypatch.setattr(swarm_mod, "init_victim", lambda src, wt: wt.mkdir(parents=True))
    monkeypatch.setattr(sw, "_enclave", lambda d: type("E", (), {"close": lambda self: None})())
    sw._hunt_pass()
    sw._hunt_pass()
    assert seen[0] == ["eval() on database values in vector_sql"]   # the model is told what is taken
    assert sw.hunt_stats == {"passes": 2, "found": 1, "dupes": 1}
    assert len(sw.queue.hunt_findings()) == 2


def test_hunting_waits_while_the_worker_has_an_item(tmp_path, monkeypatch):
    sw = _sw(tmp_path)
    assert not sw.queue.busy()
    item = _found(sw, "something")
    assert sw.queue.busy()                              # queued
    sw.queue.advance(item, "verifying", "gate")
    assert sw.queue.busy()                              # in flight
    sw.queue.advance(item, "rejected", "gate")
    assert not sw.queue.busy()                          # terminal: the hunt may go on

    sw.queue.enqueue("red-hunt", "again")
    passes = []
    monkeypatch.setattr(sw, "_hunt_pass", lambda: passes.append(1))
    monkeypatch.setattr(sw.stop, "wait", lambda t: sw.stop.set())
    sw.red_hunt_loop(pause=0)
    assert not passes and sw.doing["hunt"] == "paused (worker busy)"


def test_heartbeat_says_what_hunt_and_worker_are_doing(tmp_path):
    sw = _sw(tmp_path)
    sw.doing["hunt"] = "pass 3 exploring"
    sw.hunt_stats.update(passes=3, found=1, dupes=1)
    line = sw.liveness()
    assert "hunt: pass 3 exploring (3 passes, 1 new, 1 repeats)" in line and "worker: idle" in line


def test_hunt_task_lists_earlier_findings():
    assert red._hunt_task(None) == "Hunt the victim repo."
    assert "- a flaw" in red._hunt_task(["a flaw"]) and "do not report" in red._hunt_task(["a flaw"])
