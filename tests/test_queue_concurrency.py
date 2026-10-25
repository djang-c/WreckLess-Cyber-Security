"""Regression: `wreckless daemon` and `wreckless run` share one home from two processes.

Observed 2026-10-25 (1 of 5 hero runs): the daemon worker raced the hero for its item,
crashed in init_victim, and its crash handler failed the hero's in-flight item."""
import os
import threading

from wreckless.candidates import CandidateQueue
from wreckless.config import Settings
from wreckless.events import EventLog
from wreckless.swarm import Swarm


def _two_queues(tmp_path):
    ev = EventLog(tmp_path / "e.jsonl")
    return CandidateQueue(tmp_path / "q.db", ev), CandidateQueue(tmp_path / "q.db", ev)


def test_claim_is_atomic_across_connections(tmp_path):
    q1, q2 = _two_queues(tmp_path)
    item = q1.enqueue("purple", "x", cve="CVE-X")
    stale = q1.get(item)                      # q1 read "queued" ...
    assert q2.try_advance(item, "verifying", "gate")   # ... then another process claimed it
    q1.get = lambda _id: stale                # q1 acts on its stale read
    assert q1.try_advance(item, "verifying", "gate") is None
    q1.get = CandidateQueue.get.__get__(q1)
    assert [h["actor"] for h in q1.get(item).history] == ["gate"]   # exactly one claim


def test_ids_unique_across_connections(tmp_path):
    q1, q2 = _two_queues(tmp_path)
    ids, errors = [], []

    def produce(q):
        for i in range(25):
            try:
                ids.append(q.enqueue("red-hunt", f"t{i}"))
            except Exception as e:  # noqa: BLE001 - the regression is any error here
                errors.append(repr(e))
    ts = [threading.Thread(target=produce, args=(q,)) for q in (q1, q2)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    assert errors == [] and len(set(ids)) == 50


def test_shared_connection_threads_claim_each_item_once(tmp_path):
    q = CandidateQueue(tmp_path / "q.db", EventLog(tmp_path / "e.jsonl"))
    for i in range(40):
        q.enqueue("purple", f"t{i}", cve=f"CVE-X-{i}")
    claimed, errors, bar = [], [], threading.Barrier(3)

    def worker():
        bar.wait()
        while (i := q.next_queued()) is not None:
            try:
                if q.try_advance(i, "verifying", "gate"):
                    claimed.append(i)
            except Exception as e:  # noqa: BLE001
                errors.append(repr(e))
    ts = [threading.Thread(target=worker) for _ in range(3)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    assert errors == [] and len(claimed) == len(set(claimed)) == 40


def test_worker_never_touches_an_item_it_did_not_claim(tmp_path):
    s = Swarm(Settings(use_llm=False), tmp_path)
    item = s.queue.enqueue("purple", "x", cve="CVE-2024-21513")
    s.queue.advance(item, "verifying", "gate")     # the hero (another process) owns it
    assert s.process(item) == "skipped"
    assert s.queue.get(item).state == "verifying"
    assert not (tmp_path / "items" / item.replace("#", "-")).exists()


def test_hero_in_another_process_pauses_this_daemon(tmp_path):
    daemon, hero = Swarm(Settings(use_llm=False), tmp_path), Swarm(Settings(use_llm=False), tmp_path)
    assert not daemon.hero_active()
    with hero.hero_lock():
        assert daemon.hero_active() and hero.hero_active()
    assert not daemon.hero_active()
    (tmp_path / "hero.lock").write_text("999999999")   # crashed hero: dead pid must not pause forever
    assert not daemon.hero_active()
    (tmp_path / "hero.lock").write_text(str(os.getpid()))
    assert daemon.hero_active()


def test_daemon_start_does_not_fail_a_running_hero_item(tmp_path, monkeypatch):
    hero, daemon = Swarm(Settings(use_llm=False), tmp_path), Swarm(Settings(use_llm=False), tmp_path)
    item = hero.queue.enqueue("purple", "x", cve="CVE-2024-21513")
    hero.queue.advance(item, "verifying", "gate")
    monkeypatch.setattr(daemon.stop, "wait", lambda *_: True)   # start, then exit at once
    with hero.hero_lock():
        daemon.run_daemon(3600, hunt=False)
    assert daemon.queue.get(item).state == "verifying"
