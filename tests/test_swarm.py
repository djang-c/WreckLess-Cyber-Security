import threading
import time

import pytest

from wreckless.config import Settings
from wreckless.swarm import Swarm

CVE = "CVE-2024-21513"


@pytest.fixture(autouse=True)
def _no_slack(monkeypatch):
    for k in ("SLACK_BOT_TOKEN", "SLACK_WEBHOOK_URL"):
        monkeypatch.delenv(k, raising=False)


class FakeNotifier:
    def send(self, role, title, body):
        return "fake"


def _wait(pred, timeout=5.0):
    end = time.time() + timeout
    while time.time() < end:
        if pred():
            return True
        time.sleep(0.02)
    return False


def test_run_one_hero_reaches_notified(tmp_path):
    sw = Swarm(Settings(use_llm=False), root=tmp_path, notifier_factory=FakeNotifier)
    doc = sw.run_one(CVE)
    assert doc["state"] == "notified"
    assert [h["to"] for h in doc["history"]] == ["verifying", "verified", "patching", "patched",
                                                  "notified"]
    assert doc["label"] == "CONFIRMED_BY_REPRO"
    assert doc["history"][-1]["payload"]["ok"] is True
    assert "vulnerability_report" in doc["artifacts"]
    assert sw.queue.stats() == {"candidates": 1, "verified": 1, "rejected": 0, "patched": 1}
    assert not sw.throttled


def test_throttle_pauses_hunter(tmp_path):
    calls = []
    sw = Swarm(Settings(use_llm=False), root=tmp_path, hunter=lambda: calls.append(1) or ())
    t = threading.Thread(target=sw.red_hunt_loop, args=(0.01,))
    t.start()
    try:
        assert _wait(lambda: len(calls) >= 3)
        with sw.throttle():
            time.sleep(0.1)  # let any in-flight call finish
            n = len(calls)
            time.sleep(0.4)
            assert len(calls) == n, "hunter ran while throttled"
        assert _wait(lambda: len(calls) > n), "hunter did not resume"
    finally:
        sw.stop.set()
        t.join(2)
    assert not t.is_alive()


def test_loops_end_to_end_and_stop_cleanly(tmp_path):
    """Purple enqueues the hero, Red-hunt proposes a decoy; only the hero is verified/patched."""
    decoy = tmp_path / "decoy.py"
    decoy.write_text("print('ORACLE_HIT')\n")
    proposed = []

    def hunter():
        if not proposed:
            proposed.append(1)
            return [{"cve": None, "target": "victim_app", "repro_script": str(decoy),
                     "source": "purple", "label": "CONFIRMED_BY_REPRO"}]
        return ()

    sw = Swarm(Settings(use_llm=False), root=tmp_path / "r", hunter=hunter,
               notifier_factory=FakeNotifier)
    sw.start(purple_interval_s=60, hunt_idle_s=0.01, poll_s=0.02)
    try:
        assert _wait(lambda: sw.queue.stats()["candidates"] == 2
                     and all(d["state"] in ("rejected", "notified") for d in sw.queue.list()), 30)
    finally:
        assert sw.shutdown(5)
    docs = {d["candidate"]["source"]: d for d in sw.queue.list()}
    assert docs["red-hunt"]["state"] == "rejected"  # source forced to red-hunt, label ignored
    assert docs["red-hunt"]["label"] == "PREDICTION"
    assert docs["purple"]["state"] == "notified"
    assert sw.queue.stats() == {"candidates": 2, "verified": 1, "rejected": 1, "patched": 1}
