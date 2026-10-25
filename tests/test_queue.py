import threading

from wreckless.queue import CandidateQueue


def _c(i, src="red-hunt"):
    return {"source": src, "cve": None, "target": "victim_app", "repro_script": f"/x/{i}.py"}


def test_put_forces_prediction_label_and_fields(tmp_path):
    q = CandidateQueue(tmp_path)
    it = q.put({**_c(0), "label": "CONFIRMED_BY_REPRO", "success": True})
    c = it.candidate
    assert c["label"] == "PREDICTION" and it.label == "PREDICTION"
    assert {"id", "source", "cve", "target", "repro_script", "label", "created_at"} <= c.keys()
    assert c["producer_notes"] == {"success": True}
    assert q.list("queued")[0]["run_id"] == it.id


def test_claim_marks_verifying_and_is_fifo(tmp_path):
    q = CandidateQueue(tmp_path)
    a, b = q.put(_c(1)), q.put(_c(2))
    got = q.claim()
    assert got.id == a.id and got.state == "verifying"
    assert q.claim().id == b.id
    assert q.claim() is None


def test_concurrent_put_and_claim_no_double_claim(tmp_path):
    q = CandidateQueue(tmp_path)
    n_per_producer, claimed, lock = 40, [], threading.Lock()
    done = threading.Event()

    def producer(src):
        for i in range(n_per_producer):
            q.put(_c(i, src))

    def consumer():
        while True:
            it = q.claim()
            if it:
                with lock:
                    claimed.append(it.id)
            elif done.is_set():
                return

    prods = [threading.Thread(target=producer, args=(s,)) for s in ("purple", "red-hunt")]
    cons = [threading.Thread(target=consumer) for _ in range(3)]  # >1 consumer to stress it
    for t in prods + cons:
        t.start()
    for t in prods:
        t.join()
    done.set()
    for t in cons:
        t.join()
    assert len(claimed) == 2 * n_per_producer
    assert len(set(claimed)) == len(claimed), "an item was claimed twice"
    assert all(d["state"] == "verifying" for d in q.list())
    assert not list(tmp_path.glob(".*.tmp"))


def test_stats(tmp_path):
    q = CandidateQueue(tmp_path)
    for i in range(3):
        q.put(_c(i))
    a, b = q.claim(), q.claim()
    a.advance("verified", "gate")
    a.advance("patching", "blue")
    a.advance("patched", "blue")
    b.advance("rejected", "gate")
    assert q.stats() == {"candidates": 3, "verified": 1, "rejected": 1, "patched": 1}
