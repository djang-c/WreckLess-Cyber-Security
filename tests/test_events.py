"""events.py: ordering under concurrency, and a replay that survives a damaged log."""
import json
import threading

from wreckless import events, ui


def test_concurrent_emits_are_written_in_timestamp_order(tmp_path):
    log = events.EventLog(tmp_path / "events.jsonl")

    def burst(n):
        for i in range(200):
            log.emit("core", "say", text=f"{n}-{i}")

    threads = [threading.Thread(target=burst, args=(n,)) for n in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    recs = [json.loads(line) for line in log.path.read_text().splitlines()]
    assert len(recs) == 1600
    ts = [r["t"] for r in recs]
    assert ts == sorted(ts)


def test_replay_never_sleeps_negative(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("NO_COLOR", "1")
    p = tmp_path / "events.jsonl"
    p.write_text("\n".join(json.dumps({"t": t, "actor": "core", "kind": "say", "item": None,
                                       "text": f"at {t}"}) for t in (10.0, 9.5, 11.0)) + "\n")
    sleeps = []
    monkeypatch.setattr(events.time, "sleep", lambda s: sleeps.append(s))
    events.replay(p, speed=1.0)
    assert sleeps and all(s >= 0 for s in sleeps)
    out = capsys.readouterr().out
    assert "at 9.5" in out and "at 11.0" in out


def test_replay_skips_truncated_and_garbled_lines(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("NO_COLOR", "1")
    monkeypatch.setattr(events.time, "sleep", lambda s: None)
    good = lambda t, text: json.dumps({"t": t, "actor": "core", "kind": "say", "item": None, "text": text})
    p = tmp_path / "events.jsonl"
    p.write_text(good(1, "first") + "\n" + "[1, 2]\n" + good(2, "second") + "\n"
                 + '{"t": 3, "actor": "core", "kind": "transition"}\n'  # valid JSON, missing fields
                 + good(4, "third")[:25])                              # writer killed mid-line
    events.replay(p, speed=0)
    cap = capsys.readouterr()
    assert "first" in cap.out and "second" in cap.out
    assert "skipping unreadable line 2" in cap.err and "skipping unreadable line 5" in cap.err
    assert "skipping 'transition'" in cap.err


def test_gb10_panel_is_not_replayable():
    # `wreckless metrics` never records the panel, so replay has nothing to render for it
    assert "gb10_panel" not in ui.REPLAYABLE
