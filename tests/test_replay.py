import json
import re
from pathlib import Path

from wreckless import replay as rp
from wreckless.cli import run
from wreckless.config import Settings
from wreckless.ui import strip_ansi

CVE = "CVE-2024-21513"
TS = re.compile(r"^\d\d:\d\d:\d\d ")


def _norm(text: str) -> list[str]:
    """De-colour and strip the leading HH:MM:SS so live and replay can be compared."""
    return [TS.sub("", ln.rstrip()) for ln in strip_ansi(text).splitlines()]


def _live_and_replay(tmp_path, monkeypatch, capsys, speed=2.0):
    monkeypatch.delenv("SLACK_BOT_TOKEN", raising=False)
    monkeypatch.delenv("SLACK_WEBHOOK_URL", raising=False)
    doc = run(CVE, Settings(use_llm=False), runs_dir=tmp_path)
    live = _norm(capsys.readouterr().out)
    run_dir = Path(doc["artifacts"]["vulnerability_report"]).parent
    sleeps = []
    rc = rp.replay(run_dir, speed=speed, sleep=sleeps.append)
    replayed = _norm(capsys.readouterr().out)
    return doc, run_dir, live, replayed, rc, sleeps


def test_replay_matches_live_state_lines(tmp_path, monkeypatch, capsys):
    doc, _, live, replayed, rc, _ = _live_and_replay(tmp_path, monkeypatch, capsys)
    assert rc == 0 and doc["state"] == "NOTIFIED"

    def state(lines):
        return [ln for ln in lines if "[NEMOCLAW] state " in ln]

    assert len(state(live)) == 6
    assert state(replayed) == state(live)


def test_replay_is_tagged_and_an_ordered_subsequence_of_live(tmp_path, monkeypatch, capsys):
    _, _, live, replayed, _, _ = _live_and_replay(tmp_path, monkeypatch, capsys)
    assert replayed[0].startswith("[REPLAY of ") and replayed[-1].startswith("[REPLAY of ")
    body = replayed[1:-1]
    it = iter(live)
    missing = [ln for ln in body if not any(ln == x for x in it)]
    assert not missing, missing[:5]
    for beat in ("INTRUSION", "PATCH VALIDATED", "3/3 ALL PASS", "Draft PR Ready"):
        assert any(beat in ln for ln in body), beat


def test_replay_timing_is_original_scaled(tmp_path, monkeypatch, capsys):
    doc, run_dir, _, _, _, sleeps = _live_and_replay(tmp_path, monkeypatch, capsys, speed=2.0)
    t0 = json.loads((run_dir / "ui_meta.json").read_text())["t0"]
    expected = (doc["history"][-1]["t"] - t0) / 2.0
    assert abs(sum(sleeps) - expected) < 1e-6


def test_replay_of_failed_patch_shows_fail_and_no_success_beats(tmp_path, capsys):
    run_dir = tmp_path / "CVE-X-20260101-000000"
    run_dir.mkdir()
    hist = [("IDLE", "INTEL_READY", "purple", {"cve": "CVE-X"}),
            ("INTEL_READY", "EXPLOITING", "red", {}),
            ("EXPLOITING", "EXPLOIT_VERIFIED", "red", {}),
            ("EXPLOIT_VERIFIED", "PATCHING", "blue", {}),
            ("PATCHING", "PATCH_FAILED", "blue",
             {"validation": {"regression": True, "functional": True, "exploit_blocked": False}})]
    (run_dir / "state.json").write_text(json.dumps({
        "run_id": run_dir.name, "state": "PATCH_FAILED", "artifacts": {},
        "history": [{"t": 1.0e9 + i, "from": f, "to": t, "actor": a, "payload": p}
                    for i, (f, t, a, p) in enumerate(hist)]}))
    assert rp.replay(run_dir, speed=0) == 1
    out = strip_ansi(capsys.readouterr().out)
    assert "FAIL" in out and "2/3" in out
    assert "PATCH VALIDATED" not in out and "Draft PR Ready" not in out
