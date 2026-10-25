"""Replay a finished run from what it persisted: state.json history + artifacts.

Stage safety net for when live inference dies. It renders through the same ``ui`` functions
as ``cli.run`` in the same order, with the original timing scaled by ``speed``. It renders
only what was recorded: agent-internal chatter (LLM tool calls) is not persisted, so it is
not shown, and every replay is tagged "REPLAY of <run_id>".
"""
import json
import time
from datetime import datetime
from pathlib import Path

from wreckless import ui


def _load(path: Path, default=None):
    try:
        return json.loads(path.read_text())
    except (OSError, ValueError):
        return default


def _scores(run_dir: Path, entry: dict) -> tuple:
    """Booleans as recorded. PATCH_VALIDATED is only reachable when all three passed (cli.run)."""
    if entry["to"] == "PATCH_FAILED":
        v = entry["payload"].get("validation") or {}
        return v.get("regression"), v.get("functional"), v.get("exploit_blocked")
    logs = _load(run_dir / "validation.json", {}) or {}
    # Cross-check the exploit verdict with the oracle string blue.validate uses; disagree -> FAIL.
    blocked = "ORACLE_MISS" in str(logs.get("exploit", ""))
    return True, True, blocked


def events(run_dir: Path) -> tuple[str, list]:
    """Return (run_id, [(t, render_fn), ...]) mirroring the call order in cli.run."""
    run_dir = Path(run_dir).resolve()
    doc = _load(run_dir / "state.json")
    if not doc or not doc.get("history"):
        raise SystemExit(f"no replayable state.json history in {run_dir}")
    hist, run_id = doc["history"], doc["run_id"]
    meta = _load(run_dir / "ui_meta.json", {}) or {}
    report = _load(run_dir / "vulnerability_report.json", {}) or {}
    cve = hist[0]["payload"].get("cve", run_id.rsplit("-", 2)[0])
    t0 = meta.get("t0")
    if t0 is None:
        try:
            t0 = datetime.strptime(run_id[-15:], "%Y%m%d-%H%M%S").timestamp()
        except ValueError:
            t0 = hist[0]["t"]
    t0 = min(t0, hist[0]["t"])
    backend = report.get("enclave") or "unknown (not recorded)"

    ev = [(t0, lambda: ui.banner(meta.get("banner", f"WreckLess · {cve}"))),
          (t0, lambda: ui.mascot("core")),
          (t0, lambda: ui.say("core", f"run {run_id} · enclave backend: {backend}", ts=t0)),
          (t0, lambda: ui.mascot("purple"))]

    def tr(h):
        return lambda: ui.transition(h["from"], h["to"], h["actor"], ts=h["t"])

    for h in hist:
        t, to, p = h["t"], h["to"], h["payload"]
        if to == "EXPLOITING":
            ev.append((t, lambda: ui.mascot("red")))
        if to in ("PATCH_VALIDATED", "PATCH_FAILED"):
            patch = (run_dir / "fix.patch")
            if patch.exists():
                text = patch.read_text()
                ev.append((t, lambda text=text: ui.diff("blue", text, limit=1500)))
            sc = _scores(run_dir, h)
            ev.append((t, lambda sc=sc, t=t: ui.scoreboard(*sc, ts=t)))
        ev.append((t, tr(h)))
        if to == "EXPLOIT_FAILED":
            ev.append((t, lambda t=t: ui.say(
                "red", "no verified exploit — not reporting (exploit-verified findings only)", ts=t)))
        elif to == "EXPLOIT_VERIFIED":
            script = Path(report.get("repro_script", "repro_exploit.py")).name
            src = report.get("exploit_source", "unknown")
            ev.append((t, lambda: ui.intrusion(script, src)))
        elif to == "PATCHING":
            ev.append((t, lambda: ui.mascot("blue")))
        elif to == "PATCH_VALIDATED":
            ev.append((t, lambda p=p: ui.patch_validated(p.get("branch", "?"), p.get("commit", "?"),
                                                         p.get("source", "?"))))
        elif to == "NOTIFIED":
            ev.append((t, lambda p=p, t=t: ui.notified(p.get("channel", "?"), ts=t)))
            ev.append((t, lambda p=p, t=t: ui.say(
                "core", f"done in {p.get('elapsed_s', 0):.1f}s → {run_dir}", ts=t)))
    return run_id, ev


def replay(run_dir: Path, speed: float = 1.0, max_gap: float = 0.0, sleep=time.sleep) -> int:
    run_id, ev = events(run_dir)
    ui.replay_tag(run_id, speed)
    prev = ev[0][0]
    for t, fn in ev:
        gap = max(0.0, t - prev)
        if max_gap > 0:
            gap = min(gap, max_gap)
        if speed > 0 and gap > 0:
            sleep(gap / speed)
        prev = t
        fn()
    final = _load(Path(run_dir) / "state.json", {}).get("state")
    ui.replay_tag(run_id, speed)
    return 0 if final == "NOTIFIED" else 1
