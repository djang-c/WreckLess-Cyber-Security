"""NemoClaw-style orchestrator: drives Purple -> Red -> Blue through the JSON state machine."""
import argparse
import json
import sys
import time
from pathlib import Path

from wreckless import ui
from wreckless.agents import blue, purple, red
from wreckless.config import RUNS, TARGETS, Settings
from wreckless.gitops import commit_all, git, init_victim, worktree
from wreckless.notify import Notifier
from wreckless.sandbox import Enclave
from wreckless.state import StateMachine


class _TracedStateMachine(StateMachine):
    """Display-only hook: print each persisted transition (replay renders the same lines)."""
    def advance(self, new: str, actor: str, payload: dict | None = None) -> None:
        super().advance(new, actor, payload)
        h = self.doc["history"][-1]
        ui.transition(h["from"], h["to"], h["actor"])


def run(cve: str, s: Settings, runs_dir: Path = RUNS) -> dict:
    t0 = time.time()
    run_id = f"{cve}-{time.strftime('%Y%m%d-%H%M%S')}"
    run_dir = (runs_dir / run_id).resolve()
    run_dir.mkdir(parents=True)
    sm, slack = _TracedStateMachine(run_dir, run_id), Notifier()
    enclave = Enclave(run_dir, sys.executable)
    slack.bind(run_id=run_id, enclave=enclave.backend)
    title = f"WreckLess · {cve} · {s.mode} mode{' · demo' if s.demo_mode else ''}"
    (run_dir / "ui_meta.json").write_text(json.dumps({"banner": title, "t0": t0}))
    ui.banner(title)
    ui.mascot("core")
    ui.say("core", f"run {run_id} · enclave backend: {enclave.backend}")

    # Purple: intel
    ui.mascot("purple")
    intel = purple.ingest(cve, s)
    (run_dir / "intel.json").write_text(json.dumps(intel, indent=2))
    sm.advance("INTEL_READY", "purple", {"cve": cve})
    slack.send("purple", f"Advisory ingested: {cve}", f"*{intel['severity'].upper()}* — {intel['summary']}")

    # Red: exploit in its own worktree
    src = run_dir / "victim-src"
    commit = init_victim(TARGETS / "victim_app", src)
    red_wt = worktree(src, run_dir / "wt-red", f"red/{cve}")
    ui.mascot("red")
    sm.advance("EXPLOITING", "red", {"commit": commit})
    outcome = red.attack(intel, red_wt, enclave, run_dir, s)
    if not outcome:
        sm.advance("EXPLOIT_FAILED", "red")
        ui.say("red", "no verified exploit — not reporting (exploit-verified findings only)")
        return sm.doc

    report = {
        "cve": cve, "commit": commit, "affected_file": intel["affected_file"],
        "repro_script": str(outcome.script), "exploit_source": outcome.source,
        "attack_trace": outcome.output[-2000:], "oracle": "nonce file written by eval'd DB value",
        "agentic": s.agentic_exploit, "enclave": enclave.backend,
    }
    report_path = run_dir / "vulnerability_report.json"
    report_path.write_text(json.dumps(report, indent=2))
    sm.artifact("vulnerability_report", report_path)
    sm.advance("EXPLOIT_VERIFIED", "red", {"report": str(report_path)})
    ui.intrusion(outcome.script.name, outcome.source)
    slack.send("red", f"🚨 Intrusion reproduced: {cve}",
               f"Commit `{commit[:10]}` exploitable.\n```{outcome.output[-600:]}```")

    # Blue: patch in a separate worktree, then orchestrator-run held-out validation
    sm.advance("PATCHING", "blue", {"report": str(report_path)})
    ui.mascot("blue")
    blue_wt = worktree(src, run_dir / "wt-blue", f"wreckless/fix-{cve}")
    diff, source = blue.defend(report, blue_wt, enclave, run_dir, s)
    (run_dir / "fix.patch").write_text(diff)
    ui.diff("blue", diff, limit=1500)
    v = blue.validate(cve, blue_wt, enclave, report)
    ui.scoreboard(v.regression, v.functional, v.exploit_blocked)
    (run_dir / "validation.json").write_text(json.dumps(v.logs, indent=2))
    if not v.ok:
        sm.advance("PATCH_FAILED", "blue", {"validation": v.__dict__ | {"logs": None}})
        slack.send("blue", f"Patch failed validation: {cve}", "Needs a human.")
        return sm.doc

    fix_commit = commit_all(blue_wt, f"fix({cve}): stop evaluating database values as code\n\n"
                                     f"Patch source: {source}. Validated by WreckLess.")
    sm.advance("PATCH_VALIDATED", "blue", {"branch": f"wreckless/fix-{cve}", "commit": fix_commit,
                                           "source": source})
    ui.patch_validated(f"wreckless/fix-{cve}", fix_commit, source)
    elapsed = time.time() - t0
    via = slack.send("blue", f"✅ Draft PR Ready: {cve}",
                     f"Branch `wreckless/fix-{cve}` @ `{fix_commit[:10]}` · patch: {source}\n"
                     f"Held-out regression ✅ · functional ✅ · exploit blocked ✅ · {elapsed:.0f}s\n"
                     f"```{diff[:1500]}```")
    sm.advance("NOTIFIED", "core", {"channel": via, "elapsed_s": round(elapsed, 1)})
    ui.notified(via)
    ui.say("core", f"done in {elapsed:.1f}s → {run_dir}")
    return sm.doc


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="wreckless")
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run", help="run the Purple->Red->Blue pipeline on a CVE")
    r.add_argument("--cve", default="CVE-2024-21513")
    r.add_argument("--mode", choices=["airgap", "live"], default="airgap")
    r.add_argument("--demo-mode", action="store_true", help="N=1, temp 0, cached fallback")
    r.add_argument("--no-llm", action="store_true", help="scripted run with cached exploit/patch")
    r.add_argument("--agentic", action="store_true", help="exploit via prompt injection into victim LLM")
    r.add_argument("--swarm", action="store_true",
                   help="walk the CVE through the queue + verify gate (per-item lifecycle)")
    rp = sub.add_parser("replay", help="replay a finished run from its state.json (stage safety net)")
    rp.add_argument("run_dir", type=Path)
    rp.add_argument("--speed", type=float, default=1.0, help="time scale; 2 = twice as fast, 0 = instant")
    rp.add_argument("--max-gap", type=float, default=0.0, help="cap any single pause (s); 0 = no cap")
    sw = sub.add_parser("swarm", help="always-on: scheduled Purple + continuous Red-hunt + gate -> Blue")
    sw.add_argument("--purple-interval", type=float, default=600, help="seconds between Purple ticks")
    sw.add_argument("--no-llm", action="store_true")
    sw.add_argument("--slack-listener", action="store_true", help="also listen for Approve/Reject")
    sub.add_parser("seed", help="seed the liveness backlog through the real gate", add_help=False)
    sub.add_parser("queue", help="print candidate queue stats (liveness panel)")
    a, rest = ap.parse_known_args(argv)
    if a.cmd == "replay":
        from wreckless.replay import replay
        return replay(a.run_dir, speed=a.speed, max_gap=a.max_gap)
    if a.cmd == "seed":
        import runpy
        seed = runpy.run_path(str(Path(__file__).resolve().parent.parent / "scripts" / "seed_backlog.py"))
        return seed["main"](rest)
    if rest:
        ap.error(f"unrecognized arguments: {' '.join(rest)}")
    if a.cmd == "queue":
        from wreckless.queue import CandidateQueue
        st = CandidateQueue().stats()
        ui.say("core", f"queue · {st['candidates']} candidates · {st['verified']} verified · "
                       f"{st['rejected']} rejected · {st['patched']} patched")
        return 0
    if a.cmd == "swarm":
        return _swarm(Settings(use_llm=not a.no_llm), a.purple_interval, a.slack_listener)
    s = Settings(mode=a.mode, demo_mode=a.demo_mode, use_llm=not a.no_llm, agentic_exploit=a.agentic)
    if a.demo_mode:
        s.max_agent_steps = 8
    if a.swarm:
        from wreckless.swarm import Swarm
        doc = Swarm(s).run_one(a.cve)
        return 0 if doc["state"] == "notified" and doc["history"][-1]["payload"].get("ok") else 1
    doc = run(a.cve, s)
    return 0 if doc["state"] == "NOTIFIED" else 1


def _swarm(s: Settings, purple_interval: float, slack_listener: bool) -> int:
    from wreckless.swarm import Swarm
    if slack_listener:
        from wreckless.slack_socket import start_listener
        start_listener()
    sw = Swarm(s)
    sw.start(purple_interval_s=purple_interval)
    ui.say("core", "swarm up · Purple scheduled · Red-hunt continuous · Ctrl-C to stop")
    try:
        while True:
            time.sleep(30)
            st = sw.queue.stats()
            ui.say("core", f"liveness · {st['candidates']} candidates · {st['verified']} verified · "
                           f"{st['rejected']} rejected · {st['patched']} patched")
    except KeyboardInterrupt:
        ui.say("core", "stopping swarm")
    return 0 if sw.shutdown() else 1


if __name__ == "__main__":
    sys.exit(main())
