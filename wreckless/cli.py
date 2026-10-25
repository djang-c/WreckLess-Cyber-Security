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


def run(cve: str, s: Settings, runs_dir: Path = RUNS) -> dict:
    t0 = time.time()
    run_id = f"{cve}-{time.strftime('%Y%m%d-%H%M%S')}"
    run_dir = (runs_dir / run_id).resolve()
    run_dir.mkdir(parents=True)
    sm, slack = StateMachine(run_dir, run_id), Notifier()
    enclave = Enclave(run_dir, sys.executable)
    ui.banner(f"WreckLess · {cve} · {s.mode} mode{' · demo' if s.demo_mode else ''}")
    ui.say("core", f"run {run_id} · enclave backend: {enclave.backend}")

    # Purple: intel
    intel = purple.ingest(cve, s)
    (run_dir / "intel.json").write_text(json.dumps(intel, indent=2))
    sm.advance("INTEL_READY", "purple", {"cve": cve})
    slack.send("purple", f"Advisory ingested: {cve}", f"*{intel['severity'].upper()}* — {intel['summary']}")

    # Red: exploit in its own worktree
    src = run_dir / "victim-src"
    commit = init_victim(TARGETS / "victim_app", src)
    red_wt = worktree(src, run_dir / "wt-red", f"red/{cve}")
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
    ui.say("red", f"\033[41;97m EXPLOIT VERIFIED \033[0m {outcome.script.name} ({outcome.source})")
    slack.send("red", f"🚨 Intrusion reproduced: {cve}",
               f"Commit `{commit[:10]}` exploitable.\n```{outcome.output[-600:]}```")

    # Blue: patch in a separate worktree, then orchestrator-run held-out validation
    sm.advance("PATCHING", "blue", {"report": str(report_path)})
    blue_wt = worktree(src, run_dir / "wt-blue", f"wreckless/fix-{cve}")
    diff, source = blue.defend(report, blue_wt, enclave, run_dir, s)
    (run_dir / "fix.patch").write_text(diff)
    ui.detail("blue", diff, limit=1500)
    v = blue.validate(cve, blue_wt, enclave, report)
    ui.say("blue", f"held-out regression: {'PASS' if v.regression else 'FAIL'} · "
                   f"functional: {'PASS' if v.functional else 'FAIL'} · "
                   f"exploit blocked: {'YES' if v.exploit_blocked else 'NO'}")
    (run_dir / "validation.json").write_text(json.dumps(v.logs, indent=2))
    if not v.ok:
        sm.advance("PATCH_FAILED", "blue", {"validation": v.__dict__ | {"logs": None}})
        slack.send("blue", f"Patch failed validation: {cve}", "Needs a human.")
        return sm.doc

    fix_commit = commit_all(blue_wt, f"fix({cve}): stop evaluating database values as code\n\n"
                                     f"Patch source: {source}. Validated by WreckLess.")
    sm.advance("PATCH_VALIDATED", "blue", {"branch": f"wreckless/fix-{cve}", "commit": fix_commit,
                                           "source": source})
    elapsed = time.time() - t0
    via = slack.send("blue", f"✅ Draft PR Ready: {cve}",
                     f"Branch `wreckless/fix-{cve}` @ `{fix_commit[:10]}` · patch: {source}\n"
                     f"Held-out regression ✅ · functional ✅ · exploit blocked ✅ · {elapsed:.0f}s\n"
                     f"```{diff[:1500]}```")
    sm.advance("NOTIFIED", "core", {"channel": via, "elapsed_s": round(elapsed, 1)})
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
    a = ap.parse_args(argv)
    s = Settings(mode=a.mode, demo_mode=a.demo_mode, use_llm=not a.no_llm, agentic_exploit=a.agentic)
    if a.demo_mode:
        s.max_agent_steps = 8
    doc = run(a.cve, s)
    return 0 if doc["state"] == "NOTIFIED" else 1


if __name__ == "__main__":
    sys.exit(main())
