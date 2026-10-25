"""wreckless run | daemon | status | replay"""
import argparse
import json
import sys
from pathlib import Path

from wreckless import ui
from wreckless.config import RUNS, Settings
from wreckless.events import replay
from wreckless.sandbox import Enclave
from wreckless.swarm import Swarm


def _settings(a) -> Settings:
    s = Settings(mode=a.mode, demo_mode=a.demo_mode, use_llm=not a.no_llm,
                 agentic_exploit=getattr(a, "agentic", False))
    if a.demo_mode:
        s.max_agent_steps = 8
    return s


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="wreckless")
    sub = ap.add_subparsers(dest="cmd", required=True)

    def common(p):
        p.add_argument("--home", type=Path, default=RUNS / "swarm", help="queue + events + item dirs")
        p.add_argument("--mode", choices=["airgap", "live"], default="airgap")
        p.add_argument("--demo-mode", action="store_true", help="N=1, temp 0, cached fallback")
        p.add_argument("--no-llm", action="store_true", help="scripted run with cached exploit/patch")

    r = sub.add_parser("run", help="walk one CVE through the pipeline (demo critical path)")
    common(r)
    r.add_argument("--cve", default="CVE-2024-21513")
    r.add_argument("--agentic", action="store_true", help="exploit via prompt injection into victim LLM")

    d = sub.add_parser("daemon", help="always-on: scheduled Purple + continuous Red-hunt + worker")
    common(d)
    d.add_argument("--purple-interval", type=float, default=600)
    d.add_argument("--no-hunt", action="store_true")
    d.add_argument("--slack-listener", action="store_true",
                   help="serve the card's Approve/Reject buttons (Socket Mode; needs SLACK_APPROVERS)")

    st = sub.add_parser("status", help="queue summary")
    st.add_argument("--home", type=Path, default=RUNS / "swarm")

    rp = sub.add_parser("replay", help="re-render a recorded run from events.jsonl")
    rp.add_argument("events", type=Path)
    rp.add_argument("--speed", type=float, default=1.0)
    rp.add_argument("--item")

    a = ap.parse_args(argv)
    if a.cmd == "replay":
        replay(a.events, a.speed, a.item)
        return 0
    if a.cmd == "status":
        return _status(a.home)

    swarm = Swarm(_settings(a), a.home)
    if a.cmd == "run":
        ui.banner(f"WreckLess · {a.cve} · {a.mode} mode{' · demo' if a.demo_mode else ''}")
        ui.say("core", f"home {swarm.home} · enclave: {Enclave(swarm.home, sys.executable).backend}")
        return 0 if swarm.run_hero(a.cve) == "notified" else 1
    swarm.run_daemon(a.purple_interval, hunt=not a.no_hunt, slack_listener=a.slack_listener)
    return 0


def _status(home: Path) -> int:
    from wreckless.candidates import CandidateQueue
    from wreckless.events import EventLog
    q = CandidateQueue(home / "queue.db", EventLog(home / "events.jsonl"))
    print(json.dumps(q.stats(), indent=2))
    for it in q.all()[-20:]:
        print(f"{it.id:22} {it.label:10} {it.state:13} {it.source:9} {it.title[:60]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
