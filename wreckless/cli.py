"""wreckless run | daemon | status | replay | metrics | intel"""
import argparse
import json
import sys
from pathlib import Path

from wreckless import ui
from wreckless import targets
from wreckless.config import RUNS, Settings
from wreckless.events import replay
from wreckless.sandbox import openshell_available
from wreckless.swarm import Swarm


def _settings(a) -> Settings:
    s = Settings(mode=a.mode, demo_mode=a.demo_mode, use_llm=not a.no_llm,
                 agentic_exploit=getattr(a, "agentic", False), target=a.target)
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
        p.add_argument("--target", choices=targets.names(), default="victim_app",
                       help="victim_app (minimal repro) | langchain (real upstream @ vulnerable commit)")

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

    m = sub.add_parser("metrics", help="GB10 memory + per-port tokens/sec from vLLM /metrics")
    m.add_argument("--watch", type=float, metavar="SECONDS", help="refresh every N seconds")
    m.add_argument("--json", action="store_true", help="one JSON line per sample (for dashboards)")

    it = sub.add_parser("intel", help="Purple's advisory DB: sync feeds, list, search, show")
    it.add_argument("action", choices=["sync", "list", "search", "show"])
    it.add_argument("query", nargs="?", help="search text, or the CVE/GHSA id for show")
    it.add_argument("--feeds", default="osv,github,kev", help="comma list for sync")
    it.add_argument("--target", choices=targets.names(), default="victim_app", help="whose inventory to sync")

    a = ap.parse_args(argv)
    if a.cmd == "intel":
        return _intel(a.action, a.query, tuple(a.feeds.split(",")), a.target)
    if a.cmd == "metrics":
        return _metrics(a.watch, a.json)
    if a.cmd == "replay":
        replay(a.events, a.speed, a.item)
        return 0
    if a.cmd == "status":
        return _status(a.home)

    swarm = Swarm(_settings(a), a.home)
    if a.cmd == "run":
        ui.banner(f"WreckLess · {a.cve} · {a.mode} mode{' · demo' if a.demo_mode else ''}")
        backend = "openshell" if openshell_available() else "userland-guard"
        ui.say("core", f"home {swarm.home} · target: {swarm.target.name} · enclave: {backend}")
        return 0 if swarm.run_hero(a.cve) == "notified" else 1
    swarm.run_daemon(a.purple_interval, hunt=not a.no_hunt, slack_listener=a.slack_listener)
    return 0


def _intel(action: str, query: str | None, which: tuple, target: str) -> int:
    from wreckless import feeds
    from wreckless.config import INTEL_DB
    from wreckless.kb import IntelDB
    db = IntelDB(INTEL_DB)
    if action == "sync":   # the one command that needs the network: run it before an airgapped demo
        inv = feeds.load_inventory(targets.load(target).inventory)
        rep = feeds.sync(db, inv, Settings(mode="live"), which)
        ui.say("purple", "feeds: " + rep.line())
        for k in rep.new:
            ui.detail("purple", f"new  {k}")
        action = "list"
    if action == "show":
        adv = db.get(query or "")
        print(json.dumps(adv, indent=2) if adv else f"{query}: not in {INTEL_DB}")
        return 0 if adv else 1
    rows = db.search(query) if action == "search" else db.relevant()
    for r in rows:
        flag = "KEV " if r["kev"] else "    "
        print(f"{flag}{r['key']:18} {(r['severity'] or '?'):9} {(r['vulnerable_versions'] or '?'):12} "
              f"{(r['summary'] or '')[:58]}")
    print(f"{len(rows)} shown · {db.count()} in {INTEL_DB}")
    return 0


def _metrics(watch: float | None, as_json: bool) -> int:
    import dataclasses
    import time
    from wreckless.metrics import Monitor
    mon = Monitor()
    if watch and not as_json:
        mon.sample()          # prime the counters so the first panel already has tokens/sec
        time.sleep(min(watch, 2))
    while True:
        snap = mon.sample()
        ports = [dataclasses.asdict(p) for p in snap.ports]
        if as_json:
            print(json.dumps({"t": snap.t, "mem_total_gb": snap.mem_total_gb,
                              "mem_used_gb": snap.mem_used_gb, "ports": ports}), flush=True)
        else:
            if watch and ui.color_enabled():
                print("\033[H\033[2J", end="")
            ui.gb10_panel(snap.mem_total_gb, snap.mem_used_gb, ports, _record=False)
        if not watch:
            return 0 if any(p.up for p in snap.ports) else 1
        time.sleep(watch)


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
