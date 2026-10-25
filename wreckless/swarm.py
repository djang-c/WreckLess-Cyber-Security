"""Always-on swarm: two producers (scheduled Purple, continuous Red-hunt) -> one queue ->
one verify gate -> Blue -> validation -> notify. Each item walks its own lifecycle."""
import json
import sys
import threading
import time
from pathlib import Path

from wreckless import gate, ui
from wreckless.agents import blue, purple, red
from wreckless.candidates import CandidateQueue
from wreckless.config import BENCHMARKS, TARGETS, Settings
from wreckless.events import EventLog
from wreckless.gitops import commit_all, init_victim, worktree
from wreckless.notify import Notifier
from wreckless.sandbox import Enclave


class Swarm:
    def __init__(self, s: Settings, home: Path):
        self.s, self.home = s, home.resolve()
        self.home.mkdir(parents=True, exist_ok=True)
        self.events = EventLog(self.home / "events.jsonl").attach()
        self.queue = CandidateQueue(self.home / "queue.db", self.events)
        self.hero = threading.Event()      # set while the demo's critical path runs
        self.stop = threading.Event()
        self.started = time.time()

    # ---------- producers ----------
    def submit_cve(self, cve: str) -> str:
        self.events.item.id = None
        intel = purple.ingest(cve, self.s)
        item_id = self.queue.enqueue("purple", intel["summary"], cve=cve, payload={"intel": intel})
        ui.say("purple", f"{item_id} queued as \033[1mPREDICTION\033[0m")
        return item_id

    def purple_loop(self, interval: float) -> None:
        """Scheduled: pick up any cached/live advisory not yet in the queue."""
        while not self.stop.is_set():
            for adv in sorted(BENCHMARKS.glob("*/advisory.json")):
                cve = adv.parent.name
                if not self.queue.has_cve(cve):
                    self.submit_cve(cve)
            self.stop.wait(interval)

    def red_hunt_loop(self, pause: float = 5.0) -> None:
        """Continuous: propose candidate flaws. Yields to the hero item (bandwidth on one GPU)."""
        n = 0
        while not self.stop.is_set():
            if self.hero.is_set():
                self.stop.wait(pause)
                continue
            n += 1
            d = self.home / "hunts" / f"pass-{n:04d}"
            d.mkdir(parents=True, exist_ok=True)
            wt = d / "victim"
            init_victim(TARGETS / "victim_app", wt)
            prop = red.hunt(wt, Enclave(d, sys.executable), d, self.s)
            if prop:
                item_id = self.queue.enqueue("red-hunt", prop.title, payload={
                    "hunt_dir": str(d), "script": str(prop.script), "file": prop.file,
                    "hypothesis": prop.hypothesis})
                ui.say("red", f"hunt pass {n}: candidate {item_id} \033[1mPREDICTION\033[0m — {prop.title}")
            if self.s.use_llm is False:
                return  # nothing to hunt with
            self.stop.wait(pause)

    # ---------- the per-item lifecycle ----------
    def process(self, item_id: str) -> str:
        self.events.item.id = item_id
        item = self.queue.get(item_id)
        d = self.home / "items" / item_id.replace("#", "-")
        d.mkdir(parents=True, exist_ok=True)
        enclave = Enclave(d, sys.executable)
        src = d / "victim-src"
        commit = init_victim(TARGETS / "victim_app", src)
        t0 = time.time()

        # verifying: Red proposes (if needed), the gate disposes
        self.queue.advance(item_id, "verifying", "gate", commit=commit)
        red_wt = worktree(src, d / "wt-red", f"red/{item_id.replace('#', '-')}")
        if item.source == "purple":
            prop = red.attack(item.payload["intel"], red_wt, enclave, d, self.s)
            script, source = (prop.script, prop.source) if prop else (None, None)
        else:
            script, source = Path(item.payload["script"]), "llm"
        args = ["--agentic"] if self.s.agentic_exploit else []
        verdict = gate.verify(script, red_wt, enclave, args, red._victim_env(self.s)) if script else None
        if not verdict or not verdict.verified:
            reason = verdict.reason if verdict else "no exploit proposed"
            self.queue.advance(item_id, "rejected", "gate", reason=reason)
            ui.say("gate", f"{item_id} REJECTED — {reason}")
            return "rejected"

        report = {
            "id": item_id, "cve": item.cve, "commit": commit, "source": item.source,
            "affected_file": item.payload.get("intel", {}).get("affected_file") or item.payload.get("file"),
            "repro_script": str(script), "exploit_source": source,
            "oracle": {"verdict": verdict.reason, "via": verdict.result.via_victim,
                       "backend": verdict.result.backend},
            "attack_trace": verdict.result.output[-2000:], "agentic": self.s.agentic_exploit,
        }
        report_path = d / "vulnerability_report.json"
        report_path.write_text(json.dumps(report, indent=2))
        self.queue.advance(item_id, "verified", "gate", report=str(report_path))
        ui.say("red", f"\033[41;97m EXPLOIT VERIFIED \033[0m {item_id} · {script.name} ({source})")
        slack = Notifier()
        slack.send("red", f"🚨 Intrusion reproduced: {item_id}",
                   f"Commit `{commit[:10]}` exploitable · {verdict.reason}\n"
                   f"```{verdict.result.output[-600:]}```")

        # patching: Blue in its own worktree; validation is not Blue's call
        self.queue.advance(item_id, "patching", "blue")
        branch = f"wreckless/fix-{item_id.replace('#', '-')}"
        blue_wt = worktree(src, d / "wt-blue", branch)
        diff, patch_source = blue.defend(report, blue_wt, enclave, d, self.s)
        (d / "fix.patch").write_text(diff)
        ui.detail("blue", diff or "(no diff)", limit=1500)
        v = blue.validate(blue_wt, enclave, report)
        ui.say("blue", v.summary())
        (d / "validation.json").write_text(json.dumps(v.logs, indent=2))
        if not diff or not v.ok:
            self.queue.advance(item_id, "patch_failed", "blue", summary=v.summary())
            slack.send("blue", f"Patch failed validation: {item_id}", "Needs a human.")
            return "patch_failed"

        fix_commit = commit_all(blue_wt, f"fix({item_id}): {item.title[:60]}\n\n"
                                         f"Patch source: {patch_source}. {v.summary()}")
        self.queue.advance(item_id, "patched", "blue", branch=branch, commit=fix_commit, source=patch_source)
        elapsed = time.time() - t0
        via = slack.send("blue", f"✅ Draft PR Ready: {item_id}",
                         f"Branch `{branch}` @ `{fix_commit[:10]}` · patch: {patch_source}\n"
                         f"{v.summary()} · {elapsed:.0f}s\n```{diff[:1500]}```")
        self.queue.advance(item_id, "notified", "core", channel=via, elapsed_s=round(elapsed, 1))
        ui.say("core", f"{item_id} done in {elapsed:.1f}s → {d}")
        return "notified"

    # ---------- runtime ----------
    def run_hero(self, cve: str) -> str:
        """The demo critical path: one item, background hunting paused."""
        self.hero.set()
        try:
            return self.process(self.submit_cve(cve))
        finally:
            self.hero.clear()

    def worker_loop(self) -> None:
        while not self.stop.is_set():
            item_id = self.queue.next_queued()
            if item_id:
                self.process(item_id)
            else:
                self.stop.wait(2)

    def run_daemon(self, purple_interval: float, hunt: bool) -> None:
        ui.banner(f"WreckLess always-on swarm · {self.s.mode} mode · home {self.home}")
        threads = [threading.Thread(target=self.purple_loop, args=(purple_interval,), daemon=True),
                   threading.Thread(target=self.worker_loop, daemon=True)]
        if hunt:
            threads.append(threading.Thread(target=self.red_hunt_loop, daemon=True))
        for t in threads:
            t.start()
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            self.stop.set()
            ui.say("core", f"stopping · {self.queue.stats()}")
