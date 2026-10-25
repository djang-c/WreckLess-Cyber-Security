"""Always-on swarm: two producers (scheduled Purple, continuous Red-hunt) -> one queue ->
one verify gate -> Blue -> validation -> notify. Each item walks its own lifecycle."""
import json
import os
import threading
import time
from contextlib import contextmanager
from pathlib import Path

from wreckless import gate, ui
from wreckless import feeds
from wreckless.agents import blue, purple, red
from wreckless.candidates import CandidateQueue
from wreckless import targets
from wreckless.config import BENCHMARKS, INTEL_DB, Settings
from wreckless.events import EventLog
from wreckless.kb import IntelDB
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
        self.hero_file = self.home / "hero.lock"   # same signal for a daemon in another process
        self.stop = threading.Event()
        self.started = time.time()
        self.intel = IntelDB(INTEL_DB)
        self.target = targets.load(s.target)
        self.target.ensure()

    def hero_active(self) -> bool:
        """A hero run is in flight here or in another process sharing this home."""
        if self.hero.is_set():
            return True
        try:
            os.kill(int(self.hero_file.read_text()), 0)
        except PermissionError:         # alive, owned by another user
            return True
        except (OSError, ValueError):   # no file, junk, or a hero that died without cleanup
            return False
        return True

    @contextmanager
    def hero_lock(self):
        self.hero.set()
        self.hero_file.write_text(str(os.getpid()))
        try:
            yield
        finally:
            self.hero_file.unlink(missing_ok=True)
            self.hero.clear()

    def _enclave(self, d: Path) -> Enclave:
        return Enclave(d, self.target.python, image=self.target.image)

    # ---------- producers ----------
    def submit_cve(self, cve: str) -> str:
        self.events.item.id = None
        ui.mascot("purple")
        intel = purple.ingest(cve, self.s, self.intel, self.target.source)
        item_id = self.queue.enqueue("purple", intel["summary"], cve=cve, payload={"intel": intel})
        ui.say("purple", f"{item_id} queued as \033[1mPREDICTION\033[0m")
        return item_id

    def purple_loop(self, interval: float) -> None:
        """Scheduled: poll the feeds (live mode), then queue every benchmark bundle and every
        inventory-matched advisory not yet in the queue (KEV first, then severity)."""
        inv = feeds.load_inventory(self.target.inventory)
        while not self.stop.is_set():
            if self.hero_active():          # the hero beat owns the GPU; poll again shortly
                self.stop.wait(5)
                continue
            if self.s.mode == "live":
                ui.say("purple", f"polling feeds for {', '.join(f'{n}@{v}' for n, v in inv['packages'].items())}")
                ui.say("purple", "feeds: " + feeds.sync(self.intel, inv, self.s).line())
            keys = [a.parent.name for a in sorted(BENCHMARKS.glob("*/advisory.json"))]
            keys += [a["key"] for a in self.intel.relevant()]
            for cve in dict.fromkeys(keys):
                if self.stop.is_set():
                    break
                if not self.queue.has_cve(cve):
                    self.submit_cve(cve)
            self.stop.wait(interval)

    def red_hunt_loop(self, pause: float = 5.0) -> None:
        """Continuous: propose candidate flaws. Yields to the hero item (bandwidth on one GPU)."""
        n = 0
        while not self.stop.is_set():
            if self.hero_active():
                self.stop.wait(pause)
                continue
            n += 1
            d = self.home / "hunts" / f"pass-{n:04d}"
            d.mkdir(parents=True, exist_ok=True)
            wt = d / "victim"
            init_victim(self.target.source, wt)
            enclave = self._enclave(d)
            try:
                prop = red.hunt(wt, enclave, d, self.s)
            finally:
                enclave.close()
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
        # claim before touching disk: an unclaimed item belongs to someone else (maybe the hero)
        if not self.queue.try_advance(item_id, "verifying", "gate"):
            return "skipped"  # another worker or process claimed it first
        d = self.home / "items" / item_id.replace("#", "-")
        d.mkdir(parents=True, exist_ok=True)
        enclave = self._enclave(d)
        try:
            return self._process(item_id, d, enclave)
        finally:
            enclave.close()

    def _process(self, item_id: str, d: Path, enclave: Enclave) -> str:
        item = self.queue.get(item_id)
        src = d / "victim-src"
        commit = init_victim(self.target.source, src)
        t0 = time.time()

        # verifying: Red proposes (if needed), the gate disposes
        red_wt = worktree(src, d / "wt-red", f"red/{item_id.replace('#', '-')}")
        ui.mascot("red")
        if item.source == "purple":
            prop = red.attack(item.payload["intel"], red_wt, enclave, d, self.s, self.target)
            script, source = (prop.script, prop.source) if prop else (None, None)
        else:
            script, source = Path(item.payload["script"]), "llm"
        args = ["--agentic"] if self.s.agentic_exploit else []
        if script:
            ui.mascot("gate")
        ref = BENCHMARKS / str(item.cve) / "known_good" / "fix.patch" if item.cve else None
        verdict = gate.verify(script, red_wt, enclave, args, red._victim_env(self.s),
                              reference_patch=ref) if script else None
        if not verdict or not verdict.verified:
            reason = verdict.reason if verdict else "no exploit proposed"
            self.queue.advance(item_id, "rejected", "gate", reason=reason)
            ui.say("gate", f"{item_id} REJECTED — {reason}")
            return "rejected"

        report = {
            "id": item_id, "cve": item.cve, "commit": commit, "source": item.source,
            "affected_file": item.payload.get("intel", {}).get("affected_file") or item.payload.get("file"),
            "repro_script": str(script), "exploit_source": source,
            "oracle": {"verdict": verdict.reason, "via": verdict.result.via_victim, "control": verdict.control,
                       "backend": verdict.result.backend},
            "attack_trace": verdict.result.output[-2000:], "agentic": self.s.agentic_exploit,
        }
        report_path = d / "vulnerability_report.json"
        report_path.write_text(json.dumps(report, indent=2))
        self.queue.advance(item_id, "verified", "gate", report=str(report_path))
        ui.intrusion(item_id, script.name, source)
        slack = Notifier(run_id=item_id, enclave=enclave.backend)
        slack.send("red", f"🚨 Intrusion reproduced: {item_id}",
                   f"Commit `{commit[:10]}` exploitable · {verdict.reason}\n"
                   f"```{verdict.result.output[-600:]}```")

        # patching: Blue in its own worktree; validation is not Blue's call
        self.queue.advance(item_id, "patching", "blue")
        ui.mascot("blue")
        branch = f"wreckless/fix-{item_id.replace('#', '-')}"
        blue_wt = worktree(src, d / "wt-blue", branch)
        diff, patch_source = blue.defend(report, blue_wt, enclave, d, self.s, self.target)
        (d / "fix.patch").write_text(diff)
        ui.diff("blue", diff or "(no diff)", limit=1500)
        v = blue.validate(blue_wt, enclave, report, self.target)
        ui.scoreboard(v.regression, v.functional, v.exploit_blocked, v.hardening)
        (d / "validation.json").write_text(json.dumps(v.logs, indent=2))
        if not diff or not v.ok:
            self.queue.advance(item_id, "patch_failed", "blue", summary=v.summary())
            slack.send("blue", f"Patch failed validation: {item_id}", "Needs a human.")
            return "patch_failed"

        src_label = blue.CACHED_LABEL if patch_source == "fallback" else f"patch: {patch_source}"
        fix_commit = commit_all(blue_wt, f"fix({item_id}): {item.title[:60]}\n\n"
                                         f"Patch source: {src_label}. {v.summary()}")
        self.queue.advance(item_id, "patched", "blue", branch=branch, commit=fix_commit, source=patch_source)
        ui.patch_validated(item_id, branch, fix_commit, patch_source)
        elapsed = time.time() - t0
        slack.bind(branch=branch, commit=fix_commit, patch_source=patch_source)
        if patch_source == "fallback":
            ui.say("blue", f"\033[1;43;30m {blue.CACHED_LABEL} \033[0m")
        title = "Fix branch ready (local, pending review)"
        if patch_source == "fallback":
            title += f" · ⚠️ {blue.CACHED_LABEL}"
        via = slack.send("blue", f"✅ {title}: {item_id}",
                         f"Branch `{branch}` @ `{fix_commit[:10]}` · {src_label}\n"
                         f"{v.summary()} · {elapsed:.0f}s\n```{diff[:1500]}```")
        self.queue.advance(item_id, "notified", "core", channel=via, elapsed_s=round(elapsed, 1))
        ui.notified(item_id, via)
        ui.say("core", f"{item_id} done in {elapsed:.1f}s → {d}")
        return "notified"

    # ---------- runtime ----------
    def run_hero(self, cve: str) -> str:
        """The demo critical path: one item, background hunting paused."""
        with self.hero_lock():
            return self.process(self.submit_cve(cve))

    def worker_loop(self) -> None:
        while not self.stop.is_set():
            # the hero lock is taken before its item is enqueued, so this also keeps us off it
            item_id = None if self.hero_active() else self.queue.next_queued()
            if not item_id:
                self.stop.wait(2)
                continue
            try:
                self.process(item_id)
            except Exception as e:  # one bad item must not kill the worker thread
                ui.say("core", f"{item_id} crashed: {type(e).__name__}: {e}")
                self.queue.fail(item_id, "core", f"crashed: {type(e).__name__}: {e}"[:300])

    def liveness(self) -> str:
        st, up = self.queue.stats(), int(time.time() - self.started)
        by = st["by_label"]
        return (f"up {up // 3600}h{up % 3600 // 60:02d}m · {st['total']} candidates · "
                f"{by.get('VERIFIED', 0)} verified · {by.get('REJECTED', 0)} rejected · "
                f"{st['by_state'].get('notified', 0)} PRs drafted")

    def run_daemon(self, purple_interval: float, hunt: bool, slack_listener: bool = False,
                   heartbeat: float = 30) -> None:
        ui.banner(f"WreckLess always-on swarm · {self.s.mode} mode · home {self.home}")
        # a hero in another process really is in flight: only recover when none is running
        for item_id in ([] if self.hero_active() else self.queue.recover()):
            ui.say("core", f"{item_id} was interrupted by a restart → failed")
        threads = [threading.Thread(target=self.purple_loop, args=(purple_interval,), daemon=True),
                   threading.Thread(target=self.worker_loop, daemon=True)]
        if hunt:
            threads.append(threading.Thread(target=self.red_hunt_loop, daemon=True))
        for t in threads:
            t.start()
        listener = None
        if slack_listener:
            from wreckless.slack_socket import start_listener
            listener = start_listener(runs_dir=self.home / "items")
        try:
            while not self.stop.wait(heartbeat):
                ui.say("core", self.liveness())
        except KeyboardInterrupt:
            self.stop.set()
            ui.say("core", f"stopping · {self.liveness()}")
        finally:
            if listener:
                listener.stop()
