"""Always-on swarm: two producers -> one queue -> one verify gate -> Blue -> notify.

    Purple (scheduled) ─┐
                        ├─► CandidateQueue ─► gate (exploit-as-test) ─► Blue defend+validate ─► notify
    Red-hunt (continuous)┘     PREDICTION        CONFIRMED_BY_REPRO

Only gate-verified items reach Blue. `run_one(cve)` walks one item through the same lifecycle
synchronously (the demo's critical path) with Red-hunt throttled for the duration.
"""
import json
import sys
import threading
import time
import traceback
from pathlib import Path
from typing import Callable, Iterable

from wreckless import gate, ui
from wreckless.agents import blue, purple
from wreckless.config import BENCHMARKS, RUNS, Settings
from wreckless.gitops import commit_all, git, worktree
from wreckless.lifecycle import CONFIRMED, Item
from wreckless.notify import Notifier
from wreckless.queue import CandidateQueue
from wreckless.sandbox import Enclave

Hunter = Callable[[], Iterable[dict]]


def no_hunt() -> Iterable[dict]:
    """Default Red-hunt stub: proposes nothing. Person A plugs the real hunter in."""
    return ()


def cached_exploit(intel: dict) -> Path | None:
    """Default exploit source for Purple advisories: the cached reference exploit (same file
    red.attack falls back to). Still enters the queue as a PREDICTION and must pass the gate."""
    p = BENCHMARKS / intel["id"] / "known_good" / "repro_exploit.py"
    return p if p.is_file() else None


def local_advisories() -> list[str]:
    return sorted(p.parent.name for p in BENCHMARKS.glob("*/advisory.json"))


class _Throttle:
    def __init__(self, swarm: "Swarm"):
        self.swarm = swarm

    def __enter__(self):
        return self.swarm

    def __exit__(self, *exc):
        self.swarm.resume()


class Swarm:
    def __init__(self, s: Settings, root: Path = RUNS, hunter: Hunter = no_hunt,
                 exploit_for: Callable[[dict], Path | None] = cached_exploit,
                 notifier_factory: Callable[[], Notifier] = Notifier,
                 gate_timeout: int = gate.DEFAULT_TIMEOUT_S):
        self.s, self.root = s, Path(root)
        self.queue = CandidateQueue(self.root / "queue")
        self.work_root = self.root / "items"
        self.hunter, self.exploit_for = hunter, exploit_for
        self.notifier_factory, self.gate_timeout = notifier_factory, gate_timeout
        self.stop = threading.Event()
        self._hunt_ok = threading.Event()
        self._hunt_ok.set()
        self.hunter_calls = 0
        self.threads: list[threading.Thread] = []

    # -- hero-beat throttle ------------------------------------------------------------
    def throttle(self) -> _Throttle:
        """Pause Red-hunt. Usable as a call or as `with swarm.throttle(): ...` (auto-resume)."""
        self._hunt_ok.clear()
        return _Throttle(self)

    def resume(self) -> None:
        self._hunt_ok.set()

    @property
    def throttled(self) -> bool:
        return not self._hunt_ok.is_set()

    # -- producers ---------------------------------------------------------------------
    def purple_tick(self, cves: Iterable[str] | None = None) -> list[Item]:
        out = []
        for cve in cves if cves is not None else local_advisories():
            if self.queue.has("purple", cve):
                continue
            out.append(self._enqueue_advisory(cve))
        return out

    def _enqueue_advisory(self, cve: str) -> Item:
        intel = purple.ingest(cve, self.s)
        script = self.exploit_for(intel)
        return self.queue.put({"source": "purple", "cve": cve, "target": "victim_app",
                               "repro_script": str(script) if script else None,
                               "affected_file": intel.get("affected_file")})

    def purple_loop(self, interval_s: float = 600) -> None:
        while not self.stop.is_set():
            self._guard("purple", self.purple_tick)
            self.stop.wait(interval_s)

    def red_hunt_loop(self, idle_s: float = 1.0) -> None:
        while not self.stop.is_set():
            if not self._hunt_ok.wait(timeout=0.05):
                continue  # throttled: do not call the hunter (frees GPU bandwidth for Blue)
            self.hunter_calls += 1
            self._guard("red", lambda: [self.queue.put({**c, "source": "red-hunt"})
                                        for c in (self.hunter() or ())])
            self.stop.wait(idle_s)

    # -- consumer ----------------------------------------------------------------------
    def consumer_loop(self, poll_s: float = 0.5) -> None:
        while not self.stop.is_set():
            it = self.queue.claim()
            if it is None:
                self.stop.wait(poll_s)
                continue
            self.process(it)

    def process(self, item: Item) -> dict:
        """claimed item -> gate -> (verified) Blue -> patched|patch_failed -> notified."""
        work = self.work_root / item.id
        try:
            v = gate.run(item, work, self.gate_timeout)
            ui.say("core", f"gate {item.id}: {'VERIFIED' if v.verified else 'REJECTED'} ({v.reason})")
            if v.verified:
                self._defend(item, work)
        except Exception as e:  # never leave an item stranded mid-lifecycle
            err = {"error": f"{type(e).__name__}: {e}", "trace": traceback.format_exc()[-1500:]}
            if item.state == "verifying":
                item.advance("rejected", "core", err)
            elif item.state == "patching":
                item.advance("patch_failed", "core", err)
                self._notify(item, ok=False, detail=err["error"])
            else:
                raise
        return item.doc

    def _defend(self, item: Item, work: Path) -> None:
        cand, cve = item.candidate, item.candidate["cve"]
        src = gate.victim_src(work, cand["target"])
        commit = git(src, "rev-parse", "HEAD")
        adv = BENCHMARKS / str(cve) / "advisory.json"
        affected = (json.loads(adv.read_text())["affected_file"] if cve and adv.is_file()
                    else cand.get("producer_notes", {}).get("affected_file"))
        verdict = item.doc["history"][-1]["payload"]
        # Same contract as cli.run's vulnerability_report.json, plus per-item provenance.
        report = {
            "cve": cve, "commit": commit, "affected_file": affected,
            "repro_script": str(work / "exploit" / "repro_exploit.py"),
            "exploit_source": cand["source"],
            "attack_trace": Path(item.doc["artifacts"]["gate_output"]).read_text()[-2000:],
            "oracle": "nonce file written by exploited code path (gate-checked host-side)",
            "agentic": self.s.agentic_exploit, "enclave": verdict.get("backend"),
            "item_id": item.id, "label": CONFIRMED, "script_sha256": verdict.get("script_sha256"),
        }
        report_path = work / "vulnerability_report.json"
        report_path.write_text(json.dumps(report, indent=2))
        item.artifact("vulnerability_report", report_path)
        item.advance("patching", "blue", {"report": str(report_path)})

        if not cve or not (BENCHMARKS / cve / "regression_test.py").is_file():
            item.advance("patch_failed", "core", {"reason": "no held-out regression oracle for this "
                                                            "finding; Blue output cannot be validated"})
            self._notify(item, ok=False, detail="verified exploit, no held-out oracle — needs a human")
            return

        enclave = Enclave(work, sys.executable)
        branch = f"wreckless/fix-{cve}"
        blue_wt = worktree(src, work / "wt-blue", branch)
        diff, source = blue.defend(report, blue_wt, enclave, work, self.s)
        (work / "fix.patch").write_text(diff)
        v = blue.validate(cve, blue_wt, enclave, report)
        (work / "validation.json").write_text(json.dumps(v.logs, indent=2))
        item.artifact("validation", work / "validation.json")
        if not v.ok:
            item.advance("patch_failed", "blue", {"validation": v.__dict__ | {"logs": None},
                                                  "source": source})
            self._notify(item, ok=False, detail="patch failed held-out validation — needs a human")
            return
        fix = commit_all(blue_wt, f"fix({cve}): stop evaluating database values as code\n\n"
                                  f"Patch source: {source}. Validated by WreckLess (item {item.id}).")
        item.advance("patched", "blue", {"branch": branch, "commit": fix, "source": source})
        self._notify(item, ok=True, detail=f"Branch `{branch}` @ `{fix[:10]}` · patch: {source}\n"
                                           f"Held-out regression ✅ · functional ✅ · exploit blocked ✅\n"
                                           f"```{diff[:1500]}```")

    def _notify(self, item: Item, ok: bool, detail: str) -> None:
        cve = item.candidate["cve"] or item.id
        title = f"✅ Draft PR Ready: {cve}" if ok else f"Patch failed validation: {cve}"
        via = self.notifier_factory().send("blue", title, detail)
        item.advance("notified", "core", {"channel": via, "ok": ok})

    # -- demo critical path --------------------------------------------------------------
    def run_one(self, cve: str) -> dict:
        """Walk one CVE through the full lifecycle synchronously, Red-hunt throttled."""
        t0 = time.time()
        with self.throttle():
            item = self._enqueue_advisory(cve)
            claimed = self.queue.claim(item.id)
            if claimed is None:
                raise RuntimeError(f"could not claim {item.id}")
            doc = self.process(claimed)
        ui.say("core", f"run_one {cve}: {doc['state']} in {time.time() - t0:.1f}s")
        return doc

    # -- lifecycle of the swarm itself ---------------------------------------------------
    def start(self, purple_interval_s: float = 600, hunt_idle_s: float = 1.0,
              poll_s: float = 0.5) -> list[threading.Thread]:
        self.stop.clear()
        specs = [("purple", self.purple_loop, purple_interval_s),
                 ("red-hunt", self.red_hunt_loop, hunt_idle_s),
                 ("consumer", self.consumer_loop, poll_s)]
        self.threads = [threading.Thread(target=f, args=(a,), name=f"wreckless-{n}", daemon=True)
                        for n, f, a in specs]
        for t in self.threads:
            t.start()
        return self.threads

    def shutdown(self, timeout: float = 10) -> bool:
        self.stop.set()
        self._hunt_ok.set()
        for t in self.threads:
            t.join(timeout)
        return not any(t.is_alive() for t in self.threads)

    def _guard(self, role: str, fn: Callable) -> None:
        try:
            fn()
        except Exception as e:  # an always-on loop logs and keeps going
            ui.say("core", f"{role} loop error: {type(e).__name__}: {e}")
