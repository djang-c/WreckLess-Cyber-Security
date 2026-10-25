"""Blue / Hard Hat: patch the victim, emit a runtime policy. Validation is run by the orchestrator."""
import json
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from wreckless import llm, ui
from wreckless.config import BENCHMARKS, Settings
from wreckless.gitops import git
from wreckless.sandbox import Enclave

SYSTEM = """You are Hard Hat, a defensive engineer. You receive a verified vulnerability report
with a working exploit. Fix the root cause in the victim repo with a minimal patch that keeps
existing functionality. Prefer structural fixes (safe parsers such as ast.literal_eval,
allowlists, removing dynamic evaluation) over extending denylists, which attackers bypass.
Workflow: read_file the vulnerable code -> edit_file or git_apply_patch -> run_pytest on the
repo's tests -> run_exploit to confirm it is now blocked -> generate_openshell_egress_rule for any
domain the service legitimately needs (none for this target: call it with domain "none").
Stop when run_pytest passes and run_exploit reports BLOCKED."""


@dataclass
class Validation:
    regression: bool | None        # None: no held-out test exists (e.g. Red-hunt finding)
    functional: bool
    exploit_blocked: bool
    hardening: str | None = None   # "2/3" style score, reported but not gating
    logs: dict = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return self.regression is not False and self.functional and self.exploit_blocked

    def summary(self) -> str:
        mark = lambda v: "n/a" if v is None else ("PASS" if v else "FAIL")  # noqa: E731
        s = (f"held-out regression: {mark(self.regression)} · functional: {mark(self.functional)} · "
             f"exploit blocked: {'YES' if self.exploit_blocked else 'NO'}")
        return s + (f" · hardening probes: {self.hardening}" if self.hardening else "")


class BlueTools:
    def __init__(self, wt: Path, enclave: Enclave, report: dict, item_dir: Path):
        self.wt, self.enclave, self.report, self.dir = wt, enclave, report, item_dir
        self.tests_ok = self.exploit_blocked = False

    def _path(self, path: str) -> Path | None:
        p = (self.wt / path).resolve()
        return p if p.is_relative_to(self.wt.resolve()) and ".git" not in p.parts else None

    def read_file(self, path: str) -> str:
        p = self._path(path)
        return p.read_text() if p else "ERROR: path outside repo"

    def edit_file(self, path: str, old: str, new: str) -> str:
        p = self._path(path)
        if not p:
            return "ERROR: path outside repo"
        text = p.read_text()
        if text.count(old) != 1:
            return f"ERROR: old string found {text.count(old)} times (must be exactly 1)"
        p.write_text(text.replace(old, new))
        return f"edited {path}"

    def git_apply_patch(self, diff: str) -> str:
        p = subprocess.run(["git", "apply", "--recount", "-"], cwd=self.wt, input=diff,
                           capture_output=True, text=True)
        return "patch applied" if p.returncode == 0 else f"ERROR: {p.stderr}"

    def run_pytest(self, test_file: str = "tests") -> str:
        r = _pytest(self.enclave, self.wt, test_file)
        self.tests_ok = r.returncode == 0
        return r.output[-3000:]

    def run_exploit(self) -> str:
        r = self.enclave.run_exploit(Path(self.report["repro_script"]), self.wt)
        self.exploit_blocked = not r.hit
        return ("BLOCKED: oracle not reached\n" if not r.hit else "STILL EXPLOITABLE\n") + r.output[-2000:]

    def generate_openshell_egress_rule(self, domain: str) -> str:
        policy = {"version": 1, "name": f"wreckless-{self.report['id']}",
                  "process": {"run_as_user": "nobody", "no_new_privileges": True, "drop_capabilities": ["ALL"]},
                  "filesystem": {"read_only": ["/"], "read_write": ["/tmp"]},
                  "network": {"default": "deny",
                              "egress_allow": [] if domain in ("", "none") else [{"host": domain, "port": 443}]}}
        out = self.dir / "openshell_policy.json"
        out.write_text(json.dumps(policy, indent=2))
        return f"policy written: {out.name}\n{json.dumps(policy['network'])}"

    def tools(self) -> list[llm.Tool]:
        T, s = llm.Tool, {"type": "string"}
        obj = lambda props, req: {"type": "object", "properties": props, "required": req}  # noqa: E731
        return [
            T("read_file", "Read a file in the victim repo.", obj({"path": s}, ["path"]), self.read_file),
            T("edit_file", "Replace one exact occurrence of `old` with `new` in a file.",
              obj({"path": s, "old": s, "new": s}, ["path", "old", "new"]), self.edit_file),
            T("git_apply_patch", "Apply a unified diff to the repo.", obj({"diff": s}, ["diff"]),
              self.git_apply_patch),
            T("run_pytest", "Run pytest on a test file/dir of the repo.", obj({"test_file": s}, ["test_file"]),
              self.run_pytest),
            T("run_exploit", "Re-run Red's repro_exploit.py against the patched repo.", obj({}, []),
              self.run_exploit),
            T("generate_openshell_egress_rule", "Emit the OpenShell runtime policy (egress allowlist).",
              obj({"domain": s}, ["domain"]), self.generate_openshell_egress_rule),
        ]


def _pytest(enclave: Enclave, wt: Path, target: str):
    return enclave.run([enclave.python, "-m", "pytest", "-q", "-p", "no:cacheprovider", target], cwd=wt)


def _held_out(enclave: Enclave, wt: Path, test: Path):
    probe = wt / "tests" / f"test_heldout_{test.stem}.py"
    shutil.copy(test, probe)
    try:
        return _pytest(enclave, wt, str(probe.relative_to(wt)))
    finally:
        probe.unlink()


def validate(wt: Path, enclave: Enclave, report: dict) -> Validation:
    """Final checks, run by the orchestrator (never by Blue): held-out test + exploit + functional."""
    bench = BENCHMARKS / report["cve"] if report.get("cve") else None
    logs, regression, hardening = {}, None, None
    if bench and (bench / "regression_test.py").exists():
        r = _held_out(enclave, wt, bench / "regression_test.py")
        regression, logs["regression"] = r.returncode == 0, r.output
    if bench and (bench / "hardening_test.py").exists():
        r = _held_out(enclave, wt, bench / "hardening_test.py")
        passed, failed = _counts(r.output)
        hardening, logs["hardening"] = f"{passed}/{passed + failed}", r.output
    fun = _pytest(enclave, wt, "tests")
    exp = enclave.run_exploit(Path(report["repro_script"]), wt)
    logs |= {"functional": fun.output, "exploit": exp.output}
    return Validation(regression, fun.returncode == 0, not exp.hit, hardening, logs)


def _counts(out: str) -> tuple[int, int]:
    import re
    p = re.search(r"(\d+) passed", out)
    f = re.search(r"(\d+) failed", out)
    return int(p.group(1)) if p else 0, int(f.group(1)) if f else 0


def defend(report: dict, wt: Path, enclave: Enclave, item_dir: Path, s: Settings) -> tuple[str, str]:
    tools = BlueTools(wt, enclave, report, item_dir)
    ep = s.blue if llm.reachable(s.blue) else s.blue_fallback
    if s.use_llm and llm.reachable(ep):
        ui.say("blue", f"engaging {ep.model} — remediating {report['id']}")
        public = {k: v for k, v in report.items() if k != "attack_trace"} | {"attack_trace": report["attack_trace"][-1500:]}
        llm.run_agent(ep, "blue", SYSTEM, "Vulnerability report:\n" + json.dumps(public, indent=2), tools.tools(),
                      lambda: tools.tests_ok and tools.exploit_blocked,
                      max_steps=s.max_agent_steps, temperature=0 if s.demo_mode else 0.2)
        if git(wt, "diff"):
            if not (item_dir / "openshell_policy.json").exists():
                tools.generate_openshell_egress_rule("none")
            return git(wt, "diff"), "llm"
        ui.say("blue", "LLM produced no patch")
        if not s.demo_mode:
            return "", "llm"

    known = BENCHMARKS / str(report.get("cve")) / "known_good" / "fix.patch"
    if not known.exists():
        return "", "none"
    ui.say("blue", "applying cached reference patch" + (" (demo-mode fallback)" if s.use_llm else ""))
    git(wt, "checkout", "-q", "--", ".")
    ui.detail("blue", tools.git_apply_patch(known.read_text()))
    tools.generate_openshell_egress_rule("none")
    return git(wt, "diff"), "fallback"
