"""Blue / Hard Hat: patch the victim, emit a runtime policy, then pass the held-out oracle."""
import json
import secrets
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from wreckless import llm, ui
from wreckless.config import BENCHMARKS, Settings
from wreckless.gitops import git
from wreckless.sandbox import Enclave

SYSTEM = """You are Hard Hat, a defensive engineer. You receive a verified vulnerability report
(with a working exploit). Fix the root cause in the victim repo with a minimal patch that keeps
existing functionality. Prefer safe parsing (e.g. ast.literal_eval) over raw evaluation.
Workflow: read_file the vulnerable code -> edit_file or git_apply_patch -> run_pytest on the
repo's tests -> run_exploit to confirm it now fails -> generate_openshell_egress_rule for any
domain the service legitimately needs (none for this target: call it with domain "none").
Stop when run_pytest passes and run_exploit reports ORACLE_MISS."""


@dataclass
class Validation:
    regression: bool
    functional: bool
    exploit_blocked: bool
    logs: dict = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return self.regression and self.functional and self.exploit_blocked


class BlueTools:
    def __init__(self, wt: Path, enclave: Enclave, report: dict, run_dir: Path):
        self.wt, self.enclave, self.report, self.run_dir = wt, enclave, report, run_dir
        self.tests_ok = self.exploit_blocked = False

    def read_file(self, path: str) -> str:
        p = (self.wt / path).resolve()
        if not p.is_relative_to(self.wt.resolve()) or ".git" in p.parts:
            return "ERROR: path outside repo"
        return p.read_text()

    def edit_file(self, path: str, old: str, new: str) -> str:
        p = (self.wt / path).resolve()
        if not p.is_relative_to(self.wt.resolve()):
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
        r = _exploit(self.enclave, self.wt, Path(self.report["repro_script"]))
        self.exploit_blocked = "ORACLE_MISS" in r.output
        return r.output[-2000:]

    def generate_openshell_egress_rule(self, domain: str) -> str:
        policy = {"version": 1, "name": f"wreckless-{self.report['cve']}",
                  "process": {"run_as_user": "nobody", "no_new_privileges": True, "drop_capabilities": ["ALL"]},
                  "filesystem": {"read_only": ["/"], "read_write": ["/tmp"]},
                  "network": {"default": "deny",
                              "egress_allow": [] if domain in ("", "none") else [{"host": domain, "port": 443}]}}
        out = self.run_dir / "openshell_policy.json"
        out.write_text(json.dumps(policy, indent=2))
        return f"policy written: {out.name}\n{json.dumps(policy['network'])}"

    def tools(self) -> list[llm.Tool]:
        T, obj = llm.Tool, lambda props, req: {"type": "object", "properties": props, "required": req}
        s = {"type": "string"}
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


def _exploit(enclave: Enclave, wt: Path, script: Path):
    env = {"WRECKLESS_ORACLE": str(enclave.root / "tmp" / f"oracle_{secrets.token_hex(4)}"),
           "WRECKLESS_NONCE": secrets.token_hex(8)}
    return enclave.run([enclave.python, str(script), str(wt)], env=env)


def validate(cve: str, wt: Path, enclave: Enclave, report: dict) -> Validation:
    """Final oracle, run by the orchestrator (not Blue): held-out test + exploit + functional."""
    held_out = BENCHMARKS / cve / "regression_test.py"
    probe = wt / "tests" / "test_heldout_regression.py"
    shutil.copy(held_out, probe)
    try:
        reg = _pytest(enclave, wt, str(probe.relative_to(wt)))
    finally:
        probe.unlink()
    fun = _pytest(enclave, wt, "tests")
    exp = _exploit(enclave, wt, Path(report["repro_script"]))
    return Validation(reg.returncode == 0, fun.returncode == 0, "ORACLE_MISS" in exp.output,
                      {"regression": reg.output, "functional": fun.output, "exploit": exp.output})


def defend(report: dict, wt: Path, enclave: Enclave, run_dir: Path, s: Settings) -> tuple[str, str]:
    tools = BlueTools(wt, enclave, report, run_dir)
    ep = s.blue if llm.reachable(s.blue) else s.blue_fallback
    if s.use_llm and llm.reachable(ep):
        ui.say("blue", f"engaging {ep.model} — remediating {report['cve']}")
        task = "Vulnerability report:\n" + json.dumps(report, indent=2)
        llm.run_agent(ep, "blue", SYSTEM, task, tools.tools(),
                      lambda: tools.tests_ok and tools.exploit_blocked,
                      max_steps=s.max_agent_steps, temperature=0 if s.demo_mode else 0.2)
        if git(wt, "diff"):
            if not (run_dir / "openshell_policy.json").exists():
                tools.generate_openshell_egress_rule("none")
            return git(wt, "diff"), "llm"
        ui.say("blue", "LLM produced no patch")
        if not s.demo_mode:
            return "", "llm"

    ui.say("blue", "applying cached reference patch" + (" (demo-mode fallback)" if s.use_llm else ""))
    git(wt, "checkout", "-q", "--", ".")
    print(tools.git_apply_patch((BENCHMARKS / report["cve"] / "known_good" / "fix.patch").read_text()))
    tools.generate_openshell_egress_rule("none")
    return git(wt, "diff"), "fallback"
