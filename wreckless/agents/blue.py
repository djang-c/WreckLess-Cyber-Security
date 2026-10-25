"""Blue / Hard Hat: patch the victim, emit a runtime policy. Validation is run by the orchestrator."""
import ast
import json
import os
import re
import secrets
import shutil
import subprocess
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path

from wreckless import llm, ui
from wreckless.config import BENCHMARKS, Settings
from wreckless.gitops import git
from wreckless.sandbox import Enclave

SYSTEM = """You are Hard Hat, a defensive engineer. You receive a verified vulnerability report
with a working exploit. Fix the root cause in the victim repo with a minimal patch that keeps
existing functionality. Fix the root cause; do not special-case the exploit payload.
Only non-test source files may change: tests/, conftest.py, pytest/packaging config and
interpreter hooks are read-only, and a patch touching them fails validation.
Workflow: read_file the vulnerable code -> edit_file or git_apply_patch -> run_pytest on the
repo's tests -> run_exploit to confirm it is now blocked -> generate_openshell_egress_rule for any
domain the service legitimately needs (none for this target: call it with domain "none").
Stop when run_pytest passes and run_exploit reports BLOCKED."""

CACHED_LABEL = "CACHED REFERENCE PATCH — not AI-generated"

# Blue may only change non-test source. Anything that can steer pytest or the interpreter
# (or hide files from git) is off limits, both for its tools and in the final worktree.
FORBIDDEN_NAMES = {"conftest.py", "pytest.ini", ".pytest.ini", "tox.ini", "setup.cfg", "pyproject.toml",
                   "sitecustomize.py", "usercustomize.py", ".gitignore", ".gitattributes"}
GATING = ("regression_test.py", "static_test.py")   # held-out; together they decide `regression`
REPORTED = ("hardening_test.py",)                    # held-out; scored, not gating


def forbidden(rel: str) -> str | None:
    """Reason a repo-relative path may not be changed by Blue, else None."""
    p = Path(rel)
    if not rel or p.is_absolute() or ".." in p.parts:
        return f"{rel}: outside the repo"
    if ".git" in p.parts:
        return f"{rel}: git metadata"
    if p.parts[0] == "tests":
        return f"{rel}: tests are read-only for Blue"
    if p.name in FORBIDDEN_NAMES or p.suffix in (".pth", ".pyc") or "__pycache__" in p.parts:
        return f"{rel}: test/interpreter config is read-only for Blue"
    return None


def _changed_paths(wt: Path, base: str) -> list[str]:
    """Tracked changes vs base plus every untracked file (ignored ones included)."""
    tracked = git(wt, "diff", "--name-only", "--no-renames", base).splitlines()
    untracked = git(wt, "ls-files", "--others").splitlines()
    return sorted(set(tracked + untracked) - {""})


def _patch_violations(wt: Path, base: str) -> list[str]:
    bad = []
    for rel in _changed_paths(wt, base):
        if why := forbidden(rel):
            bad.append(why)
        elif rel.endswith(".py") and (wt / rel).is_file() and "pytest" in (wt / rel).read_text(errors="replace"):
            bad.append(f"{rel}: victim source may not reference pytest")
    return bad


_DIFF_PATH = re.compile(r"^(?:diff --git a/(\S+) b/(\S+)|(?:---|\+\+\+) (?:[ab]/)?([^\t\n]+)|"
                        r"(?:rename|copy) (?:from|to) (\S+))", re.M)


def _diff_paths(diff: str) -> set[str]:
    return {g.strip() for m in _DIFF_PATH.finditer(diff) for g in m.groups() if g and g.strip() != "/dev/null"}


@dataclass
class Validation:
    regression: bool | None        # None: no held-out test exists (e.g. Red-hunt finding)
    functional: bool
    exploit_blocked: bool
    hardening: str | None = None   # "2/3" style score, reported but not gating
    logs: dict = field(default_factory=dict)
    rejected: str | None = None    # patch touched files Blue may not change

    @property
    def ok(self) -> bool:
        return (self.rejected is None and self.regression is not False and self.functional
                and self.exploit_blocked)

    def summary(self) -> str:
        if self.rejected:
            return f"PATCH REJECTED: {self.rejected}"
        mark = lambda v: "n/a" if v is None else ("PASS" if v else "FAIL")  # noqa: E731
        s = (f"held-out regression: {mark(self.regression)} · functional: {mark(self.functional)} · "
             f"exploit blocked: {'YES' if self.exploit_blocked else 'NO'}")
        return s + (f" · hardening probes: {self.hardening}" if self.hardening else "")


class BlueTools:
    def __init__(self, wt: Path, enclave: Enclave, report: dict, item_dir: Path):
        self.wt, self.enclave, self.report, self.dir = wt, enclave, report, item_dir
        self.tests_ok = self.exploit_blocked = False

    def _path(self, path: str) -> Path | None:
        root = self.wt.resolve()
        p = (self.wt / path).resolve()
        ok = p.is_relative_to(root) and not p.is_relative_to(BENCHMARKS.resolve())
        return p if ok and ".git" not in p.relative_to(root).parts else None

    def read_file(self, path: str) -> str:
        p = self._path(path)
        if not p:
            return "ERROR: path outside repo"
        return p.read_text() if p.is_file() else f"ERROR: no such file {path}"

    def edit_file(self, path: str, old: str, new: str) -> str:
        p = self._path(path)
        if not p:
            return "ERROR: path outside repo"
        if why := forbidden(str(p.relative_to(self.wt.resolve()))):
            return f"ERROR: {why}"
        if not p.is_file():
            return f"ERROR: no such file {path}"
        text = p.read_text()
        if text.count(old) != 1:
            return f"ERROR: old string found {text.count(old)} times (must be exactly 1)"
        p.write_text(text.replace(old, new))
        return f"edited {path}"

    def git_apply_patch(self, diff: str) -> str:
        bad = [w for rel in sorted(_diff_paths(diff)) if (w := forbidden(rel))]
        if re.search(r"^(?:new file |new )?mode 120000", diff, re.M):
            bad.append("symlinks may not be created")
        if bad:
            return "ERROR: patch rejected: " + "; ".join(bad)
        p = subprocess.run(["git", "apply", "--recount", "-"], cwd=self.wt, input=diff,
                           capture_output=True, text=True)
        return "patch applied" if p.returncode == 0 else f"ERROR: {p.stderr}"

    def run_pytest(self, test_file: str = "tests") -> str:
        self.tests_ok = False
        target = test_file.split("::")[0]
        tests = (self.wt / "tests").resolve()
        p = (self.wt / target).resolve()
        if not target or test_file.startswith("-") or not p.is_relative_to(tests) or not p.exists():
            return "ERROR: run_pytest only runs files under the repo's tests/ directory"
        r = _pytest(self.enclave, self.wt, test_file, _deny_benchmarks())
        self.tests_ok = r.returncode == 0
        return r.output[-3000:]

    def run_exploit(self) -> str:
        script = Path(self.report["repro_script"])
        r = self.enclave.run_exploit(script, self.wt, env=_deny_benchmarks(script))
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
            T("edit_file", "Replace one exact occurrence of `old` with `new` in a non-test source file.",
              obj({"path": s, "old": s, "new": s}, ["path", "old", "new"]), self.edit_file),
            T("git_apply_patch", "Apply a unified diff to non-test source files.", obj({"diff": s}, ["diff"]),
              self.git_apply_patch),
            T("run_pytest", "Run pytest on a test file/dir under the repo's tests/.",
              obj({"test_file": s}, ["test_file"]), self.run_pytest),
            T("run_exploit", "Re-run Red's repro_exploit.py against the patched repo.", obj({}, []),
              self.run_exploit),
            T("generate_openshell_egress_rule", "Emit the OpenShell runtime policy (egress allowlist).",
              obj({"domain": s}, ["domain"]), self.generate_openshell_egress_rule),
        ]


def _deny_benchmarks(*allow: Path) -> dict:
    """Guard env so code Blue influences cannot open held-out tests or reference fixes."""
    return {"WRECKLESS_DENY_READ": str(BENCHMARKS.resolve()),
            "WRECKLESS_ALLOW_READ": os.pathsep.join(str(Path(a).resolve()) for a in allow)}


def _pytest(enclave: Enclave, wt: Path, target: str, env: dict | None = None):
    return enclave.run([enclave.python, "-m", "pytest", "-q", "-p", "no:cacheprovider", "--", target],
                       cwd=wt, env=env)


@dataclass
class HeldOut:
    returncode: int     # 0 only if pytest exited 0 AND junit shows every held-out test passed
    output: str
    passed: int
    failed: int


def _expected_tests(test: Path) -> set[str]:
    tree = ast.parse(test.read_text())
    return {n.name for n in tree.body if isinstance(n, ast.FunctionDef) and n.name.startswith("test_")}


def _junit(path: Path) -> tuple[set[str], int, int]:
    if not path.exists():
        return set(), 0, 0
    names, passed, failed = set(), 0, 0
    for case in ET.parse(path).getroot().iter("testcase"):
        names.add(case.get("name", "").split("[")[0])
        if any(c.tag in ("failure", "error", "skipped") for c in case):
            failed += 1
        else:
            passed += 1
    return names, passed, failed


def _held_out(enclave: Enclave, wt: Path, test: Path) -> HeldOut:
    """Run a pristine copy of a held-out test from its own rootdir: no victim conftest, no
    victim ini, no plugin autoload. Pass/fail is read by the host from exit code + junit."""
    run = enclave.root / "tmp" / f"heldout-{secrets.token_hex(6)}"
    run.mkdir(parents=True)
    try:
        (run / "pytest.ini").write_text("[pytest]\n")
        probe = run / f"test_heldout_{test.stem}.py"
        shutil.copy(test, probe)
        junit = run / "junit.xml"
        r = enclave.run([enclave.python, "-m", "pytest", "-q", "-p", "no:cacheprovider", "--noconftest",
                         "-c", str(run / "pytest.ini"), "--rootdir", str(run), "--confcutdir", str(run),
                         f"--junitxml={junit}", "--", str(probe)],
                        cwd=run, env={"PYTHONPATH": f"{enclave.guard_dir}{os.pathsep}{wt.resolve()}",
                                      "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
                                      "WRECKLESS_TARGET_ROOT": str(wt.resolve())})
        names, passed, failed = _junit(junit)
        missing = _expected_tests(test) - names
        ok = r.returncode == 0 and failed == 0 and passed > 0 and not missing
        note = f"\n[held-out] junit: {passed} passed, {failed} failed, missing {sorted(missing)}"
        return HeldOut(0 if ok else (r.returncode or 1), r.output + note, passed, failed)
    finally:
        shutil.rmtree(run, ignore_errors=True)


def validate(wt: Path, enclave: Enclave, report: dict) -> Validation:
    """Final checks, run by the orchestrator (never by Blue): held-out tests + exploit + functional."""
    bench = BENCHMARKS / report["cve"] if report.get("cve") else None
    gating = [bench / f for f in GATING if (bench / f).exists()] if bench else []
    reported = [bench / f for f in REPORTED if (bench / f).exists()] if bench else []
    base = report.get("commit") or "HEAD"
    bad = _patch_violations(wt, base)
    if bad:
        reason = "; ".join(bad)
        return Validation(False if gating else None, False, False, rejected=reason, logs={"rejected": reason})
    # Belt and braces: the functional run always uses the victim's own tests from git.
    git(wt, "checkout", "-q", base, "--", "tests")
    git(wt, "clean", "-fdxq", "--", "tests")

    logs, regression, hardening = {}, None, None
    for t in gating:
        r = _held_out(enclave, wt, t)
        logs[t.stem] = r.output
        regression = (regression is not False) and r.returncode == 0
    for t in reported:
        r = _held_out(enclave, wt, t)
        hardening, logs[t.stem] = f"{r.passed}/{r.passed + r.failed}", r.output
    fun = _pytest(enclave, wt, "tests")
    exp = enclave.run_exploit(Path(report["repro_script"]), wt)
    logs |= {"functional": fun.output, "exploit": exp.output}
    # Host-side verdict: the nonce is not in the oracle file AND the exploit process itself
    # exited non-zero. Nothing the patched code prints is consulted.
    blocked = not exp.hit and exp.returncode != 0
    return Validation(regression, fun.returncode == 0, blocked, hardening, logs)


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
    why = ("" if not s.use_llm else " (demo-mode fallback)" if llm.reachable(ep)
           else f" (LLM unreachable at {ep.url})")
    ui.say("blue", f"applying \033[1;43;30m {CACHED_LABEL} \033[0m" + why)
    git(wt, "checkout", "-q", "--", ".")
    ui.detail("blue", tools.git_apply_patch(known.read_text()))
    tools.generate_openshell_egress_rule("none")
    return git(wt, "diff"), "fallback"
