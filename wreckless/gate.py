"""The single trust gate: PREDICTION -> VERIFIED | REACHABLE | REJECTED.

The verdict comes from code executing, never from a model's say-so. It is differential:
1. on fresh copies of the vulnerable tree, with a fresh nonce the proposer has never seen,
   the nonce must land in the oracle file *and* the write must happen with genuine victim
   code on the call stack, on every run;
2. on a control copy without the flaw, the same exploit must NOT reach the oracle;
3. when a reference exploit exists, the innermost victim function at the oracle write must
   be the one the reference exploit goes through (the flawed code path), not just any
   victim code (a benign callback through an unpatched helper does not count).

The vulnerable copies and the control look alike (same basename and depth, random parent
dirs) and the control runs at a random position, so an exploit cannot cheaply tell them apart.

Strength:
- ``verified``  reference-patched control AND the flawed function confirmed (2 + 3);
- ``reachable`` otherwise (e.g. Red-hunt finds: null-victim control, no reference exploit):
  the oracle is written by victim code and the effect disappears without the victim, but
  that this is *the* flaw is unconfirmed.

Known limit: the provenance record is made inside the exploit's process (userland guard),
so code written specifically to beat the gate (e.g. by digging the guard's state out of
gc) can still forge it. The gate is built to catch a model's false claims of success.
"""
import os
import secrets
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from wreckless import ui
from wreckless.sandbox import Enclave, OracleResult

_RNG = secrets.SystemRandom()


@dataclass
class Verdict:
    passed: bool
    reason: str
    result: OracleResult
    control: str | None = None    # "reference-patched" | "null-victim"
    strength: str | None = None   # "verified" | "reachable" (only when passed)
    flaw_site: str = ""           # "victim/vector_sql.py:_try_eval" when known

    @property
    def verified(self) -> bool:
        return self.passed and self.strength == "verified"


def _null_victim(tree: Path) -> None:
    for f in tree.rglob("*.py"):
        if "tests" not in f.relative_to(tree).parts:
            f.write_text("")


def _neutralize(tree: Path, reference_patch: Path | None) -> str:
    if reference_patch and reference_patch.is_file():
        # The tree usually sits inside some other git repo (runs/ is under ours). There `git apply`
        # resolves paths from that repo's root and silently skips everything outside cwd: exit 0,
        # nothing patched. Stop repo discovery at the tree, and check the patch now reverses cleanly.
        env = {**os.environ, "GIT_CEILING_DIRECTORIES": str(tree.resolve().parent)}
        patch = str(reference_patch.resolve())
        p = subprocess.run(["git", "apply", "--recount", patch], cwd=tree, env=env,
                           capture_output=True, text=True)
        landed = p.returncode == 0 and subprocess.run(
            ["git", "apply", "--recount", "--reverse", "--check", patch], cwd=tree, env=env,
            capture_output=True).returncode == 0
        if landed:
            return "reference-patched"
        ui.say("gate", f"reference patch does not apply here ({p.stderr.strip()[:80]}) → null-victim control")
    _null_victim(tree)
    return "null-victim"


def _site(r: OracleResult, tree: Path) -> str:
    try:
        rel = Path(r.via_victim).resolve().relative_to(tree.resolve()).as_posix()
    except ValueError:
        rel = Path(r.via_victim).name
    return f"{rel}:{r.via_func}"


def verify(script: Path, victim: Path, enclave: Enclave, extra_args: list[str] = (),
           env: dict | None = None, runs: int = 2, reference_patch: Path | None = None,
           reference_exploit: Path | None = None) -> Verdict:
    arena = enclave.root / ".gate" / secrets.token_hex(4)

    def copy() -> Path:
        d = arena / secrets.token_hex(4) / victim.name
        shutil.copytree(victim, d, ignore=shutil.ignore_patterns(".git", "__pycache__"))
        return d

    try:
        vulns, ctl = [copy() for _ in range(runs)], copy()
        kind = _neutralize(ctl, reference_patch)

        flaw = None
        if kind == "reference-patched" and reference_exploit and reference_exploit.is_file():
            t = copy()
            ref = enclave.run_exploit(reference_exploit, t, (), env)
            if ref.hit and ref.via_victim:
                flaw = _site(ref, t)
            else:
                ui.say("gate", "reference exploit did not reach the oracle here → flawed function unknown")

        ui.say("gate", f"running {script.name}: {runs}× vulnerable + 1× {kind} control, random order, "
                       f"fresh nonce each" + (f" · flawed path {flaw}" if flaw else ""))
        order = vulns + [ctl]
        _RNG.shuffle(order)
        res = {t: enclave.run_exploit(script, t, extra_args, env) for t in order}
    finally:
        shutil.rmtree(arena, ignore_errors=True)

    last = res[vulns[-1]]
    for t in vulns:
        r = res[t]
        if not r.hit:
            return Verdict(False, "oracle not reached", r, kind)
        if r.violation:
            return Verdict(False, "the exploit tripped the enclave guard", r, kind)
        if r.via_victim is None:
            return Verdict(False, "nonce written by the exploit script itself, not via victim code", r, kind)
    if res[ctl].hit:
        return Verdict(False, f"oracle also reached on the {kind} control: not caused by the target flaw",
                       res[ctl], kind)
    sites = {_site(res[t], t) for t in vulns}
    if flaw and sites != {flaw}:
        return Verdict(False, f"oracle written from {', '.join(sorted(sites))}, not the flawed code path "
                              f"({flaw})", last, kind, flaw_site=flaw)

    site = next(iter(sites))
    if flaw:
        ui.say("gate", f"oracle reached via \033[1m{site}\033[0m on every run, not on the {kind} control → VERIFIED")
        return Verdict(True, f"oracle written from {site} (the flawed path); blocked on the {kind} control",
                       last, kind, "verified", flaw)
    ui.say("gate", f"oracle reached via \033[1m{site}\033[0m, not on the {kind} control → "
                   f"REACHABLE (flaw unconfirmed: no reference exploit to confirm the flawed path)")
    return Verdict(True, f"oracle written from {site}; blocked on the {kind} control; flawed path unconfirmed",
                   last, kind, "reachable", "")
