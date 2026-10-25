"""The single trust gate: PREDICTION -> VERIFIED | REJECTED.

The verdict comes from code executing, never from a model's say-so. It is differential:
1. on the vulnerable tree, with a fresh nonce the proposer has never seen, the nonce must
   land in the oracle file *and* the write must happen with victim code on the call stack,
   on every run;
2. on a control tree without the flaw, the same exploit must NOT reach the oracle.

Anything the exploit forges in its own process (writing the nonce, faking provenance)
works just as well on the control, so (2) rejects it. The control is the reference-patched
tree when a reference fix exists, else a "null victim" (every victim module emptied).
"""
import secrets
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from wreckless import ui
from wreckless.sandbox import Enclave, OracleResult


@dataclass
class Verdict:
    verified: bool
    reason: str
    result: OracleResult
    control: str | None = None   # "reference-patched" | "null-victim" | None (not reached)


def _null_victim(tree: Path) -> None:
    for f in tree.rglob("*.py"):
        if "tests" not in f.relative_to(tree).parts:
            f.write_text("")


def _control(victim: Path, root: Path, reference_patch: Path | None) -> tuple[Path, str]:
    ctl = root / f"gate-control-{secrets.token_hex(4)}"
    shutil.copytree(victim, ctl, ignore=shutil.ignore_patterns(".git", "__pycache__"))
    if reference_patch and reference_patch.is_file():
        p = subprocess.run(["git", "apply", "--recount", str(reference_patch.resolve())], cwd=ctl,
                           capture_output=True, text=True)
        if p.returncode == 0:
            return ctl, "reference-patched"
        ui.say("gate", f"reference patch does not apply here ({p.stderr.strip()[:80]}) → null-victim control")
    _null_victim(ctl)
    return ctl, "null-victim"


def verify(script: Path, victim: Path, enclave: Enclave, extra_args: list[str] = (),
           env: dict | None = None, runs: int = 2, reference_patch: Path | None = None) -> Verdict:
    ui.say("gate", f"running {script.name} against vulnerable commit · fresh nonce × {runs}")
    last = None
    for _ in range(runs):
        last = enclave.run_exploit(script, victim, extra_args, env)
        if not last.hit:
            return Verdict(False, "oracle not reached", last)
        if last.via_victim is None:
            return Verdict(False, "nonce written by the exploit script itself, not via victim code", last)
    rel = Path(last.via_victim).name

    ctl, kind = _control(victim, enclave.root, reference_patch)
    try:
        ui.say("gate", f"differential: same exploit against the {kind} control · fresh nonce")
        c = enclave.run_exploit(script, ctl, extra_args, env)
    finally:
        shutil.rmtree(ctl, ignore_errors=True)
    if c.hit:
        return Verdict(False, f"oracle also reached on the {kind} control: not caused by the target flaw",
                       c, kind)
    ui.say("gate", f"oracle reached via \033[1m{rel}\033[0m on every run, not on the {kind} control → VERIFIED")
    return Verdict(True, f"oracle written from {rel}; blocked on the {kind} control", last, kind)
