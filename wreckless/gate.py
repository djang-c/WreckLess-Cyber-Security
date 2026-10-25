"""The single trust gate: PREDICTION -> VERIFIED | REJECTED.

The verdict comes from code executing, never from a model's say-so. A candidate is
verified only if, with a fresh nonce the proposer has never seen, the nonce lands in
the oracle file *and* the write happened with victim code on the call stack.
"""
from dataclasses import dataclass
from pathlib import Path

from wreckless import ui
from wreckless.sandbox import Enclave, OracleResult


@dataclass
class Verdict:
    verified: bool
    reason: str
    result: OracleResult


def verify(script: Path, victim: Path, enclave: Enclave, extra_args: list[str] = (),
           env: dict | None = None, runs: int = 2) -> Verdict:
    ui.say("gate", f"running {script.name} against vulnerable commit · fresh nonce × {runs}")
    last = None
    for _ in range(runs):
        last = enclave.run_exploit(script, victim, extra_args, env)
        if not last.hit:
            return Verdict(False, "oracle not reached", last)
        if last.via_victim is None:
            return Verdict(False, "nonce written by the exploit script itself, not via victim code", last)
    rel = Path(last.via_victim).name
    ui.say("gate", f"oracle reached via \033[1m{rel}\033[0m on every run → VERIFIED")
    return Verdict(True, f"oracle written from {rel}", last)
