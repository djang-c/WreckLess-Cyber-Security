"""The verify gate: the only thing allowed to promote a PREDICTION. Deterministic, no LLM.

Exploit-as-test using the existing WreckLess oracle convention (red.py RedTools.oracle_env,
blue.py _exploit, known_good/repro_exploit.py):
    env WRECKLESS_ORACLE = <enclave.root>/tmp/oracle_<hex4>   (a file path)
    env WRECKLESS_NONCE  = <hex8>
    argv = [python, repro_script, <victim_repo>]
    success = the oracle file contains exactly NONCE; the script prints ORACLE_HIT / exits 0.

The gate is stricter than trusting stdout: it holds the nonce itself and reads the oracle
file host-side. Verified requires ALL of: oracle file == nonce, exit 0, ORACLE_HIT printed.
Nothing the candidate says about itself (labels, "success": true, attack traces) is read.

Known limit (UNVERIFIED as a security property): the script receives the nonce in its env,
so a script that writes the oracle file *directly* (not through the vulnerable code path)
would pass. Blue's validate() re-running the same exploit on the patched tree (must MISS)
is the differential control that catches that for items that reach Blue.
"""
import hashlib
import secrets
import shutil
import sys
from dataclasses import asdict, dataclass
from pathlib import Path

from wreckless.config import TARGETS
from wreckless.gitops import init_victim
from wreckless.lifecycle import CONFIRMED, Item
from wreckless.sandbox import Enclave

DEFAULT_TIMEOUT_S = 60


@dataclass
class Verdict:
    verified: bool
    reason: str
    exit_code: int | None = None
    oracle_file_ok: bool = False
    stdout_claims_hit: bool = False
    backend: str = ""
    script_sha256: str = ""
    output: str = ""


def victim_src(work: Path, target: str) -> Path:
    """The vulnerable target as a fresh git repo under the item's work dir (created once)."""
    src = work / "victim-src"
    if not src.exists():
        init_victim(TARGETS / target, src)
    return src


def verify(candidate: dict, work: Path, timeout: int = DEFAULT_TIMEOUT_S,
           python: str = sys.executable) -> Verdict:
    """Run the candidate's exploit against the vulnerable target and read the oracle."""
    script_in = candidate.get("repro_script")
    if not script_in or not Path(script_in).is_file():
        return Verdict(False, "no_repro_script")
    target = candidate.get("target") or ""
    if not target or not (TARGETS / target).is_dir() or Path(target).name != target:
        return Verdict(False, f"unknown_target:{target}")

    work.mkdir(parents=True, exist_ok=True)
    exploit_dir = work / "exploit"
    exploit_dir.mkdir(exist_ok=True)
    script = exploit_dir / "repro_exploit.py"  # immutable snapshot of what was actually run
    shutil.copy(script_in, script)
    sha = hashlib.sha256(script.read_bytes()).hexdigest()
    src = victim_src(work, target)

    enclave = Enclave(work, python)
    oracle = enclave.root / "tmp" / f"oracle_{secrets.token_hex(4)}"
    nonce = secrets.token_hex(8)
    r = enclave.run([enclave.python, str(script), str(src)],
                    env={"WRECKLESS_ORACLE": str(oracle), "WRECKLESS_NONCE": nonce},
                    timeout=timeout)
    file_ok = oracle.is_file() and oracle.read_text() == nonce
    claims = "ORACLE_HIT" in r.output
    base = dict(exit_code=r.returncode, oracle_file_ok=file_ok, stdout_claims_hit=claims,
                backend=r.backend, script_sha256=sha, output=r.output[-2000:])

    if r.returncode == 124 and r.output.startswith("TIMEOUT"):
        return Verdict(False, f"timeout_{timeout}s", **base)
    if file_ok and r.returncode == 0 and claims:
        return Verdict(True, "oracle_fired", **base)
    if claims and not file_ok:
        return Verdict(False, "oracle_claim_without_nonce", **base)
    if file_ok:
        return Verdict(False, "oracle_written_but_script_failed", **base)
    return Verdict(False, "oracle_not_fired", **base)


def run(item: Item, work: Path, timeout: int = DEFAULT_TIMEOUT_S) -> Verdict:
    """Gate a claimed item: verifying -> verified (label CONFIRMED_BY_REPRO) | rejected."""
    if item.state != "verifying":
        raise RuntimeError(f"gate needs a claimed (verifying) item, got {item.state}")
    v = verify(item.candidate, work, timeout)
    payload = {k: val for k, val in asdict(v).items() if k != "output"}
    work.mkdir(parents=True, exist_ok=True)
    item.artifact("gate_output", _write(work / "gate_output.txt", v.output))
    if v.verified:
        item.doc["label"] = CONFIRMED
        item.advance("verified", "gate", payload)
    else:
        item.advance("rejected", "gate", payload)
    return v


def _write(p: Path, text: str) -> Path:
    p.write_text(text)
    return p
