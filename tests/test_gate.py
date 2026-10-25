"""Differential verify gate: HIT on the vulnerable tree, MISS on a control without the flaw.

Regression for 2026-10-25: a decoy that never touches the vulnerability wrote the nonce
itself, forged the provenance file (its path shared the oracle's token) and was VERIFIED."""
import sys
from pathlib import Path

import pytest

from wreckless import gate
from wreckless.config import BENCHMARKS, TARGETS
from wreckless.gitops import init_victim
from wreckless.sandbox import Enclave

CVES = ["CVE-2024-21513", "CVE-2023-44467"]

FORGE = '''
import glob, json, os, sys
oracle = os.environ["WRECKLESS_ORACLE"]
root = os.environ["WRECKLESS_SANDBOX_ROOT"]
victim_file = os.path.join(os.path.realpath(sys.argv[1]), "victim", "vector_sql.py")
open(oracle, "w").write(os.environ["WRECKLESS_NONCE"])
# forge every provenance file we can find, plus the one named after the oracle token
token = os.path.basename(oracle).split("_", 1)[1]
targets = set(glob.glob(os.path.join(root, ".enclave", "prov_*.json")))
targets.add(os.path.join(root, ".enclave", f"prov_{token}.json"))
for p in targets:
    with open(p, "w") as f:
        json.dump({"via_victim": victim_file, "frames": [victim_file]}, f)
print("ORACLE_HIT")
'''


def _item(tmp_path):
    d = tmp_path / "item"
    d.mkdir()
    victim = d / "victim-src"
    init_victim(TARGETS / "victim_app", victim)
    return victim, Enclave(d, sys.executable)


def _ref(cve):
    return BENCHMARKS / cve / "known_good" / "fix.patch"


@pytest.mark.parametrize("cve", CVES)
def test_reference_exploit_verified_against_reference_control(tmp_path, cve):
    victim, enclave = _item(tmp_path)
    v = gate.verify(BENCHMARKS / cve / "known_good" / "repro_exploit.py", victim, enclave,
                    reference_patch=_ref(cve), reference_exploit=BENCHMARKS / cve / "known_good" / "repro_exploit.py")
    assert v.verified, v.reason
    assert v.control == "reference-patched"


def test_reference_control_without_reference_exploit_is_only_reachable(tmp_path):
    victim, enclave = _item(tmp_path)
    v = gate.verify(BENCHMARKS / "CVE-2024-21513" / "known_good" / "repro_exploit.py", victim, enclave,
                    reference_patch=_ref("CVE-2024-21513"))
    assert v.passed and v.strength == "reachable" and not v.verified


def test_reference_exploit_against_null_control_is_reachable(tmp_path):
    victim, enclave = _item(tmp_path)
    v = gate.verify(BENCHMARKS / "CVE-2024-21513" / "known_good" / "repro_exploit.py", victim, enclave)
    assert v.passed and v.strength == "reachable", v.reason
    assert v.control == "null-victim"


@pytest.mark.parametrize("with_ref", [True, False])
def test_forged_provenance_decoy_rejected(tmp_path, with_ref):
    victim, enclave = _item(tmp_path)
    script = tmp_path / "forge.py"
    script.write_text(FORGE)
    v = gate.verify(script, victim, enclave, reference_patch=_ref("CVE-2024-21513") if with_ref else None)
    assert not v.verified
    assert "control" in v.reason


def test_unappliable_reference_patch_falls_back_to_null_control(tmp_path):
    victim, enclave = _item(tmp_path)
    bad = tmp_path / "bad.patch"
    bad.write_text("diff --git a/victim/nope.py b/victim/nope.py\n--- a/victim/nope.py\n"
                   "+++ b/victim/nope.py\n@@ -1 +1 @@\n-x\n+y\n")
    v = gate.verify(BENCHMARKS / "CVE-2024-21513" / "known_good" / "repro_exploit.py", victim, enclave,
                    reference_patch=bad, reference_exploit=BENCHMARKS / "CVE-2024-21513" / "known_good" / "repro_exploit.py")
    assert v.passed and v.control == "null-victim" and v.strength == "reachable"


def test_control_tree_is_removed_and_victim_untouched(tmp_path):
    victim, enclave = _item(tmp_path)
    before = (victim / "victim" / "vector_sql.py").read_text()
    gate.verify(BENCHMARKS / "CVE-2024-21513" / "known_good" / "repro_exploit.py", victim, enclave,
                reference_patch=_ref("CVE-2024-21513"))
    assert (victim / "victim" / "vector_sql.py").read_text() == before
    assert not any((enclave.root / ".gate").iterdir())


def test_oracle_and_provenance_tokens_are_independent(tmp_path):
    victim, enclave = _item(tmp_path)
    script = tmp_path / "peek.py"
    script.write_text("import os, glob\no = os.environ['WRECKLESS_ORACLE']\nopen(o, 'w').write('x')\n"
                      "print('ORACLE', o)\n"
                      "print('PROV', glob.glob(os.environ['WRECKLESS_SANDBOX_ROOT'] + '/.enclave/prov_*'))\n")
    out = enclave.run_exploit(script, victim).output
    token = out.split("ORACLE ")[1].split()[0].rsplit("_", 1)[1]
    assert "prov_" in out.split("PROV")[1], "probe must see a provenance file for the test to mean anything"
    assert f"prov_{token}" not in out


# ---------- skeptical review 2026-10-25: scripts that never use the flaw got VERIFIED ----------
# tests/fixtures/gate_bypass/ holds the reviewer's scripts verbatim.
BYPASS = Path(__file__).parent / "fixtures" / "gate_bypass"


def _verify(tmp_path, script, cve, args=()):
    victim, enclave = _item(tmp_path)
    bench = BENCHMARKS / cve / "known_good" if cve else None
    return gate.verify(script, victim, enclave, list(args),
                       reference_patch=bench / "fix.patch" if bench else None,
                       reference_exploit=bench / "repro_exploit.py" if bench else None)


@pytest.mark.parametrize("cve", CVES)
@pytest.mark.parametrize("name", ["a1_sitecustomize_forge", "a2_benign_callback",
                                  "a3_benign_callback_detect", "a4_replace_guard"])
def test_reviewer_bypasses_rejected_with_reference(tmp_path, name, cve):
    v = _verify(tmp_path, BYPASS / f"{name}.py", cve)
    assert not v.passed and not v.verified, v.reason


@pytest.mark.parametrize("name", ["a1_sitecustomize_forge", "a4_replace_guard"])
def test_guard_forgeries_rejected_without_reference(tmp_path, name):
    v = _verify(tmp_path, BYPASS / f"{name}.py", None)
    assert not v.passed, v.reason


@pytest.mark.parametrize("name", ["a2_benign_callback", "a3_benign_callback_detect"])
def test_without_reference_a_pass_is_only_reachable(tmp_path, name):
    v = _verify(tmp_path, BYPASS / f"{name}.py", None)
    assert not v.verified and v.strength != "verified"


@pytest.mark.parametrize("cve,site", [("CVE-2024-21513", "_try_eval"), ("CVE-2023-44467", "run_pal")])
def test_reference_exploits_reach_the_flawed_function(tmp_path, cve, site):
    v = _verify(tmp_path, BENCHMARKS / cve / "known_good" / "repro_exploit.py", cve)
    assert v.verified and v.strength == "verified" and v.control == "reference-patched", v.reason
    assert site in v.flaw_site


def test_hunt_find_without_reference_is_reachable_not_verified(tmp_path):
    v = _verify(tmp_path, BENCHMARKS / "CVE-2024-21513" / "known_good" / "repro_exploit.py", None)
    assert v.passed and not v.verified and v.strength == "reachable" and v.control == "null-victim"


def test_guard_file_is_restored_before_every_run(tmp_path):
    from wreckless.sandbox import GUARD
    victim, enclave = _item(tmp_path)
    enclave.run_exploit(BYPASS / "a4_replace_guard.py", victim)
    enclave.run_exploit(BENCHMARKS / "CVE-2024-21513" / "known_good" / "repro_exploit.py", victim)
    r = enclave.run_exploit(BENCHMARKS / "CVE-2024-21513" / "known_good" / "repro_exploit.py", victim)
    assert r.verified, "the replaced guard must not survive into later runs"
    assert (enclave.guard_dir / "sitecustomize.py").read_text() == GUARD


def test_guard_state_is_not_importable(tmp_path):
    victim, enclave = _item(tmp_path)
    probe = tmp_path / "probe.py"
    probe.write_text("import sitecustomize as g\n"
                     "print('NAMES', sorted(k for k in vars(g) if not k.startswith('__')))\n")
    out = enclave.run_exploit(probe, victim).output
    assert "NAMES []" in out, out


def test_vulnerable_and_control_trees_look_alike(tmp_path):
    victim, enclave = _item(tmp_path)
    probe = tmp_path / "paths.py"
    probe.write_text("import os, sys\nopen(os.path.join(os.environ['WRECKLESS_SANDBOX_ROOT'], 'seen.txt'), 'a')"
                     ".write(os.path.realpath(sys.argv[1]) + '\\n')\n"
                     + (BENCHMARKS / "CVE-2024-21513" / "known_good" / "repro_exploit.py").read_text())
    ref = BENCHMARKS / "CVE-2024-21513" / "known_good"
    gate.verify(probe, victim, enclave, reference_patch=ref / "fix.patch", reference_exploit=ref / "repro_exploit.py")
    seen = (enclave.root / "seen.txt").read_text().split()
    assert len(seen) == 3 and len(set(seen)) == 3
    assert len({Path(p).name for p in seen}) == 1 and len({len(Path(p).parts) for p in seen}) == 1
    below = [str(Path(p).relative_to(enclave.root.resolve())) for p in seen]
    assert not any("control" in p or "ref" in p for p in below), below


@pytest.mark.xfail(strict=True, reason="KNOWN LIMIT: in-process provenance can be forged by code that "
                   "digs the guard's state out of gc; needs out-of-process recording (OpenShell/kernel)")
def test_known_limit_gc_dig_forgery_is_rejected(tmp_path):
    v = _verify(tmp_path, BYPASS / "a8_gc_dig_forge.py", "CVE-2024-21513")
    assert not v.passed, v.reason
