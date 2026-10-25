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
                    reference_patch=_ref(cve))
    assert v.verified, v.reason
    assert v.control == "reference-patched"


def test_reference_exploit_verified_against_null_control(tmp_path):
    victim, enclave = _item(tmp_path)
    v = gate.verify(BENCHMARKS / "CVE-2024-21513" / "known_good" / "repro_exploit.py", victim, enclave)
    assert v.verified, v.reason
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
                    reference_patch=bad)
    assert v.verified and v.control == "null-victim"


def test_control_tree_is_removed_and_victim_untouched(tmp_path):
    victim, enclave = _item(tmp_path)
    before = (victim / "victim" / "vector_sql.py").read_text()
    gate.verify(BENCHMARKS / "CVE-2024-21513" / "known_good" / "repro_exploit.py", victim, enclave,
                reference_patch=_ref("CVE-2024-21513"))
    assert (victim / "victim" / "vector_sql.py").read_text() == before
    assert not list(enclave.root.glob("gate-control-*"))


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
