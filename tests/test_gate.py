import json

import pytest

from wreckless import gate
from wreckless.config import BENCHMARKS
from wreckless.queue import CandidateQueue

HERO = BENCHMARKS / "CVE-2024-21513" / "known_good" / "repro_exploit.py"

DECOYS = {
    # prints the success token but never makes the vulnerable code write the nonce
    "fake_hit": "print('ORACLE_HIT')\n",
    # self-certifies in JSON; the gate must not read claims
    "json_claim": "import json; print(json.dumps({'success': True, 'verified': True, "
                  "'label': 'CONFIRMED_BY_REPRO', 'oracle': 'ORACLE_HIT'}))\n",
    # writes the wrong value into the oracle file
    "wrong_nonce": "import os, pathlib; pathlib.Path(os.environ['WRECKLESS_ORACLE']).write_text('x')\n"
                   "print('ORACLE_HIT')\n",
    "hang": "import time; time.sleep(30)\n",
}


def _gate(tmp_path, script, timeout=30, **extra):
    q = CandidateQueue(tmp_path / "q")
    q.put({"source": "red-hunt", "cve": None, "target": "victim_app",
           "repro_script": str(script), **extra})
    it = q.claim()
    return it, gate.run(it, tmp_path / "work", timeout=timeout)


def test_gate_verifies_hero_exploit(tmp_path):
    it, v = _gate(tmp_path, HERO)
    assert v.verified and v.reason == "oracle_fired" and v.oracle_file_ok and v.exit_code == 0
    assert it.state == "verified" and it.label == "CONFIRMED_BY_REPRO"
    assert json.loads(it.path.read_text())["label"] == "CONFIRMED_BY_REPRO"


@pytest.mark.parametrize("name", ["fake_hit", "json_claim", "wrong_nonce"])
def test_gate_rejects_decoys(tmp_path, name):
    s = tmp_path / f"{name}.py"
    s.write_text(DECOYS[name])
    it, v = _gate(tmp_path, s, success=True, label="CONFIRMED_BY_REPRO")
    assert not v.verified and not v.oracle_file_ok
    assert v.reason == "oracle_claim_without_nonce"  # all three print/echo ORACLE_HIT
    assert it.state == "rejected" and it.label == "PREDICTION"


def test_gate_rejects_timeout(tmp_path):
    s = tmp_path / "hang.py"
    s.write_text(DECOYS["hang"])
    it, v = _gate(tmp_path, s, timeout=2)
    assert not v.verified and v.reason == "timeout_2s" and it.state == "rejected"


def test_gate_rejects_missing_script_and_bad_target(tmp_path):
    assert gate.verify({"repro_script": None, "target": "victim_app"}, tmp_path).reason == "no_repro_script"
    assert gate.verify({"repro_script": str(HERO), "target": "../etc"},
                       tmp_path).reason.startswith("unknown_target")


def test_gate_requires_claimed_item(tmp_path):
    it = CandidateQueue(tmp_path).put({"source": "purple", "repro_script": str(HERO)})
    with pytest.raises(RuntimeError):
        gate.run(it, tmp_path / "w")
