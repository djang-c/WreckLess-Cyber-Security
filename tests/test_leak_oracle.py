"""The leak oracle (``# wreckless-oracle: leak``): what counts as a leak and what must not.

Uses the aiohttp_app tree. The host plants a fresh secret outside the victim tree; a script has to get it
from the victim. Reading it directly is a guard violation, getting it without the flaw also gets it on
the control, and the oracle must equal the secret exactly. Nonce mode is covered by test_gate.py.
"""
import sys
from pathlib import Path

import pytest

from wreckless import gate, targets
from wreckless.config import BENCHMARKS
from wreckless.gitops import init_victim
from wreckless.sandbox import Enclave, is_leak_script

TARGET = targets.load("aiohttp_app")
KG = BENCHMARKS / "CVE-2024-23334" / "known_good"
HEAD = "# wreckless-oracle: leak\nimport os, pathlib, subprocess, sys\n"


def _item(tmp_path):
    d = tmp_path / "item"
    d.mkdir()
    victim = d / "victim-src"
    init_victim(TARGET.source, victim)
    return victim, Enclave(d, sys.executable)


def _script(tmp_path, body, marker=True):
    p = tmp_path / "x.py"
    p.write_text((HEAD if marker else HEAD.replace("# wreckless-oracle: leak\n", "")) + body)
    return p


def _verify(tmp_path, script):
    victim, enclave = _item(tmp_path)
    return gate.verify(script, victim, enclave, reference_patch=KG / "fix.patch")


def test_marker_detection(tmp_path):
    assert is_leak_script(_script(tmp_path, "pass\n"))
    assert not is_leak_script(_script(tmp_path, "pass\n", marker=False))
    p = tmp_path / "late.py"
    p.write_text("x = 1\n" * 1000 + "# wreckless-oracle: leak\n")
    assert not is_leak_script(p)   # only the first 2 KB count


def test_leak_script_gets_a_secret_path_and_no_nonce(tmp_path):
    victim, enclave = _item(tmp_path)
    s = _script(tmp_path, "print('NONCE' , 'WRECKLESS_NONCE' in os.environ, 'SECRET', os.path.isfile(os.environ['WRECKLESS_SECRET_FILE']))\n")
    out = enclave.run_exploit(s, victim).output
    assert "NONCE False" in out and "SECRET True" in out


def test_the_secret_is_fresh_every_run_and_removed_afterwards(tmp_path):
    victim, enclave = _item(tmp_path)
    s = _script(tmp_path, "print('P', os.environ['WRECKLESS_SECRET_FILE'])\n")
    a = enclave.run_exploit(s, victim).output.split("P ")[1].split()[0]
    b = enclave.run_exploit(s, victim).output.split("P ")[1].split()[0]
    assert a != b
    assert not list(enclave.guard_dir.glob("secret_*"))


def test_payload_reading_the_secret_itself_is_a_violation(tmp_path):
    s = _script(tmp_path, "d = open(os.environ['WRECKLESS_SECRET_FILE']).read()\n"
                          "pathlib.Path(os.environ['WRECKLESS_ORACLE']).write_text(d)\nprint('ORACLE_HIT')\n")
    v = _verify(tmp_path, s)
    assert not v.passed and v.result.violation and "[enclave-violation]" in v.result.output, v.reason


def test_child_process_reading_the_secret_is_caught_by_the_control(tmp_path):
    """The guard cannot see a child process; the control run, which has no flaw, still gives the secret."""
    s = _script(tmp_path, "d = subprocess.run(['cat', os.environ['WRECKLESS_SECRET_FILE']], capture_output=True, text=True).stdout\n"
                          "pathlib.Path(os.environ['WRECKLESS_ORACLE']).write_text(d)\nprint('ORACLE_HIT')\n")
    v = _verify(tmp_path, s)
    assert not v.passed and "control" in v.reason, v.reason


def test_a_guess_is_a_miss(tmp_path):
    s = _script(tmp_path, "pathlib.Path(os.environ['WRECKLESS_ORACLE']).write_text('0' * 24)\nprint('ORACLE_HIT')\n")
    v = _verify(tmp_path, s)
    assert not v.passed and "oracle not reached" in v.reason


def test_a_script_that_reads_nothing_from_the_victim_is_a_miss(tmp_path):
    s = _script(tmp_path, "print('ORACLE_MISS')\n")
    assert not _verify(tmp_path, s).passed


def test_nonce_mode_is_unchanged_without_the_marker(tmp_path):
    """No marker: the old contract. Writing the nonce from the script itself is still rejected."""
    victim, enclave = _item(tmp_path)
    s = _script(tmp_path, "pathlib.Path(os.environ['WRECKLESS_ORACLE']).write_text(os.environ['WRECKLESS_NONCE'])\n", marker=False)
    r = enclave.run_exploit(s, victim)
    assert r.hit and not r.leak and not r.verified
