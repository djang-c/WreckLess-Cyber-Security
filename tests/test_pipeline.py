import sys

import pytest

from wreckless import gate
from wreckless.agents import blue
from wreckless.candidates import CandidateQueue
from wreckless.config import BENCHMARKS, TARGETS, Settings
from wreckless.events import EventLog, replay
from wreckless.gitops import git, init_victim
from wreckless.sandbox import Enclave, openshell_available
from wreckless.swarm import Swarm

CVES = ["CVE-2024-21513", "CVE-2023-44467"]
LIFECYCLE = ["verifying", "verified", "patching", "patched", "notified"]


@pytest.fixture(autouse=True)
def no_slack(monkeypatch):
    for k in ("SLACK_BOT_TOKEN", "SLACK_WEBHOOK_URL"):
        monkeypatch.delenv(k, raising=False)


@pytest.fixture
def victim(tmp_path):
    src = tmp_path / "victim"
    init_victim(TARGETS / "victim_app", src)
    enclave = Enclave(tmp_path, sys.executable)
    yield src, enclave
    enclave.close()


@pytest.mark.parametrize("cve", CVES)
def test_scripted_item_walks_full_lifecycle(tmp_path, cve):
    swarm = Swarm(Settings(use_llm=False), tmp_path)
    assert swarm.run_hero(cve) == "notified"
    item = swarm.queue.all()[0]
    assert item.label == "VERIFIED"
    assert [h["to"] for h in item.history] == LIFECYCLE
    assert (tmp_path / "events.jsonl").stat().st_size > 0


@pytest.mark.parametrize("cve", CVES)
def test_gate_verifies_reference_exploit_via_victim_code(victim, cve):
    src, enclave = victim
    v = gate.verify(BENCHMARKS / cve / "known_good" / "repro_exploit.py", src, enclave)
    assert v.verified and "victim" in v.result.via_victim


def test_gate_rejects_exploit_that_writes_oracle_itself(victim, tmp_path):
    """Red can't grade its own homework: writing the nonce directly is not an exploit."""
    src, enclave = victim
    cheat = tmp_path / "cheat.py"
    cheat.write_text("import os, pathlib\n"
                     "pathlib.Path(os.environ['WRECKLESS_ORACLE']).write_text(os.environ['WRECKLESS_NONCE'])\n"
                     "print('ORACLE_HIT')\n")
    v = gate.verify(cheat, src, enclave)
    assert not v.verified and v.result.hit and "itself" in v.reason


@pytest.mark.parametrize("cve", CVES)
def test_validation_fails_on_unpatched_victim(victim, cve):
    """The checks must fail on vulnerable code, or passing them proves nothing."""
    src, enclave = victim
    report = {"cve": cve, "repro_script": str(BENCHMARKS / cve / "known_good" / "repro_exploit.py")}
    v = blue.validate(src, enclave, report)
    assert v.regression is False and v.functional and not v.exploit_blocked and not v.ok


def test_hardening_probes_beat_upstream_style_fix(victim):
    src, enclave = victim
    report = {"cve": "CVE-2023-44467",
              "repro_script": str(BENCHMARKS / "CVE-2023-44467" / "known_good" / "repro_exploit.py")}
    # upstream's one-word denylist fix: passes regression, fails the bypass probes
    p = src / "victim" / "pal_chain.py"
    p.write_text(p.read_text().replace('"eval"]', '"eval", "__import__"]'))
    v = blue.validate(src, enclave, report)
    assert v.ok and v.hardening == "0/3"
    # reference Blue patch: closes the bypasses too
    git(src, "checkout", "-q", "--", ".")
    git(src, "apply", str(BENCHMARKS / "CVE-2023-44467" / "known_good" / "fix.patch"))
    assert blue.validate(src, enclave, report).hardening == "3/3"


@pytest.mark.parametrize("code,needle", [
    ("open('/home/escape_test_wreckless','w')", "write outside sandbox blocked"),
    ("import socket; socket.create_connection(('1.1.1.1', 443), timeout=2)", "egress blocked"),
])
def test_enclave_guard_blocks(tmp_path, code, needle):
    enclave = Enclave(tmp_path, sys.executable)
    r = enclave.run([sys.executable, "-c", code])
    enclave.close()
    assert r.returncode != 0 and needle in r.output


def test_queue_rejects_lifecycle_skips(tmp_path):
    q = CandidateQueue(tmp_path / "q.db", EventLog(tmp_path / "e.jsonl"))
    item = q.enqueue("red-hunt", "x")
    assert q.get(item).label == "PREDICTION"
    with pytest.raises(RuntimeError):
        q.advance(item, "patching", "blue")


def test_replay_renders_recorded_run(tmp_path, capsys):
    Swarm(Settings(use_llm=False), tmp_path).run_hero(CVES[0])
    capsys.readouterr()
    replay(tmp_path / "events.jsonl", speed=1000)
    out = capsys.readouterr().out
    assert "EXPLOIT VERIFIED" in out and "done in" in out


@pytest.mark.skipif(not openshell_available(), reason="OpenShell gateway not running")
def test_openshell_blocks_even_with_guard_disabled(tmp_path):
    """`python3 -I` skips our sitecustomize guard; the kernel-level sandbox must still hold."""
    enclave = Enclave(tmp_path, sys.executable, backend="openshell")
    code = ("import socket, sys\n"
            "try:\n    socket.create_connection(('1.1.1.1', 443), timeout=5); print('EGRESS_OPEN')\n"
            "except OSError as e:\n    print('EGRESS_BLOCKED', e)\n"
            "try:\n    open('/usr/pwn', 'w'); print('FS_OPEN')\n"
            "except OSError as e:\n    print('FS_BLOCKED', e)\n")
    r = enclave.run([sys.executable, "-I", "-c", code])
    enclave.close()
    assert "EGRESS_BLOCKED" in r.output and "FS_BLOCKED" in r.output, r.output
