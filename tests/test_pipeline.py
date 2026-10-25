import sys

import pytest

from wreckless import gate
from wreckless.agents import blue
from wreckless.candidates import CandidateQueue
from wreckless.config import BENCHMARKS, TARGETS, Settings
from wreckless.events import EventLog, replay
from wreckless.gitops import git, init_victim
from wreckless.sandbox import Enclave
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
    return src, Enclave(tmp_path, sys.executable)


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


FORGED = {
    # compile() with a victim filename fakes co_filename; the code object is still the script's
    "forged_filename": (
        "import os, sys\n"
        "src = \"open(os.environ['WRECKLESS_ORACLE'],'w').write(os.environ['WRECKLESS_NONCE'])\"\n"
        "exec(compile(src, os.path.join(os.path.realpath(sys.argv[1]), 'victim', 'vector_sql.py'), 'exec'))\n"),
    # plant oracle-writing code in the victim tree, then import it as victim code
    "planted_module": (
        "import os, sys, pathlib\n"
        "root = pathlib.Path(sys.argv[1]).resolve()\n"
        "(root / 'victim' / 'planted.py').write_text(\"import os\\n\"\n"
        "  \"def go(): open(os.environ['WRECKLESS_ORACLE'],'w').write(os.environ['WRECKLESS_NONCE'])\\n\")\n"
        "sys.path.insert(0, str(root)); import victim.planted; victim.planted.go()\n"),
}


@pytest.mark.parametrize("name", FORGED)
def test_gate_rejects_forged_provenance(victim, tmp_path, name):
    src, enclave = victim
    cheat = tmp_path / f"{name}.py"
    cheat.write_text(FORGED[name] + "print('ORACLE_HIT')\n")
    v = gate.verify(cheat, src, enclave)
    assert not v.verified, v.result.output


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
    r = Enclave(tmp_path, sys.executable).run([sys.executable, "-c", code])
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
