import json
import sys

import pytest

from wreckless.agents import blue
from wreckless.cli import run
from wreckless.config import BENCHMARKS, TARGETS, Settings
from wreckless.gitops import init_victim
from wreckless.sandbox import Enclave
from wreckless.state import StateMachine

CVE = "CVE-2024-21513"


def test_scripted_pipeline_reaches_notified(tmp_path, monkeypatch):
    monkeypatch.delenv("SLACK_BOT_TOKEN", raising=False)
    monkeypatch.delenv("SLACK_WEBHOOK_URL", raising=False)
    doc = run(CVE, Settings(use_llm=False), runs_dir=tmp_path)
    assert doc["state"] == "NOTIFIED"
    states = [h["to"] for h in doc["history"]]
    assert states == ["INTEL_READY", "EXPLOITING", "EXPLOIT_VERIFIED", "PATCHING",
                      "PATCH_VALIDATED", "NOTIFIED"]
    report = json.loads(open(doc["artifacts"]["vulnerability_report"]).read())
    assert {"cve", "commit", "repro_script", "attack_trace"} <= report.keys()


def test_oracle_rejects_unpatched_victim(tmp_path):
    """The held-out test and exploit check must fail on vulnerable code, or they prove nothing."""
    src = tmp_path / "victim"
    init_victim(TARGETS / "victim_app", src)
    enclave = Enclave(tmp_path, sys.executable)
    script = BENCHMARKS / CVE / "known_good" / "repro_exploit.py"
    v = blue.validate(CVE, src, enclave, {"repro_script": str(script)})
    assert not v.regression
    assert v.functional
    assert not v.exploit_blocked


@pytest.mark.parametrize("code,needle", [
    ("open('/home/escape_test_wreckless','w')", "write outside sandbox blocked"),
    ("import socket; socket.create_connection(('1.1.1.1', 443), timeout=2)", "egress blocked"),
])
def test_enclave_guard_blocks(tmp_path, code, needle):
    r = Enclave(tmp_path, sys.executable).run([sys.executable, "-c", code])
    assert r.returncode != 0 and needle in r.output


def test_state_machine_rejects_skips(tmp_path):
    sm = StateMachine(tmp_path, "x")
    with pytest.raises(RuntimeError):
        sm.advance("PATCHING", "blue")
