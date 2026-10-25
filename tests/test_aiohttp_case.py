"""Case CVE-2024-23334 (target aiohttp_app): a static route with follow_symlinks=True serves files outside its
folder for a request path with dot segments. Leak oracle: see wreckless/sandbox.py and test_leak_oracle.py.

Every lazy fix in tests/fixtures/bypass/cve-2024-23334_* is applied to a Blue worktree and run through
``blue.validate`` exactly as ``Swarm.process`` does.
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

CASE = "CVE-2024-23334"
TARGET = targets.load("aiohttp_app")
KG = BENCHMARKS / CASE / "known_good"
FIX = Path(__file__).parent / "fixtures" / "bypass"
# lazy fix -> does it at least stop the reference exploit?
LAZY = {"cve-2024-23334_disable_follow": True, "cve-2024-23334_dotdot_filter": True,
        "cve-2024-23334_startswith": True, "cve-2024-23334_raw_filter": True}


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
    assert v.result.leak and "static.py" in v.flaw_site


def test_reference_fix_passes_all_checks(tmp_path):
    v = _validate(tmp_path, KG / "fix.patch")
    assert v.ok, _logs(v)
    assert v.regression and v.functional and v.exploit_blocked and v.rejected is None
    assert v.hardening == "3/3", _logs(v)


def test_vulnerable_tree_fails_the_held_out_tests(tmp_path):
    v = _validate(tmp_path, None)
    assert v.regression is False and not v.exploit_blocked and v.functional and not v.ok


@pytest.mark.parametrize("name", list(LAZY))
def test_lazy_fixes_fail_the_held_out_tests(tmp_path, name):
    v = _validate(tmp_path, FIX / f"{name}.patch")
    assert v.exploit_blocked is LAZY[name], _logs(v)
    assert v.regression is False and not v.ok, _logs(v)


def test_static_check_rejects_a_fix_keyed_on_the_lab(tmp_path):
    d, enclave, _ = _item(tmp_path)
    wt = worktree(d / "victim-src", d / "wt-blue", "wreckless/fix-test")
    (wt / "victim" / "static.py").write_text(
        (wt / "victim" / "static.py").read_text().replace(
            "            filename = Path(rel_url)\n",
            "            if 'secret_' in rel_url:\n                raise HTTPError(404, 'Not Found')\n            filename = Path(rel_url)\n"))
    r = blue._held_out(enclave, wt, BENCHMARKS / CASE / "static_test.py", TARGET.adapter)
    assert r.returncode != 0 and "lab's plumbing" in r.output


def test_scripted_item_walks_full_lifecycle(tmp_path):
    swarm = Swarm(Settings(use_llm=False, target="aiohttp_app"), tmp_path)
    assert swarm.run_hero(CASE) == "notified"
    item = swarm.queue.all()[0]
    assert item.label == "VERIFIED"
    assert [h["to"] for h in item.history] == ["verifying", "verified", "patching", "patched", "notified"]
