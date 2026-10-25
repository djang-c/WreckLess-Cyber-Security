"""Regressions for the pipeline review: validation verdicts, exploit mode, Blue's fallback
commit, queue claims and failure states, restart-safe hunting, LLM errors, ref injection."""
import subprocess
import sys
from pathlib import Path

import pytest

from wreckless import llm
from wreckless.agents import blue, red
from wreckless.candidates import CandidateQueue
from wreckless.config import BENCHMARKS, TARGETS, Settings
from wreckless.events import EventLog
from wreckless.gitops import git, init_victim, worktree
from wreckless.sandbox import Enclave, OracleResult
from wreckless.swarm import Swarm

CVE = "CVE-2024-21513"


@pytest.fixture(autouse=True)
def no_slack(monkeypatch):
    for k in ("SLACK_BOT_TOKEN", "SLACK_WEBHOOK_URL"):
        monkeypatch.delenv(k, raising=False)


@pytest.fixture
def item(tmp_path):
    d = tmp_path / "item"
    d.mkdir()
    enclave = Enclave(d, sys.executable, backend="userland")
    commit = init_victim(TARGETS / "victim_app", d / "victim-src")
    wt = worktree(d / "victim-src", d / "wt-blue", "wreckless/fix-test")
    report = {"id": "t", "cve": CVE, "commit": commit, "attack_trace": "",
              "repro_script": str(BENCHMARKS / CVE / "known_good" / "repro_exploit.py")}
    yield wt, enclave, report, d
    enclave.close()


def _queue(tmp_path) -> CandidateQueue:
    return CandidateQueue(tmp_path / "queue.db", EventLog(tmp_path / "events.jsonl"))


# ---------- validation verdict ----------

def _oracle(hit, rc, out=""):
    return OracleResult(hit, None, out, "userland-guard", [], rc)


@pytest.mark.parametrize("r,blocked", [
    (_oracle(False, 0), True),          # an LLM exploit that exits 0 on a miss: still blocked
    (_oracle(False, 1), True),
    (_oracle(True, 1), False),          # nonce landed: not blocked, whatever the exit code says
    (_oracle(False, 124, "TIMEOUT after 120s"), False),   # inconclusive
])
def test_exploit_verdict_reads_the_oracle_not_the_exit_code(r, blocked):
    assert blue._exploit_verdict(r)[0] is blocked


def test_patched_tree_blocks_exploit_that_exits_zero_on_a_miss(item):
    wt, enclave, report, d = item
    git(wt, "apply", str(BENCHMARKS / CVE / "known_good" / "fix.patch"))
    lenient = d / "lenient.py"
    src = Path(report["repro_script"]).read_text()
    assert "sys.exit(0 if hit else 1)" in src
    lenient.write_text(src.replace("sys.exit(0 if hit else 1)", "sys.exit(0)"))
    v = blue.validate(wt, enclave, report | {"repro_script": str(lenient)})
    assert v.exploit_blocked, v.logs.get("exploit")


def test_agentic_reports_rerun_in_agentic_mode():
    args, env = blue._exploit_mode({"agentic": True}, Settings())
    assert args == ["--agentic"] and "VICTIM_LLM_URL" in env
    assert blue._exploit_mode({"agentic": False}, Settings()) == ([], {})


# ---------- Blue's patch and fallback ----------

def test_worktree_diff_includes_new_files(item):
    wt, *_ = item
    (wt / "victim" / "brand_new.py").write_text("X = 1\n")
    assert "brand_new.py" in blue.worktree_diff(wt)


def test_cached_fallback_drops_untracked_llm_files(item, monkeypatch):
    wt, enclave, report, d = item
    monkeypatch.setattr(llm, "reachable", lambda ep: True)

    def half_done(*a, **k):
        (wt / "victim" / "llm_leftover.py").write_text("junk = 1\n")
        raise llm.LLMError("context overflow")
    monkeypatch.setattr(llm, "run_agent", half_done)
    diff, source = blue.defend(report, wt, enclave, d, Settings(demo_mode=True))
    assert source == "fallback" and "llm_leftover" not in diff
    assert not (wt / "victim" / "llm_leftover.py").exists()


def test_changed_paths_are_not_c_quoted(item):
    wt, _, report, _ = item
    weird = wt / "tests" / "tab\tname.py"
    weird.write_text("x = 1\n")
    paths = blue._changed_paths(wt, report["commit"])
    assert "tests/tab\tname.py" in paths and blue.forbidden("tests/tab\tname.py")


# ---------- queue ----------

def test_claimed_enqueue_is_never_offered_to_workers(tmp_path):
    q = _queue(tmp_path)
    hero = q.enqueue("purple", "hero", cve=CVE, claim="gate")
    assert q.get(hero).state == "verifying"
    assert q.claim_next("gate") is None


def test_claim_next_takes_each_item_once(tmp_path):
    q = _queue(tmp_path)
    a = q.enqueue("purple", "a")
    assert q.claim_next("gate") == a and q.claim_next("gate") is None


@pytest.mark.parametrize("path,terminal", [
    (["verifying", "verified"], "patch_failed"),
    (["verifying", "verified", "patching", "patched"], "notify_failed"),
])
def test_crash_in_any_in_flight_state_reaches_a_terminal_state(tmp_path, path, terminal):
    q = _queue(tmp_path)
    i = q.enqueue("purple", "x")
    for s in path:
        q.advance(i, s, "test")
    assert q.recover() == [i]
    assert q.get(i).state == terminal


def test_process_crash_after_verify_fails_the_item(tmp_path, monkeypatch):
    sw = Swarm(Settings(use_llm=False), tmp_path)
    monkeypatch.setattr("wreckless.swarm.Notifier", lambda **k: (_ for _ in ()).throw(RuntimeError("slack down")))
    with pytest.raises(RuntimeError):
        sw.run_hero(CVE)
    assert sw.queue.all()[0].state == "patch_failed"


# ---------- daemon restarts / producer threads ----------

def test_hunt_dirs_continue_after_an_earlier_run(tmp_path):
    (tmp_path / "hunts" / "pass-0001").mkdir(parents=True)
    (tmp_path / "hunts" / "pass-0007").mkdir()
    n, d = Swarm(Settings(use_llm=False), tmp_path)._new_hunt_dir()
    assert n == 8 and d.name == "pass-0008"


def test_hunt_loop_survives_a_crashing_pass(tmp_path, monkeypatch):
    sw = Swarm(Settings(use_llm=False), tmp_path)
    monkeypatch.setattr(sw, "_hunt_pass", lambda: (_ for _ in ()).throw(FileExistsError("pass-0001")))
    sw.red_hunt_loop(pause=0)   # use_llm=False: one pass, then return instead of dying


def test_purple_loop_survives_a_bad_advisory(tmp_path, monkeypatch):
    sw = Swarm(Settings(use_llm=False), tmp_path)
    calls = []

    def boom(cve, claim=None):
        calls.append(cve)
        sw.stop.set()
        raise ValueError("bad advisory")
    monkeypatch.setattr(sw, "submit_cve", boom)
    sw.purple_loop(interval=0)
    assert calls


# ---------- LLM errors and Red's tools ----------

def test_red_llm_error_falls_back_to_cached_exploit(item, monkeypatch):
    wt, enclave, _, d = item
    monkeypatch.setattr(llm, "reachable", lambda ep: True)
    monkeypatch.setattr(llm, "run_agent", lambda *a, **k: (_ for _ in ()).throw(llm.LLMError("timeout")))
    intel = {"id": CVE, "description": "x", "affected_file": "victim/vector_sql.py"}
    prop = red.attack(intel, wt, enclave, d, Settings(demo_mode=True))
    assert prop and prop.source == "fallback"


@pytest.mark.parametrize("ref", ["--orphan=x", "-b", "main\n--", "nope-no-such-branch"])
def test_git_checkout_rejects_option_like_or_unknown_refs(item, ref):
    wt, enclave, _, d = item
    tools = red.RedTools(wt, enclave, d, Settings())
    assert tools.git_checkout(ref).startswith("ERROR")
    assert git(wt, "rev-parse", "--abbrev-ref", "HEAD") == "wreckless/fix-test"


def test_git_checkout_still_switches_real_branches(item):
    wt, enclave, _, d = item
    git(wt, "branch", "other")
    assert red.RedTools(wt, enclave, d, Settings()).git_checkout("other") == "checked out other"
    assert subprocess.run(["git", "rev-parse", "--abbrev-ref", "HEAD"], cwd=wt, capture_output=True,
                          text=True).stdout.strip() == "other"


def test_a_verified_exploit_under_another_name_becomes_the_contract_script(item):
    """Live run: Ralph's winning script was simple_exploit.py, and the gate only takes repro_exploit.py."""
    import shutil
    wt, enclave, _, d = item
    shutil.copy(BENCHMARKS / CVE / "known_good" / "repro_exploit.py", d / "simple_exploit.py")
    tools = red.RedTools(wt, enclave, d, Settings())
    assert "VERIFIED-ELIGIBLE" in tools.sandbox_exec("simple_exploit.py")
    assert tools.eligible and (d / "repro_exploit.py").read_bytes() == (d / "simple_exploit.py").read_bytes()


def test_write_file_always_saves_the_contract_script_and_sandbox_exec_finds_it(item):
    import shutil
    wt, enclave, _, d = item
    tools = red.RedTools(wt, enclave, d, Settings())
    ref = (BENCHMARKS / CVE / "known_good" / "repro_exploit.py").read_text()
    assert "repro_exploit.py" in tools.write_file("exploit.py", ref) and not (d / "exploit.py").exists()
    assert "VERIFIED-ELIGIBLE" in tools.sandbox_exec("exploit.py")   # the name the model remembers


def test_a_script_that_grades_itself_is_told_the_hosts_check_is_exact(item, monkeypatch):
    """Batch 3: `echo NONCE > oracle` leaves a newline, the script's strip() printed ORACLE_HIT, the host said no."""
    from types import SimpleNamespace
    wt, enclave, _, d = item
    (d / "repro_exploit.py").write_text("print('ORACLE_HIT')\n")
    monkeypatch.setattr(enclave, "run_exploit", lambda *a, **k: SimpleNamespace(
        verified=False, hit=False, backend="x", output="ORACLE_HIT\n"))
    out = red.RedTools(wt, enclave, d, Settings()).sandbox_exec("repro_exploit.py")
    assert "ORACLE NOT REACHED" in out and "no trailing newline" in out
