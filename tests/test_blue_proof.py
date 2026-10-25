"""Blue's proof must fail for patches that leave the bug in (skeptical-review findings).

Every bypass fixture in tests/fixtures/bypass/ is applied to a Blue worktree and run
through ``blue.validate`` exactly as ``Swarm.process`` calls it.
"""
import sys
from pathlib import Path

import pytest

from wreckless import swarm as swarm_mod
from wreckless.agents import blue
from wreckless.config import BENCHMARKS, TARGETS, Settings
from wreckless.gitops import git, init_victim, worktree
from wreckless.sandbox import Enclave
from wreckless.swarm import Swarm

FIX = Path(__file__).parent / "fixtures" / "bypass"
CVES = ["CVE-2024-21513", "CVE-2023-44467"]


@pytest.fixture(autouse=True)
def no_slack(monkeypatch):
    for k in ("SLACK_BOT_TOKEN", "SLACK_WEBHOOK_URL"):
        monkeypatch.delenv(k, raising=False)


def _setup(tmp_path: Path, cve: str):
    """Mirror Swarm.process: enclave per item, victim-src repo, Blue worktree, report."""
    d = tmp_path / "item"
    d.mkdir()
    enclave = Enclave(d, sys.executable)
    commit = init_victim(TARGETS / "victim_app", d / "victim-src")
    wt = worktree(d / "victim-src", d / "wt-blue", "wreckless/fix-test")
    report = {"id": "test", "cve": cve, "commit": commit,
              "repro_script": str(BENCHMARKS / cve / "known_good" / "repro_exploit.py")}
    return wt, enclave, report, d


def _validate_patch(tmp_path, cve, patch: Path):
    wt, enclave, report, _ = _setup(tmp_path, cve)
    git(wt, "apply", str(patch))
    return blue.validate(wt, enclave, report)


# ---------- known-good reference fixes still pass everything ----------

@pytest.mark.parametrize("cve", CVES)
def test_reference_fix_passes_all_checks(tmp_path, cve):
    v = _validate_patch(tmp_path, cve, BENCHMARKS / cve / "known_good" / "fix.patch")
    assert v.ok, v.summary() + "\n" + "\n".join(f"--{k}--\n{o}" for k, o in v.logs.items())
    assert v.regression and v.functional and v.exploit_blocked and v.rejected is None


# ---------- 1: conftest / stdout spoofing ----------

def test_conftest_spoof_bypass_fails(tmp_path):
    v = _validate_patch(tmp_path, "CVE-2024-21513", FIX / "cve-2024-21513_conftest_spoof.patch")
    assert not v.ok
    assert v.rejected and "tests/conftest.py" in v.rejected


def test_untracked_root_conftest_rejected(tmp_path):
    """Files Blue creates but `git diff` never shows still count."""
    wt, enclave, report, _ = _setup(tmp_path, "CVE-2024-21513")
    git(wt, "apply", str(BENCHMARKS / "CVE-2024-21513" / "known_good" / "fix.patch"))
    (wt / "conftest.py").write_text("")
    v = blue.validate(wt, enclave, report)
    assert not v.ok and "conftest.py" in v.rejected


def test_heldout_runs_without_victim_conftest(tmp_path):
    """Even an unflagged conftest in the victim must not reach the held-out run."""
    wt, enclave, report, _ = _setup(tmp_path, "CVE-2024-21513")
    git(wt, "apply", str(FIX / "cve-2024-21513_conftest_spoof.patch"))
    r = blue._held_out(enclave, wt, BENCHMARKS / "CVE-2024-21513" / "regression_test.py")
    assert r.returncode != 0, r.output


def test_exploit_verdict_ignores_stdout(tmp_path):
    """A victim that prints ORACLE_MISS but still lets the nonce land is not 'blocked'."""
    wt, enclave, report, _ = _setup(tmp_path, "CVE-2024-21513")
    (wt / "victim" / "__init__.py").write_text("print('ORACLE_MISS BLOCKED')\n")
    v = blue.validate(wt, enclave, report)
    assert not v.exploit_blocked and not v.ok


# ---------- 2: denylist patches ----------

def test_denylist_patch_21513_fails(tmp_path):
    v = _validate_patch(tmp_path, "CVE-2024-21513", FIX / "cve-2024-21513_denylist.patch")
    assert v.exploit_blocked, "sanity: the denylist does stop the reference exploit"
    assert v.regression is False and not v.ok


def test_string_denylist_patch_44467_fails(tmp_path):
    v = _validate_patch(tmp_path, "CVE-2023-44467", FIX / "cve-2023-44467_string_denylist.patch")
    assert v.exploit_blocked, "sanity: the denylist does stop the reference exploit"
    assert v.regression is False and not v.ok


def test_static_check_rejects_remaining_eval(tmp_path):
    """Held-out static check alone: eval left on the result path fails even if guarded."""
    wt, enclave, report, _ = _setup(tmp_path, "CVE-2024-21513")
    git(wt, "apply", str(FIX / "cve-2024-21513_denylist.patch"))
    r = blue._held_out(enclave, wt, BENCHMARKS / "CVE-2024-21513" / "static_test.py")
    assert r.returncode != 0 and "eval" in r.output


# ---------- 3: Blue's tools must not leak the oracle ----------

@pytest.fixture
def tools(tmp_path):
    wt, enclave, report, d = _setup(tmp_path, "CVE-2024-21513")
    return blue.BlueTools(wt, enclave, report, d)


@pytest.mark.parametrize("arg", [
    str(BENCHMARKS / "CVE-2024-21513" / "regression_test.py"),
    "../../../benchmarks/CVE-2024-21513/regression_test.py",
    "--co",
    "-p",
    "victim",
    "tests/../../",
])
def test_run_pytest_rejects_paths_outside_tests(tools, arg):
    out = tools.run_pytest(arg)
    assert out.startswith("ERROR") and "HELD-OUT" not in out and not tools.tests_ok


def test_run_pytest_still_runs_repo_tests(tools):
    assert "passed" in tools.run_pytest("tests") and tools.tests_ok


def test_victim_code_cannot_read_benchmarks_during_blue_runs(tools):
    (tools.wt / "victim" / "__init__.py").write_text(
        f"print(open({str(BENCHMARKS / 'CVE-2024-21513' / 'regression_test.py')!r}).read())\n")
    out = tools.run_pytest("tests") + tools.run_exploit()
    assert "HELD-OUT" not in out


@pytest.mark.parametrize("path", [
    str(BENCHMARKS / "CVE-2024-21513" / "regression_test.py"),
    str(BENCHMARKS / "CVE-2024-21513" / "known_good" / "fix.patch"),
    "../../../benchmarks/CVE-2024-21513/regression_test.py",
])
def test_read_file_cannot_reach_benchmarks(tools, path):
    assert tools.read_file(path).startswith("ERROR")


@pytest.mark.parametrize("path", ["tests/conftest.py", "tests/test_functional.py", "pytest.ini",
                                  "victim/conftest.py", "setup.cfg", "pyproject.toml",
                                  "sitecustomize.py", ".git/config"])
def test_edit_file_rejects_forbidden_paths(tools, path):
    assert tools.edit_file(path, "x", "y").startswith("ERROR")


def test_git_apply_patch_rejects_forbidden_paths(tools):
    out = tools.git_apply_patch((FIX / "cve-2024-21513_conftest_spoof.patch").read_text())
    assert out.startswith("ERROR") and "tests/conftest.py" in out
    assert git(tools.wt, "status", "--porcelain") == "", "nothing may be applied"


def test_git_apply_patch_allows_source_fix(tools):
    out = tools.git_apply_patch((BENCHMARKS / "CVE-2024-21513" / "known_good" / "fix.patch").read_text())
    assert out == "patch applied"


# ---------- 3b: small models double-escape newlines in tool-call JSON ----------
# Observed 2026-10-25, qwen3:8b on Ollama: every edit_file/git_apply_patch arrived with a
# literal backslash-n instead of a newline, so Blue never applied its (correct) fix.

OLD_ESC = "    try:\\n        return eval(x)\\n    except Exception:\\n        return x"


def test_edit_file_accepts_double_escaped_newlines(tools):
    assert "\\n" in OLD_ESC and "\n" not in OLD_ESC
    assert tools.edit_file("victim/vector_sql.py", OLD_ESC, "    return x") == "edited victim/vector_sql.py"
    assert "return eval(x)" not in (tools.wt / "victim" / "vector_sql.py").read_text()


def test_edit_file_prefers_exact_match_over_unescaping(tools):
    f = tools.wt / "victim" / "vector_sql.py"
    f.write_text(f.read_text() + "\nRAW = 'a\\\\nb'\n")   # file really contains a\\nb
    assert tools.edit_file("victim/vector_sql.py", "'a\\\\nb'", "'ok'").startswith("edited")
    assert "RAW = 'ok'" in f.read_text()


def test_edit_file_escape_fallback_keeps_path_rules(tools):
    assert tools.edit_file("tests/conftest.py", "x\\ny", "z").startswith("ERROR")


def test_git_apply_patch_accepts_double_escaped_diff_and_patch_kwarg(tools):
    diff = (BENCHMARKS / "CVE-2024-21513" / "known_good" / "fix.patch").read_text()
    assert tools.git_apply_patch(patch=diff.replace("\n", "\\n")) == "patch applied"


# ---------- 4: no reference-fix hint ----------

def test_blue_prompt_does_not_leak_reference_fix():
    assert "literal_eval" not in blue.SYSTEM
    assert "do not special-case the exploit payload" in blue.SYSTEM


# ---------- 5: functional suite covers _try_eval's legitimate purpose ----------

def test_str_cast_patch_fails_functional(tmp_path):
    v = _validate_patch(tmp_path, "CVE-2024-21513", FIX / "cve-2024-21513_str_cast.patch")
    assert v.exploit_blocked, "sanity: str() does stop the reference exploit"
    assert v.functional is False and not v.ok


def test_upstream_style_fix_passes_all_checks(tmp_path):
    """Upstream 7b13292e deletes _try_eval and returns raw DB values. Option A (2026-10-25):
    our checks must accept that design as well as literal_eval, not only our reference."""
    v = _validate_patch(tmp_path, "CVE-2024-21513", FIX / "cve-2024-21513_upstream_style.patch")
    assert v.ok, v.summary()


# ---------- 6: labels ----------

class _Recorder:
    sent: list = []

    def __init__(self, **meta):
        pass

    def bind(self, **meta):
        pass

    def send(self, role, title, body):
        _Recorder.sent.append((role, title, body))
        return "recorded"


def test_fallback_patch_is_labelled_cached_not_ai(tmp_path, monkeypatch, capsys):
    _Recorder.sent = []
    monkeypatch.setattr(swarm_mod, "Notifier", _Recorder)
    assert Swarm(Settings(use_llm=False), tmp_path).run_hero("CVE-2024-21513") == "notified"
    out = capsys.readouterr().out
    final = _Recorder.sent[-1]
    assert "Draft PR" not in final[1] and "Fix branch ready (local, pending review)" in final[1]
    assert "CACHED REFERENCE PATCH — not AI-generated" in final[1] + final[2]
    assert "CACHED REFERENCE PATCH — not AI-generated" in out


def test_read_file_lists_a_directory_and_hints_on_bad_paths(tools):
    listing = tools.read_file(".")
    assert "victim/vector_sql.py" in listing.splitlines() and ".git/" not in listing
    assert "victim/vector_sql.py" in tools.read_file("victim")
    assert "relative to the repo root" in tools.read_file("/etc/passwd")
    assert "read_file(" in tools.read_file("nope.py")
