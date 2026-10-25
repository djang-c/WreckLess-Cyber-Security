"""Approve -> GitHub: push the approved commit and open a draft PR. Nothing is pushed without it.

A local bare repo stands in for GitHub and a fake `gh` records the PR call, so no test touches the network."""
import json
import subprocess

import pytest

from wreckless import publish
from wreckless.config import Settings, TARGETS
from wreckless.gitops import git, init_victim
from wreckless.swarm import Swarm

CVE = "CVE-2024-21513"


def test_victim_base_commit_is_reproducible(tmp_path):
    a = init_victim(TARGETS / "victim_app", tmp_path / "a")
    b = init_victim(TARGETS / "victim_app", tmp_path / "b")
    assert a == b, "same code must give the same base commit, or PRs share no history"


@pytest.fixture
def approved(tmp_path, monkeypatch):
    for k in ("SLACK_BOT_TOKEN", "SLACK_WEBHOOK_URL"):
        monkeypatch.delenv(k, raising=False)
    home = tmp_path / "home"
    sw = Swarm(Settings(use_llm=False), home)
    assert sw.run_hero(CVE) == "notified"
    item = sw.queue.all()[0]
    patched = next(h for h in item.history if h["to"] == "patched")
    info = {"decision": "approved", "user": "U0TEST", "run_id": item.id, "branch": patched["branch"],
            "commit": patched["commit"], "cve": CVE, "t": 0}
    bare = tmp_path / "github.git"
    subprocess.run(["git", "init", "-q", "--bare", str(bare)], check=True)
    calls = []

    def fake_gh(*args):
        calls.append(args)
        if args[:2] == ("pr", "create"):
            return "https://github.com/acme/wreckless-victim/pull/7"
        raise AssertionError(args)

    return info, home / "items", bare, calls, fake_gh


def run(info, items, bare, gh, **kw):
    return publish.publish(info, items, repo="acme/wreckless-victim", remote=str(bare), gh=gh, **kw)


def test_approve_pushes_base_and_fix_and_opens_draft_pr(approved):
    info, items, bare, calls, gh = approved
    pr = run(info, items, bare, gh)
    assert pr["url"].endswith("/pull/7")
    assert git(bare, "rev-parse", f"refs/heads/{info['branch']}") == info["commit"]
    base = pr["base_branch"]
    assert base.startswith("wreckless/base-") and git(bare, "rev-parse", f"{info['commit']}^") == \
        git(bare, "rev-parse", f"refs/heads/{base}")
    args = calls[0]
    assert "--draft" in args and args[args.index("--base") + 1] == base
    assert args[args.index("--head") + 1] == info["branch"]
    body = args[args.index("--body") + 1]
    assert info["commit"] in body and "<@U0TEST>" not in body and "U0TEST" in body and CVE in body
    rec = json.loads((items / info["run_id"].replace("#", "-") / "pr.json").read_text())
    assert rec["url"] == pr["url"] and rec["commit"] == info["commit"]


def test_second_approve_reuses_the_recorded_pr(approved):
    info, items, bare, calls, gh = approved
    first = run(info, items, bare, gh)
    assert run(info, items, bare, gh) == first and len(calls) == 1


def test_branch_moved_after_approval_is_not_pushed(approved):
    info, items, bare, calls, gh = approved
    src = items / info["run_id"].replace("#", "-") / "victim-src"
    wt = items / info["run_id"].replace("#", "-") / "wt-blue"
    (wt / "sneaky.py").write_text("x = 1\n")
    git(wt, "add", "-A")
    git(wt, "-c", "user.name=x", "-c", "user.email=x@x", "commit", "-q", "-m", "after approval")
    with pytest.raises(publish.PublishError, match="moved"):
        run(info, items, bare, gh)
    assert not calls and not git(bare, "for-each-ref")   # nothing left the box
    assert git(src, "rev-parse", info["branch"]) != info["commit"]


@pytest.mark.parametrize("field,value", [("branch", "main"), ("branch", "--upload-pack=evil"),
                                          ("commit", "HEAD"), ("run_id", "../../etc")])
def test_untrusted_button_values_are_refused(approved, field, value):
    info, items, bare, calls, gh = approved
    with pytest.raises(publish.PublishError):
        run({**info, field: value}, items, bare, gh)
    assert not calls


def test_only_approved_decisions_publish(approved):
    info, items, bare, calls, gh = approved
    with pytest.raises(publish.PublishError, match="approved"):
        run({**info, "decision": "rejected"}, items, bare, gh)


def test_disabled_without_repo(approved, monkeypatch):
    info, items, bare, calls, gh = approved
    monkeypatch.delenv(publish.REPO_ENV, raising=False)
    assert publish.publish(info, items, gh=gh) is None and not calls


@pytest.mark.parametrize("repo", ["acme", "acme/x y", "https://evil/x", "-o/x"])
def test_bad_repo_names_are_refused(approved, repo):
    info, items, bare, calls, gh = approved
    with pytest.raises(publish.PublishError, match="WRECKLESS_GITHUB_REPO"):
        publish.publish(info, items, repo=repo, remote=str(bare), gh=gh)
