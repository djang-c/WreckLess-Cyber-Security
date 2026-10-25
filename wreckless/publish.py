"""Approve -> GitHub: push the approved fix commit to the demo repo and open a draft PR.

Runs only after a human clicks Approve on the Slack card (wreckless/slack_socket.py); nothing
leaves the box before that. Enabled by WRECKLESS_GITHUB_REPO=owner/name; unset, an approval
stays a local sign-off (decision.json). Auth is the host's own gh login
(`gh auth login && gh auth setup-git`); no token lives in this repo.

What gets pushed, from the item's victim repo (hooks off, like every git call here):
- `wreckless/base-<12 hex>`: the vulnerable base. init_victim gives the same code the same
  commit, so one base branch serves every fix of that target version;
- `wreckless/fix-<item>`: exactly the approved commit, refused if the branch has moved since.
The draft PR (base <- fix) is recorded in <item>/pr.json; a repeat approve reuses it.

Retry by hand (e.g. after a network error): python -m wreckless.publish <item-id>
"""
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

from wreckless.config import RUNS
from wreckless.gitops import git

REPO_ENV = "WRECKLESS_GITHUB_REPO"
ITEMS = RUNS / "swarm" / "items"
_REPO = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9._][A-Za-z0-9._-]{0,99}$")
_BRANCH = re.compile(r"^wreckless/fix-[A-Za-z0-9][A-Za-z0-9._-]{0,120}$")
_SHA = re.compile(r"^[0-9a-f]{40}$")
_RUN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._#-]{0,127}$")
NET = ("-c", "protocol.https.allow=always")   # gitops.SAFE denies every remote protocol by default


class PublishError(Exception):
    pass


def _gh(*args: str) -> str:
    p = subprocess.run(["gh", *args], capture_output=True, text=True, timeout=60)
    if p.returncode:
        raise PublishError(f"gh {args[0]} {args[1]} failed: {(p.stderr or p.stdout).strip()[:300]}")
    return p.stdout.strip()


def _body(info: dict, d: Path, src: Path) -> str:
    try:
        rep = json.loads((d / "vulnerability_report.json").read_text())
    except (OSError, ValueError):
        rep = {}
    o = rep.get("oracle") or {}
    msg = git(src, "log", "-1", "--format=%B", info["commit"])
    return "\n".join([
        f"**{info.get('cve') or rep.get('cve') or 'finding'}** · WreckLess item `{info['run_id']}`",
        "",
        f"- Gate: {o.get('verdict', 'n/a')} (strength: {o.get('strength', 'n/a')}, control: "
        f"{o.get('control', 'n/a')}, flawed path: `{o.get('flaw_site') or 'unconfirmed'}`)",
        f"- Approved commit: `{info['commit']}` by Slack user `{info.get('user', '?')}`",
        f"- Validation and patch source (from the fix commit):\n\n```\n{msg}\n```",
        "",
        "Draft opened by WreckLess after a human Approve in Slack. The patch is AI-generated unless "
        "the commit says CACHED REFERENCE PATCH. Review before merging.",
    ])


def _save(path: Path, rec: dict) -> None:
    fd, tmp = tempfile.mkstemp(prefix=".pr-", suffix=".tmp", dir=path.parent)
    with os.fdopen(fd, "w") as f:
        json.dump(rec, f, indent=2)
    os.replace(tmp, path)


def publish(info: dict, runs_dir: Path = ITEMS, repo: str | None = None, remote: str | None = None,
            gh=_gh) -> dict | None:
    """Push + draft PR for one approved decision. None if GitHub is not configured."""
    repo = repo if repo is not None else os.environ.get(REPO_ENV)
    if not repo:
        return None
    if not _REPO.match(repo):
        raise PublishError(f"{REPO_ENV} must be owner/name, got {repo!r}")
    if info.get("decision") != "approved":
        raise PublishError("only approved decisions are published")
    run_id, branch, commit = info.get("run_id") or "", info.get("branch") or "", info.get("commit") or ""
    if not _RUN.match(run_id) or ".." in run_id:
        raise PublishError(f"unsafe run_id {run_id!r}")
    if not _BRANCH.match(branch) or not _SHA.match(commit):
        raise PublishError(f"refusing branch {branch!r} / commit {commit!r}")
    d = Path(runs_dir) / run_id.replace("#", "-")
    out = d / "pr.json"
    if out.exists():
        return json.loads(out.read_text())
    src = d / "victim-src"
    if not (src / ".git").exists():
        raise PublishError(f"no victim repo at {src}")
    try:
        head = git(src, "rev-parse", "--verify", "-q", f"refs/heads/{branch}")
        base = git(src, "rev-parse", "--verify", "-q", f"{commit}^")
        main = git(src, "rev-parse", "--verify", "-q", "refs/heads/main")
    except subprocess.CalledProcessError:
        raise PublishError(f"{branch} or its base is missing in {src}") from None
    if head != commit:
        raise PublishError(f"{branch} moved since approval ({head[:10]} != approved {commit[:10]}); not pushed")
    if base != main:
        raise PublishError(f"approved commit is not a single commit on the victim base ({base[:10]})")
    base_branch = f"wreckless/base-{base[:12]}"
    try:
        git(src, *NET, "push", "-q", remote or f"https://github.com/{repo}.git",
            f"{base}:refs/heads/{base_branch}", f"{commit}:refs/heads/{branch}", timeout=120)
    except subprocess.CalledProcessError as e:
        raise PublishError(f"push failed: {(e.stderr or '').strip()[:300]}") from None
    title = git(src, "log", "-1", "--format=%s", commit)[:200]
    url = gh("pr", "create", "--repo", repo, "--base", base_branch, "--head", branch, "--draft",
             "--title", title, "--body", _body(info, d, src))
    rec = {"url": url.strip().splitlines()[-1] if url else "", "repo": repo, "branch": branch,
           "base_branch": base_branch, "commit": commit, "approved_by": info.get("user"), "run_id": run_id}
    _save(out, rec)
    return rec


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 1:
        print("usage: python -m wreckless.publish <item-id>   (re-publishes an approved item)", file=sys.stderr)
        return 2
    d = ITEMS / args[0].replace("#", "-")
    try:
        info = json.loads((d / "decision.json").read_text())
    except (OSError, ValueError):
        print(f"no decision.json in {d}", file=sys.stderr)
        return 1
    try:
        rec = publish(info)
    except PublishError as e:
        print(f"publish failed: {e}", file=sys.stderr)
        return 1
    print(rec["url"] if rec else f"{REPO_ENV} not set: approval stays local")
    return 0


if __name__ == "__main__":
    sys.exit(main())
