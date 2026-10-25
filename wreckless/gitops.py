"""Victim repo + per-swarm worktrees."""
import shutil
import subprocess
from pathlib import Path


def git(cwd: Path, *args: str) -> str:
    return subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True,
                          text=True).stdout.strip()


def init_victim(template: Path, dest: Path) -> str:
    shutil.copytree(template, dest)
    git(dest, "init", "-q", "-b", "main")
    git(dest, "-c", "user.name=victim", "-c", "user.email=victim@local", "add", "-A")
    git(dest, "-c", "user.name=victim", "-c", "user.email=victim@local",
        "commit", "-q", "-m", "victim app (vulnerable)")
    return git(dest, "rev-parse", "HEAD")


def worktree(repo: Path, path: Path, branch: str) -> Path:
    git(repo, "worktree", "add", "-q", "-b", branch, str(path))
    return path


def commit_all(wt: Path, msg: str) -> str:
    git(wt, "add", "-A")
    git(wt, "-c", "user.name=WreckLess Blue", "-c", "user.email=blue@wreckless.local",
        "commit", "-q", "-m", msg)
    return git(wt, "rev-parse", "HEAD")
