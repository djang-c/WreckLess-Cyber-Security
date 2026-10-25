"""Targets the swarm can attack: targets/<name>/target.json.

  victim_app  minimal vendored reproduction (default; fast, host python, no deps)
  langchain   the real upstream code at the vulnerable commit (scripts/fetch_target.sh)

Benchmark bundles stay per CVE; a target's files live in benchmarks/<CVE>/<benchmarks>/ with the
same layout (known_good/{repro_exploit.py,fix.patch}, regression_test.py, ...). Advisory metadata
(advisory.json) is shared.
"""
import json
import os
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

from wreckless.config import BENCHMARKS, ROOT, TARGETS


@dataclass(frozen=True)
class Target:
    name: str
    dir: Path
    source: Path
    python: str
    functional_tests: str
    benchmarks: str
    inventory: Path
    image: str
    fetch: str | None = None

    def bench(self, cve: str | None) -> Path | None:
        """This target's benchmark dir for `cve` (None when there is no bundle for it)."""
        if not cve:
            return None
        d = BENCHMARKS / cve / self.benchmarks if self.benchmarks else BENCHMARKS / cve
        return d if d.is_dir() else None

    @property
    def adapter(self) -> Path:
        return self.dir / "heldout_adapter.py"

    def heldout(self, cve: str | None, fname: str) -> Path | None:
        """A held-out test: this target's own copy if it has one, else the CVE's shared one
        (shared tests reach the target only through the adapter)."""
        for d in (self.bench(cve), BENCHMARKS / cve if cve else None):
            if d and (d / fname).is_file():
                return d / fname
        return None

    def ensure(self) -> None:
        """Fetch third-party source on first use."""
        if not self.source.is_dir() and self.fetch:
            subprocess.run([str(ROOT / self.fetch)], check=True)
        if not self.source.is_dir():
            raise FileNotFoundError(f"target {self.name}: {self.source} missing")


def default() -> "Target":
    return load("victim_app")


def names() -> list[str]:
    return sorted(p.parent.name for p in TARGETS.glob("*/target.json"))


def load(name: str) -> Target:
    d = TARGETS / name
    cfg = json.loads((d / "target.json").read_text())
    py = cfg.get("python", "host")
    # keep the venv path unresolved: resolving follows bin/python to the system interpreter
    python = sys.executable if py == "host" else os.path.abspath(ROOT / py)
    return Target(name=name, dir=d, source=(d / cfg.get("source", ".")).resolve(), python=python,
                  functional_tests=cfg.get("functional_tests", "tests"),
                  benchmarks=cfg.get("benchmarks", ""), inventory=d / cfg.get("inventory", "inventory.json"),
                  image=cfg.get("image", "wreckless-sandbox:py312"), fetch=cfg.get("fetch"))
