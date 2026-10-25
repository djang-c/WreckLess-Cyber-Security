"""The real upstream target (langchain-experimental @ ce61840e, langchain 0.0.292).
Skipped unless scripts/fetch_target.sh ran and .venv-target exists."""
from pathlib import Path

import pytest

from wreckless import targets
from wreckless.config import Settings
from wreckless.swarm import Swarm

LC = targets.load("langchain")
pytestmark = pytest.mark.skipif(not (LC.source.is_dir() and Path(LC.python).exists()),
                                reason="upstream target not fetched (scripts/fetch_target.sh) or no .venv-target")


@pytest.mark.parametrize("cve", ["CVE-2024-21513", "CVE-2023-44467"])
def test_real_upstream_cve_walks_full_lifecycle(tmp_path, monkeypatch, cve):
    monkeypatch.setenv("WRECKLESS_SANDBOX", "userland")   # the langchain image is optional
    sw = Swarm(Settings(use_llm=False, target="langchain"), tmp_path)
    assert sw.run_hero(cve) == "notified"
    item = sw.queue.all()[0]
    report = (tmp_path / "items").glob("*/vulnerability_report.json")
    assert item.label == "VERIFIED" and any(report)


def test_target_metadata_stays_out_of_the_victim_repo(tmp_path):
    from wreckless.gitops import init_victim
    init_victim(targets.default().source, tmp_path / "v")
    assert not {"target.json", "heldout_adapter.py", "inventory.json"} & {p.name for p in (tmp_path / "v").iterdir()}
