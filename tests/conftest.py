import pytest


@pytest.fixture(autouse=True)
def _isolated_intel_db(tmp_path_factory, monkeypatch):
    """Never let a test read or write the real runs/intel.db (live-synced advisories would
    turn into extra queue items)."""
    import wreckless.swarm
    monkeypatch.setattr(wreckless.swarm, "INTEL_DB", tmp_path_factory.mktemp("intel") / "intel.db")
