import pytest


@pytest.fixture(autouse=True)
def _isolated_intel_db(tmp_path_factory, monkeypatch):
    """Never let a test read or write the real runs/intel.db (live-synced advisories would
    turn into extra queue items)."""
    import wreckless.swarm
    monkeypatch.setattr(wreckless.swarm, "INTEL_DB", tmp_path_factory.mktemp("intel") / "intel.db")


@pytest.fixture(autouse=True)
def _close_enclaves(monkeypatch):
    """Close every Enclave a test builds. Each tmp_path hashes to its own OpenShell sandbox, so
    a test that forgets close() leaves one running per test (hundreds per full run)."""
    from wreckless import sandbox
    made, init = [], sandbox.Enclave.__init__

    def tracked(self, *a, **kw):
        init(self, *a, **kw)
        made.append(self)

    monkeypatch.setattr(sandbox.Enclave, "__init__", tracked)
    yield
    for e in made:
        e.close()
