"""Purple's feeds + intel DB, offline: canned OSV/GitHub/KEV responses shaped like the real APIs."""
import pytest

from wreckless import feeds
from wreckless.agents import purple
from wreckless.config import Settings
from wreckless.kb import IntelDB
from wreckless.swarm import Swarm

INV = {"ecosystem": "PyPI", "packages": {"langchain-experimental": "0.0.14"}}
PKG = {"name": "langchain-experimental", "ecosystem": "PyPI"}
OSV = {
    "GHSA-aaaa-1111-xxxx": {
        "id": "GHSA-aaaa-1111-xxxx", "aliases": ["CVE-2099-0001", "PYSEC-2099-1"],
        "summary": "PALChain sandbox escape", "details": "validate_code misses __import__",
        "modified": "2026-01-02T00:00:00Z", "published": "2025-01-01T00:00:00Z",
        "database_specific": {"severity": "HIGH", "cwe_ids": ["CWE-94"]},
        "references": [{"type": "WEB", "url": "https://github.com/o/r/commit/abcdef1234567"}],
        "affected": [{"package": PKG, "ranges": [
            {"type": "GIT", "events": [{"introduced": "0"}, {"fixed": "abcdef1234567"}]},
            {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "0.0.15"}]}]}]},
    "PYSEC-2099-1": {  # same bug, second id: must merge, not duplicate
        "id": "PYSEC-2099-1", "aliases": ["CVE-2099-0001", "GHSA-aaaa-1111-xxxx"],
        "details": "PALChain sandbox escape", "modified": "2026-03-01T00:00:00Z",
        "affected": [{"package": PKG, "ranges": [{"type": "ECOSYSTEM", "events": [{"fixed": "0.0.15"}]}]}]},
    "GHSA-bbbb-2222-yyyy": {
        "id": "GHSA-bbbb-2222-yyyy", "aliases": ["CVE-2099-0002"], "summary": "REPL code execution",
        "details": "python repl", "modified": "2026-01-01T00:00:00Z", "published": "2025-06-01T00:00:00Z",
        "database_specific": {"severity": "CRITICAL"},
        "affected": [{"package": PKG, "ranges": [{"type": "ECOSYSTEM", "events": [{"fixed": "0.0.61"}]}]}]},
}
GITHUB = [{"ghsa_id": "GHSA-aaaa-1111-xxxx", "cve_id": "CVE-2099-0001", "severity": "high",
           "summary": "PALChain sandbox escape", "description": "long markdown",
           "updated_at": "2025-02-01T00:00:00Z", "published_at": "2025-01-01T00:00:00Z",
           "identifiers": [{"type": "GHSA", "value": "GHSA-aaaa-1111-xxxx"},
                           {"type": "CVE", "value": "CVE-2099-0001"}],
           "references": ["https://github.com/o/r/commit/abcdef1234567"], "cwes": [{"cwe_id": "CWE-94"}],
           "vulnerabilities": [{"package": {"name": "langchain-experimental"},
                                "vulnerable_version_range": "<= 0.0.14"}], "withdrawn_at": None}]
KEV = {"vulnerabilities": [{"cveID": "CVE-2099-0002"}, {"cveID": "CVE-1999-9999"}]}


@pytest.fixture
def fake_feeds(monkeypatch):
    calls = []

    def get(url, s, data=None, headers=None, timeout=20):
        calls.append(url)
        if s.mode != "live":
            raise PermissionError("airgap")
        if url.endswith("/querybatch"):
            return {"results": [{"vulns": [{"id": k, "modified": v["modified"]} for k, v in OSV.items()]}]}
        if "/v1/vulns/" in url:
            return OSV[url.rsplit("/", 1)[1]]
        if "api.github.com" in url:
            return GITHUB
        return KEV
    monkeypatch.setattr(feeds, "_get", get)
    monkeypatch.setattr(feeds, "github_token", lambda: None)
    return calls


def test_sync_dedupes_aliases_across_feeds(tmp_path, fake_feeds):
    db = IntelDB(tmp_path / "i.db")
    rep = feeds.sync(db, INV, Settings(mode="live"))
    assert sorted(rep.new) == ["CVE-2099-0001", "CVE-2099-0002"] and not rep.errors
    assert db.count() == 2
    a = db.get("PYSEC-2099-1")                       # any alias finds the one row
    assert a["key"] == "CVE-2099-0001" and a["sources"] == "github,osv"
    assert a["modified"] == "2026-03-01T00:00:00Z"   # newest wins, so the next poll is a no-op
    assert "abcdef" not in (a["vulnerable_versions"] or "")  # GIT ranges are not versions
    assert a["fix_commits"] == ["abcdef1234567"]
    assert rep.kev == ["CVE-2099-0002"]
    # second poll: nothing new, nothing updated, and no detail re-fetch for unchanged vulns
    fake_feeds.clear()
    rep2 = feeds.sync(db, INV, Settings(mode="live"))
    assert (rep2.new, rep2.updated, rep2.kev) == ([], [], [])
    assert not [u for u in fake_feeds if "/v1/vulns/" in u]


def test_relevant_puts_kev_first(tmp_path, fake_feeds):
    db = IntelDB(tmp_path / "i.db")
    feeds.sync(db, INV, Settings(mode="live"))
    assert [a["key"] for a in db.relevant()] == ["CVE-2099-0002", "CVE-2099-0001"]


def test_airgap_sync_reports_errors_never_raises(tmp_path, fake_feeds):
    rep = feeds.sync(IntelDB(tmp_path / "i.db"), INV, Settings(mode="airgap"))
    assert set(rep.errors) == {"osv", "github", "kev"} and not rep.new


def test_real_get_refuses_unlisted_host_and_airgap():
    with pytest.raises(PermissionError):
        feeds._get("https://evil.example/x", Settings(mode="live"))
    with pytest.raises(PermissionError):
        feeds._get("https://api.osv.dev/v1/querybatch", Settings(mode="airgap"), data={})


def test_search_is_safe_against_fts_syntax(tmp_path, fake_feeds):
    db = IntelDB(tmp_path / "i.db")
    feeds.sync(db, INV, Settings(mode="live"))
    assert db.search("PALChain __import__")[0]["key"] == "CVE-2099-0001"
    db.search('" OR NEAR( * ) AND title:x')                # FTS5 syntax in input must not raise
    assert db.search("") == []


def test_purple_ingests_feed_only_cve(tmp_path, fake_feeds):
    db = IntelDB(tmp_path / "i.db")
    feeds.sync(db, INV, Settings(mode="live"))
    intel = purple.ingest("CVE-2099-0002", Settings(use_llm=False), db)
    assert intel["id"] == "CVE-2099-0002" and intel["kev"] is True
    with pytest.raises(KeyError):
        purple.ingest("CVE-2000-0000", Settings(use_llm=False), db)


def test_purple_loop_queues_benchmarks_then_feed_findings(tmp_path, fake_feeds, monkeypatch):
    sw = Swarm(Settings(use_llm=False, mode="live"), tmp_path / "home")
    monkeypatch.setattr(sw.stop, "wait", lambda t=None: sw.stop.set())   # one pass
    sw.purple_loop(interval=1)
    cves = [it.cve for it in sw.queue.all()]
    assert cves[:2] == ["CVE-2023-44467", "CVE-2024-21513"]        # curated bundles first
    assert cves[2:] == ["CVE-2099-0002", "CVE-2099-0001"]          # then KEV-first feed matches
    sw.stop.clear()
    sw.purple_loop(interval=1)                                      # re-poll: no duplicates
    assert len(sw.queue.all()) == 4
