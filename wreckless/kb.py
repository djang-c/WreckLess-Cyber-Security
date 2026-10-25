"""Local intel store: advisories in SQLite with an FTS5 (BM25) index, plus per-feed cursors.

One row per vulnerability, keyed by CVE when there is one, so the same bug seen as a GHSA, a
PYSEC and a CVE from three feeds is stored once (aliases are kept). No embeddings: lookups are
mostly exact ids and package names, and the corpus is small (see docs/knowledge-and-intel.md).
"""
import json
import re
import sqlite3
import threading
import time
from pathlib import Path

SEVERITY_RANK = {"critical": 4, "high": 3, "moderate": 2, "medium": 2, "low": 1}
_JSON = ("aliases", "cwe", "references", "fix_commits")


def key_of(adv: dict) -> str:
    return adv.get("cve") or adv["id"]


class IntelDB:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(path, check_same_thread=False, timeout=30)
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.lock = threading.Lock()
        with self.conn:
            self.conn.executescript("""
            CREATE TABLE IF NOT EXISTS advisories (
              key TEXT PRIMARY KEY, id TEXT, cve TEXT, ghsa_id TEXT, aliases TEXT, package TEXT,
              vulnerable_versions TEXT, severity TEXT, summary TEXT, description TEXT, cwe TEXT,
              "references" TEXT, fix_commits TEXT, published TEXT, modified TEXT,
              sources TEXT, kev INTEGER DEFAULT 0, matched INTEGER DEFAULT 0, fetched REAL);
            CREATE VIRTUAL TABLE IF NOT EXISTS adv_fts USING fts5(
              key UNINDEXED, ids, package, summary, description, cwe);
            CREATE TABLE IF NOT EXISTS cursors (feed TEXT PRIMARY KEY, value TEXT, updated REAL);
            """)

    def upsert(self, adv: dict, source: str, matched: bool = False) -> str:
        """Insert or merge one normalised advisory. Returns 'new', 'updated' or 'same'."""
        key = key_of(adv)
        with self.lock, self.conn:
            old = self.get(key)
            if old:
                if (old["modified"] or "") >= (adv.get("modified") or "") \
                        and source in old["sources"] and (old["matched"] or not matched):
                    return "same"
                # fill gaps from the new source; never let a sparse feed blank a richer field
                merged = {k: v for k, v in adv.items() if v not in (None, "", [])}
                adv = old | merged
                # feeds disagree on "modified"; keep the newest so the other feed reads as unchanged
                adv["modified"] = max(old["modified"] or "", merged.get("modified") or "") or None
                adv["aliases"] = sorted(set(old["aliases"]) | set(merged.get("aliases", [])))
                adv["references"] = list(dict.fromkeys(old["references"] + merged.get("references", [])))
                adv["fix_commits"] = list(dict.fromkeys(old["fix_commits"] + merged.get("fix_commits", [])))
            adv["sources"] = ",".join(sorted(set(filter(None, ((old or {}).get("sources", "") or "")
                                                          .split(","))) | {source}))
            adv["matched"] = int(bool(matched or (old and old["matched"])))
            row = {c: adv.get(c) for c in ("id", "cve", "ghsa_id", "package", "vulnerable_versions",
                                           "severity", "summary", "description", "published",
                                           "modified", "sources", "matched")}
            for c in _JSON:
                row[c] = json.dumps(adv.get(c) or [])
            row.update(key=key, kev=int(bool(adv.get("kev"))), fetched=time.time())
            cols = ", ".join(f'"{c}"' for c in row)
            self.conn.execute(f"INSERT OR REPLACE INTO advisories ({cols}) VALUES "
                              f"({', '.join('?' * len(row))})", list(row.values()))
            self.conn.execute("DELETE FROM adv_fts WHERE key=?", (key,))
            self.conn.execute("INSERT INTO adv_fts VALUES (?,?,?,?,?,?)",
                              (key, " ".join([key, adv.get("id") or ""] + list(adv.get("aliases") or [])),
                               adv.get("package") or "", adv.get("summary") or "",
                               adv.get("description") or "", " ".join(adv.get("cwe") or [])))
            return "updated" if old else "new"

    def get(self, key: str) -> dict | None:
        """By CVE, GHSA or any alias."""
        cur = self.conn.execute(
            "SELECT * FROM advisories WHERE key=? OR id=? OR ghsa_id=? OR aliases LIKE ?",
            (key, key, key, f'%"{key}"%'))
        row = cur.fetchone()
        return self._row(cur, row) if row else None

    def mark_kev(self, cves: set[str]) -> list[str]:
        """Flag known-exploited CVEs; returns the ones newly flagged."""
        with self.lock, self.conn:
            hits = [r[0] for r in self.conn.execute("SELECT cve FROM advisories WHERE kev=0 AND cve IS NOT NULL")
                    if r[0] in cves]
            self.conn.executemany("UPDATE advisories SET kev=1 WHERE cve=?", [(c,) for c in hits])
        return hits

    def relevant(self) -> list[dict]:
        """Advisories that matched the dependency inventory, KEV first, then by severity."""
        cur = self.conn.execute("SELECT * FROM advisories WHERE matched=1")
        rows = [self._row(cur, r) for r in cur.fetchall()]
        return sorted(rows, key=lambda a: (-a["kev"], -SEVERITY_RANK.get(a["severity"] or "", 0),
                                           a["published"] or ""))

    def search(self, query: str, limit: int = 5) -> list[dict]:
        """BM25 over ids/package/summary/description/CWE. Free text is tokenised and OR-ed,
        so user or LLM input can never inject FTS5 query syntax."""
        terms = re.findall(r"[\w.-]+", query)
        if not terms:
            return []
        q = " OR ".join('"' + t.replace('"', "") + '"' for t in terms)
        keys = [r[0] for r in self.conn.execute(
            "SELECT key FROM adv_fts WHERE adv_fts MATCH ? ORDER BY bm25(adv_fts) LIMIT ?", (q, limit))]
        return [a for a in (self.get(k) for k in keys) if a]

    def cursor(self, feed: str) -> str | None:
        row = self.conn.execute("SELECT value FROM cursors WHERE feed=?", (feed,)).fetchone()
        return row[0] if row else None

    def set_cursor(self, feed: str, value: str) -> None:
        with self.lock, self.conn:
            self.conn.execute("INSERT OR REPLACE INTO cursors VALUES (?,?,?)", (feed, value, time.time()))

    def count(self) -> int:
        return self.conn.execute("SELECT COUNT(*) FROM advisories").fetchone()[0]

    @staticmethod
    def _row(cur, row) -> dict:
        d = dict(zip([c[0] for c in cur.description], row))
        for c in _JSON:
            d[c] = json.loads(d[c] or "[]")
        return d
