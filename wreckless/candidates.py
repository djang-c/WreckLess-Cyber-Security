"""Candidate queue (SQLite) with a per-item lifecycle.

Every item starts as a PREDICTION. Only the verify gate can make it VERIFIED.
"""
import json
import sqlite3
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from wreckless import ui
from wreckless.events import EventLog

LIFECYCLE = {
    "queued": {"verifying"},
    "verifying": {"verified", "rejected"},
    "verified": {"patching"},
    "patching": {"patched", "patch_failed"},
    "patched": {"notified"},
}
LABEL = {"verified": "VERIFIED", "rejected": "REJECTED"}

SCHEMA = """
CREATE TABLE IF NOT EXISTS items (
    id TEXT PRIMARY KEY, source TEXT, cve TEXT, title TEXT,
    state TEXT, label TEXT, payload TEXT, history TEXT, created REAL, updated REAL
);
"""


@dataclass
class Item:
    id: str
    source: str
    cve: str | None
    title: str
    state: str
    label: str
    payload: dict
    history: list


class CandidateQueue:
    def __init__(self, db: Path, events: EventLog):
        self.events = events
        # One connection shared by this process's threads (RLock), several processes on one
        # file (daemon + `run` share a home): writes take the db lock up front (BEGIN IMMEDIATE).
        self._lock = threading.RLock()
        self.conn = sqlite3.connect(db, check_same_thread=False, timeout=30, isolation_level=None)
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.executescript(SCHEMA)

    @contextmanager
    def _write(self):
        with self._lock:
            self.conn.execute("BEGIN IMMEDIATE")
            try:
                yield
            except BaseException:
                self.conn.execute("ROLLBACK")
                raise
            self.conn.execute("COMMIT")

    def _read(self, sql: str, args: tuple = ()) -> list:
        with self._lock:
            return self.conn.execute(sql, args).fetchall()

    def enqueue(self, source: str, title: str, cve: str | None = None, payload: dict | None = None) -> str:
        now = time.time()
        with self._write():
            n = self.conn.execute("SELECT COUNT(*) FROM items").fetchone()[0] + 1
            item_id = f"{cve or 'HUNT'}#{n}"
            self.conn.execute("INSERT INTO items VALUES (?,?,?,?,?,?,?,?,?,?)",
                              (item_id, source, cve, title, "queued", "PREDICTION",
                               json.dumps(payload or {}), "[]", now, now))
        self.events.emit("core", "enqueue", item_id, source=source, title=title)
        return item_id

    def get(self, item_id: str) -> Item:
        row = self._read("SELECT id, source, cve, title, state, label, payload, history "
                         "FROM items WHERE id=?", (item_id,))[0]
        return Item(*row[:6], json.loads(row[6]), json.loads(row[7]))

    def advance(self, item_id: str, new: str, actor: str, **data) -> Item:
        with self._write():
            item = self.get(item_id)
            if new not in LIFECYCLE.get(item.state, set()):
                raise RuntimeError(f"{item_id}: illegal transition {item.state} -> {new}")
            item.history.append({"t": time.time(), "from": item.state, "to": new, "actor": actor, **data})
            label = LABEL.get(new, item.label)
            cur = self.conn.execute(
                "UPDATE items SET state=?, label=?, history=?, updated=? WHERE id=? AND state=?",
                (new, label, json.dumps(item.history), time.time(), item_id, item.state))
            if cur.rowcount != 1:  # moved by someone else since we read it
                raise RuntimeError(f"{item_id}: {item.state} -> {new} lost a race")
        self.events.emit(actor, "transition", item_id, frm=item.state, to=new, data=data)
        ui.transition(item_id, item.state, new, actor)
        return self.get(item_id)

    def update_payload(self, item_id: str, **fields) -> None:
        with self._write():
            payload = self.get(item_id).payload | fields
            self.conn.execute("UPDATE items SET payload=? WHERE id=?", (json.dumps(payload), item_id))

    def try_advance(self, item_id: str, new: str, actor: str, **data) -> Item | None:
        """advance(), but None instead of raising if another worker already moved the item."""
        try:
            return self.advance(item_id, new, actor, **data)
        except RuntimeError:
            return None

    def fail(self, item_id: str, actor: str, reason: str) -> None:
        """Move an in-flight item to its terminal failure state (no-op if it has none)."""
        terminal = {"queued": None, "verifying": "rejected", "verified": None,
                    "patching": "patch_failed"}.get(self.get(item_id).state)
        if terminal:
            self.try_advance(item_id, terminal, actor, reason=reason)

    def recover(self) -> list[str]:
        """After a crash, nothing is really in flight: fail items left mid-verify/patch."""
        stuck = [r[0] for r in self._read("SELECT id FROM items WHERE state IN ('verifying', 'patching')")]
        for item_id in stuck:
            self.fail(item_id, "core", "interrupted (process restarted)")
        return stuck

    def next_queued(self) -> str | None:
        rows = self._read("SELECT id FROM items WHERE state='queued' ORDER BY created LIMIT 1")
        return rows[0][0] if rows else None

    def has_cve(self, cve: str) -> bool:
        return bool(self._read("SELECT 1 FROM items WHERE cve=?", (cve,)))

    def stats(self) -> dict:
        rows = self._read("SELECT source, label, state, COUNT(*) FROM items GROUP BY 1,2,3")
        return {"total": sum(r[3] for r in rows),
                "by_label": _sum(rows, 1), "by_state": _sum(rows, 2), "by_source": _sum(rows, 0)}

    def all(self) -> list[Item]:
        ids = [r[0] for r in self._read("SELECT id FROM items ORDER BY created")]
        return [self.get(i) for i in ids]


def _sum(rows, col):
    out: dict = {}
    for r in rows:
        out[r[col]] = out.get(r[col], 0) + r[3]
    return out
