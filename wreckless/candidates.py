"""Candidate queue (SQLite) with a per-item lifecycle.

Every item starts as a PREDICTION. Only the verify gate can make it VERIFIED.
"""
import json
import sqlite3
import threading
import time
from dataclasses import dataclass
from pathlib import Path

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
        self._lock = threading.Lock()
        self.conn = sqlite3.connect(db, check_same_thread=False)
        self.conn.executescript(SCHEMA)

    def enqueue(self, source: str, title: str, cve: str | None = None, payload: dict | None = None) -> str:
        now = time.time()
        with self._lock:
            n = self.conn.execute("SELECT COUNT(*) FROM items").fetchone()[0] + 1
            item_id = f"{cve or 'HUNT'}#{n}"
            self.conn.execute("INSERT INTO items VALUES (?,?,?,?,?,?,?,?,?,?)",
                              (item_id, source, cve, title, "queued", "PREDICTION",
                               json.dumps(payload or {}), "[]", now, now))
            self.conn.commit()
        self.events.emit("core", "enqueue", item_id, source=source, title=title)
        return item_id

    def get(self, item_id: str) -> Item:
        row = self.conn.execute("SELECT id, source, cve, title, state, label, payload, history "
                                "FROM items WHERE id=?", (item_id,)).fetchone()
        return Item(*row[:6], json.loads(row[6]), json.loads(row[7]))

    def advance(self, item_id: str, new: str, actor: str, **data) -> Item:
        with self._lock:
            item = self.get(item_id)
            if new not in LIFECYCLE.get(item.state, set()):
                raise RuntimeError(f"{item_id}: illegal transition {item.state} -> {new}")
            item.history.append({"t": time.time(), "from": item.state, "to": new, "actor": actor, **data})
            label = LABEL.get(new, item.label)
            self.conn.execute("UPDATE items SET state=?, label=?, history=?, updated=? WHERE id=?",
                              (new, label, json.dumps(item.history), time.time(), item_id))
            self.conn.commit()
        self.events.emit(actor, "transition", item_id, frm=item.state, to=new, data=data)
        return self.get(item_id)

    def update_payload(self, item_id: str, **fields) -> None:
        with self._lock:
            payload = self.get(item_id).payload | fields
            self.conn.execute("UPDATE items SET payload=? WHERE id=?", (json.dumps(payload), item_id))
            self.conn.commit()

    def next_queued(self) -> str | None:
        row = self.conn.execute("SELECT id FROM items WHERE state='queued' ORDER BY created LIMIT 1").fetchone()
        return row[0] if row else None

    def has_cve(self, cve: str) -> bool:
        return self.conn.execute("SELECT 1 FROM items WHERE cve=?", (cve,)).fetchone() is not None

    def stats(self) -> dict:
        rows = self.conn.execute("SELECT source, label, state, COUNT(*) FROM items GROUP BY 1,2,3").fetchall()
        return {"total": sum(r[3] for r in rows),
                "by_label": _sum(rows, 1), "by_state": _sum(rows, 2), "by_source": _sum(rows, 0)}

    def all(self) -> list[Item]:
        ids = [r[0] for r in self.conn.execute("SELECT id FROM items ORDER BY created")]
        return [self.get(i) for i in ids]


def _sum(rows, col):
    out: dict = {}
    for r in rows:
        out[r[col]] = out.get(r[col], 0) + r[3]
    return out
