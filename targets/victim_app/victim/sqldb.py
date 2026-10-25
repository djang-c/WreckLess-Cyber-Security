"""Minimal stand-in for langchain's SQLDatabase over sqlite3."""
import sqlite3
from typing import Any, Dict, List


class SQLDatabase:
    def __init__(self, path: str = ":memory:"):
        self.conn = sqlite3.connect(path)
        self.conn.row_factory = sqlite3.Row

    def _execute(self, cmd: str, fetch: str = "all") -> List[Dict[str, Any]]:
        cur = self.conn.execute(cmd)
        rows = [dict(r) for r in cur.fetchall()]
        return rows if fetch == "all" else (rows[0] if rows else {})

    def seed_demo(self) -> "SQLDatabase":
        self.conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS customers (id INTEGER, name TEXT, embedding TEXT);
            INSERT INTO customers VALUES (1, 'Acme Corp', '[0.12, 0.88, 0.40]');
            INSERT INTO customers VALUES (2, 'Globex', '[0.91, 0.05, 0.33]');
            """
        )
        return self
