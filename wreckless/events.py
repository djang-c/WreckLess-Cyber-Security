"""Append-only event log (events.jsonl): audit trail and source for `wreckless replay`."""
import json
import threading
import time
from pathlib import Path

from wreckless import ui


class EventLog:
    def __init__(self, path: Path):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self.item = threading.local()  # item id that terminal output belongs to, per thread

    def attach(self) -> "EventLog":
        ui.SINK = lambda role, kind, text: self.emit(role, kind, text=text)
        return self

    def emit(self, actor: str, kind: str, item: str | None = None, **data) -> None:
        rec = {"t": round(time.time(), 3), "actor": actor, "kind": kind,
               "item": item or getattr(self.item, "id", None), **data}
        with self._lock, self.path.open("a") as f:
            f.write(json.dumps(rec) + "\n")


def replay(path: Path, speed: float = 1.0, item: str | None = None, max_gap: float = 3.0) -> None:
    """Re-render a recorded run with its original pacing (gaps capped, then divided by speed)."""
    prev = None
    for line in path.read_text().splitlines():
        ev = json.loads(line)
        if item and ev.get("item") != item:
            continue
        if prev is not None:
            time.sleep(min(ev["t"] - prev, max_gap) / speed)
        prev = ev["t"]
        if ev["kind"] == "say":
            ui.say(ev["actor"], ev["text"], _record=False)
        elif ev["kind"] == "detail":
            ui.detail(ev["actor"], ev["text"], _record=False)
        elif ev["kind"] == "banner":
            ui.banner(ev["text"], _record=False)
