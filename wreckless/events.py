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
        ui.SINK = lambda role, kind, **data: self.emit(role, kind, **data)
        return self

    def emit(self, actor: str, kind: str, item: str | None = None, **data) -> None:
        rec = {"t": round(time.time(), 3), "actor": actor, "kind": kind,
               "item": item or getattr(self.item, "id", None), **data}
        with self._lock, self.path.open("a") as f:
            f.write(json.dumps(rec) + "\n")


def replay(path: Path, speed: float = 1.0, item: str | None = None, max_gap: float = 3.0) -> None:
    """Re-render a recorded run with its original pacing (gaps capped, then divided by speed).

    Only what was recorded is shown, through the same ``ui`` functions, tagged as a replay.
    """
    events = [ev for ev in map(json.loads, path.read_text().splitlines())
              if not item or ev.get("item") == item]
    recorded = events[0]["t"] if events else None
    ui.replay_tag(path.name if item is None else f"{item} in {path.name}", speed, recorded)
    prev = None
    ui.REPLAYING = True
    try:
        for ev in events:
            if prev is not None and speed > 0:
                time.sleep(min(ev["t"] - prev, max_gap) / speed)
            prev = ev["t"]
            _render(ev)
    finally:
        ui.REPLAYING = False
    ui.replay_tag(path.name, speed, recorded)


def _render(ev: dict) -> None:
    kind, actor, t = ev["kind"], ev["actor"], ev["t"]
    args = {k: v for k, v in ev.items() if k not in ("t", "actor", "kind", "item")}
    if kind == "transition":
        ui.transition(ev["item"], ev["frm"], ev["to"], actor, ts=t)
    elif kind == "say":
        ui.say(actor, ev["text"], ts=t, _record=False)
    elif kind in ("detail", "diff"):
        getattr(ui, kind)(actor, ev["text"], _record=False)
    elif kind == "mascot":
        ui.mascot(actor, _record=False)
    elif kind == "notified":
        ui.notified(ev["item"], ev["channel"], ts=t, _record=False)
    elif kind in ("intrusion", "patch_validated"):
        getattr(ui, kind)(ev["item"], **args, _record=False)
    elif kind in ui.REPLAYABLE:
        getattr(ui, kind)(**args, _record=False)
