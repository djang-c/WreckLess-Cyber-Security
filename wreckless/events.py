"""Append-only event log (events.jsonl): audit trail and source for `wreckless replay`."""
import json
import os
import sys
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
        item = item or getattr(self.item, "id", None)
        with self._lock:  # stamp inside the lock so file order == timestamp order (per process)
            rec = {"t": round(time.time(), 3), "actor": actor, "kind": kind, "item": item, **data}
            line = (json.dumps(rec) + "\n").encode()
            # one O_APPEND write per record: lines from other processes (daemon + hero run
            # sharing a home) land whole instead of interleaving mid-line
            fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o644)
            try:
                view = memoryview(line)
                while view:
                    view = view[os.write(fd, view):]
            finally:
                os.close(fd)


def _events(path: Path):
    """Yield parsed records; a truncated or garbled line (killed writer) is skipped with a warning."""
    with path.open(errors="replace") as f:
        for n, line in enumerate(f, 1):
            if not line.strip():
                continue
            try:
                ev = json.loads(line)
            except ValueError:
                ev = None
            if not isinstance(ev, dict) or not isinstance(ev.get("t"), (int, float)) \
                    or "kind" not in ev or "actor" not in ev:
                print(f"[replay] skipping unreadable line {n} of {path.name}", file=sys.stderr)
                continue
            yield ev


def replay(path: Path, speed: float = 1.0, item: str | None = None, max_gap: float = 3.0) -> None:
    """Re-render a recorded run with its original pacing (gaps capped, then divided by speed).

    Only what was recorded is shown, through the same ``ui`` functions, tagged as a replay.
    """
    events = [ev for ev in _events(path) if not item or ev.get("item") == item]
    recorded = events[0]["t"] if events else None
    ui.replay_tag(path.name if item is None else f"{item} in {path.name}", speed, recorded)
    prev = None
    ui.REPLAYING = True
    try:
        for ev in events:
            if prev is not None and speed > 0:
                time.sleep(max(0.0, min(ev["t"] - prev, max_gap)) / speed)
            prev = ev["t"]
            try:
                _render(ev)
            except (KeyError, TypeError, ValueError) as e:  # a record from an older/newer schema
                print(f"[replay] skipping {ev.get('kind')!r} event: {type(e).__name__}: {e}", file=sys.stderr)
    finally:
        ui.REPLAYING = False
    ui.replay_tag(path.name, speed, recorded)


def _render(ev: dict) -> None:
    prev, ui.CLOCK = ui.CLOCK, ev.get("t")
    try:
        _render_one(ev)
    finally:
        ui.CLOCK = prev


def _render_one(ev: dict) -> None:
    kind, actor, t = ev["kind"], ev["actor"], ev["t"]
    args = {k: v for k, v in ev.items() if k not in ("t", "actor", "kind", "item")}
    if kind == "transition":
        ui.transition(ev["item"], ev["frm"], ev["to"], actor, ts=t)
    elif kind == "say":
        ui.say(actor, ev["text"], ts=t, _record=False)
    elif kind in ("detail", "diff", "think"):
        getattr(ui, kind)(actor, ev["text"], _record=False)
    elif kind == "step":
        ui.step(actor, ev["model"], ev["prompt_tokens"], ev["out_tokens"], ev["secs"], ev.get("limit"), _record=False)
    elif kind == "tool":
        ui.tool_call(actor, ev["name"], ev["args"], _record=False)
    elif kind == "result":
        ui.tool_result(actor, ev["name"], ev["text"], _record=False)
    elif kind == "mascot":
        ui.mascot(actor, ev.get("task"), _record=False)
    elif kind == "notified":
        ui.notified(ev["item"], ev["channel"], ts=t, _record=False)
    elif kind in ("intrusion", "patch_validated"):
        getattr(ui, kind)(ev["item"], **args, _record=False)
    elif kind in ui.REPLAYABLE:
        getattr(ui, kind)(**args, _record=False)
