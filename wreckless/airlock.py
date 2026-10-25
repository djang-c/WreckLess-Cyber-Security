"""Porter's airlock: the only path between Slack and the agents.

Two doors, two processes:
- outer door (wreckless/porter_outer.py, in the Slack listener): talks to Slack. It never imports
  anything that reads the codebase, the item folders, the queue or the models (tested).
- inner door (wreckless/porter.py, next to the agents): reads findings and asks the local model.
  It makes no network call except to the local model on loopback.

Between them only small typed JSON messages pass, through two spool folders (inbox: Slack ->
agents, outbox: agents -> Slack). Each side validates every message it reads: unknown kinds,
oversize text, malformed ids and extra fields are dropped. A door is an exclusive lock: a side
must hold it to touch the spool and only one side can hold it at a time, so the two doors are
never open together, and no side does slow work (Slack I/O, the model) while holding it.

The security boundary is the two processes plus this schema; the lock is defence in depth (and
what the app animates). On the GB10 the boundary can be enforced later with a separate OS user
for the outer door and a no-network sandbox for the inner one (see docs/porter.md).
"""
import fcntl
import json
import os
import re
import secrets
import tempfile
import time
from contextlib import contextmanager
from pathlib import Path

from wreckless.config import RUNS

KINDS = ("ask", "status", "note", "change", "exploit")
MAX_TEXT, MAX_REPLY = 2000, 3500
_ID = re.compile(r"^[0-9a-f]{16}$")
_ITEM = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,60}#\d{1,6}$")
_USER = re.compile(r"^[UW][A-Z0-9]{2,20}$")
_CHAN = re.compile(r"^[CGD][A-Z0-9]{2,20}$")
_TS = re.compile(r"^\d{1,12}\.\d{1,8}$")
REQUEST_FIELDS = {"id", "kind", "text", "user", "item", "channel", "thread", "t"}
REPLY_FIELDS = {"id", "request", "text", "channel", "thread", "t"}


class BadMessage(ValueError):
    pass


def _check(m: dict, fields: set) -> dict:
    if not isinstance(m, dict) or set(m) - fields:
        raise BadMessage(f"unexpected fields {sorted(set(m) - fields) if isinstance(m, dict) else type(m)}")
    for k in ("text",):
        if not isinstance(m.get(k), str):
            raise BadMessage("text must be a string")
    if m.get("channel") is not None and not _CHAN.match(str(m["channel"])):
        raise BadMessage("bad channel")
    if m.get("thread") is not None and not _TS.match(str(m["thread"])):
        raise BadMessage("bad thread ts")
    if not isinstance(m.get("t"), (int, float)):
        raise BadMessage("bad time")
    return m


def validate_request(m: dict) -> dict:
    _check(m, REQUEST_FIELDS)
    if not _ID.match(str(m.get("id"))):
        raise BadMessage("bad id")
    if m.get("kind") not in KINDS:
        raise BadMessage(f"unknown kind {m.get('kind')!r}")
    if len(m["text"]) > MAX_TEXT:
        raise BadMessage("text too long")
    if not _USER.match(str(m.get("user"))):
        raise BadMessage("bad user")
    if m.get("item") is not None and not _ITEM.match(str(m["item"])):
        raise BadMessage("bad item id")
    return m


def validate_reply(m: dict) -> dict:
    _check(m, REPLY_FIELDS)
    if not _ID.match(str(m.get("id"))) or not _ID.match(str(m.get("request"))):
        raise BadMessage("bad id")
    if len(m["text"]) > MAX_REPLY:
        raise BadMessage("reply too long")
    return m


def request(kind: str, text: str, user: str, item: str | None = None, channel: str | None = None,
            thread: str | None = None) -> dict:
    return validate_request({"id": secrets.token_hex(8), "kind": kind, "text": text, "user": user,
                             "item": item, "channel": channel, "thread": thread, "t": time.time()})


def reply(req: dict, text: str) -> dict:
    return validate_reply({"id": secrets.token_hex(8), "request": req["id"], "text": text[:MAX_REPLY],
                           "channel": req.get("channel"), "thread": req.get("thread"), "t": time.time()})


class Airlock:
    SIDES = ("outer", "inner")

    def __init__(self, root: Path | None = None):
        self.root = Path(root or os.environ.get("WRECKLESS_AIRLOCK") or RUNS / "airlock")
        for d in ("inbox", "outbox"):
            (self.root / d).mkdir(parents=True, exist_ok=True)
        self.lock_path = self.root / ".door"
        self.dropped = 0

    @contextmanager
    def door(self, side: str):
        """Hold this side's door open. Blocks while the other side's door is open."""
        if side not in self.SIDES:
            raise ValueError(side)
        fd = os.open(self.lock_path, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            self._state(side)
            try:
                yield self
            finally:
                self._state(None)
                fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)

    def _state(self, side: str | None) -> None:
        tmp = self.root / ".door.json.tmp"
        tmp.write_text(json.dumps({"open": side, "t": time.time()}))
        os.replace(tmp, self.root / "door.json")

    def state(self) -> dict:
        try:
            return json.loads((self.root / "door.json").read_text())
        except (OSError, ValueError):
            return {"open": None, "t": 0}

    # which side may write which box: outer -> inbox, inner -> outbox
    _WRITES = {"outer": "inbox", "inner": "outbox"}
    _READS = {"outer": "outbox", "inner": "inbox"}

    def put(self, side: str, msg: dict) -> None:
        box = self._WRITES[side]
        (validate_request if box == "inbox" else validate_reply)(msg)
        d = self.root / box
        fd, tmp = tempfile.mkstemp(dir=d, prefix=".", suffix=".tmp")
        with os.fdopen(fd, "w") as f:
            json.dump(msg, f)
        os.replace(tmp, d / f"{msg['t']:.6f}-{msg['id']}.json")

    def take(self, side: str) -> list[dict]:
        box = self._READS[side]
        check = validate_request if box == "inbox" else validate_reply
        out = []
        for p in sorted((self.root / box).glob("*.json")):
            try:
                if p.stat().st_size > 16 * 1024:
                    raise BadMessage("file too large")
                out.append(check(json.loads(p.read_text())))
            except (BadMessage, ValueError, OSError):
                self.dropped += 1
            finally:
                p.unlink(missing_ok=True)
        return out
