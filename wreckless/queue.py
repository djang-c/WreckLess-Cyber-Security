"""Durable candidate queue: one JSON file per item under runs/queue/.

Producers (Purple loop, Red-hunt loop) `put`; the consumer `claim`s. Every write is
tmp+rename (see StateMachine._save), so readers never see a torn file. `claim` is
exclusive across threads *and* processes: the winner is whoever creates
`<id>.claim` with O_CREAT|O_EXCL; losers move on to the next item.

Every candidate enters as label PREDICTION regardless of what the producer claims.
Only the gate may relabel it.
"""
import os
import threading
import time
import uuid
from pathlib import Path

from wreckless.config import RUNS
from wreckless.lifecycle import PREDICTION, Item

SOURCES = {"purple", "red-hunt"}
FIELDS = ("id", "source", "cve", "target", "repro_script", "label", "created_at")


class CandidateQueue:
    def __init__(self, root: Path = RUNS / "queue"):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def _path(self, item_id: str) -> Path:
        return self.root / f"{item_id}.json"

    def put(self, candidate: dict) -> Item:
        src = candidate.get("source")
        if src not in SOURCES:
            raise ValueError(f"unknown candidate source {src!r} (expected one of {sorted(SOURCES)})")
        now = time.time()
        c = {
            "id": f"{time.time_ns():019d}-{src}-{uuid.uuid4().hex[:6]}",
            "source": src,
            "cve": candidate.get("cve"),
            "target": candidate.get("target", "victim_app"),
            "repro_script": str(candidate["repro_script"]) if candidate.get("repro_script") else None,
            "label": PREDICTION,  # producer-supplied labels/claims are never trusted
            "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now)),
        }
        # Keep any extra producer context (e.g. affected_file, rationale) but under its own key,
        # so nothing the producer says can masquerade as a lifecycle field.
        extra = {k: v for k, v in candidate.items() if k not in FIELDS}
        if extra:
            c["producer_notes"] = extra
        return Item.create(self._path(c["id"]), c)

    def get(self, item_id: str) -> Item:
        return Item.load(self._path(item_id))

    def _items(self) -> list[Item]:
        out = []
        for p in sorted(self.root.glob("*.json")):  # ids are time-prefixed -> FIFO order
            try:
                out.append(Item.load(p))
            except (OSError, ValueError):
                continue  # vanished or foreign file; never crash the consumer
        return out

    def claim(self, item_id: str | None = None) -> Item | None:
        """Atomically take the oldest queued item (or `item_id`) and mark it verifying."""
        for it in ([self.get(item_id)] if item_id else self._items()):
            if it.state != "queued":
                continue
            try:
                fd = os.open(self.root / f"{it.id}.claim", os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            except FileExistsError:
                continue
            os.write(fd, f"{os.getpid()}:{threading.get_ident()}".encode())
            os.close(fd)
            with self._lock:
                it = self.get(it.id)  # re-read under the claim
                it.advance("verifying", "gate", {"claimed_by": os.getpid()})
            return it
        return None

    def list(self, state: str | None = None) -> list[dict]:
        return [it.doc for it in self._items() if state is None or it.state == state]

    def has(self, source: str, cve: str) -> bool:
        return any(d["candidate"]["source"] == source and d["candidate"]["cve"] == cve
                   for d in self.list())

    def stats(self) -> dict:
        items = self._items()
        return {
            "candidates": len(items),
            "verified": sum(it.reached("verified") for it in items),
            "rejected": sum(it.state == "rejected" for it in items),
            "patched": sum(it.reached("patched") for it in items),
        }
