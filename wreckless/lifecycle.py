"""Per-candidate lifecycle: the swarm's state machine, one instance per queue item.

    queued -> verifying -> verified | rejected
    verified -> patching -> patched | patch_failed -> notified

Reuses Kevin's StateMachine (atomic JSON persisted after every transition, history with
actor/payload/timestamps, illegal transitions raise RuntimeError) with a different table.
`rejected` is terminal: a candidate the gate refused never reaches Blue or Slack.
"""
import json
from pathlib import Path

from wreckless.state import StateMachine

LIFECYCLE = {
    "queued": {"verifying"},
    "verifying": {"verified", "rejected"},
    "verified": {"patching"},
    "patching": {"patched", "patch_failed"},
    "patched": {"notified"},
    "patch_failed": {"notified"},
}
STATES = ("queued", "verifying", "verified", "rejected", "patching", "patched",
          "patch_failed", "notified")
TERMINAL = {"rejected", "notified"}

PREDICTION = "PREDICTION"
CONFIRMED = "CONFIRMED_BY_REPRO"


class Item(StateMachine):
    """One candidate. The JSON file at `path` is the single source of truth for it."""
    transitions = LIFECYCLE
    initial = "queued"

    @classmethod
    def create(cls, path: Path, candidate: dict) -> "Item":
        doc = {"run_id": candidate["id"], "state": cls.initial, "history": [], "artifacts": {},
               "label": PREDICTION, "candidate": candidate}
        return cls(path.parent, candidate["id"], path=path, doc=doc)

    @classmethod
    def load(cls, path: Path) -> "Item":
        it = cls.__new__(cls)  # no _save on load: reading must not rewrite the file
        it.path, it.doc = path, json.loads(path.read_text())
        return it

    @property
    def id(self) -> str:
        return self.doc["run_id"]

    @property
    def candidate(self) -> dict:
        return self.doc["candidate"]

    @property
    def label(self) -> str:
        return self.doc["label"]

    def set_label(self, label: str) -> None:
        self.doc["label"] = label
        self._save()

    def reached(self, state: str) -> bool:
        return self.state == state or any(h["to"] == state for h in self.doc["history"])
