"""Event-driven JSON state machine shared by the swarm. Persisted after every transition."""
import json
import os
import threading
import time
from pathlib import Path

TRANSITIONS = {
    "IDLE": {"INTEL_READY"},
    "INTEL_READY": {"EXPLOITING"},
    "EXPLOITING": {"EXPLOIT_VERIFIED", "EXPLOIT_FAILED"},
    "EXPLOIT_VERIFIED": {"PATCHING"},
    "PATCHING": {"PATCH_VALIDATED", "PATCH_FAILED"},
    "PATCH_VALIDATED": {"NOTIFIED"},
}


class StateMachine:
    # Subclasses override these to reuse the persistence/history machinery with another table.
    transitions: dict[str, set[str]] = TRANSITIONS
    initial: str = "IDLE"

    def __init__(self, run_dir: Path, run_id: str, *, path: Path | None = None,
                 doc: dict | None = None):
        self.path = path or run_dir / "state.json"
        self.doc = doc if doc is not None else {"run_id": run_id, "state": self.initial,
                                                "history": [], "artifacts": {}}
        self._save()

    @property
    def state(self) -> str:
        return self.doc["state"]

    def advance(self, new: str, actor: str, payload: dict | None = None) -> None:
        if new not in self.transitions.get(self.state, set()):
            raise RuntimeError(f"illegal transition {self.state} -> {new}")
        self.doc["history"].append({"t": time.time(), "from": self.state, "to": new,
                                    "actor": actor, "payload": payload or {}})
        self.doc["state"] = new
        self._save()

    def artifact(self, key: str, path: Path) -> None:
        self.doc["artifacts"][key] = str(path)
        self._save()

    def _save(self) -> None:
        # Atomic: readers (queue stats, UI) never observe a half-written file.
        tmp = self.path.with_name(f".{self.path.name}.{os.getpid()}.{threading.get_ident()}.tmp")
        tmp.write_text(json.dumps(self.doc, indent=2))
        os.replace(tmp, self.path)
