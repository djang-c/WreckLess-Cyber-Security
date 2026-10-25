"""Event-driven JSON state machine shared by the swarm. Persisted after every transition."""
import json
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
    def __init__(self, run_dir: Path, run_id: str):
        self.path = run_dir / "state.json"
        self.doc = {"run_id": run_id, "state": "IDLE", "history": [], "artifacts": {}}
        self._save()

    @property
    def state(self) -> str:
        return self.doc["state"]

    def advance(self, new: str, actor: str, payload: dict | None = None) -> None:
        if new not in TRANSITIONS.get(self.state, set()):
            raise RuntimeError(f"illegal transition {self.state} -> {new}")
        self.doc["history"].append({"t": time.time(), "from": self.state, "to": new,
                                    "actor": actor, "payload": payload or {}})
        self.doc["state"] = new
        self._save()

    def artifact(self, key: str, path: Path) -> None:
        self.doc["artifacts"][key] = str(path)
        self._save()

    def _save(self) -> None:
        self.path.write_text(json.dumps(self.doc, indent=2))
