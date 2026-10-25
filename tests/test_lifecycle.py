import json

import pytest

from wreckless.lifecycle import CONFIRMED, PREDICTION, Item
from wreckless.state import StateMachine


def _item(tmp_path):
    return Item.create(tmp_path / "x.json", {"id": "x", "source": "purple", "cve": None})


def test_happy_path_persists_every_transition(tmp_path):
    it = _item(tmp_path)
    assert it.label == PREDICTION
    for s in ["verifying", "verified", "patching", "patched", "notified"]:
        it.advance(s, "t")
        assert json.loads(it.path.read_text())["state"] == s
    assert Item.load(it.path).doc["history"][-1]["to"] == "notified"
    assert {"t", "from", "to", "actor", "payload"} <= it.doc["history"][0].keys()


@pytest.mark.parametrize("path", [
    ["verified"],                                   # cannot skip the gate
    ["patching"],
    ["verifying", "patching"],                      # verifying must resolve first
    ["verifying", "rejected", "patching"],          # rejected is terminal
    ["verifying", "rejected", "notified"],
    ["verifying", "verified", "notified"],          # cannot notify without patching
])
def test_illegal_transitions_raise(tmp_path, path):
    it = _item(tmp_path)
    with pytest.raises(RuntimeError):
        for s in path:
            it.advance(s, "t")


def test_patch_failed_still_notifies(tmp_path):
    it = _item(tmp_path)
    for s in ["verifying", "verified", "patching", "patch_failed", "notified"]:
        it.advance(s, "t")
    assert it.state == "notified" and not it.reached("patched")


def test_kevin_state_machine_unchanged(tmp_path):
    sm = StateMachine(tmp_path, "r")
    assert sm.state == "IDLE" and (tmp_path / "state.json").exists()
    sm.advance("INTEL_READY", "purple")
    with pytest.raises(RuntimeError):
        sm.advance("queued", "x")
    assert not list(tmp_path.glob("*.tmp"))
    assert CONFIRMED == "CONFIRMED_BY_REPRO"
