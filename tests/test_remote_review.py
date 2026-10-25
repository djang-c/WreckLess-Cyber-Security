"""24/7 remote review: every outcome of an item reaches Slack with enough to act on it remotely.

Regression 2026-10-25: a failed patch posted only "Needs a human.", and gate rejections and
crashes posted nothing, so a reviewer away from the box could not tell what went wrong."""
import pytest

from wreckless.agents import blue, red
from wreckless.config import Settings
from wreckless.notify import Notifier
from wreckless.swarm import Swarm

CVE = "CVE-2024-21513"


@pytest.fixture
def cards(monkeypatch):
    for k in ("SLACK_BOT_TOKEN", "SLACK_WEBHOOK_URL", "WRECKLESS_SLACK_REJECTS"):
        monkeypatch.delenv(k, raising=False)
    sent = []

    def send(self, role, title, body):
        sent.append({"role": role, "title": title, "body": body, "blocks": self.card(role, title, body)})
        return "outbox"

    monkeypatch.setattr(Notifier, "send", send)
    return sent


def test_patch_failure_card_says_what_failed(tmp_path, cards, monkeypatch):
    def useless_patch(report, wt, enclave, item_dir, s, target=None):
        f = wt / "victim" / "vector_sql.py"
        f.write_text(f.read_text() + "\n# looks busy, fixes nothing\n")
        return blue.worktree_diff(wt), "llm"

    monkeypatch.setattr(blue, "defend", useless_patch)
    assert Swarm(Settings(use_llm=False), tmp_path).run_hero(CVE) == "patch_failed"
    last = cards[-1]
    assert last["title"].startswith("Patch failed validation")
    assert "Failed: *" in last["body"] and "exploit blocked" in last["body"]
    assert "1 file · +2 −0" in last["body"] and "(end of log)" in last["body"]
    assert "Needs a human" in last["blocks"][0]["text"]["text"]


def test_gate_rejection_posts_a_card(tmp_path, cards, monkeypatch):
    def decoy(intel, wt, enclave, out_dir, s, target=None):
        p = out_dir / "decoy.py"
        p.write_text("print('trust me, it worked')\n")
        return red.Proposal(p, "llm")

    monkeypatch.setattr(red, "attack", decoy)
    assert Swarm(Settings(use_llm=False), tmp_path).run_hero(CVE) == "rejected"
    last = cards[-1]
    assert last["title"].startswith("🛑 Gate rejected") and "Reason: oracle not reached" in last["body"]
    assert "Not reproduced" in last["blocks"][0]["text"]["text"]


def test_crash_posts_a_card_and_still_fails_the_item(tmp_path, cards, monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("disk on fire")

    monkeypatch.setattr(blue, "defend", boom)
    sw = Swarm(Settings(use_llm=False), tmp_path)
    with pytest.raises(RuntimeError):
        sw.run_hero(CVE)
    assert cards[-1]["title"].startswith("💥 Crashed") and "disk on fire" in cards[-1]["body"]
    assert sw.queue.all()[0].state == "patch_failed"   # the in-flight state's terminal failure


def test_success_card_is_summary_not_full_patch(tmp_path, cards):
    assert Swarm(Settings(use_llm=False), tmp_path).run_hero(CVE) == "notified"
    body = cards[-1]["body"]
    assert "Changes: 1 file" in body and "ast.literal_eval" in body   # short patch: excerpt is all of it
