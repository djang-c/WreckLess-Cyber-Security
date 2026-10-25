import json

import pytest

from wreckless import notify
from wreckless.notify import APPROVE_ACTION, REJECT_ACTION, Notifier, build_blocks

CVE = "CVE-2024-21513"
FINAL_BODY = (f"Branch `wreckless/fix-{CVE}` @ `abcdef1234` · patch: cached\n"
              "Held-out regression ✅ · functional ✅ · exploit blocked ✅ · 12s\n```- eval(x)\n+ x```")


@pytest.fixture
def bot(monkeypatch, tmp_path):
    monkeypatch.setenv("SLACK_BOT_TOKEN", "xoxb-fake")
    monkeypatch.setenv("SLACK_CHANNEL", "#sec")
    monkeypatch.delenv("SLACK_WEBHOOK_URL", raising=False)
    calls = []

    def fake_post(url, payload, headers=None):
        calls.append((url, payload))
        return {"ok": True, "ts": "111.222", "channel": "C0FAKE"}

    monkeypatch.setattr(Notifier, "_post", staticmethod(fake_post))
    n = Notifier(run_id=f"{CVE}-20261025-020400", enclave="subprocess")
    n.outbox = tmp_path / "outbox.jsonl"
    return n, calls


def texts(blocks):
    out = []
    for b in blocks:
        if "text" in b:
            out.append(b["text"]["text"])
        for e in b.get("elements", []):
            out.append(e.get("text", {}).get("text") if e["type"] == "button" else e.get("text", ""))
    return "\n".join(t for t in out if t)


def actions(blocks):
    return [b for b in blocks if b["type"] == "actions"]


def run_beats(n, fail=False):
    n.send("purple", f"Advisory ingested: {CVE}", "*HIGH* — eval of DB values")
    n.send("red", f"🚨 Intrusion reproduced: {CVE}", "Commit `deadbeef00` exploitable.\n```pwned```")
    if fail:
        return n.send("blue", f"Patch failed validation: {CVE}", "Needs a human.")
    return n.send("blue", f"✅ Fix branch ready (local, pending review): {CVE}", FINAL_BODY)


def test_first_beat_posts_later_beats_update_same_ts(bot):
    n, calls = bot
    assert run_beats(n) == "slack:chat.update"
    urls = [u.rsplit("/", 1)[1] for u, _ in calls]
    assert urls == ["chat.postMessage", "chat.update", "chat.update"]
    assert all(p["ts"] == "111.222" and p["channel"] == "C0FAKE" for _, p in calls[1:])


def test_card_is_cumulative_per_beat(bot):
    n, calls = bot
    run_beats(n)
    b1, b2, b3 = (p["blocks"] for _, p in calls)
    assert "🕵️" in texts(b1) and "Intrusion" not in texts(b1) and not actions(b1)
    assert b2[0]["text"]["text"].startswith("⏳") and "Advisory ingested" in texts(b2)
    assert "🎩" in texts(b2) and not actions(b2)
    t3 = texts(b3)
    assert b3[0]["text"]["text"] == f"✅ WreckLess · {CVE} · Fix branch ready (pending review)"
    assert all(s in t3 for s in ("🕵️", "🎩", "👷", "Fix branch ready", "enclave: `subprocess`",
                                 "patch: `cached`"))
    [act] = actions(b3)
    ids = [e["action_id"] for e in act["elements"]]
    assert ids == [APPROVE_ACTION, REJECT_ACTION]
    value = json.loads(act["elements"][0]["value"])
    assert {k: value[k] for k in ("run_id", "branch", "cve")} == \
        {"run_id": f"{CVE}-20261025-020400", "branch": f"wreckless/fix-{CVE}", "cve": CVE}
    assert "commit" in value


def test_failure_path_renders_cross_and_no_buttons(bot):
    n, calls = bot
    run_beats(n, fail=True)
    final = calls[-1][1]["blocks"]
    assert final[0]["text"]["text"].startswith("❌") and "Needs a human" in final[0]["text"]["text"]
    assert "✅" not in final[0]["text"]["text"] and not actions(final)
    assert "❌ 👷 *Patch failed validation" in texts(final)


def test_slack_exception_goes_to_outbox_and_never_raises(monkeypatch, tmp_path, bot):
    n, _ = bot

    def boom(*a, **k):
        raise OSError("network down")

    monkeypatch.setattr(Notifier, "_post", staticmethod(boom))
    assert n.send("purple", f"Advisory ingested: {CVE}", "x") == "outbox"
    rec = json.loads(n.outbox.read_text().splitlines()[-1])
    assert "slack error: network down" in rec["title"] and rec["blocks"][0]["type"] == "header"


def test_slack_ok_false_goes_to_outbox(monkeypatch, bot):
    n, _ = bot
    monkeypatch.setattr(Notifier, "_post", staticmethod(lambda *a, **k: {"ok": False, "error": "not_in_channel"}))
    assert n.send("purple", "t", "b") == "outbox"
    assert "not_in_channel" in n.outbox.read_text()


def test_non_json_slack_body_is_a_failure_not_a_silent_success(monkeypatch, bot):
    n, _ = bot
    monkeypatch.setattr(Notifier, "_post", staticmethod(lambda *a, **k: {}))  # proxy HTML page
    assert n.send("purple", "t", "b") == "outbox" and n.ts is None
    assert "non-JSON" in n.outbox.read_text()


def test_failed_update_resets_ts_so_next_beat_posts_fresh(monkeypatch, bot):
    n, calls = bot
    assert n.send("purple", "t1", "b") == "slack:chat.postMessage" and n.ts == "111.222"
    real = Notifier._post

    def deleted(url, payload, headers=None):
        calls.append((url, payload))
        return {"ok": False, "error": "message_not_found"}

    monkeypatch.setattr(Notifier, "_post", staticmethod(deleted))
    assert n.send("red", "t2", "b") == "outbox" and n.ts is None
    monkeypatch.setattr(Notifier, "_post", staticmethod(real))
    assert n.send("blue", "t3", "b") == "slack:chat.postMessage"
    assert calls[-1][0].endswith("chat.postMessage") and "ts" not in calls[-1][1]


def test_webhook_and_outbox_fallbacks(monkeypatch, tmp_path):
    monkeypatch.delenv("SLACK_BOT_TOKEN", raising=False)
    monkeypatch.setenv("SLACK_WEBHOOK_URL", "https://hooks.invalid/x")
    sent = []
    monkeypatch.setattr(Notifier, "_post", staticmethod(lambda url, p, h=None: sent.append(p) or {}))
    n = Notifier()
    assert n.send("purple", "a", "b") == "slack:webhook" and sent[0]["blocks"][0]["type"] == "header"
    monkeypatch.delenv("SLACK_WEBHOOK_URL")
    n2 = Notifier()
    n2.outbox = tmp_path / "o.jsonl"
    assert n2.send("purple", "a", "b") == "outbox" and n2.outbox.exists()


def test_slack_limits_respected():
    huge = "x" * 10_000
    beats = [{"role": "red", "title": huge, "body": "```" + huge, "t_rel": i} for i in range(80)]
    beats[-1]["title"] = "✅ Fix branch ready (local, pending review): " + huge
    blocks = build_blocks(beats, cve="CVE-" + huge, run_id="r", branch="b")
    assert len(blocks) <= notify.BLOCKS_MAX
    assert len(blocks[0]["text"]["text"]) <= 150
    for b in blocks:
        if b["type"] == "section":
            assert len(b["text"]["text"]) <= 3000
    assert blocks[3]["text"]["text"].rstrip().endswith("```")  # clipped fence is closed
    assert all(len(e["value"]) <= 2000 for e in actions(blocks)[0]["elements"])


def test_build_blocks_empty():
    assert build_blocks([]) == []


def test_swarm_final_title_gets_the_approve_buttons():
    """The final beat swarm.py actually sends must render as success (buttons shown)."""
    import inspect
    from wreckless import notify, swarm
    assert 'title = "Fix branch ready (local, pending review)"' in inspect.getsource(swarm)
    assert notify.beat_outcome("✅ Fix branch ready (local, pending review): CVE-X#1") == "ok"
    assert notify.beat_outcome("✅ Fix branch ready (local, pending review) · ⚠️ CACHED: CVE-X#1") == "ok"
