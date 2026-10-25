import json
import sys

import pytest

from wreckless import slack_socket
from wreckless.notify import APPROVE_ACTION, REJECT_ACTION, build_blocks

CVE = "CVE-2024-21513"
RUN_ID = f"{CVE}-20261025-020400"
BRANCH = f"wreckless/fix-{CVE}"


class FakeClient:
    def __init__(self):
        self.updates = []

    def chat_update(self, **kw):
        self.updates.append(kw)
        return {"ok": True}


def final_card():
    return build_blocks([{"role": "blue", "title": f"✅ Draft PR Ready: {CVE}", "body": "diff", "t_rel": 9}],
                        cve=CVE, run_id=RUN_ID, branch=BRANCH)


def action_body(action_id, value=None):
    blocks = final_card()
    value = value if value is not None else next(b for b in blocks if b["type"] == "actions")["elements"][0]["value"]
    return {"type": "block_actions", "user": {"id": "U123", "username": "alice"},
            "channel": {"id": "C0FAKE"}, "container": {"channel_id": "C0FAKE", "message_ts": "111.222"},
            "message": {"ts": "111.222", "blocks": blocks},
            "actions": [{"action_id": action_id, "value": value}]}


@pytest.fixture
def acks():
    seen = []
    return seen, (lambda *a, **k: seen.append(1))


def test_approve_acks_updates_card_and_records(tmp_path, acks):
    seen, ack = acks
    client = FakeClient()
    handlers = slack_socket.make_handlers(runs_dir=tmp_path)
    handlers[APPROVE_ACTION](ack=ack, body=action_body(APPROVE_ACTION), client=client)
    assert seen == [1]
    [up] = client.updates
    assert up["channel"] == "C0FAKE" and up["ts"] == "111.222"
    assert not [b for b in up["blocks"] if b["type"] == "actions"]  # buttons gone
    last = up["blocks"][-1]["text"]["text"]
    assert f"Approved by <@U123>* — merging branch `{BRANCH}`" in last
    rec = json.loads((tmp_path / RUN_ID / "approval.json").read_text())
    assert rec["decision"] == "approved" and rec["user"] == "U123" and rec["branch"] == BRANCH


def test_reject_updates_card_and_custom_callback_called(tmp_path, acks):
    seen, ack = acks
    got, client = [], FakeClient()
    handlers = slack_socket.make_handlers(on_reject=got.append, runs_dir=tmp_path)
    handlers[REJECT_ACTION](ack=ack, body=action_body(REJECT_ACTION), client=client)
    assert seen == [1] and got[0]["decision"] == "rejected"
    assert "Rejected by <@U123>" in client.updates[0]["blocks"][-1]["text"]["text"]
    assert not (tmp_path / RUN_ID / "approval.json").exists()


def test_custom_approve_callback_error_does_not_raise(acks):
    _, ack = acks
    client = FakeClient()

    def bad(info):
        raise RuntimeError("merge bot offline")

    slack_socket.make_handlers(on_approve=bad)[APPROVE_ACTION](
        ack=ack, body=action_body(APPROVE_ACTION), client=client)
    assert "callback error: merge bot offline" in client.updates[0]["blocks"][-1]["text"]["text"]


def test_handler_survives_garbage_body_and_client_failure(acks):
    seen, ack = acks

    class Broken:
        def chat_update(self, **kw):
            raise ConnectionError("socket closed")

    h = slack_socket.make_handlers(on_approve=lambda i: None)[APPROVE_ACTION]
    h(ack=ack, body={"actions": [{"value": "not json"}]}, client=Broken())
    h(ack=ack, body=action_body(APPROVE_ACTION), client=Broken())
    assert seen == [1, 1]


@pytest.mark.parametrize("run_id", ["../../etc", "/abs", "", None, "a/b"])
def test_record_decision_rejects_unsafe_run_id(tmp_path, run_id):
    assert slack_socket.record_decision({"decision": "approved", "run_id": run_id}, tmp_path) is None
    assert list(tmp_path.iterdir()) == []


def test_register_wires_both_action_ids():
    class FakeApp:
        def __init__(self):
            self.reg = {}

        def action(self, action_id):
            return lambda fn: self.reg.setdefault(action_id, fn)

    app = FakeApp()
    slack_socket.register(app, slack_socket.make_handlers())
    assert set(app.reg) == {APPROVE_ACTION, REJECT_ACTION}


@pytest.mark.parametrize("env", [{}, {"SLACK_BOT_TOKEN": "xoxb-x"}, {"SLACK_APP_TOKEN": "xapp-x"}])
def test_missing_tokens_disables_listener(monkeypatch, capsys, env):
    for k in ("SLACK_BOT_TOKEN", "SLACK_APP_TOKEN"):
        monkeypatch.delenv(k, raising=False)
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    assert slack_socket.start_listener() is None
    err = capsys.readouterr().err.strip().splitlines()
    assert len(err) == 1 and "disabled" in err[0]


def test_missing_slack_bolt_disables_listener(monkeypatch, capsys):
    monkeypatch.setenv("SLACK_BOT_TOKEN", "xoxb-x")
    monkeypatch.setenv("SLACK_APP_TOKEN", "xapp-x")
    monkeypatch.setitem(sys.modules, "slack_bolt", None)  # import -> ImportError
    assert slack_socket.start_listener() is None
    assert "slack_bolt not installed" in capsys.readouterr().err


def test_listener_runs_in_daemon_thread_and_swallows_errors(monkeypatch, capsys):
    pytest.importorskip("slack_bolt")
    monkeypatch.setenv("SLACK_BOT_TOKEN", "xoxb-x")
    monkeypatch.setenv("SLACK_APP_TOKEN", "xapp-x")

    def boom(*a):
        raise RuntimeError("invalid_auth")

    monkeypatch.setattr(slack_socket, "_build_handler", boom)  # no network in tests
    h = slack_socket.start_listener()
    assert h is not None and h.thread.daemon
    h.thread.join(timeout=5)
    assert "listener stopped: invalid_auth" in capsys.readouterr().err
    h.stop()
