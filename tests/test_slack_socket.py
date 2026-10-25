import json
import sys

import pytest

from wreckless import slack_socket
from wreckless.notify import APPROVE_ACTION, REJECT_ACTION, build_blocks

CVE = "CVE-2024-21513"
RUN_ID = f"{CVE}#3"
RUN_DIR = f"{CVE}-3"
BRANCH = f"wreckless/fix-{CVE}"
COMMIT = "c0ffee" * 6 + "abcd"


class FakeClient:
    def __init__(self):
        self.updates = []

        self.ephemeral = []

    def chat_update(self, **kw):
        self.updates.append(kw)
        return {"ok": True}

    def chat_postEphemeral(self, **kw):
        self.ephemeral.append(kw)
        return {"ok": True}


def final_card():
    return build_blocks([{"role": "blue", "title": f"✅ Fix branch ready (local, pending review): {CVE}", "body": "diff", "t_rel": 9}],
                        cve=CVE, run_id=RUN_ID, branch=BRANCH, commit=COMMIT)


@pytest.fixture(autouse=True)
def approvers(monkeypatch):
    monkeypatch.setenv("SLACK_APPROVERS", "U123, U456")
    monkeypatch.delenv("SLACK_CHANNEL", raising=False)


def action_body(action_id, value=None, user="U123"):
    blocks = final_card()
    value = value if value is not None else next(b for b in blocks if b["type"] == "actions")["elements"][0]["value"]
    return {"type": "block_actions", "user": {"id": user, "username": "alice"},
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
    assert f"Approved by <@U123>* — approval recorded for branch `{BRANCH}`" in last
    rec = json.loads((tmp_path / RUN_DIR / "decision.json").read_text())
    assert rec["commit"] == COMMIT and rec["run_id"] == RUN_ID
    assert rec["decision"] == "approved" and rec["user"] == "U123" and rec["branch"] == BRANCH


def test_reject_updates_card_and_custom_callback_called(tmp_path, acks):
    seen, ack = acks
    got, client = [], FakeClient()
    handlers = slack_socket.make_handlers(on_reject=got.append, runs_dir=tmp_path)
    handlers[REJECT_ACTION](ack=ack, body=action_body(REJECT_ACTION), client=client)
    assert seen == [1] and got[0]["decision"] == "rejected"
    assert "Rejected by <@U123>" in client.updates[0]["blocks"][-1]["text"]["text"]
    assert not (tmp_path / RUN_DIR / "decision.json").exists()


def test_custom_approve_callback_error_does_not_raise(acks):
    _, ack = acks
    client = FakeClient()

    def bad(info):
        raise RuntimeError("merge bot offline")

    slack_socket.make_handlers(on_approve=bad)[APPROVE_ACTION](
        ack=ack, body=action_body(APPROVE_ACTION), client=client)
    assert not client.updates                       # card keeps its buttons: nothing was recorded
    text = client.ephemeral[0]["text"]
    assert "could not be recorded" in text and "merge bot offline" not in text  # no internals in Slack


def test_save_failure_keeps_buttons_and_retry_works(tmp_path, acks, monkeypatch):
    client = FakeClient()
    h = slack_socket.make_handlers(runs_dir=tmp_path)
    real_link = slack_socket.os.link
    monkeypatch.setattr(slack_socket.os, "link", lambda *a: (_ for _ in ()).throw(OSError("disk full")))
    h[APPROVE_ACTION](ack=acks[1], body=action_body(APPROVE_ACTION), client=client)
    assert not client.updates and "could not be recorded" in client.ephemeral[0]["text"]
    assert not (tmp_path / RUN_DIR / "decision.json").exists()
    assert list((tmp_path / RUN_DIR).iterdir()) == []   # temp file cleaned up
    monkeypatch.setattr(slack_socket.os, "link", real_link)
    h[APPROVE_ACTION](ack=acks[1], body=action_body(APPROVE_ACTION), client=client)
    assert "Approved by <@U123>" in client.updates[0]["blocks"][-1]["text"]["text"]


def test_unsafe_run_id_with_default_callback_keeps_buttons(tmp_path, acks):
    client = FakeClient()
    body = action_body(APPROVE_ACTION, value=json.dumps({"run_id": "../../etc", "commit": COMMIT}))
    slack_socket.make_handlers(runs_dir=tmp_path)[APPROVE_ACTION](ack=acks[1], body=body, client=client)
    assert not client.updates and "could not be recorded" in client.ephemeral[0]["text"]


def test_concurrent_clicks_record_one_decision_and_report_it(tmp_path, acks, monkeypatch):
    """Two approvers click at once: exactly one decision lands; the loser is told the real one."""
    import threading
    h = slack_socket.make_handlers(runs_dir=tmp_path)
    clients = {"U123": FakeClient(), "U456": FakeClient()}
    barrier = threading.Barrier(2)
    real_mkstemp = slack_socket.tempfile.mkstemp

    def synced(*a, **k):
        out = real_mkstemp(*a, **k)
        barrier.wait(timeout=5)                     # both past the exists() check, both writing
        return out

    monkeypatch.setattr(slack_socket.tempfile, "mkstemp", synced)
    threads = [threading.Thread(target=h[APPROVE_ACTION if u == "U123" else REJECT_ACTION],
                                kwargs={"ack": acks[1], "client": c,
                                        "body": action_body(APPROVE_ACTION if u == "U123" else REJECT_ACTION, user=u)})
               for u, c in clients.items()]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=10)
    rec = json.loads((tmp_path / RUN_DIR / "decision.json").read_text())
    winner = clients[rec["user"]]
    loser = clients["U456" if rec["user"] == "U123" else "U123"]
    assert len(winner.updates) == 1 and not loser.updates
    assert f"already {rec['decision']} by <@{rec['user']}>" in loser.ephemeral[0]["text"]
    assert [p.name for p in (tmp_path / RUN_DIR).iterdir()] == ["decision.json"]


def test_handler_survives_garbage_body_and_client_failure(acks):
    seen, ack = acks

    class Broken:
        def chat_update(self, **kw):
            raise ConnectionError("socket closed")

    h = slack_socket.make_handlers(on_approve=lambda i: None)[APPROVE_ACTION]
    h(ack=ack, body={"actions": [{"value": "not json"}]}, client=Broken())
    h(ack=ack, body=action_body(APPROVE_ACTION), client=Broken())
    assert seen == [1, 1]


@pytest.mark.parametrize("user", ["U999", ""])
def test_unlisted_user_cannot_decide(tmp_path, acks, user):
    _, ack = acks
    client = FakeClient()
    slack_socket.make_handlers(runs_dir=tmp_path)[APPROVE_ACTION](
        ack=ack, body=action_body(APPROVE_ACTION, user=user), client=client)
    assert not client.updates and not list(tmp_path.iterdir())


def test_no_approvers_configured_means_nobody(tmp_path, acks, monkeypatch):
    monkeypatch.delenv("SLACK_APPROVERS")
    client = FakeClient()
    slack_socket.make_handlers(runs_dir=tmp_path)[APPROVE_ACTION](
        ack=acks[1], body=action_body(APPROVE_ACTION), client=client)
    assert not client.updates and not list(tmp_path.iterdir())


def test_wrong_channel_is_ignored(tmp_path, acks, monkeypatch):
    monkeypatch.setenv("SLACK_CHANNEL", "C0REAL123")
    client = FakeClient()
    slack_socket.make_handlers(runs_dir=tmp_path)[APPROVE_ACTION](
        ack=acks[1], body=action_body(APPROVE_ACTION), client=client)
    assert not client.updates and client.ephemeral


def test_first_decision_wins(tmp_path, acks):
    h = slack_socket.make_handlers(runs_dir=tmp_path)
    c1, c2 = FakeClient(), FakeClient()
    h[APPROVE_ACTION](ack=acks[1], body=action_body(APPROVE_ACTION), client=c1)
    h[REJECT_ACTION](ack=acks[1], body=action_body(REJECT_ACTION, user="U456"), client=c2)
    rec = json.loads((tmp_path / RUN_DIR / "decision.json").read_text())
    assert rec["decision"] == "approved" and not c2.updates and "already approved" in c2.ephemeral[0]["text"]


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


class FakeHandler:
    def __init__(self, fail_connect=False):
        self.fail_connect, self.connected, self.closed = fail_connect, False, False

    def connect(self):
        if self.fail_connect:
            raise ConnectionError("apps.connections.open failed")
        self.connected = True

    def close(self):
        self.closed = True


@pytest.fixture
def fake_bolt(monkeypatch):
    monkeypatch.setattr(slack_socket, "_enabled", lambda: (True, "enabled"))  # no slack_bolt, no network
    monkeypatch.setattr(slack_socket, "RETRY_FIRST", 0.01)
    monkeypatch.setattr(slack_socket, "RETRY_MAX", 0.02)


def _wait_for(cond, timeout=5.0):
    import time
    end = time.monotonic() + timeout
    while not cond() and time.monotonic() < end:
        time.sleep(0.01)
    return cond()


def test_listener_retries_and_logs_enabled_only_after_connect(fake_bolt, monkeypatch, capsys):
    made = []

    def build(*a):
        made.append(None)
        if len(made) == 1:
            raise RuntimeError("invalid_auth")      # App() auth.test fails
        h = FakeHandler(fail_connect=len(made) == 2)
        made[-1] = h
        return h

    monkeypatch.setattr(slack_socket, "_build_handler", build)
    h = slack_socket.start_listener()
    assert h is not None and h.thread.daemon
    assert _wait_for(lambda: h.handler is not None and h.handler.connected)
    h.stop()
    h.thread.join(timeout=5)
    assert not h.thread.is_alive() and made[-1].closed and made[1].closed


def test_listener_log_order(fake_bolt, monkeypatch, capsys):
    calls = iter([RuntimeError("invalid_auth"), FakeHandler()])

    def build(*a):
        nxt = next(calls)
        if isinstance(nxt, Exception):
            raise nxt
        return nxt

    monkeypatch.setattr(slack_socket, "_build_handler", build)
    h = slack_socket.start_listener()
    assert _wait_for(lambda: h.handler is not None and h.handler.connected)
    h.stop()
    h.thread.join(timeout=5)
    err = capsys.readouterr().err
    assert err.index("connecting") < err.index("connect failed (attempt 1): invalid_auth") \
        < err.index("] enabled")


def test_stop_before_first_connect_finishes(fake_bolt, monkeypatch):
    import threading
    gate, built = threading.Event(), []

    def slow_build(*a):
        gate.wait(5)                                # auth.test still in flight
        built.append(FakeHandler())
        return built[-1]

    monkeypatch.setattr(slack_socket, "_build_handler", slow_build)
    h = slack_socket.start_listener()
    h.stop()                                        # handler not set yet: must still take effect
    gate.set()
    h.thread.join(timeout=5)
    assert not h.thread.is_alive()
    assert built[0].closed and not built[0].connected and h.handler is None


# ---------- offline preflight: python -m wreckless.slack_socket --check (no network) ----------

GOOD = {"SLACK_BOT_TOKEN": "xoxb-1-2-abc", "SLACK_APP_TOKEN": "xapp-1-A1-2-def",
        "SLACK_CHANNEL": "C0123ABCD", "SLACK_APPROVERS": "U01AB,U02CD"}


def _check(monkeypatch, env, bolt=True):
    for k in ("SLACK_BOT_TOKEN", "SLACK_APP_TOKEN", "SLACK_CHANNEL", "SLACK_APPROVERS", "SLACK_WEBHOOK_URL"):
        monkeypatch.delenv(k, raising=False)
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    monkeypatch.setattr(slack_socket, "_bolt_installed", lambda: bolt)
    return slack_socket.preflight()


def test_preflight_all_good(monkeypatch):
    ok, rows = _check(monkeypatch, GOOD)
    assert ok and all(r[1] == "PASS" for r in rows)


@pytest.mark.parametrize("key,val,needle", [
    ("SLACK_BOT_TOKEN", "xapp-oops", "xoxb-"),
    ("SLACK_APP_TOKEN", "xoxb-oops", "xapp-"),
    ("SLACK_CHANNEL", "#wreckless-demo", "channel ID"),
    ("SLACK_APPROVERS", "kevin,jang", "member ID"),
    ("SLACK_APPROVERS", "", "nobody can approve"),
])
def test_preflight_flags_each_mistake(monkeypatch, key, val, needle):
    ok, rows = _check(monkeypatch, GOOD | {key: val})
    assert not ok and any(r[1] == "FAIL" and needle in r[2] for r in rows), rows


def test_preflight_flags_missing_bolt(monkeypatch):
    ok, rows = _check(monkeypatch, GOOD, bolt=False)
    assert not ok and any("uv sync --extra slack" in r[2] for r in rows)


def test_preflight_never_prints_secrets(monkeypatch, capsys):
    _check(monkeypatch, GOOD)
    slack_socket.print_preflight(*slack_socket.preflight())
    out = capsys.readouterr().out
    assert "abc" not in out and "def" not in out and "xoxb-…" in out


def test_preflight_makes_no_network_calls(monkeypatch):
    import socket
    monkeypatch.setattr(socket.socket, "connect", lambda *a, **k: pytest.fail("network used"))
    _check(monkeypatch, GOOD)
