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

    def chat_postMessage(self, **kw):
        self.ephemeral.append(kw)
        return {"ok": True}


def final_card():
    return build_blocks([{"role": "blue", "title": f"✅ Fix branch ready (local, pending review): {CVE}", "body": "diff", "t_rel": 9}],
                        cve=CVE, run_id=RUN_ID, branch=BRANCH, commit=COMMIT)


@pytest.fixture(autouse=True)
def approvers(monkeypatch):
    monkeypatch.setenv("SLACK_APPROVERS", "U123, U456")
    monkeypatch.delenv("SLACK_CHANNEL", raising=False)
    monkeypatch.delenv("WRECKLESS_GITHUB_REPO", raising=False)   # no test may reach GitHub


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


# ---------- decisions go through Porter's airlock: the listener never touches a finding ----------
@pytest.fixture
def wire(tmp_path):
    """Listener handlers + Porter's inner door on one airlock; items live in tmp_path/items."""
    from wreckless import porter
    from wreckless.airlock import Airlock
    from wreckless.config import Settings
    from wreckless.porter_outer import Outer
    lock = Airlock(tmp_path / "airlock")
    outer = Outer(lock)
    inner = porter.Inner(tmp_path, lock=lock, s=Settings(use_llm=False), use_llm=False)
    h = slack_socket.make_handlers(outer=outer)

    def click(action, user="U123", value=None, client=None, settle=True):
        c = client or FakeClient()
        h[action](ack=lambda *a, **k: None, body=action_body(action, value, user), client=c)
        if settle:
            inner.run_once()
            outer.deliver(c)
        return c
    click.items, click.inner, click.outer = tmp_path / "items", inner, outer
    return click


def test_approve_goes_through_the_airlock_and_redraws_the_card(wire):
    c = wire(APPROVE_ACTION)
    pending, final = c.updates
    assert not [b for b in pending["blocks"] if b["type"] == "actions"]       # no double-click meanwhile
    assert "recording it on the WreckLess host" in pending["blocks"][-1]["text"]["text"]
    assert final["channel"] == "C0FAKE" and final["ts"] == "111.222"
    assert f"Approved by <@U123>* — approval recorded for branch `{BRANCH}`" in final["blocks"][-1]["text"]["text"]
    rec = json.loads((wire.items / RUN_DIR / "decision.json").read_text())
    assert rec["commit"] == COMMIT and rec["run_id"] == RUN_ID
    assert rec["decision"] == "approved" and rec["user"] == "U123" and rec["branch"] == BRANCH


def test_nothing_is_recorded_until_the_inside_runs(wire):
    c = wire(APPROVE_ACTION, settle=False)
    assert len(c.updates) == 1 and not (wire.items / RUN_DIR).exists()   # the listener wrote nothing


def test_reject_is_recorded_and_never_publishes(wire, monkeypatch):
    from wreckless import publish
    monkeypatch.setattr(publish, "publish", lambda *a, **k: (_ for _ in ()).throw(AssertionError("pushed")))
    c = wire(REJECT_ACTION)
    assert "Rejected by <@U123>" in c.updates[-1]["blocks"][-1]["text"]["text"]
    assert json.loads((wire.items / RUN_DIR / "decision.json").read_text())["decision"] == "rejected"


def test_custom_callbacks_still_run_in_process(acks):
    got, client = [], FakeClient()
    h = slack_socket.make_handlers(on_approve=got.append, on_reject=got.append)
    h[REJECT_ACTION](ack=acks[1], body=action_body(REJECT_ACTION), client=client)
    assert got[0]["decision"] == "rejected" and "Rejected by <@U123>" in client.updates[0]["blocks"][-1]["text"]["text"]


def test_custom_approve_callback_error_does_not_raise(acks):
    _, ack = acks
    client = FakeClient()

    def bad(info):
        raise RuntimeError("merge bot offline")

    slack_socket.make_handlers(on_approve=bad, on_reject=bad)[APPROVE_ACTION](
        ack=ack, body=action_body(APPROVE_ACTION), client=client)
    assert not client.updates                       # card keeps its buttons: nothing was recorded
    text = client.ephemeral[0]["text"]
    assert "could not be recorded" in text and "merge bot offline" not in text  # no internals in Slack


def test_save_failure_restores_buttons_and_retry_works(wire, monkeypatch):
    from wreckless import decisions
    real_link = decisions.os.link
    monkeypatch.setattr(decisions.os, "link", lambda *a: (_ for _ in ()).throw(OSError("disk full")))
    c = wire(APPROVE_ACTION)
    assert [b for b in c.updates[-1]["blocks"] if b["type"] == "actions"]   # buttons back
    assert "could not be recorded" in c.ephemeral[-1]["text"]
    assert not (wire.items / RUN_DIR / "decision.json").exists()
    assert list((wire.items / RUN_DIR).iterdir()) == []   # temp file cleaned up
    monkeypatch.setattr(decisions.os, "link", real_link)
    c = wire(APPROVE_ACTION)
    assert "Approved by <@U123>" in c.updates[-1]["blocks"][-1]["text"]["text"]


@pytest.mark.parametrize("value", [json.dumps({"run_id": "../../etc", "commit": COMMIT, "branch": BRANCH}),
                                   json.dumps({"run_id": RUN_ID, "commit": "HEAD", "branch": BRANCH}),
                                   json.dumps({"run_id": RUN_ID, "commit": COMMIT, "branch": "main"}),
                                   "not json"])
def test_malformed_click_never_reaches_the_inside(wire, value):
    c = wire(APPROVE_ACTION, value=value, settle=False)
    assert not c.updates and "could not be recorded" in c.ephemeral[0]["text"]
    assert not list((wire.items.parent / "airlock" / "inbox").glob("*.json"))


def test_two_clicks_one_decision_and_the_second_is_told(wire):
    c1 = wire(APPROVE_ACTION, settle=False)
    c2 = wire(REJECT_ACTION, user="U456", settle=False)
    wire.inner.run_once()
    shared = FakeClient()
    wire.outer.deliver(shared)
    rec = json.loads((wire.items / RUN_DIR / "decision.json").read_text())
    assert rec["decision"] == "approved" and rec["user"] == "U123"
    assert all("Approved by <@U123>" in u["blocks"][-1]["text"]["text"] for u in shared.updates)
    assert any("already approved by <@U123>" in e["text"] and e["user"] == "U456" for e in shared.ephemeral)
    assert [p.name for p in (wire.items / RUN_DIR).iterdir()] == ["decision.json"]
    assert c1.updates and c2.updates                 # each clicker saw "recording…" at once


def test_handler_survives_garbage_body_and_client_failure(acks):
    seen, ack = acks

    class Broken:
        def chat_update(self, **kw):
            raise ConnectionError("socket closed")

    h = slack_socket.make_handlers(on_approve=lambda i: None, on_reject=lambda i: None)[APPROVE_ACTION]
    h(ack=ack, body={"actions": [{"value": "not json"}]}, client=Broken())
    h(ack=ack, body=action_body(APPROVE_ACTION), client=Broken())
    assert seen == [1, 1]


@pytest.mark.parametrize("user", ["U999", ""])
def test_unlisted_user_cannot_decide(wire, user):
    c = wire(APPROVE_ACTION, user=user)
    assert not c.updates and not wire.items.exists()


def test_no_approvers_configured_means_nobody(wire, monkeypatch):
    monkeypatch.delenv("SLACK_APPROVERS")
    c = wire(APPROVE_ACTION)
    assert not c.updates and not wire.items.exists()


def test_wrong_channel_is_ignored(wire, monkeypatch):
    monkeypatch.setenv("SLACK_CHANNEL", "C0REAL123")
    c = wire(APPROVE_ACTION)
    assert not c.updates and c.ephemeral and not wire.items.exists()


@pytest.mark.parametrize("run_id", ["../../etc", "/abs", "", None, "a/b"])
def test_record_decision_rejects_unsafe_run_id(tmp_path, run_id):
    from wreckless.decisions import record_decision
    assert record_decision({"decision": "approved", "run_id": run_id}, tmp_path) is None
    assert list(tmp_path.iterdir()) == []


def test_listener_process_cannot_reach_findings_github_or_models():
    """The Slack listener module loads nothing that reads or writes a finding, pushes, or runs a model."""
    import subprocess
    forbidden = ["wreckless.swarm", "wreckless.porter", "wreckless.candidates", "wreckless.sandbox",
                 "wreckless.gitops", "wreckless.agents", "wreckless.llm", "wreckless.publish",
                 "wreckless.decisions", "wreckless.gate", "openai"]
    code = f"import sys, wreckless.slack_socket; print([m for m in {forbidden!r} if m in sys.modules])"
    assert subprocess.run([sys.executable, "-c", code], capture_output=True, text=True,
                          check=True).stdout.strip() == "[]"


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


# ---------- Approve -> draft PR, opened on the inside ----------
def test_approve_opens_draft_pr_and_links_it(wire, monkeypatch):
    from wreckless import publish
    got = []

    def fake(info, runs_dir):
        assert (runs_dir / RUN_DIR / "decision.json").exists()   # recorded before anything is pushed
        got.append(info)
        return {"url": "https://github.com/acme/v/pull/7"}

    monkeypatch.setattr(publish, "publish", fake)
    text = wire(APPROVE_ACTION).updates[-1]["blocks"][-1]["text"]["text"]
    assert "draft PR opened: https://github.com/acme/v/pull/7" in text
    assert got[0]["commit"] == COMMIT and got[0]["decision"] == "approved"


def test_failed_pr_keeps_the_approval_and_says_how_to_retry(wire, monkeypatch):
    from wreckless import publish

    def fail(info, runs_dir):
        raise publish.PublishError("push failed: network unreachable")

    monkeypatch.setattr(publish, "publish", fail)
    text = wire(APPROVE_ACTION).updates[-1]["blocks"][-1]["text"]["text"]
    assert "draft PR failed: push failed: network unreachable" in text
    assert f"python -m wreckless.publish {RUN_ID}" in text
    assert json.loads((wire.items / RUN_DIR / "decision.json").read_text())["decision"] == "approved"


def test_without_github_repo_approval_stays_local(wire):
    assert "GitHub not configured: approval stays local" in wire(APPROVE_ACTION).updates[-1]["blocks"][-1]["text"]["text"]


def test_preflight_github_rows(monkeypatch):
    monkeypatch.delenv("WRECKLESS_GITHUB_REPO", raising=False)
    assert slack_socket._github_rows("")[0][1] == "PASS"            # optional
    assert slack_socket._github_rows("not a repo")[0][1] == "FAIL"
    monkeypatch.setattr(slack_socket, "_gh_logged_in", lambda: False)
    rows = dict((r[0], r[1]) for r in slack_socket._github_rows("acme/wreckless-victim"))
    assert rows == {"WRECKLESS_GITHUB_REPO": "PASS", "gh logged in": "FAIL"}
