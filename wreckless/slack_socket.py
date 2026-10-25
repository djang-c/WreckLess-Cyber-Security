"""Optional Slack Socket Mode listener for the run card's "Approve fix" / "Reject" buttons.

Socket Mode is outbound-only (wss to *.slack.com), so it survives the cloud-LLM airgap.
Enabled only if `slack_bolt` is importable AND SLACK_BOT_TOKEN + SLACK_APP_TOKEN are set;
otherwise `start_listener()` logs one line and returns None. This is Porter's OUTER door: it
never reads or writes a finding. A click is checked (approver, channel) and forwarded through the
airlock; Porter's inner door (`wreckless daemon --porter` or `python -m wreckless.porter`)
records `decision.json` and, for an approval with WRECKLESS_GITHUB_REPO set, opens the draft PR.

Only Slack user IDs in SLACK_APPROVERS (comma-separated) may decide; unset means nobody can.
If SLACK_CHANNEL is a channel ID, clicks from any other channel are ignored. The first
decision per item wins; later clicks (double-clicks, Slack retries) are refused. If a
decision cannot be recorded the card keeps its buttons. A failed connect (bad token, no
network yet) is retried with backoff; "enabled" is logged only once connected.

Blocking standalone mode (keeps buttons live after a `wreckless run` exits):
    uv run --extra slack python -m wreckless.slack_socket
"""
import json
import os
import re
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from wreckless.airlock import AlreadyDecided
from wreckless.notify import APPROVE_ACTION, REJECT_ACTION, decided_blocks, pending_blocks

Decision = Callable[[dict], object]


def _log(msg: str) -> None:
    print(f"[slack-socket] {msg}", file=sys.stderr, flush=True)


def _approvers() -> set[str]:
    return {u.strip() for u in os.environ.get("SLACK_APPROVERS", "").split(",") if u.strip()}


def _expected_channel() -> str | None:
    ch = os.environ.get("SLACK_CHANNEL", "")
    return ch if re.fullmatch(r"[CG][A-Z0-9]{6,}", ch) else None  # names like #sec can't be checked


def _deny(client, channel: str | None, user: str, text: str) -> None:
    _log(text)
    try:
        if channel and user:
            client.chat_postEphemeral(channel=channel, user=user, text=text)
    except Exception as e:  # noqa: BLE001
        _log(f"ephemeral failed: {e}")


def make_handlers(on_approve: Decision | None = None, on_reject: Decision | None = None,
                  approvers: set[str] | None = None, outer=None) -> dict[str, Callable]:
    """Return {action_id: handler}. Handlers use Bolt's kwarg injection (ack, body, client).

    Default: a click is checked here (approver, channel) and forwarded through Porter's airlock;
    the inside records it and opens the draft PR, and `Outer.deliver` redraws the card from the
    reply. This process never reads or writes a finding. `on_approve`/`on_reject` callbacks
    (library use and tests) are called in-process instead."""
    if outer is None and (on_approve is None or on_reject is None):
        from wreckless.porter_outer import Outer
        outer = Outer()

    def handle(decision: str, callback: Decision | None, ack, body: dict, client) -> None:
        try:
            ack()
        except Exception as e:  # noqa: BLE001
            _log(f"ack failed: {e}")
        try:
            action = (body.get("actions") or [{}])[0]
            try:
                value = json.loads(action.get("value") or "{}")
            except ValueError:
                value = {}
            user = (body.get("user") or {}).get("id") or ""
            msg = body.get("message") or {}
            channel = (body.get("channel") or {}).get("id") or (body.get("container") or {}).get("channel_id")
            ts = msg.get("ts") or (body.get("container") or {}).get("message_ts")
            allowed = _approvers() if approvers is None else approvers
            if user not in allowed:
                return _deny(client, channel, user, f"<@{user}> is not in SLACK_APPROVERS; {decision} ignored")
            expected = _expected_channel()
            if expected and channel != expected:
                return _deny(client, channel, user, f"decisions are only accepted in <#{expected}>")
            if callback is None:   # through the airlock
                ok, why = outer.forward_decision(decision, user, channel, ts, msg.get("blocks") or [], value)
                if not ok:
                    return _deny(client, channel, user, f"{decision} could not be recorded ({why}); try again")
                if channel and ts:
                    client.chat_update(channel=channel, ts=ts, text=f"WreckLess: {decision} received",
                                       blocks=pending_blocks(msg.get("blocks") or [], decision, user))
                return
            info = {"decision": decision, "user": user, "run_id": value.get("run_id"),
                    "branch": value.get("branch"), "commit": value.get("commit"),
                    "cve": value.get("cve"), "t": time.time()}
            note = None
            try:
                out = callback(info)
                if isinstance(out, Path):
                    note = f"recorded {out.name} for {info['run_id']} @ {(info['commit'] or '?')[:10]}"
            except AlreadyDecided as e:
                rec = e.args[0] if e.args and isinstance(e.args[0], dict) else {}
                return _deny(client, channel, user, f"{info['run_id']} was already {rec.get('decision', 'decided')}"
                                                    + (f" by <@{rec['user']}>" if rec.get("user") else "") + "; click ignored")
            except Exception as e:  # noqa: BLE001
                # nothing was recorded: leave the card and its buttons alone so someone can retry
                _log(f"callback error: {e}")
                return _deny(client, channel, user, f"{decision} for {info['run_id']} could not be "
                                                    "recorded (see the WreckLess host log); try again")
            if channel and ts:
                client.chat_update(channel=channel, ts=ts, text=f"WreckLess: {decision}",
                                   blocks=decided_blocks(msg.get("blocks") or [], decision, user,
                                                         info["branch"], note))
        except Exception as e:  # noqa: BLE001
            _log(f"{decision} handler error: {e}")

    def approve(ack, body, client):
        handle("approved", on_approve, ack, body, client)

    def reject(ack, body, client):
        handle("rejected", on_reject, ack, body, client)

    handlers = {APPROVE_ACTION: approve, REJECT_ACTION: reject}
    handlers["_outer"] = outer   # shared with register_porter (one airlock, one pending map)
    return handlers


def register(app, handlers: dict[str, Callable]) -> None:
    for action_id, fn in handlers.items():
        if not action_id.startswith("_"):
            app.action(action_id)(fn)


@dataclass
class ListenerHandle:
    thread: threading.Thread
    handler: object | None = None
    stopped: threading.Event = field(default_factory=threading.Event)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def adopt(self, handler) -> bool:
        """Listener thread hands over a fresh handler; False (and it is closed) if stop() won."""
        with self._lock:
            if not self.stopped.is_set():
                self.handler = handler
                return True
        _close(handler)
        return False

    def drop(self) -> None:
        """Close and forget the current handler (after a failed connect)."""
        with self._lock:
            handler, self.handler = self.handler, None
        if handler is not None:
            _close(handler)

    def stop(self) -> None:
        """Safe at any time, including before the first connect attempt has finished."""
        self.stopped.set()
        self.drop()


def _close(handler) -> None:
    try:
        handler.close()
    except Exception as e:  # noqa: BLE001
        _log(f"close failed: {e}")


RETRY_FIRST, RETRY_MAX = 5.0, 300.0   # seconds between connect attempts, doubling up to the cap


def _enabled() -> tuple[bool, str]:
    missing = [k for k in ("SLACK_BOT_TOKEN", "SLACK_APP_TOKEN") if not os.environ.get(k)]
    if missing:
        return False, f"disabled ({', '.join(missing)} not set)"
    try:
        import slack_bolt  # noqa: F401
        from slack_bolt.adapter.socket_mode import SocketModeHandler  # noqa: F401
    except ImportError:
        return False, "disabled (slack_bolt not installed: uv sync --extra slack)"
    return True, "enabled"


def _bolt_installed() -> bool:
    try:
        from slack_bolt.adapter.socket_mode import SocketModeHandler  # noqa: F401
    except ImportError:
        return False
    return True


def _mask(v: str) -> str:
    return (v[:5] + "…") if v else "(unset)"


def preflight() -> tuple[bool, list[tuple[str, str, str]]]:
    """Offline check of the Slack env (no network, nothing sent): rows of (check, PASS|FAIL, detail)."""
    env = os.environ.get
    rows = []

    def row(name, good, detail_ok, detail_bad):
        rows.append((name, "PASS" if good else "FAIL", detail_ok if good else detail_bad))

    bot, app, ch = env("SLACK_BOT_TOKEN", ""), env("SLACK_APP_TOKEN", ""), env("SLACK_CHANNEL", "")
    row("SLACK_BOT_TOKEN", bot.startswith("xoxb-"), f"{_mask(bot)} (posts + updates the card)",
        f"{_mask(bot)}: must be the Bot User OAuth Token, starting xoxb-")
    row("SLACK_APP_TOKEN", app.startswith("xapp-"), f"{_mask(app)} (Socket Mode buttons)",
        f"{_mask(app)}: must be an App-Level Token with connections:write, starting xapp-")
    row("SLACK_CHANNEL", bool(re.fullmatch(r"[CG][A-Z0-9]{6,}", ch)), f"{ch} (clicks from other channels ignored)",
        f"{ch or '(unset)'}: use the channel ID (channel name → About → bottom, e.g. C0123ABCD), "
        "not the #name")
    raw = [u.strip() for u in env("SLACK_APPROVERS", "").split(",") if u.strip()]
    bad = [u for u in raw if not re.fullmatch(r"[UW][A-Z0-9]{2,}", u)]
    row("SLACK_APPROVERS", bool(raw) and not bad, f"{len(raw)} approver(s): {', '.join(raw)}",
        "unset: nobody can approve" if not raw else
        f"{', '.join(bad)}: use member IDs (profile → ⋮ → Copy member ID, e.g. U01AB), not names")
    row("slack-bolt installed", _bolt_installed(), "yes", "no: uv sync --extra slack")
    rows.extend(_github_rows(env("WRECKLESS_GITHUB_REPO", "")))
    return all(r[1] == "PASS" for r in rows), rows


def _gh_logged_in() -> bool:
    """Local only: `gh auth token` reads the stored credential, it does not call GitHub."""
    import shutil
    import subprocess
    if not shutil.which("gh"):
        return False
    try:
        return subprocess.run(["gh", "auth", "token"], capture_output=True, timeout=5).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def _github_rows(repo: str) -> list[tuple[str, str, str]]:
    if not repo:
        return [("WRECKLESS_GITHUB_REPO", "PASS", "unset (optional): Approve stays a local sign-off, no PR")]
    from wreckless.publish import _REPO
    ok = bool(_REPO.match(repo))
    gh = _gh_logged_in()
    return [("WRECKLESS_GITHUB_REPO", "PASS" if ok else "FAIL",
             f"{repo} (Approve pushes + opens a draft PR)" if ok else f"{repo}: must be owner/name"),
            ("gh logged in", "PASS" if gh else "FAIL",
             "yes" if gh else "no: install gh, then gh auth login && gh auth setup-git")]


def print_preflight(ok: bool, rows: list[tuple[str, str, str]]) -> None:
    for name, res, detail in rows:
        print(f"{name:<22} {res:<5} {detail}")
    print("SLACK PREFLIGHT: " + ("PASS (offline check only: nothing was sent)" if ok else "FAIL"))


def register_porter(app, outer=None, stop: threading.Event | None = None, every: float = 1.0):
    """Porter's outer door: @mentions go into the airlock, replies come back out. Needs the
    app_mentions:read scope + the app_mention event (docs/slack-setup.md). WRECKLESS_PORTER=0 disables."""
    if os.environ.get("WRECKLESS_PORTER", "1") == "0":
        return None
    from wreckless.porter_outer import Outer
    outer = outer or Outer()

    def on_mention(event, client):
        outer.on_mention(event, client)

    app.event("app_mention")(on_mention)

    def deliver() -> None:
        while not (stop and stop.is_set()):
            try:
                outer.deliver(app.client)
            except Exception as e:  # noqa: BLE001
                _log(f"porter delivery error: {e}")
            time.sleep(every)

    threading.Thread(target=deliver, name="porter-outer", daemon=True).start()
    return outer


def _build_handler(on_approve, on_reject, stop: threading.Event | None = None):
    from slack_bolt import App
    from slack_bolt.adapter.socket_mode import SocketModeHandler
    app = App(token=os.environ["SLACK_BOT_TOKEN"])
    handlers = make_handlers(on_approve, on_reject)
    outer = handlers.pop("_outer")
    register(app, handlers)
    register_porter(app, outer=outer, stop=stop)
    return SocketModeHandler(app, os.environ["SLACK_APP_TOKEN"])


def start_listener(on_approve: Decision | None = None, on_reject: Decision | None = None,
                   runs_dir: Path | None = None) -> ListenerHandle | None:
    """Start the listener in a daemon thread. Never raises, never blocks the pipeline."""
    try:
        ok, why = _enabled()
        if not ok:
            _log(why)
            return None
        handle = ListenerHandle(thread=None)  # type: ignore[arg-type]

        def run() -> None:
            delay, attempt = RETRY_FIRST, 1
            while not handle.stopped.is_set():
                try:
                    # App() calls auth.test and connect() opens the wss: either can fail
                    handler = _build_handler(on_approve, on_reject, handle.stopped)
                    if not handle.adopt(handler):
                        return
                    handler.connect()  # non-blocking, unlike start()
                except Exception as e:  # noqa: BLE001
                    _log(f"connect failed (attempt {attempt}): {e}; retrying in {delay:g}s")
                    handle.drop()
                    handle.stopped.wait(delay)
                    delay, attempt = min(delay * 2, RETRY_MAX), attempt + 1
                    continue
                _log("enabled (Socket Mode, outbound wss)")
                handle.stopped.wait()  # the Socket Mode client reconnects by itself from here
                return

        handle.thread = threading.Thread(target=run, name="wreckless-slack-socket", daemon=True)
        _log("connecting (Socket Mode, outbound wss)")
        handle.thread.start()
        return handle
    except Exception as e:  # noqa: BLE001
        _log(f"disabled (start error: {e})")
        return None


def main() -> int:
    from wreckless.config import load_env
    load_env()
    if "--check" in sys.argv[1:]:
        ok, rows = preflight()
        print_preflight(ok, rows)
        return 0 if ok else 1
    ok, why = _enabled()
    if not ok:
        _log(why)
        return 1
    _log("serving Approve/Reject actions and Porter's outer door; Ctrl-C to stop")
    _build_handler(None, None).start()
    return 0


if __name__ == "__main__":
    sys.exit(main())
