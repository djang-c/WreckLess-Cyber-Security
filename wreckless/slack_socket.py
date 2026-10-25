"""Optional Slack Socket Mode listener for the run card's "Approve PR" / "Reject" buttons.

Socket Mode is outbound-only (wss to *.slack.com), so it survives the cloud-LLM airgap.
Enabled only if `slack_bolt` is importable AND SLACK_BOT_TOKEN + SLACK_APP_TOKEN are set;
otherwise `start_listener()` logs one line and returns None. Nothing here pushes to git or
calls GitHub: approving only records `runs/<run_id>/approval.json` (default callback).

Blocking standalone mode (keeps buttons live after a `wreckless run` exits):
    uv run --extra slack python -m wreckless.slack_socket
"""
import json
import os
import re
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from wreckless.config import RUNS
from wreckless.notify import APPROVE_ACTION, REJECT_ACTION, TEXT_MAX, _clip

Decision = Callable[[dict], object]
_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


def _log(msg: str) -> None:
    print(f"[slack-socket] {msg}", file=sys.stderr, flush=True)


def record_decision(info: dict, runs_dir: Path = RUNS) -> Path | None:
    """Default callback: write runs/<run_id>/<decision>.json. No git push, no GitHub."""
    run_id = info.get("run_id") or info.get("cve") or ""
    if not _SAFE_ID.match(run_id) or ".." in run_id:
        _log(f"refusing to record decision for unsafe/missing run_id {run_id!r}")
        return None
    path = Path(runs_dir) / run_id / f"{'approval' if info['decision'] == 'approved' else 'rejection'}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(info, indent=2))
    return path


def decided_blocks(blocks: list[dict], decision: str, user: str, branch: str | None,
                   note: str | None = None) -> list[dict]:
    """Pure: replace the actions block with the human decision (buttons removed => no double-click)."""
    if decision == "approved":
        text = f"✅ *Approved by <@{user}>* — approval recorded for branch `{branch or '?'}` (merge is a human step)"
    else:
        text = f"❌ *Rejected by <@{user}>* — branch `{branch or '?'}` left unmerged"
    if note:
        text += f"\n_{note}_"
    kept = [b for b in blocks if b.get("type") != "actions"]
    return kept + [{"type": "section", "block_id": "wreckless_decision",
                    "text": {"type": "mrkdwn", "text": _clip(text, TEXT_MAX)}}]


def make_handlers(on_approve: Decision | None = None, on_reject: Decision | None = None,
                  runs_dir: Path = RUNS) -> dict[str, Callable]:
    """Return {action_id: handler}. Handlers use Bolt's kwarg injection (ack, body, client)."""
    on_approve = on_approve or (lambda info: record_decision(info, runs_dir))
    on_reject = on_reject or (lambda info: record_decision(info, runs_dir))

    def handle(decision: str, callback: Decision, ack, body: dict, client) -> None:
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
            user = (body.get("user") or {}).get("id") or (body.get("user") or {}).get("username", "?")
            info = {"decision": decision, "user": user, "run_id": value.get("run_id"),
                    "branch": value.get("branch"), "cve": value.get("cve"), "t": time.time()}
            note = None
            try:
                out = callback(info)
                if isinstance(out, Path):
                    note = f"recorded {out.name} for run {info['run_id'] or info['cve']}"
            except Exception as e:  # noqa: BLE001
                note = f"callback error: {e}"
                _log(note)
            msg = body.get("message") or {}
            channel = (body.get("channel") or {}).get("id") or (body.get("container") or {}).get("channel_id")
            ts = msg.get("ts") or (body.get("container") or {}).get("message_ts")
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

    return {APPROVE_ACTION: approve, REJECT_ACTION: reject}


def register(app, handlers: dict[str, Callable]) -> None:
    for action_id, fn in handlers.items():
        app.action(action_id)(fn)


@dataclass
class ListenerHandle:
    thread: threading.Thread
    handler: object | None = None

    def stop(self) -> None:
        try:
            if self.handler is not None:
                self.handler.close()
        except Exception as e:  # noqa: BLE001
            _log(f"close failed: {e}")


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


def _build_handler(on_approve, on_reject):
    from slack_bolt import App
    from slack_bolt.adapter.socket_mode import SocketModeHandler
    app = App(token=os.environ["SLACK_BOT_TOKEN"])
    register(app, make_handlers(on_approve, on_reject))
    return SocketModeHandler(app, os.environ["SLACK_APP_TOKEN"])


def start_listener(on_approve: Decision | None = None,
                   on_reject: Decision | None = None) -> ListenerHandle | None:
    """Start the listener in a daemon thread. Never raises, never blocks the pipeline."""
    try:
        ok, why = _enabled()
        if not ok:
            _log(why)
            return None
        handle = ListenerHandle(thread=None)  # type: ignore[arg-type]

        def run() -> None:
            try:
                handle.handler = _build_handler(on_approve, on_reject)
                handle.handler.start()  # blocking inside this daemon thread only
            except Exception as e:  # noqa: BLE001
                _log(f"listener stopped: {e}")

        handle.thread = threading.Thread(target=run, name="wreckless-slack-socket", daemon=True)
        handle.thread.start()
        _log("enabled (Socket Mode, outbound wss)")
        return handle
    except Exception as e:  # noqa: BLE001
        _log(f"disabled (start error: {e})")
        return None


def main() -> int:
    ok, why = _enabled()
    if not ok:
        _log(why)
        return 1
    _log("serving Approve/Reject actions; Ctrl-C to stop")
    _build_handler(None, None).start()
    return 0


if __name__ == "__main__":
    sys.exit(main())
