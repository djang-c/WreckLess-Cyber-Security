"""Optional Slack Socket Mode listener for the run card's "Approve fix" / "Reject" buttons.

Socket Mode is outbound-only (wss to *.slack.com), so it survives the cloud-LLM airgap.
Enabled only if `slack_bolt` is importable AND SLACK_BOT_TOKEN + SLACK_APP_TOKEN are set;
otherwise `start_listener()` logs one line and returns None. A decision records
`<items>/<item>/decision.json`; an approval then pushes the approved commit and opens a draft
PR (wreckless/publish.py) only if WRECKLESS_GITHUB_REPO is set. Rejections never push.

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
import tempfile
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from wreckless.config import RUNS

ITEMS = RUNS / "swarm" / "items"   # Swarm's default home; item dirs use '-' for '#'
from wreckless.notify import APPROVE_ACTION, REJECT_ACTION, TEXT_MAX, _clip

Decision = Callable[[dict], object]
_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


def _log(msg: str) -> None:
    print(f"[slack-socket] {msg}", file=sys.stderr, flush=True)


class AlreadyDecided(Exception):
    """str(e) describes the decision already on disk, e.g. "approved by <@U123>"."""


def _recorded(path: Path, tries: int = 5) -> str:
    """Describe the decision in an existing decision.json (retrying a file still being written)."""
    for i in range(tries):
        try:
            rec = json.loads(path.read_text())
            who = f" by <@{rec['user']}>" if rec.get("user") else ""
            return f"{rec.get('decision', 'decided')}{who}"
        except (OSError, ValueError, TypeError, AttributeError):
            time.sleep(0.05 * (i + 1))
    return "decided"


def record_decision(info: dict, runs_dir: Path = ITEMS) -> Path | None:
    """Default callback: create <items>/<item>/decision.json once. No git push, no GitHub.

    Anything that later acts on an approval must check the branch head still equals
    info["commit"]: the approval covers that commit, not whatever the branch holds later.

    The file appears atomically and complete (written + fsynced under a temp name, then
    hard-linked into place, which fails if it already exists), so a concurrent click never
    reads a half-written decision. A later click raises AlreadyDecided naming the recorded one.
    """
    run_id = (info.get("run_id") or "").replace("#", "-")
    if not _SAFE_ID.match(run_id) or ".." in run_id:
        _log(f"refusing to record decision for unsafe/missing run_id {run_id!r}")
        return None
    path = Path(runs_dir) / run_id / "decision.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        raise AlreadyDecided(_recorded(path))
    fd, tmp = tempfile.mkstemp(prefix=".decision-", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "w") as f:
            f.write(json.dumps(info, indent=2))
            f.flush()
            os.fsync(f.fileno())
        try:
            os.link(tmp, path)  # atomic create-if-absent: first decision wins
        except FileExistsError:
            raise AlreadyDecided(_recorded(path)) from None
    finally:
        os.unlink(tmp)
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


def _publish_note(info: dict, out: dict) -> str:
    at = f"{info['run_id']} @ {(info['commit'] or '?')[:10]}"
    if out.get("pr"):
        return f"draft PR opened: {out['pr']['url']} ({at})"
    if out.get("pr_error"):
        return (f"approval recorded for {at}, but the draft PR failed: {out['pr_error'][:200]}. "
                f"Retry on the host: python -m wreckless.publish {info['run_id']}")
    return f"recorded decision.json for {at} (GitHub not configured: approval stays local)"


def make_handlers(on_approve: Decision | None = None, on_reject: Decision | None = None,
                  runs_dir: Path = ITEMS, approvers: set[str] | None = None) -> dict[str, Callable]:
    """Return {action_id: handler}. Handlers use Bolt's kwarg injection (ack, body, client)."""
    def default(info: dict) -> Path:
        out = record_decision(info, runs_dir)
        if out is None:
            raise ValueError("decision refused (unsafe or missing run_id)")
        return out

    def default_approve(info: dict) -> dict:
        path = default(info)   # the approval is on disk before anything leaves the box
        from wreckless import publish
        try:
            return {"path": path, "pr": publish.publish(info, runs_dir)}
        except Exception as e:  # noqa: BLE001  the approval stands; the PR can be retried
            _log(f"draft PR failed for {info.get('run_id')}: {e}")
            return {"path": path, "pr_error": str(e)}

    on_approve = on_approve or default_approve
    on_reject = on_reject or default

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
            user = (body.get("user") or {}).get("id") or ""
            msg = body.get("message") or {}
            channel = (body.get("channel") or {}).get("id") or (body.get("container") or {}).get("channel_id")
            allowed = _approvers() if approvers is None else approvers
            if user not in allowed:
                return _deny(client, channel, user, f"<@{user}> is not in SLACK_APPROVERS; {decision} ignored")
            expected = _expected_channel()
            if expected and channel != expected:
                return _deny(client, channel, user, f"decisions are only accepted in <#{expected}>")
            info = {"decision": decision, "user": user, "run_id": value.get("run_id"),
                    "branch": value.get("branch"), "commit": value.get("commit"),
                    "cve": value.get("cve"), "t": time.time()}
            note = None
            try:
                out = callback(info)
                if isinstance(out, dict):
                    note = _publish_note(info, out)
                elif isinstance(out, Path):
                    note = f"recorded {out.name} for {info['run_id']} @ {(info['commit'] or '?')[:10]}"
            except AlreadyDecided as e:
                return _deny(client, channel, user, f"{info['run_id']} was already {e}; click ignored")
            except Exception as e:  # noqa: BLE001
                # nothing was recorded: leave the card and its buttons alone so someone can retry
                _log(f"callback error: {e}")
                return _deny(client, channel, user, f"{decision} for {info['run_id']} could not be "
                                                    "recorded (see the WreckLess host log); try again")
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


def _build_handler(on_approve, on_reject, runs_dir: Path = ITEMS):
    from slack_bolt import App
    from slack_bolt.adapter.socket_mode import SocketModeHandler
    app = App(token=os.environ["SLACK_BOT_TOKEN"])
    register(app, make_handlers(on_approve, on_reject, runs_dir))
    return SocketModeHandler(app, os.environ["SLACK_APP_TOKEN"])


def start_listener(on_approve: Decision | None = None, on_reject: Decision | None = None,
                   runs_dir: Path = ITEMS) -> ListenerHandle | None:
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
                    handler = _build_handler(on_approve, on_reject, runs_dir)
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
    _log("serving Approve/Reject actions; Ctrl-C to stop")
    _build_handler(None, None).start()
    return 0


if __name__ == "__main__":
    sys.exit(main())
