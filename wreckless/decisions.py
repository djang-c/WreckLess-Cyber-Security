"""Approve / Reject, recorded on the inside of the airlock (Porter's inner door).

The Slack listener only forwards a click as a typed airlock request; this module writes
`<items>/<item>/decision.json` and, for an approval with WRECKLESS_GITHUB_REPO set, pushes the
approved commit and opens the draft PR (wreckless/publish.py). That push is the one deliberate
outward path from the inside, and it only follows a human Approve.

The file appears atomically and complete (written + fsynced under a temp name, then hard-linked
into place, which fails if it already exists), so the first decision wins and a later one is
told the recorded decision. Anything that acts on an approval checks that the branch head still
equals the approved commit (publish.py does).
"""
import json
import os
import re
import tempfile
import time
from pathlib import Path

from wreckless.airlock import AlreadyDecided
from wreckless.config import RUNS

ITEMS = RUNS / "swarm" / "items"
_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


def _recorded(path: Path, tries: int = 5) -> dict:
    for i in range(tries):
        try:
            return json.loads(path.read_text())
        except (OSError, ValueError, TypeError):
            time.sleep(0.05 * (i + 1))
    return {"decision": "decided"}


def record_decision(info: dict, runs_dir: Path = ITEMS) -> Path | None:
    """Create <items>/<item>/decision.json once; None for an unsafe or missing run id."""
    run_id = (info.get("run_id") or "").replace("#", "-")
    if not _SAFE_ID.match(run_id) or ".." in run_id:
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


def _publish_note(info: dict, pr: dict | None, err: str | None) -> str:
    at = f"{info['run_id']} @ {(info['commit'] or '?')[:10]}"
    if pr:
        return f"draft PR opened: {pr['url']} ({at})"
    if err:
        return (f"approval recorded for {at}, but the draft PR failed: {err[:200]}. "
                f"Retry on the host: python -m wreckless.publish {info['run_id']}")
    return f"recorded decision.json for {at} (GitHub not configured: approval stays local)"


def decide(info: dict, runs_dir: Path = ITEMS) -> dict:
    """{"outcome": recorded|already|refused|error, "decision", "by", "note"}. Never raises."""
    try:
        path = record_decision(info, runs_dir)
    except AlreadyDecided as e:
        rec = e.args[0] if e.args and isinstance(e.args[0], dict) else {}
        return {"outcome": "already", "decision": rec.get("decision"), "by": rec.get("user"),
                "note": f"{info['run_id']} was already {rec.get('decision', 'decided')}"
                        + (f" by <@{rec['user']}>" if rec.get("user") else "") + "; click ignored"}
    except Exception:  # noqa: BLE001  nothing recorded: the card keeps its buttons
        return {"outcome": "error", "decision": None, "by": None,
                "note": f"{info['decision']} for {info['run_id']} could not be recorded (see the WreckLess host log); try again"}
    if path is None:
        return {"outcome": "refused", "decision": None, "by": None,
                "note": f"{info['decision']} could not be recorded (unsafe or missing finding id)"}
    if info["decision"] != "approved":
        return {"outcome": "recorded", "decision": info["decision"], "by": info["user"],
                "note": f"recorded {path.name} for {info['run_id']} @ {(info['commit'] or '?')[:10]}"}
    from wreckless import publish
    pr, err = None, None
    try:
        pr = publish.publish(info, runs_dir)
    except Exception as e:  # noqa: BLE001  the approval stands; the PR can be retried
        err = str(e)
    return {"outcome": "recorded", "decision": "approved", "by": info["user"], "note": _publish_note(info, pr, err)}
