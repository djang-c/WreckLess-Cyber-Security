"""Porter's outer door: Slack <-> airlock, inside the Slack listener process.

It turns an @mention from an approver, in the run channel, into one typed airlock request, and
posts the agents' replies back into the thread. It never imports anything that can read the
codebase, the item folders, the queue or the models (tests/test_porter.py checks the imports),
so a bug or a hostile message on this side has nothing to leak.

    @WreckLess why is this dangerous?            ask      (answered from the finding's briefing)
    @WreckLess status                            status
    @WreckLess note: the endpoint is internal    note     (kept as an UNTRUSTED note on the item)
    @WreckLess change: also reject bytes input   change   (a revision item: re-patch, re-verify, Approve)
    @WreckLess exploit                           exploit  (the exploit script, released on request, logged)
Add a finding id (e.g. CVE-2024-21513#9) to pick one; in a card's thread, or without an id,
the inner door uses that card's finding, else the newest one.
"""
import os
import re
import sys
import time
from collections import defaultdict, deque

from wreckless.airlock import MAX_TEXT, Airlock, BadMessage, request

_MENTION = re.compile(r"<@[A-Z0-9]+>")
_ITEM = re.compile(r"\b((?:CVE-\d{4}-\d{4,}|HUNT)#\d{1,6})\b")
PREFIXES = (("status", "status"), ("note:", "note"), ("change:", "change"), ("exploit", "exploit"),
            ("show exploit", "exploit"))
RATE_N, RATE_WINDOW = 10, 60.0   # requests per user per window (seconds)


def _log(msg: str) -> None:
    print(f"[porter-outer] {msg}", file=sys.stderr, flush=True)


def parse(text: str) -> tuple[str, str, str | None]:
    """(kind, body, item) from a mention's text. Pure."""
    body = _MENTION.sub("", text or "").strip()
    m = _ITEM.search(body)
    item = m.group(1) if m else None
    low = body.lower()
    for prefix, kind in PREFIXES:
        if low.startswith(prefix):
            return kind, body[len(prefix):].strip(" :"), item
    return "ask", body, item


class Outer:
    def __init__(self, lock: Airlock | None = None, approvers: set[str] | None = None,
                 channel: str | None = None, clock=time.time):
        self.lock = lock or Airlock()
        self._approvers, self._channel = approvers, channel
        self.clock = clock
        self.recent: dict[str, deque] = defaultdict(deque)

    def approvers(self) -> set[str]:
        if self._approvers is not None:
            return self._approvers
        return {u.strip() for u in os.environ.get("SLACK_APPROVERS", "").split(",") if u.strip()}

    def channel(self) -> str | None:
        ch = self._channel if self._channel is not None else os.environ.get("SLACK_CHANNEL", "")
        return ch if re.fullmatch(r"[CG][A-Z0-9]{6,}", ch or "") else None

    def accept(self, event: dict) -> tuple[dict | None, str]:
        """(request, "") or (None, why it was refused). Nothing is written for a refusal."""
        user, chan = event.get("user") or "", event.get("channel") or ""
        if user not in self.approvers():
            return None, "only listed approvers can talk to Porter"
        want = self.channel()
        if want and chan != want:
            return None, "Porter only listens in the run channel"
        text = event.get("text") or ""
        if len(text) > MAX_TEXT:
            return None, f"message too long (max {MAX_TEXT} characters)"
        q = self.recent[user]
        now = self.clock()
        while q and now - q[0] > RATE_WINDOW:
            q.popleft()
        if len(q) >= RATE_N:
            return None, "too many requests; try again in a minute"
        kind, body, item = parse(text)
        if kind in ("ask", "note", "change") and not body:
            return None, f"nothing to {kind}"
        try:
            req = request(kind, body, user, item, chan, event.get("thread_ts") or event.get("ts"))
        except BadMessage as e:
            return None, f"refused: {e}"
        q.append(now)
        return req, ""

    def on_mention(self, event: dict, client) -> None:
        req, why = self.accept(event)
        thread = event.get("thread_ts") or event.get("ts")
        if not req:
            _log(f"refused mention from {event.get('user')}: {why}")
            try:
                client.chat_postEphemeral(channel=event.get("channel"), user=event.get("user"), text=why)
            except Exception as e:  # noqa: BLE001
                _log(f"ephemeral failed: {e}")
            return
        with self.lock.door("outer"):
            self.lock.put("outer", req)
        try:
            client.chat_postMessage(channel=req["channel"], thread_ts=thread,
                                    text=f"🚪 Porter took your {req['kind']} through the airlock; the answer follows here.")
        except Exception as e:  # noqa: BLE001
            _log(f"ack failed: {e}")

    def deliver(self, client) -> int:
        """Post every reply waiting in the outbox. The door is held only to take them."""
        with self.lock.door("outer"):
            replies = self.lock.take("outer")
        for r in replies:
            try:
                client.chat_postMessage(channel=r["channel"], thread_ts=r.get("thread"), text=r["text"])
            except Exception as e:  # noqa: BLE001
                _log(f"reply post failed: {e}")
        return len(replies)
