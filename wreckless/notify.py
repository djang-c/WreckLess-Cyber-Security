"""Outbound-only notifications. Slack bot token (post + live update) > webhook > local outbox.

Every `send()` re-renders ONE cumulative run card (header + timeline of beats + latest detail +
context, plus Approve/Reject buttons on the final "Fix branch ready" beat). With a bot token the
first beat is posted and later beats `chat.update` the same message `ts`. `build_blocks()` is pure.
"""
import json
import os
import re
import time
import urllib.request

from wreckless.config import ROOT

ICONS = {"purple": "🕵️", "red": "🎩", "blue": "👷", "core": "⚙️"}
APPROVE_ACTION, REJECT_ACTION = "wreckless_approve", "wreckless_reject"
HEADER_MAX, TEXT_MAX, BLOCKS_MAX, BUTTON_VALUE_MAX = 150, 3000, 50, 2000
_CVE = re.compile(r"CVE-\d{4}-\d{4,}")
_BRANCH = re.compile(r"[Bb]ranch `([^`]+)`")
_COMMIT = re.compile(r"@ `([0-9a-f]{6,40})`")
_SOURCE = re.compile(r"patch: ([^\s·`]+)")


def _clip(text: str, limit: int) -> str:
    """Truncate to `limit` chars without leaving an unclosed ``` fence."""
    if len(text) <= limit:
        return text
    cut = text[: limit - 6] + "…"
    if cut.count("```") % 2:
        cut += "\n```"
    return cut[:limit]


def beat_outcome(title: str) -> str:
    """'ok' (final success), 'fail', or 'progress' — derived from the beat title cli.py sends."""
    t = title.lower()
    if "fail" in t or "❌" in title:
        return "fail"
    if "fix branch ready" in t:  # swarm's final success beat
        return "ok"
    return "progress"


def build_blocks(beats: list[dict], *, cve: str | None = None, elapsed_s: float | None = None,
                 enclave: str | None = None, patch_source: str | None = None,
                 run_id: str | None = None, branch: str | None = None,
                 commit: str | None = None) -> list[dict]:
    """Pure renderer. beats: [{"role", "title", "body", "t_rel"}] in order; last one is current."""
    if not beats:
        return []
    last = beats[-1]
    outcome = beat_outcome(last["title"])
    status = {"ok": ("✅", "Fix branch ready (pending review)"), "fail": ("❌", "Needs a human"),
              "progress": ("⏳", f"{ICONS.get(last['role'], '•')} in progress")}[outcome]
    header = f"{status[0]} WreckLess · {cve or 'run'} · {status[1]}"
    lines = []
    for i, b in enumerate(beats):
        mark = ("✅" if outcome == "ok" else "❌" if outcome == "fail" else "⏳") \
            if i == len(beats) - 1 else "✓"
        lines.append(f"{mark} {ICONS.get(b['role'], '•')} *{b['title']}*  `+{b.get('t_rel', 0):.0f}s`")
    ctx = [f"⏱ {elapsed_s:.0f} s" if elapsed_s is not None else None,
           f"enclave: `{enclave}`" if enclave else None,
           f"patch: `{patch_source}`" if patch_source else None,
           f"run: `{run_id}`" if run_id else None]
    blocks = [
        {"type": "header", "text": {"type": "plain_text", "emoji": True,
                                    "text": _clip(header, HEADER_MAX)}},
        {"type": "section", "text": {"type": "mrkdwn", "text": _clip("\n".join(lines), TEXT_MAX)}},
        {"type": "divider"},
        {"type": "section", "text": {"type": "mrkdwn", "text": _clip(last["body"] or " ", TEXT_MAX)}},
        {"type": "context", "elements": [{"type": "mrkdwn", "text": _clip(" · ".join(c for c in ctx if c)
                                                                          or "WreckLess", TEXT_MAX)}]},
    ]
    if outcome == "ok":
        # the decision is bound to this exact item + commit, so a stale card can't approve a newer patch
        value = _clip(json.dumps({"run_id": run_id, "branch": branch, "commit": commit, "cve": cve}),
                      BUTTON_VALUE_MAX)
        blocks.append({"type": "actions", "block_id": "wreckless_decision", "elements": [
            {"type": "button", "action_id": APPROVE_ACTION, "style": "primary", "value": value,
             "text": {"type": "plain_text", "text": "Approve fix"}},
            {"type": "button", "action_id": REJECT_ACTION, "style": "danger", "value": value,
             "text": {"type": "plain_text", "text": "Reject"}},
        ]})
    return blocks[:BLOCKS_MAX]


class Notifier:
    def __init__(self, run_id: str | None = None, enclave: str | None = None):
        self.token = os.environ.get("SLACK_BOT_TOKEN")
        self.channel = os.environ.get("SLACK_CHANNEL")
        self.webhook = os.environ.get("SLACK_WEBHOOK_URL")
        self.ts = None
        self.outbox = ROOT / "logs" / "slack_outbox.jsonl"
        self.t0 = time.time()
        self.beats: list[dict] = []
        self.meta = {"run_id": run_id, "enclave": enclave, "cve": None,
                     "branch": None, "commit": None, "patch_source": None}

    def bind(self, **meta) -> None:
        """Optional context from the orchestrator (run_id, enclave, ...)."""
        self.meta.update({k: v for k, v in meta.items() if v is not None})

    def card(self, role: str, title: str, body: str) -> list:
        """Record a beat and return the cumulative card blocks."""
        self.beats.append({"role": role, "title": title, "body": body,
                           "t_rel": time.time() - self.t0})
        m = self.meta
        for key, rx, text in (("cve", _CVE, title + body), ("branch", _BRANCH, body),
                              ("commit", _COMMIT, body), ("patch_source", _SOURCE, body)):
            hit = rx.search(text)
            if hit and not m[key]:
                m[key] = hit.group(1) if rx.groups else hit.group(0)
        return build_blocks(self.beats, cve=m["cve"], elapsed_s=time.time() - self.t0,
                            enclave=m["enclave"], patch_source=m["patch_source"],
                            run_id=m["run_id"], branch=m["branch"], commit=m["commit"])

    def send(self, role: str, title: str, body: str) -> str:
        blocks = self.card(role, title, body)
        try:
            if self.token and self.channel:
                method = "chat.update" if self.ts else "chat.postMessage"
                payload = {"channel": self.channel, "blocks": blocks, "text": title}
                if self.ts:
                    payload["ts"] = self.ts
                r = self._post(f"https://slack.com/api/{method}", payload,
                               {"Authorization": f"Bearer {self.token}"})
                if r.get("ok") is False:
                    raise RuntimeError(r.get("error", "slack api error"))
                self.ts = r.get("ts", self.ts)
                self.channel = r.get("channel", self.channel)  # chat.update needs the channel ID
                return f"slack:{method}"
            if self.webhook:
                self._post(self.webhook, {"blocks": blocks, "text": title})
                return "slack:webhook"
        except Exception as e:
            title = f"{title} (slack error: {e})"
        try:
            self.outbox.parent.mkdir(parents=True, exist_ok=True)
            with self.outbox.open("a") as f:
                f.write(json.dumps({"t": time.time(), "title": title, "blocks": blocks}) + "\n")
        except Exception:
            pass  # notifications must never break the pipeline
        return "outbox"

    @staticmethod
    def _post(url: str, payload: dict, headers: dict | None = None) -> dict:
        req = urllib.request.Request(url, json.dumps(payload).encode(),
                                     {"Content-Type": "application/json; charset=utf-8", **(headers or {})})
        # short: a firewall that DROPs instead of REJECTs must not stall the hero run
        with urllib.request.urlopen(req, timeout=3) as r:
            body = r.read().decode()
        return json.loads(body) if body.startswith("{") else {}
