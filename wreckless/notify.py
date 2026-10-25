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
    """'ok' (final success), 'fail', 'rejected' or 'progress', from the beat title swarm.py sends."""
    t = title.lower()
    if "fail" in t or "crashed" in t or "❌" in title:
        return "fail"
    if "gate rejected" in t:
        return "rejected"
    if "fix branch ready" in t:  # swarm's final success beat
        return "ok"
    return "progress"


_ANSI = re.compile(r"\x1b\[[0-9;]*m")
_DIFF_FILE = re.compile(r"^diff --git a/(\S+) b/(\S+)")


def diffstat(diff: str, max_files: int = 6) -> str:
    """'2 files · +3 −1 · a.py (+2 −1), b.py (+1)' from a unified diff. Pure."""
    files: dict[str, list[int]] = {}
    cur = None
    for line in diff.splitlines():
        m = _DIFF_FILE.match(line)
        if m:
            cur = files.setdefault(m.group(2), [0, 0])
        elif cur is not None and line.startswith("+") and not line.startswith("+++"):
            cur[0] += 1
        elif cur is not None and line.startswith("-") and not line.startswith("---"):
            cur[1] += 1
    if not files:
        return "no changes"
    add, rem = sum(a for a, _ in files.values()), sum(r for _, r in files.values())
    per = [f"{f} (" + " ".join(x for x in (f"+{a}" if a else "", f"−{r}" if r else "") if x) + ")"
           for f, (a, r) in list(files.items())[:max_files]]
    more = f", +{len(files) - max_files} more" if len(files) > max_files else ""
    return f"{len(files)} file{'s' * (len(files) != 1)} · +{add} −{rem} · " + ", ".join(per) + more


def _tail(text: str, n: int) -> str:
    text = _ANSI.sub("", text or "").strip().replace("```", "'''")
    return ("…" + text[-n:]) if len(text) > n else text


def fixed_body(branch: str, commit: str, src_label: str, summary: str, elapsed_s: float, diff: str,
               excerpt: int = 900) -> str:
    """Final success card: summary + a short excerpt. The full patch goes to the draft PR on Approve."""
    short = diff[:excerpt].replace("```", "'''")
    cut = " (excerpt; full diff in the draft PR after Approve)" if len(diff) > excerpt else ""
    return _clip(f"Branch `{branch}` @ `{commit[:10]}` · {src_label}\n{summary} · {elapsed_s:.0f}s\n"
                 f"Changes: {diffstat(diff)}{cut}\n```{short}```", TEXT_MAX)


def patch_failed_body(summary: str, failed: list[str], logs: dict, diff: str, item_dir: str,
                      patch_source: str | None) -> str:
    """Patch-failed card: which checks failed, a diff summary and the end of each failing log."""
    keys = {"held-out regression": ("regression_test", "static_test"), "functional": ("functional",),
            "exploit blocked": ("exploit",), "patch rules": ("rejected",)}
    parts = [f"Failed: *{', '.join(failed) or 'no patch produced'}*", summary,
             f"Changes: {diffstat(diff)} · patch: {patch_source or 'none'}"]
    budget = max(300, (TEXT_MAX - 600) // max(1, len(failed)))
    for name in failed:
        for k in keys.get(name, (name,)):
            if logs.get(k):
                parts.append(f"`{k}` (end of log):\n```{_tail(logs[k], min(budget, 900))}```")
    parts.append(f"Item dir on the host: `{item_dir}` (validation.json, fix.patch)")
    return _clip("\n".join(parts), TEXT_MAX)


def rejected_body(title: str, reason: str, script: str | None, control: str | None, output: str,
                  item_dir: str) -> str:
    """Gate-rejected card: why the claim was not reproduced. Nothing was patched."""
    return _clip(f"{title[:150]}\nReason: {reason}\n"
                 f"Exploit: `{script or 'none proposed'}` · control: {control or 'n/a'}\n"
                 + (f"```{_tail(output, 700)}```\n" if output else "")
                 + f"Nothing was patched. Item dir: `{item_dir}`", TEXT_MAX)


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
              "rejected": ("🛑", "Not reproduced (gate rejected)"),
              "progress": ("⏳", f"{ICONS.get(last['role'], '•')} in progress")}[outcome]
    header = f"{status[0]} WreckLess · {cve or 'run'} · {status[1]}"
    lines = []
    for i, b in enumerate(beats):
        mark = ("✅" if outcome == "ok" else "❌" if outcome == "fail" else "🛑" if outcome == "rejected"
                else "⏳") if i == len(beats) - 1 else "✓"
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
                try:
                    r = self._post(f"https://slack.com/api/{method}", payload,
                                   {"Authorization": f"Bearer {self.token}"})
                    # the Web API always answers JSON with "ok"; anything else (proxy page,
                    # empty body) recorded nothing and gave us no ts to update later
                    if r.get("ok") is not True:
                        raise RuntimeError(r.get("error", "slack api error" if r else "non-JSON slack response"))
                except Exception:
                    if self.ts:  # message deleted / not updatable: the next beat posts a fresh card
                        self.ts = None
                    raise
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


def pending_blocks(blocks: list[dict], decision: str, user: str) -> list[dict]:
    """Pure: buttons removed while the inside records a click (no double-click meanwhile)."""
    kept = [b for b in blocks if b.get("type") != "actions"]
    return kept + [{"type": "section", "block_id": "wreckless_decision", "text": {"type": "mrkdwn", "text":
                    f"⏳ *{decision.capitalize()} by <@{user}>* received; recording it on the WreckLess host…"}}]
