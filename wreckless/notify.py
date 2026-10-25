"""Outbound-only notifications. Slack bot token (post + live update) > webhook > local outbox."""
import json
import os
import time
import urllib.request

from wreckless.config import ROOT


class Notifier:
    def __init__(self):
        self.token = os.environ.get("SLACK_BOT_TOKEN")
        self.channel = os.environ.get("SLACK_CHANNEL")
        self.webhook = os.environ.get("SLACK_WEBHOOK_URL")
        self.ts = None
        self.outbox = ROOT / "logs" / "slack_outbox.jsonl"

    def card(self, role: str, title: str, body: str) -> list:
        icon = {"purple": "🕵️", "red": "🎩", "blue": "👷"}[role]
        return [{"type": "header", "text": {"type": "plain_text", "text": f"{icon} {title}"}},
                {"type": "section", "text": {"type": "mrkdwn", "text": body[:2900]}}]

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
                self.ts = r.get("ts", self.ts)
                return f"slack:{method}"
            if self.webhook:
                self._post(self.webhook, {"blocks": blocks, "text": title})
                return "slack:webhook"
        except Exception as e:
            title = f"{title} (slack error: {e})"
        self.outbox.parent.mkdir(exist_ok=True)
        with self.outbox.open("a") as f:
            f.write(json.dumps({"t": time.time(), "title": title, "blocks": blocks}) + "\n")
        return "outbox"

    @staticmethod
    def _post(url: str, payload: dict, headers: dict | None = None) -> dict:
        req = urllib.request.Request(url, json.dumps(payload).encode(),
                                     {"Content-Type": "application/json; charset=utf-8", **(headers or {})})
        with urllib.request.urlopen(req, timeout=10) as r:
            body = r.read().decode()
        return json.loads(body) if body.startswith("{") else {}
