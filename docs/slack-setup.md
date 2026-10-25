# Slack setup (run card + Approve/Reject over Socket Mode)

WreckLess posts **one evolving run card** per run (`wreckless/notify.py`): first beat is
`chat.postMessage`, every later beat `chat.update`s the same message. The final
"Fix branch ready (local, pending review)" beat adds **Approve fix** / **Reject** buttons (`wreckless_approve`,
`wreckless_reject`), handled by `wreckless/slack_socket.py` over Socket Mode.

Socket Mode is outbound-only (wss to `*.slack.com`), so no public URL is needed and it
survives `airgap_lockdown.sh` (which blocks only cloud-LLM egress).

Approving does **not** push, merge or call GitHub. The default callback writes
`runs/swarm/items/<item>/decision.json` with the exact commit approved (first click wins; only
users in `SLACK_APPROVERS` can decide); merging is a human step.

## 1. Create the app (human step)

<https://api.slack.com/apps> → *Create New App* → *From an app manifest* → pick workspace → paste:

```yaml
display_information:
  name: WreckLess
  description: Local-first agentic security swarm (Purple/Red/Blue) on GB10
features:
  bot_user:
    display_name: WreckLess
    always_online: false
oauth_config:
  scopes:
    bot:
      - chat:write
      - chat:write.public   # optional: post to public channels without /invite
settings:
  interactivity:
    is_enabled: true        # no request_url needed in Socket Mode
  socket_mode_enabled: true
  org_deploy_enabled: false
  token_rotation_enabled: false
```

Then:

1. *Install to Workspace* → copy the **Bot User OAuth Token** (`xoxb-…`).
2. *Basic Information → App-Level Tokens → Generate* with scope **`connections:write`** → copy (`xapp-…`).
3. In Slack, `/invite @WreckLess` to the channel (not needed for public channels if `chat:write.public` is granted).
4. Get the channel ID (channel details → bottom of *About*), e.g. `C0123ABCD`.

## 2. Environment

```bash
export SLACK_BOT_TOKEN=xoxb-...      # post + live-update the run card
export SLACK_CHANNEL=C0123ABCD       # channel ID preferred (name works for the first post)
export SLACK_APP_TOKEN=xapp-...      # Socket Mode listener (buttons); optional
export SLACK_APPROVERS=U01AB,U02CD   # Slack user IDs allowed to Approve/Reject (unset = nobody)
# fallback without a bot token: export SLACK_WEBHOOK_URL=https://hooks.slack.com/...
#   (webhook cannot update, so each beat posts a new cumulative card)
# neither set: cards go to logs/slack_outbox.jsonl
```

Never commit tokens. Keep them in an untracked `.env` / shell profile.

## 3. Install the optional extra

```bash
uv sync --extra slack                 # adds slack-bolt (optional; core pipeline does not need it)
```

## 4. Check offline first (sends nothing)

```bash
source .env && uv run python -m wreckless.slack_socket --check
```

This checks offline that the token prefixes are right (`xoxb-`, `xapp-`), that `SLACK_CHANNEL` is a channel ID (not a
`#name`), that `SLACK_APPROVERS` are member IDs (not names), and that slack-bolt is installed. It
makes no network calls and prints only token prefixes. Exit 0 = ready for the first real card.

## 5. Run

`wreckless run` does not start the listener; only `wreckless daemon --slack-listener` does
(as a thread that lives as long as the daemon). For a one-off `run`, keep the buttons
clickable by running the listener as its own process:

```bash
uv run --extra slack python -m wreckless.slack_socket     # blocking; Ctrl-C to stop
uv run python -m wreckless run --cve CVE-2024-21513 --no-llm   # in another terminal
```

If `slack_bolt` is missing or either token is unset, `start_listener()` prints one
`[slack-socket] disabled (...)` line and returns `None`; the pipeline is unaffected.

## Limits respected by `build_blocks()`

header plain_text ≤ 150 chars, section text ≤ 3000 chars (code fences re-closed when clipped),
≤ 50 blocks, button value ≤ 2000 chars.
