# Slack setup (run card + Approve/Reject over Socket Mode)

WreckLess posts **one evolving run card** per run (`wreckless/notify.py`): first beat is
`chat.postMessage`, every later beat `chat.update`s the same message. The final
"Fix branch ready (local, pending review)" beat adds **Approve fix** / **Reject** buttons (`wreckless_approve`,
`wreckless_reject`), handled by `wreckless/slack_socket.py` over Socket Mode.

Socket Mode is outbound-only (wss to `*.slack.com`), so no public URL is needed and it
survives `airgap_lockdown.sh` (which blocks only cloud-LLM egress).

Approving first writes `runs/swarm/items/<item>/decision.json` with the exact commit approved (first
click wins; only users in `SLACK_APPROVERS` can decide). If `WRECKLESS_GITHUB_REPO` is set, it then
pushes that commit and opens a **draft PR** in the demo repo, and the card shows the PR link (section 6).
Nothing leaves the box before the click; Reject never pushes; merging is a human step on GitHub.

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
      - app_mentions:read   # Porter: @WreckLess questions, notes and change requests
settings:
  event_subscriptions:
    bot_events:
      - app_mention         # Porter (Socket Mode delivers it; no request URL)
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


## 6. GitHub: Approve opens a draft PR (optional)

Without `WRECKLESS_GITHUB_REPO` an approval stays a local sign-off. With it, Approve runs
`wreckless/publish.py`:

1. It refuses if the fix branch has moved since the card was posted (the approval covers that one commit).
2. It pushes the vulnerable base as `wreckless/base-<sha12>` and the approved commit as `wreckless/fix-<item>`.
3. It runs `gh pr create --draft`, then writes `<item>/pr.json` and puts the PR link on the card.

If the push or PR fails, the approval still stands and the card prints the retry command
(`uv run python -m wreckless.publish <item-id>`).

One-time setup on the box that runs the daemon:

```bash
gh repo create <you>/wreckless-victim --private      # an empty repo just for fix PRs
gh auth login && gh auth setup-git                   # git push uses gh's credential
echo 'export WRECKLESS_GITHUB_REPO=<you>/wreckless-victim' >> .env
source .env && uv run python -m wreckless.slack_socket --check   # adds the GitHub rows
```

`airgap_lockdown.sh on` leaves GitHub reachable. `airtight` allows only Slack, so PRs fail there
(the approval is still recorded; retry after `off`).

## 7. Run 24/7 (GB10)

```bash
scripts/install_services.sh --dry-run          # print the systemd units, change nothing
scripts/install_services.sh                    # models at boot + daemon with Slack buttons, auto-restart
scripts/install_services.sh --with-airgap      # also re-apply the airgap at every boot
journalctl -u wreckless-daemon -f              # follow
scripts/install_services.sh --uninstall
```

The daemon runs as your user (not root) and reads `.env` at start, so tokens never go into a unit file.
Every outcome posts a card: fix ready (Approve/Reject), patch failed (which check, log tail),
gate rejected (reason; Red-hunt rejections only with `WRECKLESS_SLACK_REJECTS=all`), crashed.
Only one Socket Mode listener should run per app, so stop any listener on another machine.


## 8. Talk to the agents: Porter

Mention the bot in the run channel, ideally in a card's thread (that picks the finding):

```
@WreckLess why is this dangerous?          answered from the finding's briefing by the local model
@WreckLess status                          queue counts
@WreckLess note: this API is internal-only kept as an UNTRUSTED note on the finding
@WreckLess change: also reject bytes input queues a revision: re-patch, re-verify, new card, Approve
@WreckLess exploit                         releases the exploit script (only on request; logged)
```

Only `SLACK_APPROVERS` in `SLACK_CHANNEL` are heard; 10 requests per user per minute.
Existing app: add the `app_mentions:read` scope and the `app_mention` bot event (manifest above),
then **reinstall the app** to the workspace. Run the two doors as two processes:
`python -m wreckless.slack_socket` (outer) and `wreckless daemon --porter` (inner); see `docs/porter.md`.
