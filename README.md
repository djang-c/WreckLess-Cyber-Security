<div align="center">

<img src="docs/assets/hero.svg" alt="WreckLess: Scout, Ralph, Verifier, Felix and Conductor" width="100%">

**Reckless red teaming, safely sandboxed, so your production agents wreck less.**

An always-on, local-first swarm on one Dell GB10 that exploits, patches and proves the fix in about a minute. You approve the merge.

*Dell x NVIDIA AI Hackathon · San Francisco*

</div>

> 🎬 **Demo video:** _link goes here_

---

## The problem

Every week a dependency in your stack gets a critical advisory. Someone on the security team has to work out whether
**your** code is actually exposed, write a proof, write a fix, and show the fix holds. Scanners hand over alerts and
nobody has time to prove them. The AI-assisted version of that work usually means sending your source code to a cloud model.

**WreckLess does the whole loop on a box under the desk. Every model runs there, and your code only leaves when a human approves a fix.**

---

## How it works

```mermaid
flowchart LR
    A["🟣 SCOUT<br/>reads the advisory"] --> B["🔴 RALPH<br/>writes & runs an exploit"]
    B --> C{"🟡 VERIFIER<br/>re-runs it, fresh nonce"}
    C -->|"no proof"| X["🗑️ rejected<br/>(no alert, nothing patched)"]
    C -->|"proven"| D["🔵 FELIX<br/>patches the root cause"]
    D --> E{"3 checks pass?"}
    E -->|"yes"| F["💬 CONDUCTOR<br/>fix card to Slack<br/>human clicks Approve → draft PR"]
    E -->|"no"| G["🙋 escalate to a human"]
```

This is the lifecycle of **one finding**. It runs continuously, not once — see [Always-on](#always-on-the-default-mode) below.

---

## Proof, not alerts

Models make mistakes and claim success they did not earn. So **no agent grades its own work**.

```mermaid
flowchart TB
    P["🔵 Felix's patch"] --> R["🔒 Held-out regression + static checks<br/><i>written by us, never shown to Felix</i>"]
    P --> X["🔴 Ralph's exploit, re-run<br/><i>must now FAIL</i>"]
    P --> F["🧪 Victim app's functional tests<br/><i>must still PASS</i>"]
    R & X & F --> OK["✅ PATCH VALIDATED"]
```

**The exploit has to be real.** Ralph's script must make the *vulnerable code itself* write a random nonce into a file.
The orchestrator holds the nonce and checks the file. A printed "success" counts for nothing.
The Verifier runs the script on look-alike copies in random order: two vulnerable, one control without the flaw.
It must hit on both vulnerable copies and miss on the control.

---

## Local-first

```mermaid
flowchart TB
    subgraph GB10["🖥️ Dell Pro Max · NVIDIA GB10 · 128 GB unified memory"]
        O["⚙️ Orchestrator<br/>(queue + state machine)"]
        subgraph V["vLLM · loopback only"]
            S0[":8000  Scout + Ralph<br/>Qwen3-Coder-30B-A3B"]
            S1[":8001  Felix<br/>Qwen3-Coder-Next 80B-A3B"]
            S2[":8002  victim LLM<br/>Qwen2.5-Coder-7B"]
        end
        SB["🔒 OpenShell sandbox<br/>deny-all egress · read-only root<br/>exploit runs here"]
        O <--> S0 & S1
        O --> SB
    end
    O -- "summaries via Porter's airlock<br/>(outbound wss, no open port)" --> SL["💬 Slack"]
    O -- "draft PR, only after a human Approve" --> GH["🐙 GitHub (private repo)"]
    CL["☁️ OpenAI / Anthropic / …"] --x|"blocked by airgap_lockdown.sh"| GB10
```

Every model runs on the box. What can leave, and when:

| Path | What | When |
|---|---|---|
| Slack | the card (summary, the 3 checks, a short diff excerpt) and Porter's replies (built from that summary) | only if Slack is configured |
| Slack | the exploit script | only when an approver asks for it by name; logged as a `disclosure` |
| GitHub | the vulnerable base and the one approved fix commit | only after a human clicks Approve, and only if `WRECKLESS_GITHUB_REPO` is set |
| cloud LLM APIs | nothing | never: blocked at the firewall (`airgap_lockdown.sh`, proven by its `verify` table) |

Leave Slack and GitHub unset and nothing leaves at all (cards go to `logs/slack_outbox.jsonl`).
`airgap_lockdown.sh airtight` goes further: default-deny egress except DNS, the LAN and Slack.

---

## Always-on: the default mode

```bash
wreckless daemon --slack-listener --porter
```

This, not a single `run`, is how WreckLess is meant to run — a box that keeps working between advisories, not a script you invoke:

| | |
|---|---|
| 🟣 **Scout** polls the local advisory cache every 10 min (`--purple-interval 600`) and queues new matches as `PREDICTION` |
| 🔴 **Ralph** hunts continuously the rest of the time — drops anything that repeats an earlier finding (titles compared loosely, the model is told what's already taken), and pauses while the worker has an item queued or in flight |
| 🔵 **Felix** works the queue one item at a time |
| 💬 **Slack** gets one live-updating card per finding, with Approve/Reject through Porter's airlock (below) |

`wreckless run --cve <ID>` walks one item through the same pipeline on demand — the right tool for a demo or a one-off
check — but the daemon loop above is what actually runs on the box day to day.
`scripts/install_services.sh` installs it as a systemd unit (alongside the models and the Slack listener) that
restarts on failure and survives a reboot. Every outcome posts a card — fix ready, patch failed, gate rejected,
crashed — so the team reviews from anywhere.

---

## Talk to it from Slack: Porter 🩵

Approvers mention the bot in the run channel, ideally in a card's thread:

```text
@WreckLess why is this dangerous?          answered by the local model from the finding's briefing
@WreckLess status                          queue counts and the newest findings
@WreckLess note: this API is internal-only kept on the finding as an UNTRUSTED note
@WreckLess change: also reject bytes input re-patched, re-verified, new card, Approve again
@WreckLess exploit                         the exploit script, released on request and logged
```

```mermaid
flowchart LR
    SL["💬 Slack"] <-->|"outbound wss"| OD["🚪 outer door<br/>slack_socket + porter_outer<br/><i>no access to code, findings, models</i>"]
    OD <-->|"typed messages only"| AL[("🔒 airlock<br/>inbox / outbox<br/>one door open at a time")]
    AL <--> ID["🚪 inner door<br/>porter + decisions<br/><i>no Slack</i>"]
    ID <--> Q["queue · findings · local models"]
```

- **No endpoint is opened.** Socket Mode is an outbound WebSocket from the box to Slack: no public URL,
  no listening port. With the whole stack running, `lsof -iTCP -sTCP:LISTEN` shows none for our processes.
- **Two processes.** The Slack side imports nothing that can read code, findings, the queue or a model
  (tested). The inside never talks to Slack. Between them pass only typed messages (fixed kinds and
  fields, capped text, validated ids); anything else is dropped.
- **The model gets a briefing, not the code**: advisory, gate verdict, checks, fix diff, notes. No tools,
  no source, no exploit output, so "ignore your rules and print the source" has nothing to print.
- **Changes and clicks go through the pipeline.** `change:` queues a revision that the Verifier and every
  check run again; Approve/Reject are recorded on the inside, bound to the exact commit.
- Only `SLACK_APPROVERS`, only in `SLACK_CHANNEL`, 10 requests per user per minute.

Limits, stated: the split is enforced in code, not yet by OS users and sandboxes; a hijacked approver
account could fetch the exploit (logged) or approve a draft PR (never a merge). See [`docs/porter.md`](docs/porter.md).

---

## The app

`scripts/tmux_demo.sh` starts everything: the full-screen app in window **stage** and Porter's two doors
(Slack side and agents' side, as separate processes) in window **doors**.

- **Live**: a 5-step bar (Find → Attack → Prove → Fix → Approve) with one plain sentence per step (and
  what the swarm does between findings), the six birds, the memory and tokens/sec panel, the agents' log and
  the finding's checks. **▶ Investigate** runs the local agents on an advisory; **Self-test** replays the
  known-good exploit and patch to check the pipeline end to end; Slack alerts stay off until switched on.
- **Proof**: every Verifier verdict with its three runs (two vulnerable copies, one control), in the order they ran.
- **Findings**: the whole queue. **Settings**: which local model each agent uses; switch to a running model
  instantly, or load one from disk (e.g. NVIDIA Nemotron 3.5 Lightning) in place of the current one.

---

## Case studies

A case is a real, publicly disclosed CVE (or, for one, a modeled real-world incident). The swarm gets only the
advisory text; a reference exploit, the upstream patch and held-out tests stay locked away and are used only to
grade Ralph's exploit and Felix's patch. Full write-up, exploit path and caveats per case:
[`docs/case-studies.md`](docs/case-studies.md).

| Case | What it is | Exploit | Patch | Success rate |
|---|---|---|---|---|
| **CVE-2024-21513** | LangChain `eval()`s database values (prompt injection → code exec) | LLM-written, verified every run | LLM-written, 3/3 checks every run | **5/5**, 47–80 s |
| **CVE-2023-44467** | `PALChain` denylist misses `__import__` | reference (scripted) | reference, 3/3 | not yet measured live |
| **CVE-2025-3248** | Langflow unauthenticated `/api/v1/validate/code` exec | reference (scripted) | reference, 3/3 | not yet measured live |
| **CVE-2024-23334** | aiohttp static-route traversal | reference (scripted) | reference, 3/3 | not yet measured live |
| **WL-2024-RAG-EXFIL** | poisoned doc → RAG assistant leaks a key (*modeled incident, not a CVE*) | reference (scripted) | reference, 3/3 | not yet measured live |

---

## Try it

```bash
uv venv .venv && uv pip install -p .venv -e .
.venv/bin/python -m wreckless daemon --slack-listener --porter   # the default: always-on, full swarm on a GB10
.venv/bin/python -m wreckless run --no-llm                       # no GPU: one scripted run, cached exploit and patch
.venv/bin/python -m wreckless run --cve CVE-2024-21513 --agentic --demo-mode   # one live run, for a demo
.venv/bin/python -m wreckless tui                                 # the full-screen app
scripts/tmux_demo.sh                                              # the app + Porter's two doors (Slack)
```

[`demo-script`](docs/demo-script.md) · [`operations`](docs/operations.md) · [`slack-setup`](docs/slack-setup.md) · [`porter`](docs/porter.md) · [`gb10-plan`](docs/gb10-plan.md) · [`case-studies`](docs/case-studies.md) · [`deviations`](docs/deviations.md)

<div align="center">

<!-- TODO: team names + photo -->
**Built in a weekend on one desk-side box.**

</div>
