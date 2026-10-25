# WreckLess stage script (~4:00, 5 beats)

Run: `scripts/demo.sh [live|demo|scripted|replay]` (default `demo`). The script runs preflight
(curl `/v1/models` on :8000/:8001/:8002, a recorded item that reached `notified`, Slack config),
prints every `sudo` command and asks before running it.

Honesty rule for the presenter: say only what the screen shows. If the terminal says
`fallback`, `outbox`, or `REPLAY of …`, say it out loud. A failed scoreboard is shown, not skipped.

## Timing budget

| Beat | Window | Budget | On screen |
|---|---|---|---|
| 1 Airgap | 0:00–0:35 | 35 s | `airgap_lockdown.sh on` ✗ BLOCKED rows, then the `verify` PASS table |
| 2 Purple | 0:35–1:05 | 30 s | Fedora mascot, advisory, item queued as `PREDICTION` |
| 3 Red + gate | 1:05–2:05 | 60 s | TopHat mascot, gate re-runs the exploit, red **INTRUSION** flash |
| 4 Blue | 2:05–3:20 | 75 s | HardHat mascot, +green/−red diff, 3-check scoreboard, green **PATCH VALIDATED** |
| 5 Slack | 3:20–4:00 | 40 s | "Fix branch ready (local, pending review)" card in Slack (or the outbox line, if Slack is down) |

Live-LLM wall time on the GB10 per beat: `UNVERIFIED` — measure in rehearsal and fill in.
Scripted (`--no-llm`) pipeline time measured on a Mac laptop: ~1.1 s total (the beats then run
on talk time; scroll back to each beat). Replay reproduces the recorded run's original pacing
(`REPLAY_SPEED=2 scripts/demo.sh replay` halves it).

## Beats and talking points

1. **Airgap on.** "We just dropped every cloud-LLM route at the firewall. Loopback and Slack
   stay up. Everything you see next runs on this box." Point at the BLOCKED rows.
   `verify` only passes on a real TCP reset from our rule; if it says FAIL, don't claim airgap.
   Linux/iptables only.
2. **Purple / Fedora.** "Purple reads the advisory from local cache and writes a hypothesis:
   which file, which sink, what the oracle is." It enters the queue as a `PREDICTION`.
3. **Red / TopHat.** "Red writes an exploit and runs it inside the enclave. We only report
   what we can reproduce — the oracle is a nonce file written by `eval` of a DB value."
   "Red doesn't grade itself: the gate re-runs it with a fresh nonce and only accepts the oracle
   if it was written from victim code." INTRUSION appears only after `verifying → verified`.
4. **Blue / HardHat.** "Blue patches in a separate worktree. Blue doesn't grade itself: the
   orchestrator runs our held-out regression test (derived from the upstream fix, which shipped
   no test), the functional suite, and replays Red's exploit." Read the scoreboard rows.
   PATCH VALIDATED only after `patching → patched`.
5. **Slack.** "The draft PR branch and the diff are already in Slack." If the terminal says
   `local outbox`, say Slack wasn't reachable and show `logs/slack_outbox.jsonl`.

## Contingency ladder

| Rung | Command | When | What to say |
|---|---|---|---|
| 1 | `scripts/demo.sh live` | all 3 endpoints up, rehearsed | — |
| 2 | `scripts/demo.sh demo` (`run --demo-mode`) | default; N=1, temp 0; per-step cached fallback | if `fallback` shows: "that step used the cached reference" |
| 2b | `scripts/demo.sh scripted` (`--no-llm`) | endpoints down | "no LLM this time; exploit and validation still execute for real" |
| 3 | `scripts/demo.sh replay` | box/inference dead | "this is a replay of our last recorded run" (dim REPLAY tag top and bottom) |

Replay renders the recorded `events.jsonl` (every terminal line, lifecycle transition and
panel) through the same `ui` functions, tagged REPLAY top and bottom. Record a fresh rung-2
run before going on stage.
