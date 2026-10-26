# WreckLess: 2-minute demo video script

Target runtime: **1:55** (5-second buffer under the submission's 2:00 cap). Voiceover recorded
separately from the terminal footage and combined in editing; the GB10 has no mic, so screen
capture here is video-only.

Corrections from the first draft, and why (see `docs/demo-script.md` and `docs/deviations.md`
for the source of each honesty rule):

- **No `wreckless benchmark` command.** The CLI is `run`, `daemon`, `status`, `replay`, `metrics`,
  `intel`, `tui`, `view`, `mascots`. Use `wreckless run --cve CVE-2024-21513`.
- **No NemoClaw.** It never shipped in this repo. "NemoClaw" was an old internal display name for
  our own orchestrator, since renamed to **Conductor**. Say "the orchestrator" or "Conductor."
- **Cut "passes the actual unit test written by the human upstream maintainer."** False: upstream
  shipped **no test** with the CVE-2024-21513 fix. Our held-out test is derived from the fix by
  us, not the maintainer's. This is a documented honesty rule — don't restate the overclaim.
- **Cut the 4-card zoom (Slack AI RAG / LangChain / MLflow BOLA / aiohttp).** Only two cases are
  committed with numbers: CVE-2024-21513 and CVE-2023-44467 (both LangChain). Show one case, named
  correctly, or say "two benchmark cases" and name both.
- **Test path is `benchmarks/CVE-2024-21513/regression_test.py`**, not
  `tests/test_vector_sql_regression.py`.
- **Kept as-is, verified against the code:** Felix really does call `generate_openshell_egress_rule`
  after a patch validates (`wreckless/agents/blue.py`). That beat is accurate.

---

## Act 1 — The hook (0:00–0:20)

Pre-recorded outdoors + guacamole-ending footage (already captured separately). No changes needed
to this act; the dialogue doesn't reference anything in the repo.

| Time | Visual | Line |
|---|---|---|
| 0:00–0:07 | Walking shot | Dev 1: "Lunch time. Grab some burritos?" / Dev 2: "Yeah, let's do it." |
| 0:07–0:13 | Phone: "CRITICAL: Agent Injection Zero-Day Dropping Now" | Dev 1: "Wait, look at this. A new agent zero-day just dropped. We need to sprint back." |
| 0:13–0:20 | Slack banner: 🟢 [P0] PR Ready: CVE Mitigated & Verified | Dev 2: "Don't worry about it. WreckLess already handled it." / Dev 1: "It dropped five minutes ago. How?" / Dev 2: "Let me show you." |

## Act 2 — The swarm, live (0:20–0:50)

| Time | Visual | Voiceover |
|---|---|---|
| 0:20–0:35 | Terminal (`wreckless tui`), pixel mascots animating | "This is WreckLess running on our Dell Pro Max with GB10 — an always-on swarm. In the background it keeps hunting our targets for new flaws; what you're about to see is one finding going through the full pipeline." |
| 0:35–0:50 | Red **INTRUSION** flash; exploit runs inside OpenShell; Slack flips to 🔴 Exploit Confirmed | "Ralph writes a Python exploit and runs it inside an OpenShell sandbox — deny-all egress, so nothing it does leaves this box. Ralph doesn't grade himself: the Verifier re-runs it with a fresh nonce before the orchestrator calls it confirmed." |

## Act 3 — Proof, not alerts (0:50–1:30)

| Time | Visual | Voiceover |
|---|---|---|
| 0:50–1:02 | Cut to the advisory: CVE-2024-21513, `langchain-experimental` | "This one's CVE-2024-21513 — prompt injection tricks a LangChain SQL tool into running `eval()` on whatever the database returns." |
| 1:02–1:18 | Felix patches; `generate_openshell_egress_rule` call shown | "Felix patches the root cause, then locks down the sandbox's egress policy for this item. Felix doesn't grade himself either." |
| 1:18–1:30 | 3-check scoreboard, green **PATCH VALIDATED**; side-by-side diff (upstream fix vs. Felix's fix) | "The orchestrator runs three checks Felix never sees: our held-out regression test — derived from the upstream fix, since upstream shipped none — the app's real test suite, and Ralph's exploit, replayed and now blocked." |

## Act 4 — Local hardware & close (1:30–1:55)

| Time | Visual | Line |
|---|---|---|
| 1:30–1:45 | Pan over the GB10 chassis; `airgap_lockdown.sh verify` PASS table | Dev 2 (voiceover): "Zero cloud LLM calls. The whole swarm — up to an 80-billion-parameter patch engineer — runs in 128 GB of unified memory." |
| 1:45–1:55 | Cut to Dev 1 & Dev 2 walking in, laughing | Dev 1: "So... double guacamole?" / Dev 2: "Double guacamole." / Text on screen: "WreckLess: Reckless red teaming in an OpenShell sandbox — so your agents wreck less." |
| 1:55–2:00 | End slate: title, GitHub link, Dell x NVIDIA banner | — |

---

## Shot list for the terminal footage (Acts 2–3)

Record each beat as its own short clip rather than one continuous take — much easier to trim and
re-cut against a voiceover recorded separately.

1. `wreckless tui` idle/opening, a few seconds of the mascot strip.
2. Scout queuing the advisory as `PREDICTION`.
3. Ralph writing + running the exploit → red **INTRUSION** flash.
4. Felix's patch diff + the 3-check scoreboard → green **PATCH VALIDATED**.
5. `airgap_lockdown.sh verify` PASS table.
6. The Slack card (or `logs/slack_outbox.jsonl` if Slack isn't reachable — say so on camera if used).

Say only what's on screen: if a clip shows `fallback`, `CACHED REFERENCE`, or `outbox`, that's fine
to use, but don't narrate it as live-generated.
