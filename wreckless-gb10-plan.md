# WreckLess — NVIDIA GB10 Deployment Scope

_As of 2026-10-25 · patched_

Scope for running the WreckLess agentic security swarm on the Dell Pro Max / NVIDIA GB10: the system architecture, key serving decisions, hardware requirements, the two-person work split, pre-transfer prep, how the transfer works, and what the running system looks like on stage.

---

## Key decisions

| # | Decision | Residual check |
|---|---|---|
| 1 | **Serving: 3-port swarm is primary; one-model collapse is the fallback.** Three vLLM servers (one per model) on three ports; keep the collapsed config as the bottom rung of the contingency ladder. | Hand-budget per-instance memory so the three fit; validate on real GB10. |
| 2 | **Quantization: AWQ-INT4 + Marlin.** The speed penalty vs native NVFP4 is modest and mostly in prefill; decode is bandwidth-bound either way. WreckLess runs 24/7, so tokens/sec isn't the KPI — the only speed-sensitive moment is the live demo, already handled by `--demo-mode` (N=1). | If real-HW testing shows an unexpectedly large gap (unlikely), revisit. |
| 3 | **Models exist and are quantized** (team's call). | Pin the exact HF repo for each and confirm the quant is Marlin-loadable on sm_121 (AWQ-INT4 ideal; GPTQ-Int4 also works via Marlin; avoid NVFP4). |
| 4 | **Airgap fixed:** block only the cloud-LLM egress, keep Slack alive. | Test the rule doesn't drop local vLLM or the Slack socket. |
| 5 | **Architecture: always-on swarm, deterministic demo.** Scheduled Purple + continuous Red both produce candidates into one queue; a single sandbox verify gate promotes only exploit-confirmed items to Blue. The demo walks one pre-verified CVE; continuous Red is background liveness, throttled during the hero beat. | Keep all hunt output labelled PREDICTION; never put live discovery in the critical path. |

---

## Architecture: always-on swarm

Two concurrent producer loops feed one candidate queue; a single deterministic gate promotes candidates to verified findings; only verified findings reach Blue. This is what makes "always-on agentic SecOps swarm" literally true rather than a one-shot reproducer.

```
Purple (scheduled, every N min) ─┐
  pulls latest advisories         │
  (NVD / GHSA, pre-cached offline) ├─► CANDIDATE QUEUE ─► VERIFY ─► VERIFIED ─► Blue (patch) ─► validate ─► Slack
Red (continuous worker) ──────────┘   (each item a      (exploit-as-test
  hunts the agent↔API surface          PREDICTION)       in OpenShell,
  for candidate flaws, 24/7                               success oracle)
```

- **Two producers, two clocks.** Purple is scheduled; Red runs continuously. Both only *produce candidates* — every candidate is a PREDICTION and carries no weight until verified.
- **One trust gate.** The exploit-as-test runs the candidate in the OpenShell sandbox and checks a success oracle. The verdict comes from code executing, not from a model's say-so — so a weak hunter cannot manufacture findings. Same gate for both Purple's advisories and Red's discoveries.
- **Red proposes, the gate disposes.** Split Red into Red-hunt (proposes candidate exploits) and Red-verify (runs them against the oracle). Red never certifies its own output; the sandbox does. This is the answer to "isn't Red grading its own homework?"
- **The state machine moves down a level.** Instead of one global linear run, each candidate walks its own lifecycle: `queued → verifying → verified | rejected → patching → patched → notified`. The Red→Blue `vulnerability_report.json` handoff is unchanged — still a strict JSON state-machine handoff, now per item.

Why this is the better story: it strengthens Business Value ("hunts overnight, files tested PRs by morning"), Local-First (continuous on-device operation *is* the 24/7 story), and generality (a live queue of multiple findings answers "is this hardcoded?"). The cost is entirely paid by the demo-discipline rule below.

### Demo discipline (non-negotiable)

The always-on behaviour is the *system*; the demo's critical path is *one pre-verified item*. Keep them separate.

- **Critical path = one VERIFIED CVE** (LangChain CVE-2024-21513), pre-confirmed, walked live: the exploit-as-test passes on the vulnerable commit, is blocked on Blue's patch, and the victim replica's functional tests (written by WreckLess, not upstream) still pass. Framing: **"exploit blocked + no regressions"** — never "the maintainer's test." Show Blue's diff beside the maintainer's fix `7b13292e`.
- **Continuous Red = background liveness panel**, pre-seeded: e.g. "Red up 6 h · 14 candidates · 3 verified." Proves always-on + generality without betting the demo on live luck.
- **Throttle background hunting during the hero beat.** On one bandwidth-bound GPU, a churning Red steals the 273 GB/s from Blue. Pause/rate-limit Red while walking the verified item; resume after.
- **Never claim autonomous 0-day discovery as proven.** Autonomous novel-vuln discovery is an open research problem, and a 4-bit model under N=1 is a weak hunter — expect mostly false positives. The gate makes that safe (garbage gets rejected), but any unverified hunt output stays labelled PREDICTION and is shown as leads-to-verify, not findings.

---

## Serving plan: 3 ports (primary)

One vLLM server per model, each on its own port. Purple and Red share the 30B server (same weights, two role prompts, batched in one forward pass); Blue and the victim get their own.

| Port | Role(s) | Model | Weights (approx) | Start `--gpu-memory-utilization` |
|---|---|---|---|---|
| 8001 | Blue (defender) | 80B-A3B 4-bit | ~42 GB | 0.40 |
| 8000 | Purple + Red | Qwen3-Coder-30B-A3B AWQ | ~16 GB | 0.20 |
| 8002 | Victim target | Qwen2.5-Coder-7B AWQ | ~5 GB | 0.08 |

**Memory math (128 GB unified):** ~63 GB weights + ~12 GB per-process overhead + ~12–15 GB for DGX OS/desktop ≈ 87–90 GB, leaving ~38–41 GB for KV cache across all three. Comfortable at demo concurrency.

**Rules for making three instances coexist in one unified pool:**

- `--gpu-memory-utilization` is a fraction of *total* device memory, and each instance reserves its own slice. The three fractions plus the OS must stay under 1.0 — the numbers above sum to 0.68, leaving generous headroom at N=1 concurrency. Tune up only if you need more KV.
- **Launch the biggest model (80B, port 8001) first**, then the 30B, then the 7B. The last instance to start sees the least free memory.
- Verify free memory between launches with `nvidia-smi` (or `tegrastats`) before starting the next instance.
- Cap context hard: `--max-model-len 16384`, `--max-num-seqs 4`, `--kv-cache-dtype fp8`. You don't need 256K context for this demo.
- **Continuous Red keeps port 8000 busy.** Rate-limit it during the hero beat so Blue (8001) isn't starved of the shared 273 GB/s bandwidth.

**Launch command (per instance):**

```bash
# Port 8001 — Blue (start this one FIRST)
vllm serve <blue-80b-a3b-repo> \
  --host 0.0.0.0 --port 8001 \
  --quantization awq_marlin \
  --gpu-memory-utilization 0.40 \
  --max-model-len 16384 --max-num-seqs 4 \
  --kv-cache-dtype fp8 \
  --enable-expert-parallel \
  --tool-call-parser qwen3_coder
  # add --enforce-eager if CUDA graphs misbehave on sm_121
```

Repeat for port 8000 (30B, util 0.20) and port 8002 (7B, util 0.08 — drop `--enable-expert-parallel`, the 7B victim is dense).

### Fallback: collapse to 2 ports

If the 80B won't stabilize on real hardware in time, degrade — don't crash:

- **Rung 1:** swap Blue's 80B for a 32B-class model on port 8001 (already planned).
- **Rung 2 (collapse):** run **one** reasoning model on port 8000 serving Purple + Red + Blue via role prompts, keep the 7B victim on port 8002. ~21 GB weights total, huge headroom, one bring-up to babysit.

**Cost of collapsing:** you lose per-role model specialization and, more importantly, the Local-First rubric flex ("we packed a 110B+ swarm into 128 GB"). So collapse is the safety net, not the plan — run the full swarm for the headline if it's stable.

---

## Requirements for the GB10

**Hardware (confirmed):** 128 GB LPDDR5X unified memory shared by CPU+GPU; 20 Arm cores (10× Cortex-X925 + 10× Cortex-A725); Blackwell GPU, 1 PFLOP FP4; 140 W; NVIDIA DGX OS (Ubuntu aarch64).

**The governing number: 273 GB/s memory bandwidth.** Generation is bandwidth-bound — the box is "memory dense, bandwidth poor." For MoE, decode cost scales with *active* params, so A3B models (~3B active) are the right call. Note: the fallback dense 32B is *slower* per token than the 80B-A3B despite being smaller, because a dense model reads all its weights every token.

**Software stack:**

- aarch64 + `sm_121a` Docker image only — x86 images won't run.
- vLLM build whose `ptxas` recognizes `sm_121a` (container CUDA/ptxas 12.9+; Triton's bundled 12.8 does not). Use the official vLLM DGX Spark image or a pinned community one (e.g. `vllm-gb10`).
- AWQ-INT4 weights + Marlin backend (`--quantization awq_marlin`).

---

## Splitting the work (2 people)

Two parallel tracks meeting at two shared contracts, defined day one: the OpenAI-compatible endpoint (A serves, B calls) and `vulnerability_report.json` (A's Red produces it, B's Blue consumes it). With both contracts fixed, neither track blocks the other.

**Person A — Serving & Offense (Purple + Red)**

- GB10 inference bring-up: pinned aarch64/sm_121 vLLM, AWQ-INT4 + Marlin.
- Model + quant validation incl. confirming the three HF repos (decision 3); the 3-port memory budget (decision 1).
- Purple scheduled intel feed + advisory into the local vector DB.
- Red (continuous): Red-hunt worker + `repro_exploit.py` + the OpenShell sandbox + the success oracle. Clone the target at the vulnerable commit.
- vLLM `/metrics` exposed (for B's memory + tokens/sec panel). Transfer/deploy to the board (A owns the image).

**Person B — Orchestration & Defense (Blue + Demo)**

- NemoClaw orchestrator: the candidate **queue**, the per-item **state lifecycle**, and the **verify gate** (runs Red's exploit-as-test in the sandbox, reads the oracle, promotes PREDICTION → VERIFIED). The `vulnerability_report.json` handoff.
- Blue: AST patch generation; wrap Red's exploit as a pytest and re-run it on the patch + re-run the victim replica's WreckLess-written functional tests → "exploit blocked + no regressions"; render Blue's diff beside the maintainer's fix `7b13292e`.
- `airgap_lockdown.sh` (decision 4) + Slack Socket Mode bridge; card ends with "Fix branch ready (local, pending review)"; only say "Draft PR" once a real PR URL exists (draft PR on a fork, needs approval) + per-agent audit trail.
- Terminal mascots/ANSI UI incl. the GB10 memory panel (3 models resident, ~110B in 128 GB) + live tokens/sec per port; the 4-minute `--demo-mode` (N=1) script with per-state timeouts, one retry, honest-failure, and a pre-recorded fallback replayed from `events.jsonl`.

Balanced: A carries the front-loaded infra risk; B carries the two heaviest logic pieces (the queue/gate/state machine + the Blue hero proof) plus the demo polish. Both halves develop on MacBooks against the shared endpoint; only Person A needs real GB10 silicon early.

---

## Developing on MacBooks

MacBooks are Apple Silicon (arm64) but have **no NVIDIA GPU and no CUDA**, so the vLLM / sm_121 / Marlin path can't run or be tested on a Mac.

- **Person B** can do ~everything on a Mac against a stand-in OpenAI-compatible endpoint (Ollama), then swap to the GB10 endpoints with no rewrite. The swap must be **config-only**, so the contract maps each role to its own `{base_url, model}` pair — Ollama is one port serving many models by name, the GB10 is three ports serving one model each:

  | Role | Mac (Ollama) | GB10 |
  |---|---|---|
  | Purple/Red | `localhost:11434` · `qwen3-coder:30b` | `localhost:8000` |
  | Blue | `localhost:11434` · `qwen3-coder:80b` | `localhost:8001` |
  | Victim | `localhost:11434` · `qwen2.5-coder:7b` | `localhost:8002` |

  Caveat: `airgap_lockdown.sh` uses Linux `iptables` — write it on the Mac, test it in a Linux container or on the box. Ollama proves the *logic*; tokens/sec, the memory panel, and quant quality are only real on the GB10.
- **Person A** can write the Dockerfile, pin versions, script launches, and pre-download weights on a Mac, but **cannot validate the GPU image there.** That needs real sm_121 silicon — the hackathon GB10 or a rented one (e.g. Vast.ai) / cloud Blackwell instance for pre-flight.

Net: both start on MacBooks; get Person A onto a real GB10 as early as possible.

---

## Before you transfer to the board

Everything that isn't local inference should be done and tested before you touch the GB10.

- [ ] Build/pull the aarch64 + sm_121 image; pin every component (CUDA base, vLLM, NCCL, FlashInfer by SHA).
- [ ] Pin the three model HF repos and confirm each quant is Marlin-loadable on sm_121 (decision 3).
- [ ] Pre-download all weights to a HF cache on a USB-C SSD; `docker save` the image to a tarball for offline `docker load`.
- [ ] Build the NemoClaw queue + per-item state lifecycle + verify gate against Ollama; build Blue, the Slack bridge, the UI, and the demo script.
- [ ] Pre-bake the hero case: clone LangChain CVE-2024-21513 at the vulnerable commit into git worktrees; capture the maintainer's fix `7b13292e`; load the advisory into the local vector DB.
- [ ] Pre-verify the hero CVE **and a 2nd CVE** end-to-end through the pipeline; record `events.jsonl` for the fallback replay.
- [ ] Seed a continuous-Red backlog (≥ ~14 candidates, ≥ 3 verified) for the liveness panel.
- [ ] Build and test `--demo-mode` (N=1) and `airgap_lockdown.sh`; confirm the airgap rule doesn't kill local vLLM or the Slack socket.
- [ ] Decide the 3-port memory fractions and rehearse the collapse fallback.

---

## How the transfer works

DGX OS is Ubuntu aarch64 with Docker + NVIDIA Container Toolkit preinstalled.

1. SSH in over the 10 GbE port, or work directly on the venue LAN.
2. `docker load` your pinned image tarball (airgap-safe) rather than `docker pull`.
3. Copy pre-downloaded weights onto the NVMe and mount them: `-v ~/.cache/huggingface:/root/.cache/huggingface`. Parallel NVMe read hits ~3.5 GB/s (~96 GB in ~27 s), so ~20–30 s for your ~63 GB. **Load once, keep resident, never load on stage.**
4. Launch the three vLLM instances (biggest first) with the flags above.
5. Point the role→endpoint config at `localhost:8000/8001/8002`; NemoClaw and the agents run unchanged.

---

## The airgap, fixed

The problem: `airgap_lockdown.sh` rejecting *all* outbound would also kill Slack Socket Mode (which is an outbound connection). The fix: block only the cloud-LLM egress and leave everything else — including Slack — up. That's exactly what the Local-First rubric wants to see ("no cloud LLM in the loop") without losing the notification channel.

**Demo path (legible, Slack-safe) — block-list the LLM endpoints:**

```bash
# Reject outbound to cloud LLM APIs; everything else (incl. Slack) still works.
for cidr in <openai-cidrs> <anthropic-cidrs>; do
  sudo iptables -A OUTPUT -d "$cidr" -j REJECT
done
# Loopback and local vLLM ports stay open by default.
```

On stage, dropping this route is the visible proof — a live `curl api.openai.com` gets REJECTED while the swarm keeps running. Keep `lo` and `localhost:8000-8002` open so the swarm keeps talking to itself.

**Airtight variant (if you want to prove more):** default-deny `OUTPUT`, then allow-list only loopback, the local subnet, and Slack's gateway. More convincing, but Slack's IPs shift, so test it well ahead — the block-list above is the safer live demo.

---

## How the finished product looks

A headless GB10 running the always-on swarm: three vLLM containers resident in the 128 GB pool, Purple on a schedule and Red running continuously, both feeding the candidate queue, the verify gate promoting only exploit-confirmed items to Blue. On screen: the color-coded Purple/Red/Blue trace, a GB10 memory panel (three models resident, ~110B params in 128 GB) with live tokens/sec per port, and Slack cards updating over Socket Mode.

The ~4-minute run — **one pre-verified item in the critical path; continuous Red throttled to background:**

1. Airgap goes up — a live `curl api.openai.com` is REJECTED while the swarm keeps running (Local-First, visible).
2. Purple retrieves the CVE advisory from the local intel cache (offline).
3. The item enters the queue as a PREDICTION; the verify gate runs the exploit-as-test in the OpenShell sandbox — it fires on the vulnerable commit. Terminal turns red, Slack fires the intrusion trace. Now VERIFIED.
4. Blue generates the AST patch; the exploit-as-test is re-run and is now **blocked**, and the victim replica's WreckLess-written functional tests still **pass** — "exploit blocked + no regressions." Blue's diff is shown beside the maintainer's fix `7b13292e`.
5. Slack card flips to "Fix branch ready (local, pending review)"; "Draft PR" only with a real PR URL (draft PR on a fork, pending approval).
6. Background panel shows the always-on proof: "Red up 6 h · 14 candidates · 3 verified," and a 2nd CVE runs through the same pipeline untouched (generality).

**Safety nets:** every state has a timeout and a degrade path; if the patch fails under `--demo-mode` it retries once, then shows the failure honestly; a pre-recorded run replays from `events.jsonl` with the same UI if the box misbehaves.
