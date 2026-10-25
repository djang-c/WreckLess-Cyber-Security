# WreckLess — NVIDIA GB10 Deployment Scope

_As of 2026-10-25 · patched_

Scope for running the WreckLess agentic security swarm on the Dell Pro Max / NVIDIA GB10: the key serving decisions, hardware requirements, the two-person work split, pre-transfer prep, how the transfer works, and what the running system looks like on stage.

---

## Key decisions

Four design questions, now resolved. Detail for each is in the sections below.

| # | Decision | Residual check |
|---|---|---|
| 1 | **Serving: 3-port swarm is primary; one-model collapse is the fallback.** Three vLLM servers (one per model) on three ports; keep the collapsed config as the bottom rung of the contingency ladder. | Hand-budget per-instance memory so the three fit; validate on real GB10. |
| 2 | **Quantization: AWQ-INT4 + Marlin.** The speed penalty vs native NVFP4 is modest and mostly in prefill; decode is bandwidth-bound either way. WreckLess runs 24/7, so tokens/sec isn't the KPI — the only speed-sensitive moment is the live demo, already handled by `--demo-mode` (N=1). | If real-HW testing shows an unexpectedly large gap (unlikely), revisit. |
| 3 | **Models exist and are quantized** (team's call). | Pin the exact HF repo for each and confirm the quant is Marlin-loadable on sm_121 (AWQ-INT4 ideal; GPTQ-Int4 also works via Marlin; avoid NVFP4). |
| 4 | **Airgap fixed:** block only the cloud-LLM egress, keep Slack alive. | Test the rule doesn't drop local vLLM or the Slack socket. |

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
- Purple intel feed + advisory into the local vector DB.
- Red: clone the target at the vulnerable commit, `repro_exploit.py`, OpenShell sandbox.
- Transfer/deploy to the board (A owns the image).

**Person B — Orchestration & Defense (Blue + Demo)**

- NemoClaw state machine + the `vulnerability_report.json` handoff.
- Blue: AST patch generation; extract the maintainer's fix + run the upstream pytest (the hero proof).
- `airgap_lockdown.sh` (decision 4) + Slack Socket Mode bridge.
- Terminal mascots/ANSI UI + the 4-minute demo script.

Balanced: A carries the front-loaded infra risk; B carries the two heaviest logic pieces (state machine + Blue hero proof) plus the demo polish. Both halves develop on MacBooks against the shared endpoint; only Person A needs real GB10 silicon early.

---

## Developing on MacBooks

MacBooks are Apple Silicon (arm64) but have **no NVIDIA GPU and no CUDA**, so the vLLM / sm_121 / Marlin path can't run or be tested on a Mac.

- **Person B** can do ~everything on a Mac against a stand-in OpenAI-compatible endpoint (Ollama / LM Studio / MLX serving a Qwen model), then swap to the GB10 endpoints with no rewrite. Caveat: `airgap_lockdown.sh` uses Linux `iptables` — write it on the Mac, test it in a Linux container or on the box.
- **Person A** can write the Dockerfile, pin versions, script launches, and pre-download weights on a Mac, but **cannot validate the GPU image there.** That needs real sm_121 silicon — the hackathon GB10 or a rented one (e.g. Vast.ai) / cloud Blackwell instance for pre-flight.

Net: both start on MacBooks; get Person A onto a real GB10 as early as possible.

---

## Before you transfer to the board

Everything that isn't local inference should be done and tested before you touch the GB10.

- [ ] Build/pull the aarch64 + sm_121 image; pin every component (CUDA base, vLLM, NCCL, FlashInfer by SHA).
- [ ] Pin the three model HF repos and confirm each quant is Marlin-loadable on sm_121 (decision 3).
- [ ] Pre-download all weights to a HF cache on a USB-C SSD; `docker save` the image to a tarball for offline `docker load`.
- [ ] Build the NemoClaw state machine, JSON handoff, `repro_exploit.py`, AST patch logic, and Slack bridge against a cloud/Mac endpoint.
- [ ] Pre-bake the hero case: clone LangChain CVE-2024-21513 at the vulnerable commit into git worktrees; capture the maintainer's fix + regression-test commit; load the advisory into the local vector DB.
- [ ] Build and test `--demo-mode` (N=1) and `airgap_lockdown.sh`; confirm the airgap rule doesn't kill local vLLM or the Slack socket.
- [ ] Decide the 3-port memory fractions and rehearse the collapse fallback.

---

## How the transfer works

DGX OS is Ubuntu aarch64 with Docker + NVIDIA Container Toolkit preinstalled.

1. SSH in over the 10 GbE port, or work directly on the venue LAN.
2. `docker load` your pinned image tarball (airgap-safe) rather than `docker pull`.
3. Copy pre-downloaded weights onto the NVMe and mount them: `-v ~/.cache/huggingface:/root/.cache/huggingface`. Parallel NVMe read hits ~3.5 GB/s (~96 GB in ~27 s), so ~20–30 s for your ~63 GB. **Load once, keep resident, never load on stage.**
4. Launch the three vLLM instances (biggest first) with the flags above.
5. NemoClaw and the agents talk to the local endpoints at `localhost:8000/8001/8002`.

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

On stage, dropping this route is the visible proof. Keep `lo` and `localhost:8000-8002` open so the swarm keeps talking to itself.

**Airtight variant (if you want to prove more):** default-deny `OUTPUT`, then allow-list only loopback, the local subnet, and Slack's gateway. More convincing, but Slack's IPs shift, so test it well ahead — the block-list above is the safer live demo.

---

## How the finished product looks

A headless GB10 on the desk running DGX OS: three vLLM containers resident in the 128 GB pool, the NemoClaw orchestrator driving the JSON state machine. On screen, a terminal streaming the color-coded Purple/Red/Blue trace, and Slack block-kit cards updating over Socket Mode.

The ~4-minute run:

1. `airgap_lockdown.sh` drops the cloud-LLM route (Slack stays up).
2. Purple ingests the CVE advisory from local cache.
3. Red runs `repro_exploit.py` in the OpenShell sandbox — terminal turns red, Slack fires the intrusion trace.
4. Blue generates the AST patch, runs the maintainer's upstream pytest, it passes.
5. Slack flips to "Draft PR Ready."

`--demo-mode` N=1 keeps it deterministic so there's no dead air.
