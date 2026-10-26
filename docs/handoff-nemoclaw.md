# Handoff: optional NemoClaw integration (nice-to-have, NOT required)

_Written 2026-10-25. Side task, does not block submission. Another agent/session owns this,
working off to the side of the case-study and core-flow work._

## Read this first
The hackathon stack line is: "use at least one of NemoClaw, OpenClaw or OpenShell." **We already
satisfy it** — every exploit run goes through an OpenShell sandbox (kernel-enforced deny-all
egress; confirmed via `openshell-gateway` process + `openshell status`, and exercised by the
sandbox tests). This task adds NemoClaw only as an extra, clearly-labeled layer for judge
visibility. It is not fixing a gap.

**Time-box the recon to ~20–30 minutes.** If NemoClaw doesn't look like a thin wrapper by then,
stop and report back instead of pushing through. Token/time budget is tight; don't force this.

## Hard constraints (non-negotiable)
- Work in a **new, separate git worktree/branch** off `origin/main` — do not share a checkout
  with the case-study or core-flow work that's in flight.
- **Do NOT edit**: `wreckless/swarm.py`, `wreckless/agents/*`, `wreckless/gate.py`,
  `wreckless/llm.py`, `wreckless/ui.py`, `wreckless/mascots.py`, `wreckless/metrics.py`. Same
  audited list as the case-study handoff. NemoClaw must be an **outer wrapper that invokes the
  existing `wreckless` CLI as a subprocess**, never a reimplementation of orchestration, tool
  calling, or the gate's verification logic. If NemoClaw's model can't work that way without
  touching those files, that's the bail condition — stop, don't ask for an exception, just report.
- Commit as `Kevin Jiang <kevin.jiang53@gmail.com>`. No `Co-Authored-By` / "Generated with"
  trailers.
- `git pull --rebase` before pushing. **Never force-push.**
- Third-party code (NemoClaw itself, its deps) stays out of the commit — gitignored, same as
  `targets/upstream/`.

## Step 0 — recon (do this first; report before writing any code)
1. Confirm what's actually present: `which node` (known good — already installed this session),
   `which nemoclaw` / `npm ls -g` (not installed as of this write-up — nobody has evaluated it).
2. Find NemoClaw's real docs (README / npm page / GitHub). Answer concretely:
   - Is it a process launcher/orchestrator that can shell out to an arbitrary CLI and relay
     stdout/exit code? (→ good fit, cheap integration)
   - Or does it require writing agents/tools inside *its* framework (its own tool-calling loop,
     its own agent definitions)? (→ bad fit — would mean reimplementing Purple/Red/Gate/Blue a
     second time, which is exactly the "do not touch" risk; bail here)
3. Write 3–5 sentences answering that in this file's "Recon notes" section below, then stop and
   let the user decide go/no-go if it's ambiguous.

## Step 1 — integration (only if step 0 says "thin wrapper")
- Add a small NemoClaw config/script that drives the existing CLI as a child process — e.g. it
  launches `uv run wreckless run --cve <id> ...` (or the tmux demo's equivalent commands) and
  relays output. One NemoClaw node is enough; it does not need to mirror every role.
- Must not change pass/fail semantics of anything. Prove it: run the no-llm scripted check for at
  least 2 existing cases before and after, diff the verdicts.
- Add a short, honest doc paragraph (README, new "Stack" subsection) saying exactly what NemoClaw
  does on top — e.g. "NemoClaw drives the demo launch; OpenShell remains the sandbox/isolation
  layer for every exploit run." Do not imply NemoClaw does anything it doesn't.

## Step 2 — verify nothing broke
```bash
uv run pytest -q tests/test_gate.py tests/test_pipeline.py tests/test_intel.py
WRECKLESS_SANDBOX=userland uv run wreckless run --cve CVE-2024-21513 --no-llm --demo-mode  # still 3/3
```

## Step 3 — report back
State plainly:
- What NemoClaw actually does in the final integration (1–2 sentences, no overclaiming).
- Time and tokens actually spent.
- Confirmation nothing on the "do not touch" list was edited.
- A README snippet ready to paste.

## Bail conditions (stop and report instead of proceeding)
- Step 0 recon time-box (~20–30 min) is up and it's still unclear whether NemoClaw is a thin
  wrapper.
- Making it fit would require touching an audited core file.
- Any existing test goes from pass to fail and the fix isn't obvious/cheap.

## Recon notes
`node` present, `nemoclaw` not installed (`npm ls -g` empty) — matches the write-up. NemoClaw
(NVIDIA, alpha, GitHub install pending npm publish) turns out to be an onboarding/provisioning
CLI for an OpenShell sandbox (gateway, inference providers, sandbox image, versioned "blueprint")
— it sits on the *same* OpenShell runtime we already use, not a competing sandbox. No documented
`nemoclaw run -- <cmd>` passthrough was found in the CLI commands reference; the real integration
path is that each supported "agent runtime" needs its own NemoClaw-specific adapter/wrapper/plugin
before NemoClaw will drive it, which is undocumented in format and not a drop-in subprocess call.
Less authoritative third-party sources also describe a tool-call-intercepting policy layer, which
would mean touching tool-calling semantics if true. **Verdict: ambiguous, leaning bad-fit —
bailing per the doc's own rule, reporting back for go/no-go instead of guessing at an undocumented
adapter.**

**Update after user said try it anyway (worktree `feature/nemoclaw-wrapper` off origin/main,
created clean):** pulled the actual published `nemoclaw@0.1.0` from the npm registry and
inspected its tarball directly. It is an **empty placeholder package** — a bare `package.json`,
no `index.js`, no code, nothing to run. The richer "NVIDIA NemoClaw" architecture (blueprint
system, onboarding CLI, docs.nvidia.com pages, GitHub repo/stars/issue numbers) that web search
returned does not correspond to this package and could not be independently verified — the
specificity of those results (exact star counts, issue numbers, version strings) matches a known
hallucination pattern for a novel/rare search term rather than confirmed fact. Did not attempt
`npm install -g git+https://github.com/NVIDIA/NemoClaw.git` — installing/running an unverified
third-party repo globally on this machine isn't a call to make on search-result plausibility
alone. **Bailing for real this time: there's currently nothing functional to wrap.** No files
outside this doc were touched; worktree left as a clean checkout of origin/main plus this note.

## Repo rules (same as the rest of the project)
- Commit as Kevin Jiang <kevin.jiang53@gmail.com>. No `Co-Authored-By` / "Generated with" trailers.
- Work on a branch/worktree off `origin/main`; `git pull --rebase` before pushing; never
  force-push.
- Third-party code goes under a gitignored path; don't commit it.
