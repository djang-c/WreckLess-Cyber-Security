# Knowledge, Intel Feeds & Learning

_Status: **Purple feeds + intel DB are built** (`wreckless/feeds.py`, `wreckless/kb.py`, `wreckless intel …`).
Red/Blue retrieval and fine-tuning are agreed direction, not yet implemented._

```bash
uv run wreckless intel sync            # live: OSV + GitHub + CISA KEV → runs/intel.db (run before going airgapped)
uv run wreckless intel list            # inventory-matched advisories, KEV first, then severity
uv run wreckless intel search "PALChain __import__"
uv run wreckless intel show CVE-2024-27444
```

First real sync for `langchain-experimental==0.0.14` (`targets/victim_app/inventory.json`): OSV and GitHub
returned 10 entries (GHSA + PYSEC ids for the same bugs) that dedupe to **4 CVEs**: the two benchmarked
ones (21513, 44467) plus **CVE-2024-27444** (PALChain bypass) and **CVE-2024-38459** (Python REPL),
which Purple found on its own. In the daemon, Purple queues benchmark bundles first, then feed matches.

## TL;DR

| Role | Gets | How |
|---|---|---|
| 🕵️ **Purple** | Target's **dependency inventory** + advisories for **those** packages | Feed pollers with cursors → filter by deps → dedupe → enqueue |
| 🎩 **Red** | Technique cards + its own **gate-verified** exploits + the target's sink map | Retrieval (no fine-tune yet) |
| 👷 **Blue** | Diffs of **similar** fixes (never the current CVE's upstream fix) + the target repo's dev/PR rules | Retrieval, plus repo linters added to validation |
| 🤖 **Victim** | Nothing | Must stay naive |

Results flow back: every gate-VERIFIED exploit and every validated patch is added to Red's and Blue's memory, and becomes fine-tuning data later.

---

## Purple: polling, not a fixed timer

None of the feeds push (NVD and the global GitHub advisory DB have no webhooks), so "continuous" means
polling each source with a **since-cursor**. Polls are cheap HTTP; the LLM runs only on new, relevant items.

| Source | Signal | Cadence | Notes |
|---|---|---|---|
| GitHub Advisories (`gh api /advisories?ecosystem=pip&affects=<pkg>`) | Package advisories, often before NVD | 5–15 min | Needs `GITHUB_TOKEN` (unauthenticated limit already hit) |
| OSV.dev (`/v1/query`) | Aggregated, exact affected versions | 15 min | No key; best for dependency matching |
| NVD API 2.0 (`lastModStartDate`) | Canonical CVE + CVSS | ~2 h | Strict rate limits without a key; don't poll aggressively |
| CISA KEV (JSON) | Exploited in the wild | daily | Priority flag: KEV matches jump the queue |
| Upstream commits/issues of watched deps | Fixes landing before a CVE exists | 15–30 min | Noisy; always PREDICTION, the gate filters |

Pipeline: `poller(cursor) → match dependency inventory → dedupe by CVE/GHSA id → LLM write-up → enqueue PREDICTION`.
Built: OSV, GitHub Advisories (token from `GITHUB_TOKEN` or `gh auth token`), CISA KEV. Not yet: NVD, upstream commit watching.
Pause during the hero beat, like Red-hunt. Skipped on purpose: social media, blogs, mailing lists (noisy; KEV covers "exploited").

**Pitch hook:** the upstream-commit watcher can "catch the fix before the CVE". LangChain `7b13292`
("Remove python eval from vector sql db chain") landed Sept 2023, long before CVE-2024-21513 was assigned.

## Red: better at breaking things, via retrieval

- **Technique cards:** CWE-94/95 patterns, Python dunder-chain escapes, denylist bypasses.
- **Own verified exploits** from earlier runs as few-shot examples.
- **Target sink map:** where user or LLM-controlled data reaches eval/exec/pickle/subprocess.

Knowledge only makes Red faster. It can never make Red "verify" itself: the gate stays the judge.

## Blue: fix patterns + the target's rules

- **Similar-fix diffs.** **Leakage rule:** exclude the upstream fix for the CVE being patched, or
  "Blue never saw the maintainer's code" stops being true. Enforce it in retrieval and test it.
- **Target repo conventions:** `CONTRIBUTING.md`, PR template, `CODEOWNERS`, lint/format config
  (ruff, mypy…), test layout, commit message style.
- Add the repo's linters to validation so "Fix branch ready" means mergeable.

## Storage: SQLite FTS5 first

Lookups are mostly exact (CVE id, package name) and the corpus is small, so use SQLite FTS5 (BM25) first.
No embedding model and no GPU memory. Add a small embedding model only if semantic recall is
actually needed.

## Data to pull (bulk downloads, not crawling)

1. **OSV PyPI dump** (single zip), filtered to the AI-agent ecosystem (langchain*, langflow,
   llama-index, crewai, autogen…). CC-BY 4.0.
2. **Fix diffs** for those advisories via `gh api` → Blue corpus (with the leakage rule).
3. **MITRE CWE list** + **CISA KEV** → Red technique cards and Purple's priority flag.

## Fine-tuning: later, from our own data

Not during the hackathon. The bottleneck is following the contract and tool format, which prompts,
few-shot examples and sandbox feedback fix faster. A LoRA on a 4-bit MoE risks breaking tool calling.

After the event, the verify gate acts as a **verifiable reward**. Overnight swarm runs produce labelled
data: verified exploits for Red, patches that pass all three checks for Blue. Use rejection-sampling
SFT on those trajectories (and RL with the gate as reward later).
Roadmap line: *"WreckLess learns from its own verified results."*
