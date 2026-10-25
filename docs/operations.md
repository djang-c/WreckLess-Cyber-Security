# Operations

Running WreckLess on the GB10 day to day. The README covers what it is; this covers keeping it up.

## 1. Model servers (vLLM)

`scripts/models.tsv` is the one list of models: repo, pinned revision, port, served name(s),
memory share and tool parser. `download_models.sh` and `serve_models.sh` both read it.

```bash
scripts/download_models.sh            # resumes; exits 1 and names any repo that failed
scripts/serve_models.sh               # all three, biggest first: blue :8001, red :8000, victim :8002
scripts/serve_models.sh blue          # or one role
BLUE_FALLBACK=1 scripts/serve_models.sh blue   # 32B dense on :8001, answers to `blue` and `blue-fallback`
scripts/serve_models.sh stop          # only our servers: pidfiles, wl-vllm-* containers, log followers
```

Two runtimes, picked automatically (`VLLM_RUNTIME=docker|pip` to force one):

| Runtime | When | Notes |
|---|---|---|
| `docker` | the NGC image (`VLLM_IMAGE`, default `nvcr.io/nvidia/vllm:26.09-py3`) is present | containers `wl-vllm-<role>`, logs followed into `logs/vllm_<role>.log` |
| `pip` | otherwise | `.venv-vllm/bin/vllm`, built from the pinned `scripts/vllm-requirements.lock` by `scripts/serve_models.sh install`; Python headers unpacked into `.venv-vllm/sysroot` for Triton's JIT (no root) |

Logs: `logs/vllm_<role>.log`. Endpoints are loopback only; override per role with
`WRECKLESS_<ROLE>_URL` / `WRECKLESS_<ROLE>_MODEL` (roles: `RED`, `BLUE`, `BLUE_FALLBACK`, `VICTIM`).

## 2. Throughput and memory

```bash
wreckless metrics                 # one sample; exit 0 if any port is up
wreckless metrics --watch 2       # refresh every 2 s, Ctrl-C to stop
wreckless metrics --json          # one JSON line per sample, for dashboards
```

Per port: tokens/sec (from vLLM's generation counter), KV-cache use, queue depth. Plus the GB10's
unified-memory panel from `/proc/meminfo`.

## 3. The daemon

```bash
wreckless daemon                         # Purple every 10 min (--purple-interval 600), Red hunting, one worker
wreckless daemon --no-hunt               # no background Red passes
wreckless daemon --mode live             # Purple also polls the feeds (needs the network)
wreckless daemon --porter                # + Porter's inner door: records card clicks, answers @mentions
wreckless daemon --slack-listener        # Slack side in this process too (starts the inner door as well)
wreckless status                         # queue summary (same --home)
wreckless replay --item CVE-2024-21513-1 # re-render an item from events.jsonl
```

Everything for one swarm lives under `--home` (default `runs/swarm`): `queue.db`, `events.jsonl`,
`items/<id>/`, `hunts/pass-NNNN/`. A `wreckless run` against the same home takes the hero lock:
the daemon's worker and hunter yield until it finishes, and its item is claimed atomically so no
worker can pick it up. On restart the daemon fails any item left in flight (each in-flight state
has a terminal failure state), so nothing stays stuck.

Intel: `wreckless intel sync` (the one networked command) fills `runs/intel.db`
(`WRECKLESS_INTEL_DB`); airgapped runs read only that cache.

## 4. Slack

Without `SLACK_BOT_TOKEN`+`SLACK_CHANNEL` (or `SLACK_WEBHOOK_URL`), cards go to
`logs/slack_outbox.jsonl`. Buttons and @mentions need both of Porter's doors: the Slack side
`python -m wreckless.slack_socket` (its own process; it never touches a finding) and the inside
`wreckless daemon --porter` (or `python -m wreckless.porter` next to a one-off `run`), which records
clicks and opens the draft PR. `scripts/tmux_demo.sh` starts both. Design: [`porter.md`](porter.md).
Setup: [`slack-setup.md`](slack-setup.md). The listener retries with backoff and logs
"enabled" only once connected.

## 5. Sandbox backend

`WRECKLESS_SANDBOX=auto` (default) uses OpenShell when `openshell status` says Connected,
else the userland guard; force with `openshell` or `userland`. Bring OpenShell up with
`scripts/openshell_up.sh` (builds `wreckless-sandbox:*` images, starts the gateway).
`wreckless run` prints which one it used. With `--agentic` the sandbox is granted one route at
runtime: the victim LLM's loopback port on the host (as `host.openshell.internal`), for `python3.12`
only. The base policy (`sandbox/policy.yaml`) has no network section, so everything else is denied.

## 6. Airgap

```bash
sudo scripts/airgap_lockdown.sh on && scripts/airgap_lockdown.sh verify
```

`on` fails closed (exit 1 if any domain does not resolve) and swaps chains atomically, so
re-running it never opens a gap. It also hooks `DOCKER-USER`, so containers started later
are covered. Run `verify` as root to also check for stale IPs (DNS moved since `on`) and the
Docker hook. Do not claim the airgap until `verify` passes. Proxies are the known hole; see
the header of `scripts/airgap_lockdown.sh`.

The airgap container test is opt-in: `pytest -m airgap tests/airgap` (needs Docker, NET_ADMIN
and internet; it skips if the host's own airgap is already on).

## 7. Installing elsewhere

The code finds `benchmarks/`, `targets/` and `runs/` next to the package. For a non-editable
install, set `WRECKLESS_ROOT` to the checkout. Extras: `.[slack]`, `.[openshell]`, `.[models]`.
