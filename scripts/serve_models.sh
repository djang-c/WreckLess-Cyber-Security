#!/usr/bin/env bash
# Launch the 3-port swarm (see docs/gb10-plan.md). Biggest model first. Models, ports, served
# names, memory share and tool parsers come from scripts/models.tsv:
#   8001 Blue   Qwen3-Coder-Next 80B-A3B   (fallback: Qwen2.5-Coder-32B-AWQ with BLUE_FALLBACK=1)
#   8000 Purple+Red  Qwen3-Coder-30B-A3B
#   8002 Victim Qwen2.5-Coder-7B
# Quantization is auto-detected: the cyankiwi repos are compressed-tensors (pack-quantized),
# so do NOT force --quantization awq_marlin; vLLM still selects Marlin kernels.
# Usage: scripts/serve_models.sh [all|blue|red|victim]
#   runtime: VLLM_RUNTIME=docker (NGC image, default when present) | pip (.venv-vllm)
#   stop:    scripts/serve_models.sh stop
set -euo pipefail
cd "$(dirname "$0")/.."
VLLM=${VLLM:-.venv-vllm/bin/vllm}
# TODO: pin by digest once pulled (VLLM_IMAGE=nvcr.io/nvidia/vllm@sha256:... works today)
IMAGE=${VLLM_IMAGE:-nvcr.io/nvidia/vllm:26.09-py3}
EXTRA=${VLLM_EXTRA:-}   # e.g. VLLM_EXTRA=--enforce-eager if CUDA graphs misbehave on sm_121
mkdir -p logs

if id -nG | grep -qw docker; then D() { "$@"; }; else D() { sg docker -c "$(printf '%q ' "$@")"; }; fi
if [[ -z ${VLLM_RUNTIME:-} ]]; then
  if D docker image inspect "$IMAGE" >/dev/null 2>&1; then VLLM_RUNTIME=docker; else VLLM_RUNTIME=pip; fi
fi

# Triton JIT-compiles a C helper against Python.h at startup. Without python3.12-dev installed
# (needs root), unpack the matching headers into the venv instead: apt-get download needs no root.
if [[ $VLLM_RUNTIME == pip && ! -f /usr/include/python3.12/Python.h ]]; then
  SYSROOT=$PWD/.venv-vllm/sysroot
  if [[ ! -f $SYSROOT/usr/include/python3.12/Python.h ]]; then
    tmp=$(mktemp -d); (cd "$tmp" && apt-get download -q python3.12-dev libpython3.12-dev >/dev/null)
    for f in "$tmp"/*.deb; do dpkg-deb -x "$f" "$SYSROOT"; done; rm -rf "$tmp"
  fi
  export CPATH=$SYSROOT/usr/include/python3.12:$SYSROOT/usr/include${CPATH:+:$CPATH}
fi
# JIT kernel builds (flashinfer, torch extensions) call `ninja`, installed in the venv
[[ $VLLM_RUNTIME == pip ]] && export PATH=$PWD/.venv-vllm/bin:$PATH

if [[ ${1:-} == stop ]]; then
  # only our servers: pidfiles from the pip runtime, our containers, our log followers
  for n in blue red victim; do
    if [[ -f logs/vllm_$n.pid ]]; then kill "$(cat "logs/vllm_$n.pid")" 2>/dev/null || true; rm -f "logs/vllm_$n.pid"; fi
    D docker rm -f "wl-vllm-$n" >/dev/null 2>&1 || true
    pkill -f "docker logs -f wl-vllm-$n\$" 2>/dev/null || true
  done
  echo "stopped"; exit 0
fi

# model <role>: "port names util parser dir" from scripts/models.tsv
model() {
  awk -v r="$1" '$1 == r {n = split($6, a, "/"); print $2, $3, $4, $5, a[n]; f = 1} END {exit !f}' scripts/models.tsv \
    || { echo "no role $1 in scripts/models.tsv" >&2; exit 1; }
}

serve() {  # name role (row of scripts/models.tsv)
  local name=$1 port names util parser model
  read -r port names util parser model < <(model "$2")
  # shellcheck disable=SC2206  # EXTRA is a flag list on purpose
  local args=(--served-model-name ${names//,/ } --host 127.0.0.1 --port "$port"
              --gpu-memory-utilization "$util"
              --max-model-len 16384 --max-num-seqs 4 --kv-cache-dtype fp8
              --enable-auto-tool-choice --tool-call-parser "$parser" $EXTRA)
  echo "[$(date +%T)] starting $name on :$port ($model, util=$util, $VLLM_RUNTIME)"
  if [[ $VLLM_RUNTIME == docker ]]; then
    D docker rm -f "wl-vllm-$name" >/dev/null 2>&1 || true
    D docker run -d --name "wl-vllm-$name" --gpus all --ipc=host --network host \
      -v "$PWD/models:/models:ro" "$IMAGE" vllm serve "/models/$model" "${args[@]}" >/dev/null
    pkill -f "docker logs -f wl-vllm-$name\$" 2>/dev/null || true   # one follower per container
    (D docker logs -f "wl-vllm-$name" > "logs/vllm_$name.log" 2>&1 &)
    alive() { [[ $(D docker inspect -f '{{.State.Running}}' "wl-vllm-$name" 2>/dev/null) == true ]]; }
  else
    nohup "$VLLM" serve "models/$model" "${args[@]}" > "logs/vllm_$name.log" 2>&1 &
    local pid=$!
    echo "$pid" > "logs/vllm_$name.pid"
    alive() { kill -0 "$pid" 2>/dev/null; }
  fi
  for _ in $(seq 1 240); do
    curl -sf "http://127.0.0.1:$port/v1/models" >/dev/null && { echo "  $name ready"; return; }
    alive || { echo "  $name DIED — see logs/vllm_$name.log"; tail -20 "logs/vllm_$name.log"; exit 1; }
    sleep 5
  done
  echo "  $name timed out"; exit 1
}

target=${1:-all}
if [[ $target == all || $target == blue ]]; then
  if [[ ${BLUE_FALLBACK:-0} == 1 ]]; then serve blue blue-fallback; else serve blue blue; fi
fi
if [[ $target == all || $target == red ]]; then serve red red; fi
if [[ $target == all || $target == victim ]]; then serve victim victim; fi
nvidia-smi --query-gpu=memory.used --format=csv 2>/dev/null || true
free -g | head -2
