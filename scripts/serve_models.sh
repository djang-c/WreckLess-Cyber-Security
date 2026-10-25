#!/usr/bin/env bash
# Launch the 3-port swarm (see wreckless-gb10-plan.md). Biggest model first.
#   8001 Blue   Qwen3-Coder-Next 80B-A3B   (fallback: Qwen2.5-Coder-32B-AWQ with BLUE_FALLBACK=1)
#   8000 Purple+Red  Qwen3-Coder-30B-A3B
#   8002 Victim Qwen2.5-Coder-7B
# Quantization is auto-detected: the cyankiwi repos are compressed-tensors (pack-quantized),
# so do NOT force --quantization awq_marlin; vLLM still selects Marlin kernels.
# Usage: scripts/serve_models.sh [all|blue|red|victim]   ·   stop: pkill -f "vllm serve"
set -euo pipefail
cd "$(dirname "$0")/.."
VLLM=${VLLM:-.venv-vllm/bin/vllm}
EXTRA=${VLLM_EXTRA:-}   # e.g. VLLM_EXTRA=--enforce-eager if CUDA graphs misbehave on sm_121
mkdir -p logs

serve() {  # name port model util [extra...]
  local name=$1 port=$2 model=$3 util=$4; shift 4
  echo "[$(date +%T)] starting $name on :$port ($model, util=$util)"
  nohup "$VLLM" serve "models/$model" --served-model-name "$name" \
    --host 127.0.0.1 --port "$port" \
    --gpu-memory-utilization "$util" \
    --max-model-len 16384 --max-num-seqs 4 --kv-cache-dtype fp8 \
    --enable-auto-tool-choice "$@" $EXTRA > "logs/vllm_$name.log" 2>&1 &
  for _ in $(seq 1 180); do
    curl -sf "http://127.0.0.1:$port/v1/models" >/dev/null && { echo "  $name ready"; return; }
    kill -0 $! 2>/dev/null || { echo "  $name DIED — see logs/vllm_$name.log"; tail -20 "logs/vllm_$name.log"; exit 1; }
    sleep 5
  done
  echo "  $name timed out"; exit 1
}

target=${1:-all}
if [[ $target == all || $target == blue ]]; then
  if [[ ${BLUE_FALLBACK:-0} == 1 ]]; then
    serve blue 8001 Qwen2.5-Coder-32B-Instruct-AWQ 0.30 --tool-call-parser hermes
  else
    serve blue 8001 Qwen3-Coder-Next-AWQ-4bit 0.40 --tool-call-parser qwen3_coder
  fi
fi
[[ $target == all || $target == red ]] && serve red 8000 Qwen3-Coder-30B-A3B-Instruct-AWQ-4bit 0.20 --tool-call-parser qwen3_coder
[[ $target == all || $target == victim ]] && serve victim 8002 Qwen2.5-Coder-7B-Instruct-AWQ 0.08 --tool-call-parser hermes
nvidia-smi --query-gpu=memory.used --format=csv 2>/dev/null || true
free -g | head -2
