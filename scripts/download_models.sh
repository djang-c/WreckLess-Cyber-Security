#!/usr/bin/env bash
# Pull all swarm models into ./models (victim + red first: smallest, needed earliest)
set -u
cd "$(dirname "$0")/.."
export HF_XET_HIGH_PERFORMANCE=1
HF=.venv/bin/hf
for repo in \
  Qwen/Qwen2.5-Coder-7B-Instruct-AWQ \
  cyankiwi/Qwen3-Coder-30B-A3B-Instruct-AWQ-4bit \
  cyankiwi/Qwen3-Coder-Next-AWQ-4bit \
  Qwen/Qwen2.5-Coder-32B-Instruct-AWQ \
  RedHatAI/NVIDIA-Nemotron-3.5-Lightning-30B-A3B-FP8 ; do
  echo "[$(date +%T)] >>> $repo"
  $HF download "$repo" --local-dir "models/${repo#*/}" || echo "FAILED $repo"
done
echo "[$(date +%T)] ALL DONE"
