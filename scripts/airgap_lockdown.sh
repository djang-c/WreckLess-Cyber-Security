#!/usr/bin/env bash
# Block egress to cloud LLM APIs only; loopback (local vLLM) and Slack stay up.
# Usage: sudo scripts/airgap_lockdown.sh [on|off|status]
set -euo pipefail
CHAIN=WRECKLESS_AIRGAP
DOMAINS=(api.openai.com api.anthropic.com generativelanguage.googleapis.com
         api.mistral.ai api.cohere.com api.together.xyz api.groq.com openrouter.ai)

on() {
  iptables -N "$CHAIN" 2>/dev/null || iptables -F "$CHAIN"
  iptables -C OUTPUT -j "$CHAIN" 2>/dev/null || iptables -I OUTPUT 1 -j "$CHAIN"
  for d in "${DOMAINS[@]}"; do
    for ip in $(getent ahostsv4 "$d" | awk '{print $1}' | sort -u); do
      iptables -A "$CHAIN" -d "$ip" -p tcp -j REJECT --reject-with tcp-reset
      echo -e "\033[1;31m  ✗ BLOCKED\033[0m $d ($ip)"
    done
  done
  echo -e "\033[1;32m  ✓ loopback / local vLLM :8000-8002 and Slack remain reachable\033[0m"
}

off() {
  iptables -D OUTPUT -j "$CHAIN" 2>/dev/null || true
  iptables -F "$CHAIN" 2>/dev/null || true
  iptables -X "$CHAIN" 2>/dev/null || true
  echo "airgap rules removed"
}

status() {
  iptables -L "$CHAIN" -n 2>/dev/null || echo "airgap off"
  for d in api.openai.com api.anthropic.com; do
    if curl -s -m 3 -o /dev/null "https://$d"; then echo "  $d: REACHABLE"; else echo "  $d: blocked"; fi
  done
}

[[ $EUID -eq 0 ]] || { echo "run with sudo"; exit 1; }
"${1:-on}"
