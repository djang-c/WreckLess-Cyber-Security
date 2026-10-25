#!/usr/bin/env bash
# Block egress to cloud LLM APIs only; loopback (local vLLM) and Slack stay up.
# Usage: sudo scripts/airgap_lockdown.sh [on|off|airtight]   (default: on)
#             scripts/airgap_lockdown.sh status|verify|dry-run [airtight]   (no root needed)
#
#   on        block-list: REJECT the cloud-LLM APIs over IPv4 AND IPv6 (stage default)
#   off       remove the WRECKLESS_AIRGAP chain + OUTPUT/DOCKER-USER jumps (v4 and v6)
#   airtight  default-deny OUTPUT; allow lo, ESTABLISHED, RFC1918, DNS, Slack only
#   status    show the chain (needs root to list rules) + quick reachability probe
#   verify    PASS/FAIL table, exits non-zero on any FAIL (the on-stage proof)
#   dry-run   print the iptables/ip6tables commands `on` (or `airtight`) would run
#
# Every rule lives in one chain (WRECKLESS_AIRGAP) in iptables and ip6tables, entered
# by a single jump at the top of OUTPUT. `on` creates-or-flushes the chain and only
# inserts the jump if missing, so running it twice yields identical rules.
# Linux only (iptables, getent). Do not run on a dev Mac.
set -euo pipefail
CHAIN=WRECKLESS_AIRGAP
DOMAINS=(api.openai.com api.anthropic.com generativelanguage.googleapis.com
         aiplatform.googleapis.com api.mistral.ai api.cohere.com api.together.xyz
         api.groq.com openrouter.ai api.x.ai api.deepseek.com)
# Anthropic publishes its API inbound ranges (https://platform.claude.com/docs/en/api/ip-addresses);
# blocked statically in addition to DNS. OpenAI publishes none, so it is DNS-resolved at run time.
STATIC_V4=(160.79.104.0/23)
STATIC_V6=(2607:6bc0::/48)
# airtight allow-list (resolved now; Slack IPs shift, so re-run right before going on stage)
SLACK_HOSTS=(slack.com api.slack.com wss-primary.slack.com wss-backup.slack.com)
LOCAL_V4=(10.0.0.0/8 172.16.0.0/12 192.168.0.0/16)
LOCAL_V6=(fc00::/7 fe80::/10)

DRY_RUN=0
IPT4=${IPTABLES:-}
IPT6=${IP6TABLES:-}

red()   { echo -e "\033[1;31m$*\033[0m"; }
green() { echo -e "\033[1;32m$*\033[0m"; }
yellow(){ echo -e "\033[1;33m$*\033[0m"; }

# Pick nft or legacy backend: use whichever can actually list OUTPUT (Docker Desktop
# and some kernels only support one of them). Override with IPTABLES=/IP6TABLES=.
pick_backend() {
  local fam=$1 cand
  for cand in "ip${fam}tables" "ip${fam}tables-nft" "ip${fam}tables-legacy"; do
    if command -v "$cand" >/dev/null 2>&1 && "$cand" -S OUTPUT >/dev/null 2>&1; then
      echo "$cand"; return 0
    fi
  done
  return 1
}
init_backends() {
  local four="" six="6"
  if [[ $DRY_RUN -eq 1 ]]; then IPT4=${IPT4:-iptables}; IPT6=${IPT6:-ip6tables}; return 0; fi
  [[ -n $IPT4 ]] || IPT4=$(pick_backend "$four") || { red "  no working iptables backend"; exit 1; }
  # ip6tables must use the same backend family as iptables (nft vs legacy).
  if [[ -z $IPT6 ]]; then
    IPT6=${IPT4/iptables/ip6tables}
    "$IPT6" -S OUTPUT >/dev/null 2>&1 || IPT6=$(pick_backend "$six") || IPT6=""
  fi
}

run() {
  if [[ $DRY_RUN -eq 1 ]]; then printf '+'; printf ' %q' "$@"; printf '\n'; else "$@"; fi
}

# resolve <host> <4|6>: unique addresses, sinkhole/loopback/mapped filtered out
resolve() {
  local db=ahostsv4 rr=A; [[ $2 == 6 ]] && db=ahostsv6 rr=AAAA
  {
    getent "$db" "$1" 2>/dev/null | awk '{print $1}' || true
    # dig as a second source: some resolvers/libc configs hide AAAA from getent
    if command -v dig >/dev/null 2>&1; then dig +short +time=2 +tries=1 "$rr" "$1" 2>/dev/null || true; fi
  } | if [[ $2 == 6 ]]; then grep ':' || true; else grep -E '^[0-9.]+$' || true; fi |
    grep -v -E '^(0\.0\.0\.0|127\.|::$|::1$|::ffff:)' | sort -u || true
}

# Containers (Docker, OpenShell sandboxes) egress via FORWARD, not OUTPUT. Docker's
# DOCKER-USER chain is the supported hook for that; jump into our chain there too.
HOOKS=(OUTPUT DOCKER-USER)

# reset_chain <ipt>: create the chain or flush it, and make sure exactly one jump exists
reset_chain() {
  local ipt=$1 hook
  if [[ $DRY_RUN -eq 1 ]]; then
    echo "+ $ipt -N $CHAIN 2>/dev/null || $ipt -F $CHAIN"
    for hook in "${HOOKS[@]}"; do
      echo "+ $ipt -C $hook -j $CHAIN 2>/dev/null || $ipt -I $hook 1 -j $CHAIN  # if $hook exists"
    done
    return 0
  fi
  "$ipt" -N "$CHAIN" 2>/dev/null || "$ipt" -F "$CHAIN"
  for hook in "${HOOKS[@]}"; do
    "$ipt" -S "$hook" >/dev/null 2>&1 || continue   # DOCKER-USER only exists with Docker
    "$ipt" -C "$hook" -j "$CHAIN" 2>/dev/null || "$ipt" -I "$hook" 1 -j "$CHAIN"
  done
}

# block_rules <ipt> <4|6>: REJECT (fast fail, no timeout) every LLM address
block_rules() {
  local ipt=$1 fam=$2 d ip
  local -a statics seen=()
  if [[ $fam == 4 ]]; then statics=("${STATIC_V4[@]}"); else statics=("${STATIC_V6[@]}"); fi
  for ip in "${statics[@]}"; do
    run "$ipt" -A "$CHAIN" -d "$ip" -p tcp -j REJECT --reject-with tcp-reset
    run "$ipt" -A "$CHAIN" -d "$ip" -j REJECT
    red "  ✗ BLOCKED anthropic published range ($ip)"
  done
  for d in "${DOMAINS[@]}"; do
    local ips; ips=$(resolve "$d" "$fam")
    [[ -n $ips || $fam == 6 ]] || yellow "  ! $d did not resolve: NOT blocked by IP (check DNS)"
    for ip in $ips; do
      [[ " ${seen[*]:-} " == *" $ip "* ]] && continue   # dedupe shared CDN IPs
      seen+=("$ip")
      run "$ipt" -A "$CHAIN" -d "$ip" -p tcp -j REJECT --reject-with tcp-reset
      run "$ipt" -A "$CHAIN" -d "$ip" -j REJECT
      red "  ✗ BLOCKED $d ($ip)"
    done
  done
}

# allow_rules <ipt> <4|6>: airtight allow-list + final default deny
allow_rules() {
  local ipt=$1 fam=$2 h ip net
  local -a nets
  if [[ $fam == 4 ]]; then nets=("${LOCAL_V4[@]}"); else nets=("${LOCAL_V6[@]}"); fi
  run "$ipt" -A "$CHAIN" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
  # IPv6 neighbour discovery / PMTU rides on ICMPv6; denying it breaks v6 entirely.
  [[ $fam == 6 ]] && run "$ipt" -A "$CHAIN" -p ipv6-icmp -j ACCEPT
  for net in "${nets[@]}"; do run "$ipt" -A "$CHAIN" -d "$net" -j ACCEPT; done
  run "$ipt" -A "$CHAIN" -p udp --dport 53 -j ACCEPT
  run "$ipt" -A "$CHAIN" -p tcp --dport 53 -j ACCEPT
  for h in "${SLACK_HOSTS[@]}"; do
    for ip in $(resolve "$h" "$fam"); do
      run "$ipt" -A "$CHAIN" -d "$ip" -p tcp --dport 443 -j ACCEPT
      green "  ✓ ALLOWED $h ($ip)"
    done
  done
  run "$ipt" -A "$CHAIN" -j REJECT
}

# apply <airtight 0|1>
apply() {
  local tight=$1 ipt fam
  for fam in 4 6; do
    if [[ $fam == 4 ]]; then ipt=$IPT4; else ipt=$IPT6; fi
    if [[ -z $ipt ]]; then
      yellow "  ! ip6tables unavailable: IPv6 egress NOT filtered"; continue
    fi
    reset_chain "$ipt"
    run "$ipt" -A "$CHAIN" -o lo -j ACCEPT        # local vLLM :8000-8002 always first
    block_rules "$ipt" "$fam"
    [[ $tight -eq 1 ]] && allow_rules "$ipt" "$fam"
  done
  green "  ✓ loopback / local vLLM :8000-8002 and Slack remain reachable (IPv4 + IPv6)"
}

on() { apply 0; }

airtight() {
  yellow "  ! AIRTIGHT: default-deny OUTPUT. Slack IPs are resolved NOW and shift over time;"
  yellow "    re-run right before stage. Block-list \`on\` is the stage default."
  apply 1
}

off() {
  local ipt hook
  for ipt in "$IPT4" "$IPT6"; do
    [[ -n $ipt ]] || continue
    for hook in "${HOOKS[@]}"; do
      while "$ipt" -D "$hook" -j "$CHAIN" 2>/dev/null; do :; done
    done
    "$ipt" -F "$CHAIN" 2>/dev/null || true
    "$ipt" -X "$CHAIN" 2>/dev/null || true
  done
  echo "airgap rules removed"
}

status() {
  local ipt
  for ipt in "${IPT4:-iptables}" "${IPT6:-ip6tables}"; do
    if [[ $EUID -ne 0 ]]; then echo "  ($ipt rules: run with sudo to list)"; break; fi
    echo "== $ipt"
    "$ipt" -L "$CHAIN" -n 2>/dev/null || echo "airgap off"
  done
  for d in api.openai.com api.anthropic.com; do
    if curl -s -m 3 -o /dev/null "https://$d"; then echo "  $d: REACHABLE"; else echo "  $d: blocked"; fi
  done
}

now_ms() { python3 -c 'import time; print(int(time.time()*1000))' 2>/dev/null || echo $(( $(date +%s) * 1000 )); }

has_global_v6() {  # a non-loopback global IPv6 address AND a default route to use it
  [[ -r /proc/net/if_inet6 ]] && awk '$4 == "00" && $6 != "lo" {f=1} END {exit !f}' /proc/net/if_inet6 &&
    [[ -n $(ip -6 route show default 2>/dev/null) ]]
}

verify() {
  local fails=0 rc t0 dt code body host fam err
  local -a rows=()
  for host in api.openai.com api.anthropic.com; do
    for fam in 4 6; do
      if [[ $fam == 6 ]] && ! has_global_v6; then
        rows+=("$host (v6) blocked|SKIP|no global IPv6 address on this host"); continue
      fi
      # Only a fast TCP reset proves our REJECT fired. DNS failure (6), no route,
      # TLS/proxy errors or timeouts say nothing about the firewall, so they FAIL.
      rc=0; t0=$(now_ms)
      err=$(curl -"$fam" -s -o /dev/null -w '%{errormsg}' --max-time 4 "https://$host/" 2>/dev/null) || rc=$?
      dt=$(( $(now_ms) - t0 ))
      if [[ $rc -eq 7 && $err == *refused* && $dt -le 3000 ]]; then
        rows+=("$host (v$fam) blocked|PASS|reset in ${dt} ms")
      elif [[ $rc -ne 0 ]]; then
        rows+=("$host (v$fam) blocked|FAIL|curl exit $rc ${err:0:40} (not our reject)"); fails=$((fails+1))
      else
        rows+=("$host (v$fam) blocked|FAIL|REACHABLE in ${dt} ms"); fails=$((fails+1))
      fi
    done
  done
  local port
  for port in 8000 8001 8002; do
    rc=0
    code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 3 "http://127.0.0.1:$port/" 2>/dev/null) || rc=$?
    if [[ $rc -eq 0 ]]; then rows+=("127.0.0.1:$port reachable|PASS|HTTP $code")
    elif [[ $rc -eq 7 ]]; then rows+=("127.0.0.1:$port reachable|INFO|no listener (connection refused)")
    else rows+=("127.0.0.1:$port reachable|FAIL|curl exit $rc"); fails=$((fails+1)); fi
  done
  body=$(curl -s --max-time 10 https://slack.com/api/api.test 2>&1 || true)
  if [[ $body == *'"ok":true'* ]]; then rows+=("slack.com/api/api.test works|PASS|ok:true")
  else rows+=("slack.com/api/api.test works|FAIL|${body:0:50}"); fails=$((fails+1)); fi

  printf '%-34s %-5s %s\n' CHECK RES DETAIL
  printf '%-34s %-5s %s\n' "----------------------------------" "-----" "------"
  local r a b c
  for r in "${rows[@]}"; do
    IFS='|' read -r a b c <<<"$r"
    case $b in PASS) b=$'\033[1;32mPASS \033[0m' ;; FAIL) b=$'\033[1;31mFAIL \033[0m' ;; *) b=$(printf '%-5s' "$b") ;; esac
    printf '%-34s %s %s\n' "$a" "$b" "$c"
  done
  if [[ $fails -eq 0 ]]; then green "AIRGAP VERIFY: PASS"; else red "AIRGAP VERIFY: FAIL ($fails)"; fi
  [[ $fails -eq 0 ]]
}

need_root() { [[ $EUID -eq 0 ]] || { echo "run with sudo"; exit 1; }; }

cmd=${1:-on}
case $cmd in
  on|off|airtight) need_root; init_backends; "$cmd" ;;
  status) [[ $EUID -eq 0 ]] && init_backends; status ;;
  verify) verify ;;
  dry-run) DRY_RUN=1; init_backends; if [[ ${2:-} == airtight ]]; then airtight; else on; fi ;;
  -h|--help|help) sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//' ;;
  *) echo "usage: $0 [on|off|airtight|status|verify|dry-run [airtight]]" >&2; exit 2 ;;
esac
