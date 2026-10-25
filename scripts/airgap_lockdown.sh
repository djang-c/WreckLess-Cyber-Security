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
#   env       AIRTIGHT_LAN=0  airtight without the RFC1918/ULA allow (closes the LAN-proxy hole)
#
# Every rule lives in one chain (WRECKLESS_AIRGAP) in iptables and ip6tables, entered by a
# single jump at the top of OUTPUT (and DOCKER-USER, for container egress). `on` builds a
# fresh chain under a temporary name, hooks it in at position 1, retires the old chain, then
# renames the new one: there is no moment without blocking, and re-running yields identical
# rules. It FAILS CLOSED: every domain is resolved before anything changes; if one does not
# resolve, the new chain still gets everything that did resolve PLUS every address the old
# chain blocked, and `on` exits 1. If ip6tables is unusable on a host with a global IPv6
# address, nothing is touched and `on` exits 1.
#
# Not covered by a block-list: an HTTP(S) proxy. With HTTPS_PROXY pointing at a LAN host, the
# connection goes to the proxy (allowed: RFC1918 in airtight, anything in `on`) and the proxy
# reaches the API. Unset proxies on the box, or use `airtight` with AIRTIGHT_LAN=0. `verify`
# probes through any proxy set in its environment, so such a bypass shows up as FAIL there.
# Linux only (iptables, getent). Do not run on a dev Mac.
set -euo pipefail
CHAIN=WRECKLESS_AIRGAP
NEW="${CHAIN}_$$"   # build name, renamed to $CHAIN once hooked in (iptables names <= 28 chars)
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

has_global_v6() {  # a non-loopback global IPv6 address AND a default route to use it
  [[ -r /proc/net/if_inet6 ]] && awk '$4 == "00" && $6 != "lo" {f=1} END {exit !f}' /proc/net/if_inet6 &&
    [[ -n $(ip -6 route show default 2>/dev/null) ]]
}

docker_present() { command -v docker >/dev/null 2>&1 || [[ -S /var/run/docker.sock ]]; }

# Docker creates DOCKER-USER (and FORWARD -> DOCKER-USER) when its daemon starts and keeps an
# existing one, so creating it ourselves means containers started AFTER `on` are covered too.
ensure_docker_user() {
  local ipt=$1
  docker_present || return 0
  if [[ $DRY_RUN -eq 1 ]]; then
    echo "+ $ipt -N DOCKER-USER 2>/dev/null; $ipt -C FORWARD -j DOCKER-USER || $ipt -I FORWARD 1 -j DOCKER-USER"
    return 0
  fi
  "$ipt" -S DOCKER-USER >/dev/null 2>&1 || "$ipt" -N DOCKER-USER
  "$ipt" -C FORWARD -j DOCKER-USER 2>/dev/null || "$ipt" -I FORWARD 1 -j DOCKER-USER
}

# our_chains <ipt>: the live chain plus any build chain an interrupted run left behind
our_chains() {
  "$1" -S 2>/dev/null | awk -v c="$CHAIN" '$1 == "-N" && ($2 == c || $2 ~ ("^" c "_[0-9]+$")) {print $2}'
}

# drop_chain <ipt> <chain>: unhook from every hook, flush, delete
drop_chain() {
  local ipt=$1 c=$2 hook
  for hook in "${HOOKS[@]}"; do
    while "$ipt" -D "$hook" -j "$c" 2>/dev/null; do :; done
  done
  "$ipt" -F "$c" 2>/dev/null || true
  "$ipt" -X "$c" 2>/dev/null || true
}

# old_rejects <ipt>: destinations the installed chain(s) REJECT (fail-closed carry-over)
old_rejects() {
  local c
  for c in $(our_chains "$1"); do
    "$1" -S "$c" 2>/dev/null | awk '/ -j REJECT/ {for (i = 1; i < NF; i++) if ($i == "-d") print $(i+1)}'
  done | sed -E 's#/(32|128)$##' | sort -u
}

declare -A RES4=() RES6=()
UNRESOLVED=()
# resolve_all: resolve every blocked domain up front, before any rule changes
resolve_all() {
  local d v6=0
  if has_global_v6; then v6=1; fi
  for d in "${DOMAINS[@]}"; do
    RES4[$d]=$(resolve "$d" 4 | tr '\n' ' ')
    RES6[$d]=$(resolve "$d" 6 | tr '\n' ' ')
    if [[ -z ${RES4[$d]// /} ]]; then
      UNRESOLVED+=("$d"); red "  ! $d did not resolve (A): NOT blocked by IP"
    elif [[ $v6 -eq 1 && -z ${RES6[$d]// /} ]]; then
      yellow "  ! $d has no AAAA record: not reachable by name over IPv6, nothing to block there"
    fi
  done
}

# block_rules <ipt> <4|6>: REJECT (fast fail, no timeout) every LLM address
block_rules() {
  local ipt=$1 fam=$2 d ip ips
  local -a statics seen=()
  if [[ $fam == 4 ]]; then statics=("${STATIC_V4[@]}"); else statics=("${STATIC_V6[@]}"); fi
  for ip in "${statics[@]}"; do
    seen+=("$ip")
    run "$ipt" -A "$NEW" -d "$ip" -p tcp -j REJECT --reject-with tcp-reset
    run "$ipt" -A "$NEW" -d "$ip" -j REJECT
    red "  ✗ BLOCKED anthropic published range ($ip)"
  done
  for d in "${DOMAINS[@]}"; do
    if [[ $fam == 4 ]]; then ips=${RES4[$d]}; else ips=${RES6[$d]}; fi
    for ip in $ips; do
      [[ " ${seen[*]} " == *" $ip "* ]] && continue   # dedupe shared CDN IPs
      seen+=("$ip")
      run "$ipt" -A "$NEW" -d "$ip" -p tcp -j REJECT --reject-with tcp-reset
      run "$ipt" -A "$NEW" -d "$ip" -j REJECT
      red "  ✗ BLOCKED $d ($ip)"
    done
  done
  # fail closed: something did not resolve, so never block less than the old chain did
  if [[ ${#UNRESOLVED[@]} -gt 0 && $DRY_RUN -eq 0 ]]; then
    for ip in $(old_rejects "$ipt"); do
      [[ " ${seen[*]} " == *" $ip "* ]] && continue
      seen+=("$ip")
      run "$ipt" -A "$NEW" -d "$ip" -p tcp -j REJECT --reject-with tcp-reset
      run "$ipt" -A "$NEW" -d "$ip" -j REJECT
      red "  ✗ BLOCKED (kept from previous chain) $ip"
    done
  fi
}

# allow_rules <ipt> <4|6>: airtight allow-list + final default deny
allow_rules() {
  local ipt=$1 fam=$2 h ip ips net
  local -a nets
  if [[ $fam == 4 ]]; then nets=("${LOCAL_V4[@]}"); else nets=("${LOCAL_V6[@]}"); fi
  run "$ipt" -A "$NEW" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
  # IPv6 neighbour discovery / PMTU rides on ICMPv6; denying it breaks v6 entirely.
  if [[ $fam == 6 ]]; then run "$ipt" -A "$NEW" -p ipv6-icmp -j ACCEPT; fi
  if [[ ${AIRTIGHT_LAN:-1} == 1 ]]; then
    # NOTE: this also allows any HTTP(S) proxy on the LAN, which can relay to the cloud APIs.
    for net in "${nets[@]}"; do run "$ipt" -A "$NEW" -d "$net" -j ACCEPT; done
  else
    yellow "  ! AIRTIGHT_LAN=0: LAN (RFC1918/ULA) egress denied except DNS"
  fi
  run "$ipt" -A "$NEW" -p udp --dport 53 -j ACCEPT
  run "$ipt" -A "$NEW" -p tcp --dport 53 -j ACCEPT
  for h in "${SLACK_HOSTS[@]}"; do
    ips=$(resolve "$h" "$fam")
    [[ -n $ips || $fam == 6 ]] || yellow "  ! $h did not resolve: Slack may be blocked (fails closed)"
    for ip in $ips; do
      run "$ipt" -A "$NEW" -d "$ip" -p tcp --dport 443 -j ACCEPT
      green "  ✓ ALLOWED $h ($ip)"
    done
  done
  run "$ipt" -A "$NEW" -j REJECT
}

# swap_in <ipt>: hook the fully built $NEW in first, then retire the old chain(s) and rename.
# Blocking never lapses: the old chain stays hooked until the new one already is.
swap_in() {
  local ipt=$1 hook c
  ensure_docker_user "$ipt"
  if [[ $DRY_RUN -eq 1 ]]; then
    for hook in "${HOOKS[@]}"; do echo "+ $ipt -I $hook 1 -j $NEW  # if $hook exists"; done
    echo "+ (unhook, flush and delete the old $CHAIN)"
    echo "+ $ipt -E $NEW $CHAIN"
    return 0
  fi
  for hook in "${HOOKS[@]}"; do
    "$ipt" -S "$hook" >/dev/null 2>&1 || continue   # DOCKER-USER only exists with Docker
    "$ipt" -I "$hook" 1 -j "$NEW"
  done
  for c in $(our_chains "$ipt"); do
    [[ $c == "$NEW" ]] || drop_chain "$ipt" "$c"
  done
  "$ipt" -E "$NEW" "$CHAIN" || { red "  ! could not rename $NEW to $CHAIN (rules ARE active under $NEW)"; return 1; }
}

# apply <airtight 0|1>
apply() {
  local tight=$1 ipt fam rc=0
  if [[ -z $IPT6 ]]; then
    if has_global_v6; then
      red "  ✗ ip6tables unusable but this host has a global IPv6 address: IPv6 egress would be"
      red "    unfiltered. Nothing changed. Fix ip6tables (or set IP6TABLES=) and re-run."
      exit 1
    fi
    yellow "  ! ip6tables unavailable; no global IPv6 address here, so IPv4-only filtering"
  fi
  resolve_all
  for fam in 4 6; do
    if [[ $fam == 4 ]]; then ipt=$IPT4; else ipt=$IPT6; fi
    [[ -n $ipt ]] || continue
    if [[ $DRY_RUN -eq 1 ]]; then echo "+ $ipt -N $NEW"; else "$ipt" -N "$NEW"; fi
    run "$ipt" -A "$NEW" -o lo -j ACCEPT        # local vLLM :8000-8002 always first
    block_rules "$ipt" "$fam"
    if [[ $tight -eq 1 ]]; then allow_rules "$ipt" "$fam"; fi
    swap_in "$ipt" || rc=1
  done
  if [[ ${#UNRESOLVED[@]} -gt 0 ]]; then
    red "  ✗ FAIL CLOSED: could not resolve ${UNRESOLVED[*]}."
    red "    Applied every address that did resolve and kept every address previously blocked."
    red "    Fix DNS and re-run; do not claim the airgap until \`verify\` passes."
    exit 1
  fi
  green "  ✓ loopback / local vLLM :8000-8002 and Slack remain reachable (IPv4 + IPv6)"
  return "$rc"
}

on() { apply 0; }

airtight() {
  yellow "  ! AIRTIGHT: default-deny OUTPUT. Slack IPs are resolved NOW and shift over time;"
  yellow "    re-run right before stage. Block-list \`on\` is the stage default."
  apply 1
}

off() {
  local ipt c
  for ipt in "$IPT4" "$IPT6"; do
    [[ -n $ipt ]] || continue
    for c in $(our_chains "$ipt"); do drop_chain "$ipt" "$c"; done
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

# reject_hits <4|6>: packets our chain's REJECT rules have matched (root only; "" if unknown)
reject_hits() {
  local ipt
  if [[ $1 == 4 ]]; then ipt=$IPT4; else ipt=$IPT6; fi
  [[ $EUID -eq 0 && -n $ipt ]] || return 0
  "$ipt" -L "$CHAIN" -v -x -n 2>/dev/null | awk '$3 == "REJECT" {s += $1} END {if (NR) print s + 0}'
}

# uncovered <4|6> <ip>...: print the IPs no REJECT rule in our chain covers (root only)
uncovered() {
  local fam=$1 ipt dests ip; shift
  if [[ $fam == 4 ]]; then ipt=$IPT4; else ipt=$IPT6; fi
  dests=$("$ipt" -S "$CHAIN" 2>/dev/null | awk '/ -j REJECT/ {for (i = 1; i < NF; i++) if ($i == "-d") print $(i+1)}')
  if command -v python3 >/dev/null 2>&1; then
    python3 - "$dests" "$@" <<'PY'
import ipaddress, sys
nets = [ipaddress.ip_network(n, strict=False) for n in sys.argv[1].split()]
for a in sys.argv[2:]:
    ip = ipaddress.ip_address(a)
    if not any(ip.version == n.version and ip in n for n in nets):
        print(a)
PY
  else
    for ip in "$@"; do grep -qxF -e "$ip/32" -e "$ip/128" <<<"$dests" || echo "$ip"; done
  fi
}

verify() {
  local fails=0 rc t0 dt code body host fam err h0 h1 ipt ips miss
  local -a rows=()
  local v6=0
  if has_global_v6; then v6=1; fi
  [[ $EUID -eq 0 ]] && init_backends
  for host in "${DOMAINS[@]}"; do
    for fam in 4 6; do
      if [[ $fam == 6 && $v6 -eq 0 ]]; then
        rows+=("$host (v6) blocked|SKIP|no global IPv6 address on this host"); continue
      fi
      ips=$(resolve "$host" "$fam" | tr '\n' ' ')
      if [[ $fam == 6 && -z ${ips// /} ]]; then
        rows+=("$host (v6) blocked|SKIP|no AAAA record"); continue
      fi
      # Only a fast TCP reset proves our REJECT fired. DNS failure (6), no route,
      # TLS/proxy errors or timeouts say nothing about the firewall, so they FAIL.
      # As root the proof is our REJECT counter going up. Without root we fall back to
      # curl's message, whose wording varies (7.88: "Couldn't connect to server").
      rc=0; h0=$(reject_hits "$fam"); t0=$(now_ms)
      err=$(curl -"$fam" -s -o /dev/null -w '%{errormsg}' --max-time 4 "https://$host/" 2>/dev/null) || rc=$?
      dt=$(( $(now_ms) - t0 )); h1=$(reject_hits "$fam")
      if [[ $rc -eq 7 && $dt -le 3000 && -n $h0 && -n $h1 ]] && (( h1 > h0 )); then
        rows+=("$host (v$fam) blocked|PASS|our REJECT hit +$((h1 - h0)) pkt, reset in ${dt} ms")
      elif [[ $rc -eq 7 && $dt -le 3000 && -n $h0 ]]; then
        rows+=("$host (v$fam) blocked|FAIL|refused, but not by our chain (counter unchanged)"); fails=$((fails+1))
      elif [[ $rc -eq 7 && $dt -le 3000 && ( $err == *refused* || $err == *"Couldn't connect to server"* ) ]]; then
        rows+=("$host (v$fam) blocked|PASS|reset in ${dt} ms (run as root to check our counter)")
      elif [[ $rc -ne 0 ]]; then
        rows+=("$host (v$fam) blocked|FAIL|curl exit $rc ${err:0:40} (not our reject)"); fails=$((fails+1))
      else
        rows+=("$host (v$fam) blocked|FAIL|REACHABLE in ${dt} ms"); fails=$((fails+1))
      fi
      # stale IPs: DNS moved since `on` ran; curl may have hit a still-blocked address
      if [[ $EUID -ne 0 ]]; then continue; fi
      if [[ $fam == 4 ]]; then ipt=$IPT4; else ipt=$IPT6; fi
      if [[ -z $ipt ]] || ! "$ipt" -S "$CHAIN" >/dev/null 2>&1; then continue; fi
      # shellcheck disable=SC2086  # word-split the address list on purpose
      miss=$(uncovered "$fam" $ips | tr '\n' ' ')
      if [[ -n ${miss// /} ]]; then
        if "$ipt" -S "$CHAIN" | grep -qx -- "-A $CHAIN -j REJECT"; then
          rows+=("$host (v$fam) IPs in chain|INFO|not listed, but default-deny covers: ${miss:0:40}")
        else
          rows+=("$host (v$fam) IPs in chain|FAIL|stale chain, re-run on: ${miss:0:40}"); fails=$((fails+1))
        fi
      fi
    done
  done
  if [[ $EUID -ne 0 ]]; then
    rows+=("stale-IP check|SKIP|run as root to compare fresh DNS with the chain")
  fi
  # containers egress via FORWARD -> DOCKER-USER, not OUTPUT
  if docker_present; then
    if [[ $EUID -ne 0 ]]; then rows+=("DOCKER-USER hooked|SKIP|run as root to check")
    else
      for ipt in "$IPT4" "$IPT6"; do
        [[ -n $ipt ]] || continue
        if "$ipt" -C DOCKER-USER -j "$CHAIN" 2>/dev/null; then rows+=("DOCKER-USER hooked ($ipt)|PASS|container egress filtered")
        else rows+=("DOCKER-USER hooked ($ipt)|FAIL|containers bypass the airgap; re-run on"); fails=$((fails+1)); fi
      done
    fi
  fi
  local p
  for p in HTTPS_PROXY https_proxy ALL_PROXY all_proxy; do
    if [[ -n ${!p:-} ]]; then
      rows+=("$p set|INFO|probes went via ${!p:0:40}; a proxy can relay past the block-list")
    fi
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

  printf '%-48s %-5s %s\n' CHECK RES DETAIL
  printf '%-48s %-5s %s\n' "------------------------------------------------" "-----" "------"
  local r a b c
  for r in "${rows[@]}"; do
    IFS='|' read -r a b c <<<"$r"
    case $b in PASS) b=$'\033[1;32mPASS \033[0m' ;; FAIL) b=$'\033[1;31mFAIL \033[0m' ;; *) b=$(printf '%-5s' "$b") ;; esac
    printf '%-48s %s %s\n' "$a" "$b" "$c"
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
  -h|--help|help) sed -n '2,/^set -euo/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//' ;;
  *) echo "usage: $0 [on|off|airtight|status|verify|dry-run [airtight]]" >&2; exit 2 ;;
esac
