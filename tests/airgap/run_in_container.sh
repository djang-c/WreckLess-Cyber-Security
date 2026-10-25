#!/usr/bin/env bash
# Host side (default): build the image and run the scenario in a NET_ADMIN container.
# Inside (--inside):   exercise scripts/airgap_lockdown.sh and print RESULT lines.
# The lockdown script only ever runs inside the container, never on the host.
set -euo pipefail

IMAGE="${WRECKLESS_AIRGAP_IMAGE:-wreckless-airgap-test}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
DOCKER="${DOCKER:-docker}"

host_main() {
  "$DOCKER" build -q -t "$IMAGE" "$HERE" >/dev/null
  "$DOCKER" run --rm --cap-add NET_ADMIN -v "$REPO:/repo:ro" "$IMAGE" \
    bash /repo/tests/airgap/run_in_container.sh --inside
}

FAILS=0
result() { # name PASS|FAIL|SKIP detail
  echo "RESULT $1 $2 ${3:-}"
  [[ $2 != FAIL ]] || FAILS=$((FAILS + 1))
}

L=/repo/scripts/airgap_lockdown.sh

# http code via family $2 (000 = not reachable); prints "code exit_status"
probe() {
  local rc=0 code
  code=$(curl -"$2" -s -o /dev/null -w '%{http_code}' --max-time 8 "https://$1/" 2>/dev/null) || rc=$?
  echo "$code $rc"
}

has_v6() { awk '$4 == "00" && $6 != "lo" {f=1} END {exit !f}' /proc/net/if_inet6 2>/dev/null; }

inside_main() {
  local ipt=iptables ip6t=ip6tables
  if ! iptables -S OUTPUT >/dev/null 2>&1; then ipt=iptables-legacy ip6t=ip6tables-legacy; fi
  echo "INFO backend: $($ipt --version) / ip6tables usable: $($ip6t -S OUTPUT >/dev/null 2>&1 && echo yes || echo no)"
  echo "INFO container global IPv6: $(has_v6 && echo yes || echo no)"

  python3 -m http.server 8000 --bind 127.0.0.1 >/dev/null 2>&1 &
  sleep 1

  local p s1 s2 s61 s62 out rc
  p=$(probe api.openai.com 4)
  echo "INFO baseline api.openai.com v4: http/exit=$p"
  [[ ${p%% *} != 000 ]] || result baseline FAIL "api.openai.com unreachable BEFORE lockdown; test invalid"

  # non-root subcommands must work without root
  rc=0; out=$(setpriv --reuid=65534 --regid=65534 --clear-groups bash "$L" dry-run 2>&1) || rc=$?
  if [[ $rc -eq 0 && $out == *"-A WRECKLESS_AIRGAP"* && $out == *ip6tables* ]]; then
    result g_dryrun_nonroot PASS "$(grep -c '^+' <<<"$out") commands printed as uid 65534"
  else result g_dryrun_nonroot FAIL "rc=$rc ${out:0:120}"; fi
  echo "INFO dry-run output:"; sed 's/^/  | /' <<<"$out" | head -n 12

  bash "$L" on
  s1=$($ipt -S WRECKLESS_AIRGAP); s61=$($ip6t -S WRECKLESS_AIRGAP 2>/dev/null || true)
  echo "INFO v4 chain after on:"; sed 's/^/  | /' <<<"$s1"
  echo "INFO v6 chain after on:"; sed 's/^/  | /' <<<"$s61"

  p=$(probe api.openai.com 4)
  [[ ${p%% *} == 000 ]] && result a_openai_blocked_v4 PASS "http/exit=$p" || result a_openai_blocked_v4 FAIL "http/exit=$p"
  if has_v6; then
    p=$(probe api.openai.com 6)
    [[ ${p%% *} == 000 ]] && result a_openai_blocked_v6 PASS "http/exit=$p" || result a_openai_blocked_v6 FAIL "http/exit=$p"
  else
    result a_openai_blocked_v6 SKIP "container has no global IPv6; v6 rules checked structurally in d"
  fi
  [[ $s61 == *"2607:6bc0::/48"* ]] && result a_v6_rules_present PASS "anthropic /48 in ip6tables chain" \
    || result a_v6_rules_present FAIL "v6 chain missing anthropic range"

  p=$(curl -s -o /dev/null -w '%{http_code}' --max-time 3 http://127.0.0.1:8000/ || true)
  [[ $p == 200 ]] && result b_localhost_8000 PASS "http=$p" || result b_localhost_8000 FAIL "http=$p"

  out=$(curl -s --max-time 10 https://slack.com/api/api.test 2>&1 || true)
  [[ $out == *'"ok":true'* ]] && result c_slack PASS "$out" || result c_slack FAIL "${out:0:80}"

  bash "$L" on >/dev/null
  s2=$($ipt -S WRECKLESS_AIRGAP); s62=$($ip6t -S WRECKLESS_AIRGAP 2>/dev/null || true)
  local j4 j6
  j4=$($ipt -S OUTPUT | grep -c -- '-j WRECKLESS_AIRGAP$' || true)
  j6=$($ip6t -S OUTPUT 2>/dev/null | grep -c -- '-j WRECKLESS_AIRGAP$' || true)
  if [[ $s1 == "$s2" && $s61 == "$s62" && $j4 == 1 && $j6 == 1 ]]; then
    result d_idempotent PASS "v4 $(wc -l <<<"$s2") lines, v6 $(wc -l <<<"$s62") lines identical; jumps v4=$j4 v6=$j6"
  else
    result d_idempotent FAIL "v4 same=$([[ $s1 == "$s2" ]] && echo y || echo n) v6 same=$([[ $s61 == "$s62" ]] && echo y || echo n) jumps v4=$j4 v6=$j6"
  fi

  echo "INFO verify (lockdown on, as uid 65534):"
  rc=0; setpriv --reuid=65534 --regid=65534 --clear-groups bash "$L" verify | sed 's/^/  | /' || rc=${PIPESTATUS[0]}
  [[ $rc -eq 0 ]] && result f_verify_exit0 PASS "exit 0" || result f_verify_exit0 FAIL "exit $rc"

  bash "$L" off
  p=$(probe api.openai.com 4)
  if [[ ${p%% *} != 000 ]] && ! $ipt -S WRECKLESS_AIRGAP >/dev/null 2>&1 && ! $ip6t -S WRECKLESS_AIRGAP >/dev/null 2>&1; then
    result e_off_restores PASS "openai http/exit=$p; v4+v6 chains gone"
  else result e_off_restores FAIL "openai http/exit=$p"; fi

  rc=0; bash "$L" verify >/dev/null || rc=$?
  [[ $rc -ne 0 ]] && result f_verify_fails_when_off PASS "exit $rc" || result f_verify_fails_when_off FAIL "exit 0 with lockdown off"

  # optional airtight: LLM blocked, Slack + localhost up, arbitrary internet denied
  bash "$L" airtight >/dev/null
  rc=0; bash "$L" verify >/dev/null || rc=$?
  p=$(probe example.com 4)
  if [[ $rc -eq 0 && ${p%% *} == 000 ]]; then result h_airtight PASS "verify exit 0; example.com http/exit=$p"
  else result h_airtight FAIL "verify exit $rc; example.com http/exit=$p"; fi
  bash "$L" off >/dev/null

  echo "SUMMARY fails=$FAILS"
  [[ $FAILS -eq 0 ]]
}

if [[ ${1:-} == --inside ]]; then inside_main; else host_main; fi
