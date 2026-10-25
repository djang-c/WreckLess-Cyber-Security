#!/usr/bin/env bash
# WreckLess stage run (~4 min, 5 beats). See docs/demo-script.md for talking points.
#
# Usage: scripts/demo.sh [live|demo|scripted|replay] [--yes-preflight]
#   live      rung 1: live local LLMs, normal sampling           (run)
#   demo      rung 2: live local LLMs, N=1 temp 0, cached fallback (run --demo-mode)   [default]
#   scripted  rung 2b: no LLM, cached exploit/patch, still really executed + validated
#   replay    rung 3: replay the last item that reached `notified`, from events.jsonl (tagged REPLAY)
#
# This script never runs sudo silently: it prints the exact command and asks first.
set -uo pipefail
cd "$(dirname "$0")/.."
[[ -f .env ]] && { set -a; . ./.env; set +a; }   # Slack tokens; shell values set before this are overwritten, so unset them to test without

RUNG="${1:-demo}"
CVE="${CVE:-CVE-2024-21513}"
SPEED="${REPLAY_SPEED:-1.0}"
PY=(uv run python -m wreckless)
ok()   { printf '  \033[1;32m✓\033[0m %s\n' "$*"; }
bad()  { printf '  \033[1;31m✗\033[0m %s\n' "$*"; }
info() { printf '  \033[2m·\033[0m %s\n' "$*"; }
beat() { printf '\n\033[1;36m── BEAT %s ──\033[0m\n' "$*"; }
ask()  { local a; read -r -p "$1 [y/N] " a; [[ "$a" =~ ^[Yy]$ ]]; }

# prints "<events.jsonl> <item>" for the newest item of $CVE that reached `notified`
# (any CVE would let the safety net replay a different bug than the one on stage)
last_good_run() {
  CVE="$CVE" uv run python - <<'EOF'
import json, os, pathlib
cve = os.environ["CVE"]
logs = sorted(pathlib.Path("runs").glob("**/events.jsonl"), key=lambda p: p.stat().st_mtime, reverse=True)
for p in logs:
    done = [e["item"] for e in map(json.loads, p.read_text().splitlines())
            if e.get("kind") == "transition" and e.get("to") == "notified"
            and str(e.get("item", "")).startswith(cve + "#")]
    if done:
        print(f"{p}\t{done[-1]}"); break   # tab: the path may contain spaces
EOF
}

# ── Preflight ──────────────────────────────────────────────────────────────
printf '\033[1mPreflight\033[0m\n'
command -v uv >/dev/null && ok "uv present" || { bad "uv missing"; exit 1; }
ENDPOINTS_UP=1
for spec in "RED:8000" "BLUE:8001" "VICTIM:8002"; do
  role="${spec%%:*}"; port="${spec##*:}"
  var="WRECKLESS_${role}_URL"; url="${!var:-http://127.0.0.1:${port}/v1}"
  if curl -s -m 3 -o /dev/null -w '%{http_code}' "${url}/models" | grep -q '^200$'; then
    ok "$role endpoint ${url}/models"
  else
    bad "$role endpoint ${url}/models unreachable"; ENDPOINTS_UP=0
  fi
done
GOOD_RUN="$(last_good_run)"
if [[ -n "$GOOD_RUN" ]]; then ok "replay safety net: $GOOD_RUN"; else bad "no recorded notified item for replay — record one first: scripts/demo.sh scripted"; fi
IFS=$'\t' read -r GOOD_EVENTS GOOD_ITEM <<<"$GOOD_RUN"
if [[ -n "${SLACK_BOT_TOKEN:-}" && -n "${SLACK_CHANNEL:-}" ]]; then ok "Slack bot token + channel set"
elif [[ -n "${SLACK_WEBHOOK_URL:-}" ]]; then ok "Slack webhook set (no live card update)"
else bad "Slack not configured — cards go to logs/slack_outbox.jsonl (the terminal says so)"; fi

if [[ "$RUNG" =~ ^(live|demo)$ && $ENDPOINTS_UP -eq 0 ]]; then
  info "LLM endpoints down: '$RUNG' would run on cached exploit/patch (labelled 'fallback' on screen)."
  if [[ -n "$GOOD_RUN" ]] && ask "Switch to replay of the last good run instead?"; then RUNG=replay; fi
fi
[[ "$RUNG" == replay && -z "$GOOD_RUN" ]] && { bad "replay requested but nothing recorded"; exit 1; }

# ── Beat 1: airgap ────────────────────────────────────────────────────────
beat "1 · AIRGAP ON (cloud-LLM routes dropped; loopback + Slack stay up)"
if [[ "$(uname -s)" == Linux ]]; then
  echo "  will run: sudo scripts/airgap_lockdown.sh on"
  if ask "  run it?"; then
    if sudo scripts/airgap_lockdown.sh on; then
      scripts/airgap_lockdown.sh verify || bad "airgap verify FAILED — do not claim airgap"
    else
      bad "airgap 'on' FAILED (see above) — do not claim airgap"
    fi
  else info "skipped (say so on stage)"; fi
else
  info "not Linux ($(uname -s)): iptables airgap unavailable here — do not claim airgap on this host"
fi

read -r -p $'\nEnter to launch the swarm (beats 2-5) ' _

# ── Beats 2-5: Purple -> Red -> Blue -> Slack ─────────────────────────────
case "$RUNG" in
  live)     "${PY[@]}" run --cve "$CVE" ;;
  demo)     "${PY[@]}" run --cve "$CVE" --demo-mode ;;
  scripted) "${PY[@]}" run --cve "$CVE" --demo-mode --no-llm ;;
  replay)   "${PY[@]}" replay "$GOOD_EVENTS" --item "$GOOD_ITEM" --speed "$SPEED" ;;
  *) echo "unknown rung: $RUNG"; exit 2 ;;
esac
RC=$?

if [[ $RC -ne 0 && "$RUNG" != replay && -n "$GOOD_RUN" ]]; then
  bad "run ended without NOTIFIED (rc=$RC) — that result stands; it is not hidden"
  if ask "Show the replay of the last good run (tagged REPLAY)?"; then
    "${PY[@]}" replay "$GOOD_EVENTS" --item "$GOOD_ITEM" --speed "$SPEED"; RC=$?
  fi
fi

beat "5 · SLACK"
if [[ "$RUNG" != replay && -f logs/slack_outbox.jsonl && -z "${SLACK_BOT_TOKEN:-}${SLACK_WEBHOOK_URL:-}" ]]; then
  info "last outbox card: $(tail -n 1 logs/slack_outbox.jsonl | uv run python -c 'import json,sys; print(json.load(sys.stdin)["title"])')"
fi
exit $RC
