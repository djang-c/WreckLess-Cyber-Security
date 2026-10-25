#!/usr/bin/env bash
# Run one case N times (fresh home each) and tabulate the outcomes: how consistent are the models?
# Usage: scripts/consistency.sh [N=5] [-- extra `wreckless run` flags]   (default: live models, agentic, OpenShell)
# Env:   CVE (default CVE-2024-21513)  TARGET (default victim_app)  OUT (default runs/consistency-<time>)
# Slack is whatever .env / the shell says; blank SLACK_BOT_TOKEN= to keep cards in logs/slack_outbox.jsonl.
set -uo pipefail
cd "$(dirname "$0")/.."
N="${1:-5}"; shift || true; [[ "${1:-}" == -- ]] && shift
CVE="${CVE:-CVE-2024-21513}"; TARGET="${TARGET:-victim_app}"
OUT="${OUT:-runs/consistency-$(date +%H%M%S)}"; mkdir -p "$OUT"
FLAGS=("$@"); [[ ${#FLAGS[@]} -eq 0 ]] && FLAGS=(--agentic)
for i in $(seq 1 "$N"); do
  echo "== run $i/$N → $OUT/$i"
  NO_COLOR=1 WRECKLESS_SANDBOX="${WRECKLESS_SANDBOX:-openshell}" \
    uv run wreckless run --home "$OUT/$i" --target "$TARGET" --cve "$CVE" "${FLAGS[@]}" > "$OUT/$i.log" 2>&1
  echo "   exit $?"
done
uv run python - "$OUT" "$N" <<'PY'
import json, pathlib, sys
out, n = pathlib.Path(sys.argv[1]), int(sys.argv[2])
print(f"\n{'run':>3} {'final state':<13} {'secs':>5} {'exploit':<8} {'patch':<8} {'checks':<8} {'fallback'}")
ok = 0
for i in range(1, n + 1):
    ev = [json.loads(l) for l in (out / str(i) / "events.jsonl").read_text().splitlines() if l.strip()] \
        if (out / str(i) / "events.jsonl").exists() else []
    tr = [e for e in ev if e["kind"] == "transition"]
    state = tr[-1]["to"] if tr else "no-run"
    secs = f"{tr[-1]['t'] - tr[0]['t']:.0f}" if tr else "-"
    rep = next(iter((out / str(i) / "items").glob("*/vulnerability_report.json")), None)
    exploit = json.loads(rep.read_text()).get("exploit_source", "-") if rep else "-"
    pv = next((e for e in ev if e["kind"] == "patch_validated"), None)
    sb = next((e for e in reversed(ev) if e["kind"] == "scoreboard"), None)
    checks = f"{sum(v is True for v in (sb['regression'], sb['functional'], sb['exploit_blocked']))}/3" if sb else "-"
    log = (out / f"{i}.log").read_text() if (out / f"{i}.log").exists() else ""
    fb = "YES" if "CACHED REFERENCE" in log or exploit == "fallback" else "no"
    ok += state == "notified"
    print(f"{i:>3} {state:<13} {secs:>5} {exploit:<8} {(pv or {}).get('source', '-'):<8} {checks:<8} {fb}")
print(f"\n{ok}/{n} reached notified")
PY
