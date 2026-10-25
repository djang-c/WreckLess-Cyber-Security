#!/usr/bin/env bash
# One-line stage bringup: tmux with the flock on top, GB10 metrics beside it, the run below.
#
# Usage: scripts/tmux_demo.sh [live|demo|scripted|replay]   -> runs scripts/demo.sh <rung> in the main pane
#        scripts/tmux_demo.sh -- <command...>               -> runs that command in the main pane instead
#        e.g. scripts/tmux_demo.sh -- env WRECKLESS_SANDBOX=userland uv run wreckless run --agentic
# Layout: flock strip (top), metrics, then the run. Mouse is on for this session (click a pane to focus, drag borders to resize, wheel to scroll).
# Re-running attaches to the existing session; kill it first with: tmux kill-session -t wl
set -euo pipefail
cd "$(dirname "$0")/.."
command -v tmux >/dev/null || { echo "tmux not installed" >&2; exit 1; }

S=wl
if tmux has-session -t "$S" 2>/dev/null; then exec tmux attach -t "$S"; fi

if [[ "${1:-}" == -- ]]; then shift; MAIN="$*"; else MAIN="scripts/demo.sh ${1:-demo}"; fi

# Flock strip on top, full width so all five birds sit in one row (78+ columns; labels shrink to fit).
# Metrics go beside it on a wide screen (170+ columns), else in their own strip below it.
COLS="$(tput cols 2>/dev/null || echo 80)"; LINES_="$(tput lines 2>/dev/null || echo 40)"
if (( COLS >= 170 )); then TOP=10; else TOP=17; fi   # rows above the run: flock 10 (+ metrics 6 + border)
tmux new-session -d -x "$COLS" -y "$LINES_" -s "$S" -c "$PWD" "uv run wreckless view; read -r -p 'view exited' _"
tmux set-option -t "$S" mouse on
tmux split-window -v -l $((LINES_ - TOP - 1)) -t "$S":0.0 -c "$PWD" "$MAIN; echo; read -r -p 'run finished, Enter to close pane' _"
if (( COLS >= 170 )); then
  tmux split-window -h -l 45% -t "$S":0.0 -c "$PWD" "uv run wreckless metrics --watch 2"
else
  tmux split-window -v -l 6 -t "$S":0.0 -c "$PWD" "uv run wreckless metrics --watch 2"
fi
tmux select-pane -t "$S":0."$(tmux list-panes -t "$S" -F '#{pane_index}' | tail -1)"
exec tmux attach -t "$S"
