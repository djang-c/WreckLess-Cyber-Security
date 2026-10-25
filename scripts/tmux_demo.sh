#!/usr/bin/env bash
# One-line stage bringup.
#
# Usage: scripts/tmux_demo.sh [tui|live|demo|scripted|replay] [--daemon] [--no-slack]
#        scripts/tmux_demo.sh -- <command...>               -> runs that command in the main pane instead
#        e.g. scripts/tmux_demo.sh -- env WRECKLESS_SANDBOX=userland uv run wreckless run --agentic
#   tui (default)  window "stage": the full-screen app (`wreckless tui`: flock, log, GB10, Settings)
#   live|demo|...  window "stage": flock strip (top), metrics, then scripts/demo.sh <rung>
#   window "doors" (unless --no-slack): Porter's two doors as two processes
#     left  : Slack side   python -m wreckless.slack_socket   (buttons + @mentions; never touches a finding)
#     right : agents' side python -m wreckless.porter         (records clicks, answers, opens the draft PR)
#             --daemon runs the full 24/7 swarm there instead: wreckless daemon --porter
#   The Slack side only starts if `python -m wreckless.slack_socket --check` passes (offline check).
# Switch windows: click the name in the status bar, or Ctrl-b n. Mouse is on (click a pane to focus,
# drag borders to resize, wheel to scroll). Re-running attaches; kill first with: tmux kill-session -t wl
# WL_SESSION=name picks another session name; WL_NO_ATTACH=1 starts it without attaching (tests).
set -euo pipefail
cd "$(dirname "$0")/.."
command -v tmux >/dev/null || { echo "tmux not installed" >&2; exit 1; }

S=${WL_SESSION:-wl}
attach() { [[ -n ${WL_NO_ATTACH:-} ]] && exit 0; exec tmux attach -t "$S"; }
if tmux has-session -t "$S" 2>/dev/null; then attach; fi

RUNG=tui DOORS=1 INNER="uv run python -m wreckless.porter" MAIN=""
while (( $# )); do
  case $1 in
    --) shift; MAIN="$*"; RUNG=custom; break ;;
    --daemon) INNER="uv run wreckless daemon --porter" ;;
    --no-slack) DOORS=0 ;;
    tui|live|demo|scripted|replay) RUNG=$1 ;;
    *) echo "unknown argument: $1 (see the header of $0)" >&2; exit 2 ;;
  esac
  shift
done
[[ $RUNG == custom || $RUNG == tui ]] || MAIN="scripts/demo.sh $RUNG"
HOLD="; echo; read -r -p 'exited: Enter to close this pane' _"

doors() {   # window "doors": the Slack side and the agents' side, two processes
  local outer
  if uv run python -m wreckless.slack_socket --check >/dev/null 2>&1; then
    outer="uv run --extra slack python -m wreckless.slack_socket"
  else
    outer="echo 'Slack side not started: the offline check failed.'; uv run python -m wreckless.slack_socket --check; echo; echo 'Fix .env (docs/slack-setup.md), then restart this window.'"
  fi
  tmux new-window -d -t "$S" -n doors -c "$PWD" "$outer$HOLD"
  tmux split-window -h -t "$S":doors -c "$PWD" "$INNER$HOLD"
  tmux set-option -t "$S" pane-border-status top
  tmux select-pane -t "$S":doors.0 -T "Porter · Slack side (outer door)"
  tmux select-pane -t "$S":doors.1 -T "Porter · agents' side (inner door)"
}

if [[ $RUNG == tui ]]; then
  tmux new-session -d -s "$S" -n stage -c "$PWD" "uv run wreckless tui$HOLD"
  tmux set-option -t "$S" mouse on
  (( DOORS )) && doors
  tmux select-window -t "$S":stage
  attach
fi

# Flock strip on top, full width so all five birds sit in one row (78+ columns; labels shrink to fit).
# Metrics go beside it on a wide screen (170+ columns), else in their own strip below it.
COLS="$(tput cols 2>/dev/null || echo 80)"; LINES_="$(tput lines 2>/dev/null || echo 40)"
if (( COLS >= 170 )); then TOP=10; else TOP=17; fi   # rows above the run: flock 10 (+ metrics 6 + border)
tmux new-session -d -x "$COLS" -y "$LINES_" -s "$S" -n stage -c "$PWD" "uv run wreckless view; read -r -p 'view exited' _"
tmux set-option -t "$S" mouse on
tmux split-window -v -l $((LINES_ - TOP - 1)) -t "$S":0.0 -c "$PWD" "$MAIN; echo; read -r -p 'run finished, Enter to close pane' _"
if (( COLS >= 170 )); then
  tmux split-window -h -l 45% -t "$S":0.0 -c "$PWD" "uv run wreckless metrics --watch 2"
else
  tmux split-window -v -l 6 -t "$S":0.0 -c "$PWD" "uv run wreckless metrics --watch 2"
fi
tmux select-pane -t "$S":0."$(tmux list-panes -t "$S" -F '#{pane_index}' | tail -1)"
(( DOORS )) && doors
tmux select-window -t "$S":stage
attach
