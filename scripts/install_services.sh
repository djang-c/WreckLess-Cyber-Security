#!/usr/bin/env bash
# Run WreckLess 24/7 on the GB10 under systemd: models at boot, the daemon (+ Slack buttons)
# restarted if it dies, and optionally the airgap re-applied at boot (iptables rules do not
# survive a reboot). Review happens remotely in Slack; Approve opens the draft PR.
#
# Usage: scripts/install_services.sh [--with-airgap] [--dry-run] [--yes] [--uninstall]
#   --with-airgap  also install wreckless-airgap.service (airgap_lockdown.sh on at boot).
#                  While it is on, cloud LLM APIs are blocked, including Claude Code on this box.
#   --dry-run      print the units and commands, change nothing (works on any OS)
#   --yes          do not ask before the sudo steps
#   --uninstall    stop, disable and remove the units
#
# Units (written to /etc/systemd/system):
#   wreckless-models.service  oneshot: scripts/serve_models.sh all (stop: serve_models.sh stop)
#   wreckless-daemon.service  `wreckless daemon --slack-listener`, as you (not root), Restart=always,
#                             env from ./.env (SLACK_*, WRECKLESS_GITHUB_REPO)
#   wreckless-airgap.service  oneshot as root: airgap_lockdown.sh on (stop: off)   [--with-airgap]
# Logs: journalctl -u wreckless-daemon -f   ·   status: systemctl status 'wreckless-*'
set -euo pipefail
cd "$(dirname "$0")/.."
REPO=$(pwd -P)

AIRGAP=0 DRY=0 YES=0 UNINSTALL=0
for a in "$@"; do
  case $a in
    --with-airgap) AIRGAP=1 ;;
    --dry-run) DRY=1 ;;
    --yes) YES=1 ;;
    --uninstall) UNINSTALL=1 ;;
    *) echo "unknown option: $a" >&2; exit 2 ;;
  esac
done

RUN_USER=${SUDO_USER:-$(id -un)}
RUN_HOME=$(eval echo "~$RUN_USER")
UV=$(command -v uv || true)
UNITS=(wreckless-models wreckless-daemon)
[[ $AIRGAP == 1 ]] && UNITS+=(wreckless-airgap)
DEST=/etc/systemd/system

if [[ $DRY == 0 ]]; then
  [[ $(uname -s) == Linux ]] || { echo "systemd units are for the Linux GB10; use --dry-run here" >&2; exit 1; }
  command -v systemctl >/dev/null || { echo "systemctl not found" >&2; exit 1; }
fi
if [[ $UNINSTALL == 0 && $DRY == 0 ]]; then
  [[ -n $UV ]] || { echo "uv not on PATH" >&2; exit 1; }
  [[ -f .env ]] || { echo ".env missing: copy it here first (see docs/slack-setup.md)" >&2; exit 1; }
fi
UV=${UV:-$RUN_HOME/.local/bin/uv}

ask() { [[ $YES == 1 ]] && return 0; local a; read -r -p "$1 [y/N] " a; [[ "$a" =~ ^[Yy]$ ]]; }
run() { echo "+ $*"; [[ $DRY == 1 ]] || "$@"; }

unit_models() {
  cat <<EOF
[Unit]
Description=WreckLess local models (vLLM on :8000 :8001 :8002)
Wants=network-online.target
After=network-online.target docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
User=$RUN_USER
WorkingDirectory=$REPO
Environment=HOME=$RUN_HOME
Environment=PATH=$RUN_HOME/.local/bin:/usr/local/bin:/usr/bin:/bin
ExecStart=$REPO/scripts/serve_models.sh all
ExecStop=$REPO/scripts/serve_models.sh stop
TimeoutStartSec=1800

[Install]
WantedBy=multi-user.target
EOF
}

unit_daemon() {
  local after="wreckless-models.service network-online.target"
  [[ $AIRGAP == 1 ]] && after+=" wreckless-airgap.service"
  cat <<EOF
[Unit]
Description=WreckLess daemon (Purple/Red/Blue + Slack Approve/Reject)
Wants=${after}
After=${after}
StartLimitIntervalSec=0

[Service]
User=$RUN_USER
WorkingDirectory=$REPO
Environment=HOME=$RUN_HOME
Environment=PATH=$RUN_HOME/.local/bin:/usr/local/bin:/usr/bin:/bin
Environment=PYTHONUNBUFFERED=1
# .env uses 'export KEY=value', which EnvironmentFile= cannot read; tokens never enter the unit
ExecStart=/bin/bash -c 'set -a; . ./.env; set +a; exec "$UV" run --all-extras wreckless daemon --slack-listener'
Restart=always
RestartSec=15

[Install]
WantedBy=multi-user.target
EOF
}

unit_airgap() {
  cat <<EOF
[Unit]
Description=WreckLess airgap (block cloud-LLM egress; loopback + Slack + GitHub stay up)
Wants=network-online.target
After=network-online.target docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=$REPO/scripts/airgap_lockdown.sh on
ExecStop=$REPO/scripts/airgap_lockdown.sh off
# 'on' fails closed and exits 1 if DNS is not up yet: try again
Restart=on-failure
RestartSec=30

[Install]
WantedBy=multi-user.target
EOF
}

if [[ $UNINSTALL == 1 ]]; then
  ask "Stop, disable and remove wreckless-*.service?" || exit 1
  for u in wreckless-daemon wreckless-airgap wreckless-models; do
    run sudo systemctl disable --now "$u.service" 2>/dev/null || true
    run sudo rm -f "$DEST/$u.service"
  done
  run sudo systemctl daemon-reload
  exit 0
fi

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
for u in "${UNITS[@]}"; do
  "unit_${u#wreckless-}" > "$TMP/$u.service"
  printf '\n\033[1m── %s.service ──\033[0m\n' "$u"
  cat "$TMP/$u.service"
done
echo
[[ $AIRGAP == 1 ]] && echo "NOTE: with the airgap unit, cloud LLM APIs (incl. Claude Code on this box) stay blocked after every boot. Undo: sudo scripts/airgap_lockdown.sh off"
[[ $DRY == 1 ]] || ask "Install and start these units with sudo?" || exit 1
for u in "${UNITS[@]}"; do
  run sudo install -m 0644 "$TMP/$u.service" "$DEST/$u.service"
done
run sudo systemctl daemon-reload
for u in "${UNITS[@]}"; do
  run sudo systemctl enable --now "$u.service"
done
echo "done. Follow: journalctl -u wreckless-daemon -f"
