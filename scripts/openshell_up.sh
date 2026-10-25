#!/usr/bin/env bash
# Bring up the OpenShell gateway (docker compute driver) and the WreckLess sandbox image.
# Usage: scripts/openshell_up.sh            stop: pkill -f '^openshell-gateway$'
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p logs ~/.config/openshell
grep -q OPENSHELL_COMPUTE_DRIVER ~/.config/openshell/gateway.env 2>/dev/null \
  || echo "OPENSHELL_COMPUTE_DRIVER=docker" >> ~/.config/openshell/gateway.env

# docker group may be missing from this login session if it was added after login
if id -nG | grep -qw docker; then D() { "$@"; }; else D() { sg docker -c "$*"; }; fi

D docker image inspect wreckless-sandbox:py312 >/dev/null 2>&1 \
  || D docker build -q -t wreckless-sandbox:py312 sandbox/

if openshell status 2>/dev/null | grep -q Connected; then
  echo "gateway already connected"; exit 0
fi

# The systemd user manager only has the docker group if it started after the group was added.
if grep -q "$(getent group docker | cut -d: -f3)" <(grep Groups /proc/"$(pgrep -u "$USER" -x systemd | head -1)"/status); then
  systemctl --user restart openshell-gateway
else
  echo "systemd user manager lacks the docker group (log out/in or reboot to fix); starting gateway via sg"
  pkill -f '^openshell-gateway$' 2>/dev/null || true
  (cd ~ && OPENSHELL_LOCAL_TLS_DIR=$HOME/.local/state/openshell/tls OPENSHELL_COMPUTE_DRIVER=docker \
     nohup sg docker -c openshell-gateway > "$OLDPWD/logs/openshell-gateway.log" 2>&1 &)
fi

for _ in $(seq 1 60); do
  openshell status 2>/dev/null | grep -q Connected && { echo "gateway connected"; exit 0; }
  sleep 2
done
echo "gateway did not come up; see logs/openshell-gateway.log"; exit 1
