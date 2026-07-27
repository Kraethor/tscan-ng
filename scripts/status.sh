#!/usr/bin/env bash
# scripts/status.sh - Quick "what's running right now" snapshot for tscan-ng.
#
# Read-only. Uses the NOPASSWD sudo grants for systemctl/journalctl/ip
# (see /etc/sudoers.d), so no root login is needed to run this.
set -uo pipefail

PIPELINE="tscan-pipeline.service"
HEALTHCHECK_TIMER="tscan-pipeline-healthcheck.timer"
IFACE="enx00242788e34c"

bold() { printf '\033[1m%s\033[0m\n' "$1"; }

bold "== ${PIPELINE} =="
sudo systemctl status "${PIPELINE}" --no-pager -l | head -n 12
echo

bold "== healthcheck timer =="
sudo systemctl status "${HEALTHCHECK_TIMER}" --no-pager -l | head -n 6
echo

bold "== capture interface (${IFACE}) =="
sudo ip -brief link show "${IFACE}" 2>/dev/null || echo "  ${IFACE} not found"
echo

bold "== worker processes =="
count=$(pgrep -cf "tscan_ng\.pipeline")
if [[ "${count}" -gt 0 ]]; then
  echo "  ${count} process(es) (1 main + forkserver workers)"
else
  echo "  none running"
fi
echo

bold "== last 15 log lines =="
sudo journalctl -u "${PIPELINE}" -n 15 --no-pager
