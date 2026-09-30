#!/usr/bin/env bash
# scripts/status.sh - Quick "what's running right now" snapshot for tscan-ng.
#
# Read-only. Prints, in order: `systemctl status` of the pipeline service
# (first 12 lines), of the healthcheck timer (first 6 lines), the capture
# interface's link state, the number of processes matching the pipeline's
# main command line, and the last 15 journal lines of the pipeline unit.
#
# Usage:  bash /opt/tscan/scripts/status.sh      (no arguments)
#
# Environment: none read. Unit names and the capture interface name are
#   hard-coded below (IFACE must be edited if the NIC changes).
#
# Privileges: runs as the invoking (non-root) user and calls
#   `sudo systemctl`, `sudo ip` and `sudo journalctl`, which rely on the
#   NOPASSWD grants in /etc/sudoers.d for exactly those binaries. No root
#   login needed, but it will prompt for a password if the grants are absent.
#   (Inference: `systemctl status` and `ip link show` do not require root by
#   themselves; sudo matters mainly for journalctl on a user outside the
#   adm/systemd-journal groups.)
#
# Exit codes: deliberately NOT `set -e` -- a stopped service or missing
#   interface must not abort the snapshot, so individual command failures are
#   ignored. The exit status is that of the final journalctl command
#   (0 normally). Because of `| head`, pipeline exit statuses are not
#   meaningful here even with pipefail.
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
# Counts processes whose full command line matches "tscan_ng.pipeline", i.e.
# the main process (`python -m tscan_ng.pipeline`). The worker children
# are started with multiprocessing's "spawn" start method (pinned in
# pipeline.main()); their command lines are `python -c 'from
# multiprocessing.spawn import spawn_main ...'`, which this pattern does not
# match, so on a healthy host this prints 1 -- use
# `systemctl status` (CGroup section) to see the workers.
count=$(pgrep -cf "tscan_ng\.pipeline")
if [[ "${count}" -gt 0 ]]; then
  echo "  ${count} process(es) (1 main; spawned workers are not counted here)"
else
  echo "  none running"
fi
echo

bold "== last 15 log lines =="
sudo journalctl -u "${PIPELINE}" -n 15 --no-pager
