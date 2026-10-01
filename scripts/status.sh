#!/usr/bin/env bash
# scripts/status.sh - Quick "what's running right now" snapshot for tscan-ng.
#
# Read-only. Prints, in order: `systemctl status` of the pipeline service
# (first 12 lines), of the healthcheck timer (first 6 lines), the capture
# interface's link state, the main PID and number of worker processes, and
# the last 15 journal lines of the pipeline unit.
#
# Usage:  bash /opt/tscan/scripts/status.sh      (no arguments)
#
# Environment: none read. Unit names and the capture interface name are
#   hard-coded below (IFACE must be edited if the NIC changes).
#
# Privileges: runs as the invoking (non-root) user. `systemctl status`,
#   `systemctl show`, `ip link show` and `pgrep` work for any user and are
#   run without sudo (TODO.md #45). Only journalctl uses `sudo`, relying on
#   the NOPASSWD grant in /etc/sudoers.d, because a user outside the
#   adm/systemd-journal groups cannot read the unit's journal; it will
#   prompt for a password if that grant is absent.
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
systemctl status "${PIPELINE}" --no-pager -l | head -n 12
echo

bold "== healthcheck timer =="
systemctl status "${HEALTHCHECK_TIMER}" --no-pager -l | head -n 6
echo

bold "== capture interface (${IFACE}) =="
ip -brief link show "${IFACE}" 2>/dev/null || echo "  ${IFACE} not found"
echo

bold "== worker processes =="
# The workers are multiprocessing "spawn" children of the service's main
# process (pinned in pipeline.main()). Their command lines are `python -c
# 'from multiprocessing.spawn import spawn_main ...'` and do not mention
# tscan_ng, so they are counted as children of systemd's MainPID whose
# command line names multiprocessing.spawn. The resource tracker, also a
# child, is not counted. Expect [dispatcher] workers (default one per CPU).
main_pid=$(systemctl show "${PIPELINE}" -p MainPID --value 2>/dev/null)
if [[ -n "${main_pid}" && "${main_pid}" != "0" ]]; then
  workers=$(pgrep -c -P "${main_pid}" -f 'multiprocessing\.spawn')
  echo "  main PID ${main_pid}, ${workers:-0} worker process(es)"
else
  echo "  pipeline not running"
fi
echo

bold "== last 15 log lines =="
sudo journalctl -u "${PIPELINE}" -n 15 --no-pager
