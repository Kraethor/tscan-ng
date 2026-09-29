#!/usr/bin/env bash
# scripts/update.sh - Deploy the latest tscan-ng code and restart the service.
#
# Steps, in order:
#   1. Stop tscan-pipeline.service if it is active.
#   2. `git pull --ff-only` as the tscan user (deploy key via the repo's own
#      core.sshCommand). A diverged or dirty tree aborts the script here.
#   3. If requirements.txt exists and /opt/tscan/venv exists, run
#      `pip install --upgrade -r requirements.txt` inside the venv as tscan
#      (a missing venv only prints a warning and skips this step).
#   4. Copy each unit in UNITS (tscan-pipeline.service,
#      tscan-pipeline-healthcheck.service, tscan-pipeline-healthcheck.timer)
#      from /opt/tscan/systemd/ to /etc/systemd/system/ if missing or
#      different, then `systemctl daemon-reload` only if any were copied.
#   5. Start the pipeline and `systemctl enable --now` the healthcheck timer.
#   6. Print whether each is active.
#
# NOT handled by this script (do these by hand, see docs/REBUILD.md):
#   - logrotate/tscan -> /etc/logrotate.d/tscan
#   - systemd/tscan-monitor.network.example -> /etc/systemd/network/
#   - edits to tscan_ng/config/tscan_ng.conf (gitignored, host-specific).
#
# Usage:  sudo /opt/tscan/scripts/update.sh        (no arguments)
#
# Environment: none read. SERVICE_USER, APP_DIR and the unit names are set
#   below. pip runs with PIP_NO_CACHE_DIR=1 in a `bash -lc` login shell as
#   tscan.
#
# Privileges: must be root (checked at start): it stops/starts services,
#   writes into /etc/systemd/system and calls `sudo -u tscan` for git/pip.
#
# Exit codes:
#   0  finished (even if the pipeline or timer then reports "NOT active" --
#      the final status lines are informational, not asserted).
#   1  not run as root.
#   other non-zero: `set -e` aborts on the first failing command (git pull,
#      pip, cp, daemon-reload, systemctl start/enable). Because the service
#      is stopped in step 1, a failure in steps 2-4 leaves the pipeline
#      STOPPED; fix the cause and re-run, or `systemctl start tscan-pipeline`.
set -euo pipefail

# Must be run as root (we call systemctl, copy into /etc/systemd, etc.)
if [[ $EUID -ne 0 ]]; then
  echo "[-] This script must be run as root" >&2
  exit 1
fi

SERVICE_USER="tscan"
APP_DIR="/opt/tscan"
PIPELINE_SERVICE="tscan-pipeline"
HEALTHCHECK_TIMER="tscan-pipeline-healthcheck.timer"
# Units installed from ${APP_DIR}/systemd/ into /etc/systemd/system/. The
# healthcheck .service is oneshot and only ever started by its .timer, so it
# is installed but never enabled or started directly here.
UNITS=("tscan-pipeline.service" "tscan-pipeline-healthcheck.service" "tscan-pipeline-healthcheck.timer")

# ---------------------------------------------------------------------------
# Stop the pipeline
# ---------------------------------------------------------------------------
echo "[+] Stopping ${PIPELINE_SERVICE}..."
if systemctl is-active --quiet "${PIPELINE_SERVICE}"; then
  systemctl stop "${PIPELINE_SERVICE}"
fi

# ---------------------------------------------------------------------------
# Pull latest code
# ---------------------------------------------------------------------------
echo "[+] Updating repository as ${SERVICE_USER} in ${APP_DIR}..."
sudo -u "${SERVICE_USER}" -H git -C "${APP_DIR}" pull --ff-only

# ---------------------------------------------------------------------------
# Update Python dependencies if requirements.txt exists
# ---------------------------------------------------------------------------
if [ -f "${APP_DIR}/requirements.txt" ]; then
  echo "[+] requirements.txt found, updating virtualenv..."
  sudo -u "${SERVICE_USER}" -H bash -lc "
    cd '${APP_DIR}'
    if [ -d 'venv' ]; then
      source venv/bin/activate
      PIP_NO_CACHE_DIR=1 pip install --upgrade -r requirements.txt
      deactivate
    else
      echo '[!] venv not found, skipping pip install' >&2
    fi
  "
else
  echo "[+] No requirements.txt found, skipping dependency update."
fi

# ---------------------------------------------------------------------------
# Reinstall systemd units if they changed
# ---------------------------------------------------------------------------
UNITS_CHANGED=0
for UNIT in "${UNITS[@]}"; do
  REPO_UNIT="${APP_DIR}/systemd/${UNIT}"
  SYSTEM_UNIT="/etc/systemd/system/${UNIT}"
  # `diff -q` exits non-zero when the files differ; inside `||` / `!` that
  # does not trip `set -e`, it just selects the reinstall branch.
  if [ ! -f "${SYSTEM_UNIT}" ] || ! diff -q "${REPO_UNIT}" "${SYSTEM_UNIT}" &>/dev/null; then
    echo "[+] ${UNIT} changed or missing, reinstalling..."
    cp "${REPO_UNIT}" "${SYSTEM_UNIT}"
    UNITS_CHANGED=1
  fi
done

if [ "${UNITS_CHANGED}" -eq 1 ]; then
  echo "[+] Reloading systemd daemon..."
  systemctl daemon-reload
else
  echo "[+] systemd units unchanged, skipping daemon-reload."
fi

# ---------------------------------------------------------------------------
# Start the pipeline and make sure the healthcheck timer is enabled
# ---------------------------------------------------------------------------
echo "[+] Starting ${PIPELINE_SERVICE}..."
systemctl start "${PIPELINE_SERVICE}"
systemctl enable --now "${HEALTHCHECK_TIMER}" >/dev/null

# ---------------------------------------------------------------------------
# Report status
# ---------------------------------------------------------------------------
echo "[+] Current status:"
if systemctl --no-pager --quiet is-active "${PIPELINE_SERVICE}"; then
  echo "  - ${PIPELINE_SERVICE}: active"
else
  echo "  - ${PIPELINE_SERVICE}: NOT active"
fi
if systemctl --no-pager --quiet is-active "${HEALTHCHECK_TIMER}"; then
  echo "  - ${HEALTHCHECK_TIMER}: active"
else
  echo "  - ${HEALTHCHECK_TIMER}: NOT active"
fi

echo "[+] Done."
