#!/usr/bin/env bash
# scripts/update.sh - Deploy the latest tscan-ng code and restart the service.
#
# Stops tscan-pipeline.service, pulls the latest commit as the tscan user,
# updates the venv from requirements.txt if present, reinstalls any systemd
# unit file under systemd/ that differs from what's in /etc/systemd/system/
# (reloading the daemon only if something actually changed), then restarts
# the pipeline and enables the healthcheck timer.
#
# Usage: sudo /opt/tscan/scripts/update.sh
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
