#!/usr/bin/env bash
set -euo pipefail

# Must be run as root (we call systemctl, copy into /etc/systemd, etc.)
if [[ $EUID -ne 0 ]]; then
  echo "[-] This script must be run as root" >&2
  exit 1
fi

SERVICE_USER="tscan"
APP_DIR="/opt/tscan"
DISPATCHER_SERVICE="tscan-dispatcher"
CAPTURE_SERVICE="tscan-capture"

# ---------------------------------------------------------------------------
# Stop services (capture first, then dispatcher)
# ---------------------------------------------------------------------------
echo "[+] Stopping services (capture then dispatcher)..."
if systemctl is-active --quiet "${CAPTURE_SERVICE}"; then
  systemctl stop "${CAPTURE_SERVICE}"
fi
if systemctl is-active --quiet "${DISPATCHER_SERVICE}"; then
  systemctl stop "${DISPATCHER_SERVICE}"
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
for SVC in "${DISPATCHER_SERVICE}" "${CAPTURE_SERVICE}"; do
  REPO_UNIT="${APP_DIR}/systemd/${SVC}.service"
  SYSTEM_UNIT="/etc/systemd/system/${SVC}.service"
  if [ ! -f "${SYSTEM_UNIT}" ] || ! diff -q "${REPO_UNIT}" "${SYSTEM_UNIT}" &>/dev/null; then
    echo "[+] ${SVC}.service changed or missing, reinstalling..."
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
# Start services (dispatcher first, then capture)
# ---------------------------------------------------------------------------
echo "[+] Starting services (dispatcher then capture)..."
systemctl start "${DISPATCHER_SERVICE}"
sleep 2
systemctl start "${CAPTURE_SERVICE}"

# ---------------------------------------------------------------------------
# Report status
# ---------------------------------------------------------------------------
echo "[+] Current service status:"
for SVC in "${DISPATCHER_SERVICE}" "${CAPTURE_SERVICE}"; do
  if systemctl --no-pager --quiet is-active "${SVC}"; then
    echo "  - ${SVC}: active"
  else
    echo "  - ${SVC}: NOT active"
  fi
done

echo "[+] Done."
