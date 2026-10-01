#!/usr/bin/env bash
# scripts/update.sh - Deploy the latest tscan-ng code and restart the service,
# rolling back if the new code does not come up (TODO.md #20).
#
# The pipeline keeps running until the new code has been pulled and checked,
# and is only restarted once. Steps, in order:
#   1. Record the current commit (HEAD) as the rollback point.
#   2. `git pull --ff-only` as the tscan user (deploy key via the repo's own
#      core.sshCommand). The service keeps running.
#   3. If requirements.txt and the venv exist, `pip install --upgrade -r
#      requirements.txt` as tscan (venv/bin/pip directly, no login shell).
#   4. Pre-flight against the new code, as tscan: the unit tests, then import
#      the pipeline and load + validate the live config (tscan_ng.config).
#      If any of 2-4 fails, the checkout and venv are put back to the
#      rollback point and the script exits 2. The running service was never
#      touched.
#   5. Install each unit in UNITS from systemd/ into the unit dir if missing
#      or different (`install -m 0644`; old copies are kept for rollback),
#      then `systemctl daemon-reload` if any changed.
#   6. `systemctl restart` the pipeline and `enable --now` the healthcheck timer.
#   7. Verify: after HEALTH_WAIT seconds the pipeline must be "active" and
#      systemd must not have auto-restarted it (NRestarts unchanged). A
#      Type=simple service reports active the moment it is started, so only
#      a later check shows whether it stayed up.
#      If verification fails, the checkout, venv and units are rolled back,
#      the pipeline is restarted on the old code and verified again.
#   Any unexpected failure after step 2 also triggers the rollback (EXIT trap).
#
# NOT handled by this script (do these by hand, see docs/REBUILD.md):
#   - logrotate/tscan -> /etc/logrotate.d/tscan
#   - systemd/tscan-monitor.network.example -> /etc/systemd/network/
#   - edits to tscan_ng/config/tscan_ng.conf (gitignored, host-specific).
#
# Usage:  sudo /opt/tscan/scripts/update.sh        (no arguments)
#
# Environment (all optional; for tests/tests/test_update_sh.py, which runs
# the script against stubs):
#   TSCAN_APP_DIR      repo checkout             (default /opt/tscan)
#   TSCAN_UNIT_DIR     systemd unit directory    (default /etc/systemd/system)
#   TSCAN_HEALTH_WAIT  seconds to wait before verifying (default 15)
#
# Privileges: must be root (checked with `id -u`): it restarts services,
#   writes into the unit directory and runs git/pip/python as tscan via sudo.
#   pip runs as tscan, so if the venv is not writable by tscan an install
#   that actually changes a package fails (and is rolled back).
#
# Exit codes:
#   0  updated, and the pipeline stayed up.
#   1  not run as root.
#   2  pull, pip or pre-flight failed; checkout restored, service untouched.
#   3  the new code did not stay up; rolled back and the old code is running.
#   4  rollback failed too: the pipeline is DOWN. Check `journalctl -u tscan-pipeline`.
set -uo pipefail

if [[ "$(id -u)" -ne 0 ]]; then
  echo "[-] This script must be run as root" >&2
  exit 1
fi

SERVICE_USER="tscan"
APP_DIR="${TSCAN_APP_DIR:-/opt/tscan}"
UNIT_DIR="${TSCAN_UNIT_DIR:-/etc/systemd/system}"
HEALTH_WAIT="${TSCAN_HEALTH_WAIT:-15}"
PIPELINE_SERVICE="tscan-pipeline"
HEALTHCHECK_TIMER="tscan-pipeline-healthcheck.timer"
# Units installed from ${APP_DIR}/systemd/ into the unit directory. The
# healthcheck .service is oneshot and only ever started by its .timer, so it
# is installed but never enabled or started directly here.
UNITS=("tscan-pipeline.service" "tscan-pipeline-healthcheck.service" "tscan-pipeline-healthcheck.timer")
PYTHON="${APP_DIR}/venv/bin/python"

as_tscan() { sudo -u "${SERVICE_USER}" -H "$@"; }
git_tscan() { as_tscan git -C "${APP_DIR}" "$@"; }

# State for rollback. CODE_CHANGED: the checkout may differ from OLD_HEAD.
# INSTALLED_UNITS: units replaced in UNIT_DIR (originals in UNIT_BACKUP,
# or marked missing). FINISHED: a deliberate exit; the EXIT trap does nothing.
CODE_CHANGED=0
FINISHED=0
INSTALLED_UNITS=()
UNIT_BACKUP="$(mktemp -d)"

pip_install() {
  if [[ -f "${APP_DIR}/requirements.txt" && -x "${APP_DIR}/venv/bin/pip" ]]; then
    echo "[+] Installing requirements into the venv as ${SERVICE_USER}..."
    as_tscan env PIP_NO_CACHE_DIR=1 "${APP_DIR}/venv/bin/pip" install --quiet \
      --upgrade -r "${APP_DIR}/requirements.txt"
  else
    echo "[+] No requirements.txt or venv, skipping dependency update."
  fi
}

preflight() {
  echo "[+] Pre-flight: unit tests..."
  as_tscan env --chdir="${APP_DIR}" PYTHONDONTWRITEBYTECODE=1 \
    "${PYTHON}" -m unittest discover -s tests -t . -q || return 1
  echo "[+] Pre-flight: import pipeline, load and validate config..."
  as_tscan env --chdir="${APP_DIR}" PYTHONDONTWRITEBYTECODE=1 \
    "${PYTHON}" -c 'import tscan_ng.pipeline; from tscan_ng.config import Config; Config()' \
    || return 1
}

install_units() {
  local unit repo_unit system_unit
  for unit in "${UNITS[@]}"; do
    repo_unit="${APP_DIR}/systemd/${unit}"
    system_unit="${UNIT_DIR}/${unit}"
    if [[ -f "${system_unit}" ]] && cmp -s "${repo_unit}" "${system_unit}"; then
      continue
    fi
    echo "[+] ${unit} changed or missing, installing..."
    if [[ -f "${system_unit}" ]]; then
      cp -p "${system_unit}" "${UNIT_BACKUP}/${unit}" || return 1
    else
      : > "${UNIT_BACKUP}/${unit}.missing"
    fi
    INSTALLED_UNITS+=("${unit}")
    install -m 0644 "${repo_unit}" "${system_unit}" || return 1
  done
  if (( ${#INSTALLED_UNITS[@]} )); then
    echo "[+] Reloading systemd..."
    systemctl daemon-reload || return 1
  else
    echo "[+] systemd units unchanged."
  fi
}

restore_units() {
  local unit
  (( ${#INSTALLED_UNITS[@]} )) || return 0
  for unit in "${INSTALLED_UNITS[@]}"; do
    if [[ -e "${UNIT_BACKUP}/${unit}.missing" ]]; then
      rm -f "${UNIT_DIR}/${unit}"
    elif ! cmp -s "${UNIT_BACKUP}/${unit}" "${UNIT_DIR}/${unit}"; then
      # (Skipped when the install never replaced it, e.g. it failed.)
      install -m 0644 "${UNIT_BACKUP}/${unit}" "${UNIT_DIR}/${unit}" || return 1
    fi
  done
  INSTALLED_UNITS=()
  systemctl daemon-reload
}

# Restart the pipeline and check it stays up for HEALTH_WAIT seconds.
restart_and_verify() {
  local before after state
  systemctl restart "${PIPELINE_SERVICE}" || return 1
  before="$(systemctl show -p NRestarts --value "${PIPELINE_SERVICE}")"
  sleep "${HEALTH_WAIT}"
  state="$(systemctl is-active "${PIPELINE_SERVICE}")"
  after="$(systemctl show -p NRestarts --value "${PIPELINE_SERVICE}")"
  echo "  - ${PIPELINE_SERVICE}: ${state} after ${HEALTH_WAIT}s (automatic restarts: ${before} -> ${after})"
  [[ "${state}" == "active" && "${after}" == "${before}" ]]
}

# Put the checkout (and venv) back to OLD_HEAD. `reset --keep` refuses to
# discard local modifications, unlike --hard.
restore_code() {
  (( CODE_CHANGED )) || return 0
  echo "[!] Restoring checkout to ${OLD_HEAD}..."
  git_tscan reset --keep "${OLD_HEAD}" || return 1
  CODE_CHANGED=0
  pip_install
}

finish() { FINISHED=1; rm -rf "${UNIT_BACKUP}"; exit "$1"; }

abort_preflight() {
  echo "[-] $1; the running service was not touched." >&2
  if ! restore_code; then
    echo "[-] Could not restore the checkout to ${OLD_HEAD}; the service still runs the old code, but the next restart would load what is on disk." >&2
  fi
  finish 2
}

rollback_after_restart() {
  echo "[-] $1. Rolling back to ${OLD_HEAD}..." >&2
  if restore_code && restore_units && restart_and_verify; then
    echo "[!] Rolled back: ${PIPELINE_SERVICE} is running the previous code (${OLD_HEAD})." >&2
    finish 3
  fi
  echo "[-] ROLLBACK FAILED: ${PIPELINE_SERVICE} is DOWN or unstable. Check: journalctl -u ${PIPELINE_SERVICE}" >&2
  finish 4
}

# Unexpected failure (a command not checked below) after the pull: roll back.
on_exit() {
  local rc=$?
  (( FINISHED )) && return
  rm -rf "${UNIT_BACKUP}"
  if (( CODE_CHANGED )) || (( ${#INSTALLED_UNITS[@]} )); then
    echo "[-] update.sh stopped unexpectedly (exit ${rc}); rolling back..." >&2
    FINISHED=1
    restore_code && restore_units && restart_and_verify && exit 3
    echo "[-] ROLLBACK FAILED: ${PIPELINE_SERVICE} may be DOWN. Check: journalctl -u ${PIPELINE_SERVICE}" >&2
    exit 4
  fi
}
trap on_exit EXIT

# ---------------------------------------------------------------------------
OLD_HEAD="$(git_tscan rev-parse HEAD)" || { echo "[-] git rev-parse failed" >&2; finish 2; }
echo "[+] Current commit: ${OLD_HEAD}"

echo "[+] Updating repository as ${SERVICE_USER} in ${APP_DIR}..."
CODE_CHANGED=1
git_tscan pull --ff-only || abort_preflight "git pull failed"
NEW_HEAD="$(git_tscan rev-parse HEAD)"
echo "[+] Now at: ${NEW_HEAD}"

pip_install || abort_preflight "pip install failed"
preflight || abort_preflight "pre-flight checks failed"

install_units || rollback_after_restart "installing systemd units failed"

echo "[+] Restarting ${PIPELINE_SERVICE}..."
restart_and_verify || rollback_after_restart "${PIPELINE_SERVICE} did not stay up on ${NEW_HEAD}"
systemctl enable --now "${HEALTHCHECK_TIMER}" >/dev/null || \
  echo "[!] Could not enable ${HEALTHCHECK_TIMER}; the pipeline itself is up." >&2

echo "[+] Done: ${PIPELINE_SERVICE} is up on ${NEW_HEAD}."
finish 0
