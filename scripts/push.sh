#!/usr/bin/env bash
# scripts/push.sh - Stage, commit, and push local tscan-ng changes.
#
# Runs every git operation as the tscan service user (the repo at /opt/tscan
# is owned by tscan, not the operator running this script), so the commit
# author and pushed history stay consistent regardless of which admin ran it.
#
# Usage: sudo /opt/tscan/scripts/push.sh "commit message" [file ...]
#   With no file arguments, all changes (including new files) are staged.
set -euo pipefail

# Must be run as root so we can run git as the tscan service user.
if [[ $EUID -ne 0 ]]; then
  echo "[-] This script must be run as root" >&2
  exit 1
fi

SERVICE_USER="tscan"
APP_DIR="/opt/tscan"

# ---------------------------------------------------------------------------
# Commit message (required)
# ---------------------------------------------------------------------------
if [[ $# -lt 1 ]]; then
  echo "Usage: $0 \"commit message\" [file ...]" >&2
  echo "  If no files are given, all changes including new files are staged." >&2
  exit 1
fi

COMMIT_MSG="$1"
shift

# ---------------------------------------------------------------------------
# Stage files
# ---------------------------------------------------------------------------
if [[ $# -gt 0 ]]; then
  echo "[+] Staging specified files..."
  sudo -u "${SERVICE_USER}" -H git -C "${APP_DIR}" add -- "$@"
else
  echo "[+] Staging all changes (including new files)..."
  sudo -u "${SERVICE_USER}" -H git -C "${APP_DIR}" add -A
fi

# ---------------------------------------------------------------------------
# Show what will be committed
# ---------------------------------------------------------------------------
echo "[+] Changes to be committed:"
sudo -u "${SERVICE_USER}" -H git -C "${APP_DIR}" diff --cached --stat

# Abort if nothing staged
if sudo -u "${SERVICE_USER}" -H git -C "${APP_DIR}" diff --cached --quiet; then
  echo "[!] Nothing staged to commit." >&2
  exit 1
fi

# ---------------------------------------------------------------------------
# Commit
# ---------------------------------------------------------------------------
echo "[+] Committing..."
sudo -u "${SERVICE_USER}" -H git -C "${APP_DIR}" commit -m "${COMMIT_MSG}"

# ---------------------------------------------------------------------------
# Push
# ---------------------------------------------------------------------------
echo "[+] Pushing to origin..."
sudo -u "${SERVICE_USER}" -H git -C "${APP_DIR}" push

echo "[+] Done."
