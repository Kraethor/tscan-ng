#!/usr/bin/env bash
# scripts/push.sh - Stage, commit, and push local tscan-ng changes.
#
# Runs every git operation as the tscan service user (the repo at /opt/tscan
# is owned by tscan, not the operator running this script), so the commit
# author and pushed history stay consistent regardless of which admin ran it.
# The git identity and the deploy-key SSH command come from the repo's own
# .git/config (user.name, user.email, core.sshCommand -- see docs/REBUILD.md
# "Deploy Code"), not from any user's home directory.
#
# Usage:
#   sudo /opt/tscan/scripts/push.sh "commit message" [file ...]
#
# Arguments:
#   commit message   required; passed verbatim to `git commit -m`.
#   file ...         optional; paths staged with `git add -- <file>...`. Paths
#                    are resolved by `git -C /opt/tscan`, i.e. relative to
#                    /opt/tscan, NOT to the caller's working directory.
#                    With no files, everything is staged with `git add -A`
#                    (tracked changes, deletions and new untracked files;
#                    .gitignore still excludes venv/, *.jsonl, tscan_ng.conf,
#                    .ssh/, etc.).
#
# Environment: none read. APP_DIR and SERVICE_USER are set below.
#
# Privileges: must be root (EUID 0), because it uses `sudo -u tscan` to switch
#   to the service user; the script itself refuses to run otherwise.
#
# Exit codes:
#   0  committed and pushed.
#   1  not root; no commit message given; or nothing staged to commit.
#   any other non-zero: `set -e` aborts on the first failing git command
#   (add, commit, push) and the script exits with that command's status.
#   NB: if `commit` succeeds but `push` fails, the commit stays local;
#   re-run `sudo -u tscan -H git -C /opt/tscan push` by hand.
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
