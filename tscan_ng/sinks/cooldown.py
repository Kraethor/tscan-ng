# Copyright (C) 2026 Kraethor
#
# This file is part of tscan-ng.
#
# tscan-ng is free software: you can redistribute it and/or modify it under
# the terms of the GNU General Public License as published by the Free
# Software Foundation, version 3.
#
# tscan-ng is distributed in the hope that it will be useful, but WITHOUT ANY
# WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along with
# tscan-ng. If not, see <https://www.gnu.org/licenses/>.
#
# Additional term under GPLv3 section 7(b): if you convey this work or a
# modified version of it, you must preserve the attribution "Based on tscan-ng
# by Kraethor (https://github.com/Kraethor/tscan-ng)" in the source and in any
# user-facing output or accompanying documentation.
#
# SPDX-License-Identifier: GPL-3.0-only

"""
sinks/cooldown.py - Cross-process "at most once per window" rate limiting,
via flock()'d marker files.

Every pipeline_worker process constructs its own sinks independently (there
is no shared memory between them), so any cooldown that needs to coordinate
across all of them has to live on disk. Two callers share this:
  - sinks/discord.py's notify(): one marker file, rate-limiting operational
    alerts (e.g. pipeline_worker exiting) so a sustained outage doesn't send
    one Discord message per RestartSec cycle.
  - pipeline.py's _emit(): one marker file per (dst, dport, creds, outcome) key,
    gating whether a finding gets written to JSONLSink/DiscordSink at all,
    so a spammer replaying the same bad credentials at the same service
    doesn't turn into one log line (and one Discord message) per attempt.
    Those markers accumulate one per distinct key, so pipeline.py removes
    expired ones with prune_markers() (TODO.md #11).
"""

import fcntl
import os
import time

# How many times claim_slot() reopens a marker that was unlinked (pruned)
# between its open() and its lock before giving up and failing open.
_CLAIM_ATTEMPTS = 3


def claim_slot(marker_path: str, cooldown_sec: float) -> bool:
    """
    Return True if the caller may act right now, False if this marker_path
    was already claimed within the last cooldown_sec (by this process or
    any other process sharing marker_path).

    Uses flock() around a read-modify-write of the marker file's mtime for
    atomicity, the same pattern sinks/jsonl.py uses for write safety across
    multiple pipeline_worker processes -- local filesystem only, per that
    module's documented NFS caveat. A file's mtime (rather than its
    contents) is the timestamp of record: any write bumps it, so claiming
    the slot is just "write one byte while holding the lock". An empty file
    (O_CREAT just created it, nothing written yet) means "never claimed" and
    always succeeds regardless of its just-created mtime -- without this, a
    brand new marker's mtime is "now", which is indistinguishable from "an
    alert was just sent" and would wrongly deny the very first claim.

    Marker files are created on demand; removing expired ones is the
    caller's job, with prune_markers() (TODO.md #11). Because a pruner can
    unlink the file between this function's open() and its lock, the locked
    file is checked to still be linked (st_nlink > 0); if it is not, the
    claim is retried on whatever is at marker_path now (a few times, then it
    fails open). Without that, a claim on the orphaned inode and a claim on
    a newly created marker could both succeed within one window.

    Fails open (returns True) if the marker file can't be opened at all --
    a missing/unwritable state directory should never be the reason a real
    alert silently never gets sent, or a real finding silently never gets
    logged.

    Args:
        marker_path:  Path to the shared marker file.
        cooldown_sec: Minimum seconds between claims. 0 always claims.

    Returns:
        True if this call claimed the slot and the caller should act; False
        if still within another call's cooldown window.

    Raises:
        OSError: If flock/ftruncate/write fail after a successful open
            (only the open itself fails open). The fd is always closed.
    """
    for _ in range(_CLAIM_ATTEMPTS):
        try:
            fd = os.open(marker_path, os.O_CREAT | os.O_RDWR, 0o644)
        except OSError:
            return True
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            try:
                st = os.fstat(fd)
                if st.st_nlink == 0:
                    continue  # pruned while we waited; reopen the path
                if st.st_size > 0 and time.time() - st.st_mtime < cooldown_sec:
                    return False
                os.ftruncate(fd, 0)
                os.write(fd, str(int(time.time())).encode())
                return True
            finally:
                fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)
    return True


def prune_markers(directory: str, max_age_sec: float) -> int:
    """
    Delete marker files in *directory* last claimed more than max_age_sec ago.

    A marker older than the cooldown no longer suppresses anything (the next
    claim_slot() on it succeeds), so removing it changes no decision; it
    only stops the directory growing by one file per distinct key for as
    long as the service runs (TODO.md #11). Pass the cooldown the markers
    were claimed with.

    Each candidate is re-checked while holding its flock: a claim that
    refreshed it after the directory scan keeps it. The unlink happens under
    the lock, and claim_slot() notices an unlinked file and reopens the
    path, so pruning cannot let a key be claimed twice in one window.

    Only regular files directly in *directory* are considered. Errors on
    individual files (already gone, permission) are skipped; a missing or
    unreadable directory prunes nothing.

    Args:
        directory:   Marker directory (e.g. pipeline._FINDING_COOLDOWN_DIR).
        max_age_sec: Age in seconds (by mtime) beyond which a marker is removed.

    Returns:
        Number of markers removed.
    """
    removed = 0
    try:
        entries = list(os.scandir(directory))
    except OSError:
        return 0
    for entry in entries:
        try:
            if not entry.is_file(follow_symlinks=False):
                continue
            if time.time() - entry.stat(follow_symlinks=False).st_mtime <= max_age_sec:
                continue
            fd = os.open(entry.path, os.O_RDWR | os.O_NOFOLLOW)
        except OSError:
            continue
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            try:
                st = os.fstat(fd)
                if st.st_nlink > 0 and time.time() - st.st_mtime > max_age_sec:
                    os.unlink(entry.path)
                    removed += 1
            finally:
                fcntl.flock(fd, fcntl.LOCK_UN)
        except OSError:
            pass
        finally:
            os.close(fd)
    return removed
