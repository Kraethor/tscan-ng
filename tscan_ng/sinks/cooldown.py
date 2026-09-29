"""
sinks/cooldown.py - Cross-process "at most once per window" rate limiting,
via flock()'d marker files.

Every pipeline_worker process constructs its own sinks independently (there
is no shared memory between them), so any cooldown that needs to coordinate
across all of them has to live on disk. Two callers share this:
  - sinks/discord.py's notify(): one marker file, rate-limiting operational
    alerts (e.g. pipeline_worker exiting) so a sustained outage doesn't send
    one Discord message per RestartSec cycle.
  - pipeline.py's _emit(): one marker file per (dst, dport, creds) key,
    gating whether a finding gets written to JSONLSink/DiscordSink at all,
    so a spammer replaying the same bad credentials at the same service
    doesn't turn into one log line (and one Discord message) per attempt.
"""

import fcntl
import os
import time


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

    Marker files are created on demand and never removed by this module;
    the caller owns cleanup (in practice /run/tscan is tmpfs, cleared at
    reboot or service restart).

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
    try:
        fd = os.open(marker_path, os.O_CREAT | os.O_RDWR, 0o644)
    except OSError:
        return True
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        try:
            st = os.fstat(fd)
            if st.st_size > 0 and time.time() - st.st_mtime < cooldown_sec:
                return False
            os.ftruncate(fd, 0)
            os.write(fd, str(int(time.time())).encode())
            return True
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)
