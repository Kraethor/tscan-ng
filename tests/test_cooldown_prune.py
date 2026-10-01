"""
Tests for TODO.md #11: finding-cooldown marker files are pruned.

_emit() leaves one marker file per (dst, dport, creds, outcome) key under
pipeline._FINDING_COOLDOWN_DIR (tmpfs). Without pruning, a password-spraying
scanner adds a file per attempt until the next restart. Markers older than
the cooldown no longer suppress anything, so they can be removed.

Pruning races with claims, so claim_slot() also checks that the file it
locked is still linked: if a pruner unlinked it in the meantime, the claim
is retried on whatever is at the path now, and one key cannot be claimed
twice within a window.

Temp dirs only; nothing is written to /run/tscan.

Run from /opt/tscan:
    PYTHONDONTWRITEBYTECODE=1 venv/bin/python -m unittest discover -s tests -t . -v
"""

import inspect
import os
import tempfile
import time
import unittest
from unittest import mock

from tscan_ng import pipeline
from tscan_ng.sinks import cooldown

COOLDOWN = 1800


def make_marker(directory: str, name: str, age: float, claimed: bool = True) -> str:
    """Create a marker file whose mtime is *age* seconds in the past."""
    path = os.path.join(directory, name)
    with open(path, "w") as f:
        if claimed:
            f.write(str(int(time.time() - age)))
    then = time.time() - age
    os.utime(path, (then, then))
    return path


class PruneMarkersTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = self.tmp.name

    def test_old_markers_removed_fresh_kept(self):
        make_marker(self.dir, "old1", COOLDOWN + 10)
        make_marker(self.dir, "old2", COOLDOWN * 3)
        make_marker(self.dir, "fresh", 5)
        make_marker(self.dir, "new-empty", 0, claimed=False)
        removed = cooldown.prune_markers(self.dir, COOLDOWN)
        self.assertEqual(removed, 2)
        self.assertEqual(sorted(os.listdir(self.dir)), ["fresh", "new-empty"])

    def test_pruned_key_can_be_claimed_again(self):
        path = make_marker(self.dir, "k", COOLDOWN + 10)
        cooldown.prune_markers(self.dir, COOLDOWN)
        self.assertTrue(cooldown.claim_slot(path, COOLDOWN))
        self.assertFalse(cooldown.claim_slot(path, COOLDOWN))

    def test_missing_directory_is_not_an_error(self):
        self.assertEqual(cooldown.prune_markers(os.path.join(self.dir, "nope"), COOLDOWN), 0)

    def test_subdirectories_are_left_alone(self):
        os.mkdir(os.path.join(self.dir, "sub"))
        old = time.time() - COOLDOWN * 2
        os.utime(os.path.join(self.dir, "sub"), (old, old))
        self.assertEqual(cooldown.prune_markers(self.dir, COOLDOWN), 0)
        self.assertEqual(os.listdir(self.dir), ["sub"])

    def test_marker_refreshed_under_the_lock_is_kept(self):
        # The pruner saw an old mtime, but by the time it holds the lock a
        # claim has refreshed the marker: it must re-check and keep it.
        path = make_marker(self.dir, "k", COOLDOWN + 10)
        real_flock = cooldown.fcntl.flock

        def flock_then_refresh(fd, op):
            real_flock(fd, op)
            if op == cooldown.fcntl.LOCK_EX:
                os.utime(path, None)

        with mock.patch.object(cooldown.fcntl, "flock", side_effect=flock_then_refresh):
            self.assertEqual(cooldown.prune_markers(self.dir, COOLDOWN), 0)
        self.assertTrue(os.path.exists(path))


class ClaimAfterUnlinkTests(unittest.TestCase):
    def test_claim_retries_when_its_file_was_unlinked(self):
        # Interleaving: this claim opens the expired marker; before it gets
        # the lock, a pruner unlinks it and another worker creates a new
        # marker at the same path and claims it. Claiming the orphaned inode
        # would emit the key twice in one window.
        with tempfile.TemporaryDirectory() as d:
            path = make_marker(d, "k", COOLDOWN + 10)
            real_open = os.open
            calls = []

            def open_then_race(p, flags, mode=0o777):
                fd = real_open(p, flags, mode)
                if not calls:
                    os.unlink(p)
                    make_marker(d, "k", 1)        # the other worker's fresh claim
                calls.append(p)
                return fd

            with mock.patch.object(cooldown.os, "open", side_effect=open_then_race):
                self.assertFalse(cooldown.claim_slot(path, COOLDOWN))
            self.assertEqual(len(calls), 2)


class PipelinePruneTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        patcher = mock.patch.object(pipeline, "_FINDING_COOLDOWN_DIR", self.tmp.name)
        patcher.start()
        self.addCleanup(patcher.stop)
        make_marker(self.tmp.name, "old", COOLDOWN + 10)

    def test_worker_zero_prunes(self):
        pipeline._prune_finding_cooldown(0, COOLDOWN)
        self.assertEqual(os.listdir(self.tmp.name), [])

    def test_other_workers_do_not(self):
        pipeline._prune_finding_cooldown(3, COOLDOWN)
        self.assertEqual(os.listdir(self.tmp.name), ["old"])

    def test_disabled_cooldown_does_nothing(self):
        pipeline._prune_finding_cooldown(0, 0)
        self.assertEqual(os.listdir(self.tmp.name), ["old"])

    def test_periodic_maintenance_calls_it(self):
        source = inspect.getsource(pipeline._maybe_run_periodic)
        self.assertIn("_prune_finding_cooldown(", source)


if __name__ == "__main__":
    unittest.main()
