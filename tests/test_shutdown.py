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
Tests for graceful SIGTERM/SIGINT handling (TODO.md #21). `systemctl stop`
sends SIGTERM; workers must notice it, leave their capture loop, and flush
pending sessions instead of dying with findings still buffered.

Only the signal plumbing is tested here (the capture loop needs a raw
AF_PACKET socket and root); the flush itself is exercised live.

Run from /opt/tscan:
    PYTHONDONTWRITEBYTECODE=1 venv/bin/python -m unittest discover -s tests -t . -v
"""

import os
import signal
import unittest

from tscan_ng import pipeline


class WorkerStopHandlerTests(unittest.TestCase):
    def setUp(self):
        saved = {s: signal.getsignal(s) for s in (signal.SIGTERM, signal.SIGINT)}
        self.addCleanup(lambda: [signal.signal(s, h) for s, h in saved.items()])

    def test_sigterm_sets_stop_flag_without_killing_process(self):
        stop = pipeline._install_worker_stop_handlers()
        self.assertFalse(stop.is_set())
        os.kill(os.getpid(), signal.SIGTERM)
        self.assertTrue(stop.is_set())

    def test_sigint_sets_stop_flag_too(self):
        stop = pipeline._install_worker_stop_handlers()
        os.kill(os.getpid(), signal.SIGINT)      # would raise KeyboardInterrupt by default
        self.assertTrue(stop.is_set())

    def test_repeated_signals_are_harmless(self):
        stop = pipeline._install_worker_stop_handlers()
        os.kill(os.getpid(), signal.SIGTERM)
        os.kill(os.getpid(), signal.SIGTERM)
        self.assertTrue(stop.is_set())


_STRESS_CHILD = r"""
import sys
sys.path.insert(0, "/opt/tscan")
from tscan_ng import pipeline
stop = pipeline._install_worker_stop_handlers()
print("ready", flush=True)
# Keep calling set() so signals routinely land while it is executing; the
# handler then re-enters set() from inside set().
for _ in range(400000):
    stop.set()
print("done", flush=True)
"""


class ReentrantHandlerTests(unittest.TestCase):
    def test_signal_arriving_inside_stop_set_does_not_deadlock(self):
        """
        systemd and main() both send SIGTERM to each worker, so a second
        signal can interrupt the first handler's stop.set(). With a
        threading.Event (non-reentrant internal lock) the nested handler
        blocked forever -- seen in production as workers that had to be
        SIGKILLed after 5 s. The stop flag must be reentrancy-safe.
        """
        import subprocess, sys, threading, time
        child = subprocess.Popen([sys.executable, "-c", _STRESS_CHILD],
                                 stdout=subprocess.PIPE, text=True)
        seen = []
        reader = threading.Thread(
            target=lambda: [seen.append(l.strip()) for l in child.stdout], daemon=True)
        reader.start()
        try:
            deadline = time.monotonic() + 30
            while "ready" not in seen and time.monotonic() < deadline:
                time.sleep(0.01)
            self.assertIn("ready", seen)
            # Hammer the child with SIGTERM until it reports it finished.
            while "done" not in seen and time.monotonic() < deadline:
                child.send_signal(signal.SIGTERM)
                time.sleep(0.0002)
            self.assertIn("done", seen, "child deadlocked in its signal handler")
            child.wait(timeout=10)
        finally:
            if child.poll() is None:
                child.kill()
            child.wait()


class MainShutdownHandlerTests(unittest.TestCase):
    def setUp(self):
        saved = signal.getsignal(signal.SIGTERM)
        self.addCleanup(lambda: signal.signal(signal.SIGTERM, saved))
        pipeline._shutdown_requested = False
        self.addCleanup(lambda: setattr(pipeline, "_shutdown_requested", False))

    def test_sigterm_becomes_keyboard_interrupt_and_marks_shutdown(self):
        pipeline._install_main_shutdown_handler()
        with self.assertRaises(KeyboardInterrupt):
            os.kill(os.getpid(), signal.SIGTERM)   # handler runs before kill() returns
        self.assertTrue(pipeline._shutdown_requested)


if __name__ == "__main__":
    unittest.main()
