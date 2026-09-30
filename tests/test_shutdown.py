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

    def test_sigterm_sets_stop_event_without_killing_process(self):
        stop = pipeline._install_worker_stop_handlers()
        self.assertFalse(stop.is_set())
        os.kill(os.getpid(), signal.SIGTERM)
        self.assertTrue(stop.is_set())

    def test_sigint_sets_stop_event_too(self):
        stop = pipeline._install_worker_stop_handlers()
        os.kill(os.getpid(), signal.SIGINT)      # would raise KeyboardInterrupt by default
        self.assertTrue(stop.is_set())

    def test_repeated_signals_are_harmless(self):
        stop = pipeline._install_worker_stop_handlers()
        os.kill(os.getpid(), signal.SIGTERM)
        os.kill(os.getpid(), signal.SIGTERM)
        self.assertTrue(stop.is_set())


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
