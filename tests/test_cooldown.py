"""
Tests for pipeline._emit()'s per-finding cooldown (TODO.md #10).

The sinks are mocks and the marker directory is a temp dir, so nothing is
written to /run/tscan and no alert is sent.

Run from /opt/tscan:
    PYTHONDONTWRITEBYTECODE=1 venv/bin/python -m unittest discover -s tests -t . -v
"""

import tempfile
import unittest
from unittest import mock

from tscan_ng import pipeline

COOLDOWN = 1800


def finding(outcome: str, creds: str = "alice:pw", dst: str = "10.0.0.9", dport: int = 80):
    """A minimal finding dict with the fields the cooldown key uses."""
    return {"type": "http_basic", "dst": dst, "dport": dport,
            "creds": creds, "outcome": outcome}


class EmitCooldownTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        patcher = mock.patch.object(pipeline, "_FINDING_COOLDOWN_DIR", self.tmp.name)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.sink = mock.Mock()
        self.discord = mock.Mock()

    def emit(self, f, cooldown=COOLDOWN):
        pipeline._emit(self.sink, self.discord, f, cooldown)

    def test_identical_repeat_is_suppressed(self):
        self.emit(finding("failed"))
        self.emit(finding("failed"))
        self.assertEqual(self.sink.write.call_count, 1)
        self.assertEqual(self.discord.write.call_count, 1)

    def test_success_after_failed_same_creds_is_emitted(self):
        self.emit(finding("failed"))
        self.emit(finding("success"))
        self.assertEqual([c.args[0]["outcome"] for c in self.sink.write.call_args_list],
                         ["failed", "success"])
        self.assertEqual(self.discord.write.call_count, 2)

    def test_success_after_no_response_same_creds_is_emitted(self):
        self.emit(finding("no_response"))
        self.emit(finding("success"))
        self.assertEqual(self.sink.write.call_count, 2)

    def test_repeat_of_success_is_still_suppressed(self):
        self.emit(finding("success"))
        self.emit(finding("success"))
        self.assertEqual(self.sink.write.call_count, 1)

    def test_different_creds_or_service_not_suppressed(self):
        self.emit(finding("failed"))
        self.emit(finding("failed", creds="bob:pw"))
        self.emit(finding("failed", dport=8080))
        self.assertEqual(self.sink.write.call_count, 3)

    def test_zero_cooldown_emits_everything(self):
        self.emit(finding("failed"), cooldown=0)
        self.emit(finding("failed"), cooldown=0)
        self.assertEqual(self.sink.write.call_count, 2)

    def test_failed_sink_write_does_not_burn_the_window(self):
        self.sink.write.side_effect = [OSError("disk full"), None]
        with self.assertRaises(OSError):
            self.emit(finding("success"))
        self.emit(finding("success"))     # the retry must not be suppressed
        self.assertEqual(self.sink.write.call_count, 2)


if __name__ == "__main__":
    unittest.main()
