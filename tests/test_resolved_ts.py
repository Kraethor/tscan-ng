"""
Tests for the "ts" field on findings resolved from a pending state
(TODO.md #17). run.py's _try_resolve() returns most findings without "ts";
pipeline._stamp_resolved() must add it (the request time, ts_start) without
overriding a "ts" that is already present.

Run from /opt/tscan:
    PYTHONDONTWRITEBYTECODE=1 venv/bin/python -m unittest discover -s tests -t . -v
"""

import unittest

from tscan_ng import pipeline
from tscan_ng.run import _try_resolve
from tscan_ng.session import Session
from tscan_ng.detectors import ftp

T_REQUEST = 1000.0
T_RESPONSE = 1003.5


class ResolvedTsTests(unittest.TestCase):
    def _resolved_ftp(self) -> dict:
        s = Session("10.0.0.2", "10.0.0.9", 50000, 21)
        s.last_ts = T_REQUEST
        s.client_buf.extend(b"USER alice\r\nPASS hunter2\r\n")
        self.assertEqual(ftp.detect_stream(s, T_REQUEST), [])   # no reply yet: pending
        self.assertEqual(len(s.pending), 1)
        s.server_buf.extend(b"230 Login successful.\r\n")
        return _try_resolve(s.pending[0], s, T_RESPONSE)

    def test_resolved_pending_lacks_ts_before_stamping(self):
        """Documents the source of the bug: _try_resolve does not add ts for ftp."""
        self.assertNotIn("ts", self._resolved_ftp())

    def test_stamp_adds_request_time(self):
        resolved = self._resolved_ftp()
        stamped = pipeline._stamp_resolved(resolved, T_RESPONSE)
        self.assertEqual(stamped["ts"], T_REQUEST)
        self.assertEqual(stamped["ts_start"], T_REQUEST)
        self.assertEqual(stamped["outcome"], "success")

    def test_stamp_keeps_existing_ts(self):
        f = {"ts": 5.0, "ts_start": 7.0, "outcome": "success"}
        self.assertEqual(pipeline._stamp_resolved(f, 99.0)["ts"], 5.0)

    def test_stamp_falls_back_to_packet_time(self):
        self.assertEqual(pipeline._stamp_resolved({"outcome": "x"}, 42.0)["ts"], 42.0)

    def test_stamp_does_not_mutate_input(self):
        f = {"ts_start": 7.0}
        pipeline._stamp_resolved(f, 1.0)
        self.assertNotIn("ts", f)


if __name__ == "__main__":
    unittest.main()
