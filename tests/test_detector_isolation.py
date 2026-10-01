"""
Tests for TODO.md #59: one detector raising must not take the others down.

detectors.run_detectors() calls every detector for a packet and isolates
each one: an exception is logged, the remaining detectors still run, and
the detector that raised is not offered that session again (its buffer is
in a state it cannot handle, so it would raise on every later packet).
resolve.resolve_pending() isolates each pending finding the same way; a
finding whose resolver raised stays pending and is closed as no_response.

Run from /opt/tscan:
    PYTHONDONTWRITEBYTECODE=1 venv/bin/python -m unittest discover -s tests -t . -v
"""

import inspect
import unittest
from unittest import mock

from tscan_ng import detectors, pipeline, resolve
from tscan_ng.detectors import ftp
from tscan_ng.session import Session

TS = 1000.0


def make_session(dport: int = 21, sport: int = 50000) -> Session:
    """A client 10.0.0.2:<sport> talking to server 10.0.0.9:<dport>."""
    s = Session("10.0.0.2", "10.0.0.9", sport, dport)
    s.last_ts = TS
    return s


class Boom:
    """A detector/resolver stand-in that counts its calls and always raises."""

    def __init__(self):
        self.calls = 0

    def __call__(self, *args):
        self.calls += 1
        raise ValueError("boom")


class DetectorIsolationTests(unittest.TestCase):
    def setUp(self):
        self.boom = Boom()
        patcher = mock.patch.object(detectors, "STREAM_DETECTORS",
                                    [self.boom, ftp.detect_stream])
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_later_detectors_still_run(self):
        s = make_session()
        s.client_buf.extend(b"USER bob\r\nPASS pw1\r\n")
        with self.assertLogs(level="ERROR") as logs:
            out = detectors.run_detectors(s, TS)
        self.assertEqual(out, [])
        self.assertEqual([p.finding["creds"] for p in s.pending], ["bob:pw1"])
        self.assertIn(s.session_id, logs.output[0])
        self.assertIn("ValueError: boom", logs.output[0])

    def test_failed_detector_is_skipped_for_that_session_only(self):
        s, other = make_session(), make_session(sport=50001)
        with self.assertLogs(level="ERROR"):
            detectors.run_detectors(s, TS)
        with self.assertNoLogs(level="ERROR"):
            detectors.run_detectors(s, TS)
        self.assertEqual(self.boom.calls, 1)
        with self.assertLogs(level="ERROR"):
            detectors.run_detectors(other, TS)
        self.assertEqual(self.boom.calls, 2)

    def test_capture_loop_uses_run_detectors(self):
        source = inspect.getsource(pipeline._capture_loop)
        self.assertIn("run_detectors(", source)
        self.assertNotIn("STREAM_DETECTORS", source)


class ResolverIsolationTests(unittest.TestCase):
    def setUp(self):
        self.boom = Boom()
        patcher = mock.patch.dict(resolve.RESOLVERS, {"boom_creds": self.boom})
        patcher.start()
        self.addCleanup(patcher.stop)

    def session_with_two_pending(self) -> Session:
        s = make_session()
        s.add_pending({"type": "boom_creds", "creds": "x:y"}, TS)
        s.client_buf.extend(b"USER bob\r\nPASS pw1\r\n")
        ftp.detect_stream(s, TS)
        s.server_buf.extend(b"230 ok\r\n")
        return s

    def test_other_pending_findings_still_resolve(self):
        s = self.session_with_two_pending()
        with self.assertLogs(level="ERROR") as logs:
            done = resolve.resolve_pending(s, TS + 1)
        self.assertEqual([(f["type"], f["outcome"]) for f in done],
                         [("ftp_creds", "success")])
        self.assertEqual([p.finding["type"] for p in s.pending], ["boom_creds"])
        self.assertIn("ValueError: boom", logs.output[0])

    def test_failed_finding_is_not_retried_and_closes_as_no_response(self):
        s = self.session_with_two_pending()
        with self.assertLogs(level="ERROR"):
            resolve.resolve_pending(s, TS + 1)
        with self.assertNoLogs(level="ERROR"):
            self.assertEqual(resolve.resolve_pending(s, TS + 2), [])
        self.assertEqual(self.boom.calls, 1)
        closed = s.expire_pending(TS + 100, 45)
        self.assertEqual([(f["creds"], f["outcome"]) for f in closed],
                         [("x:y", "no_response")])


if __name__ == "__main__":
    unittest.main()
