"""
Tests for telnet login-outcome detection (TODO.md #15).

The outcome text used to be searched over the ENTIRE server stream and never
consumed, so a "Welcome to ..." banner before the login prompt made any
password report success, and once a failure had been seen every later attempt
on the connection was reported as failed.

Run from /opt/tscan:
    PYTHONDONTWRITEBYTECODE=1 venv/bin/python -m unittest discover -s tests -t . -v
"""

import unittest

from tscan_ng.session import Session
from tscan_ng import resolve as resolve_mod
from tscan_ng.detectors import telnet

TS = 1000.0
BANNER = b"Welcome to Acme Router OS 4.2\r\n"
PROMPTS = b"login: Password: "


def make_session() -> Session:
    s = Session("10.0.0.2", "10.0.0.9", 50000, 23)
    s.last_ts = TS
    return s


def resolve(session: Session) -> list:
    """Resolve pending findings against what is buffered now."""
    return resolve_mod.resolve_pending(session, TS + 1)


def detect(session: Session, ts: float = TS) -> list:
    """What pipeline.py emits for one packet: run the detector, then resolve."""
    telnet.detect_stream(session, ts)
    return resolve_mod.resolve_pending(session, ts)


class TelnetOutcomeTests(unittest.TestCase):
    def test_prelogin_welcome_banner_is_not_success(self):
        s = make_session()
        s.server_buf.extend(BANNER + PROMPTS)
        s.client_buf.extend(b"admin\r\nwrongpass\r\n")
        self.assertEqual(detect(s, TS), [])      # no verdict yet
        self.assertEqual(len(s.pending), 1)
        s.server_buf.extend(b"\r\nLogin incorrect\r\n")
        self.assertEqual([f["outcome"] for f in resolve(s)], ["failed"])

    def test_success_after_password_is_reported(self):
        s = make_session()
        s.server_buf.extend(BANNER + PROMPTS)
        s.client_buf.extend(b"admin\r\nhunter2\r\n")
        self.assertEqual(detect(s, TS), [])
        s.server_buf.extend(b"\r\nLast login: Mon Sep 28 from 10.0.0.2\r\n")
        self.assertEqual([f["outcome"] for f in resolve(s)], ["success"])

    def test_immediate_outcome_when_response_already_buffered(self):
        s = make_session()
        s.server_buf.extend(BANNER + PROMPTS + b"\r\nLast login: Mon\r\n")
        s.client_buf.extend(b"admin\r\nhunter2\r\n")
        out = detect(s, TS)
        self.assertEqual([(f["creds"], f["outcome"]) for f in out],
                         [("admin:hunter2", "success")])

    def test_retry_after_failure_is_judged_on_its_own_response(self):
        s = make_session()
        # attempt 1 fails
        s.server_buf.extend(PROMPTS)
        s.client_buf.extend(b"admin\r\nbad\r\n")
        detect(s, TS)
        s.server_buf.extend(b"\r\nLogin incorrect\r\n\r\n")
        self.assertEqual([f["outcome"] for f in resolve(s)], ["failed"])
        # attempt 2 succeeds: must not be poisoned by attempt 1's failure text
        s.server_buf.extend(PROMPTS)
        s.client_buf.extend(b"admin\r\ngood\r\n")
        self.assertEqual(detect(s, TS + 2), [])
        s.server_buf.extend(b"\r\nLast login: Mon\r\n")
        done = resolve(s)
        self.assertEqual([(f["creds"], f["outcome"]) for f in done],
                         [("admin:good", "success")])

    def test_resolved_outcome_is_consumed_from_server_buf(self):
        s = make_session()
        s.server_buf.extend(PROMPTS)
        s.client_buf.extend(b"admin\r\nbad\r\n")
        detect(s, TS)
        s.server_buf.extend(b"\r\nLogin incorrect\r\n")
        resolve(s)
        self.assertNotIn(b"Login incorrect", bytes(s.server_buf))


if __name__ == "__main__":
    unittest.main()
