"""
Regression tests for detector parsing bugs (TODO.md #1 postgres, #2 http_basic,
#3 irc).

Each test drives a detector the same way pipeline.py does: bytes are appended
to a Session's client_buf/server_buf and detect_stream() is called after each
step; pending findings are then resolved with run._try_resolve(). No network,
no root and no config file are needed.

Run from /opt/tscan:
    PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -t . -v
"""

import struct
import unittest

from tscan_ng.session import Session
from tscan_ng.run import _try_resolve
from tscan_ng.detectors import postgres, http_basic, irc

TS = 1000.0


def make_session(dport: int) -> Session:
    """A client 10.0.0.2:50000 talking to server 10.0.0.9:<dport>."""
    s = Session("10.0.0.2", "10.0.0.9", 50000, dport)
    s.last_ts = TS
    return s


def resolve_pending(session: Session) -> list:
    """Run _try_resolve over every pending finding, as pipeline.py does."""
    done, still = [], []
    for p in session.pending:
        r = _try_resolve(p, session, TS + 1)
        (done if r else still).append(r or p)
    session.pending = still
    return done


# --------------------------------------------------------------------------
# #1 PostgreSQL
# --------------------------------------------------------------------------

def pg_startup(params: bytes) -> bytes:
    """StartupMessage: Int32 length, Int32 version 3.0, key/value NULs, NUL."""
    body = struct.pack(">I", 0x00030000) + params + b"\x00"
    return struct.pack(">I", 4 + len(body)) + body


def pg_password(pw: bytes) -> bytes:
    """PasswordMessage: 'p', Int32 length, password, NUL."""
    return b"p" + struct.pack(">I", 4 + len(pw) + 1) + pw + b"\x00"


PG_AUTH_CLEARTEXT = b"R" + struct.pack(">II", 8, 3)
PG_AUTH_OK = b"R" + struct.pack(">II", 8, 0)
PG_STARTUP_P = pg_startup(
    b"user\x00postgres\x00database\x00postgres\x00application_name\x00psql\x00")


class PostgresTests(unittest.TestCase):
    def test_password_found_when_startup_contains_p(self):
        s = make_session(5432)
        s.client_buf.extend(PG_STARTUP_P + pg_password(b"s3cret"))
        s.server_buf.extend(PG_AUTH_CLEARTEXT + PG_AUTH_OK)
        out = postgres.detect_stream(s, TS)
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["creds"], "postgres:s3cret")
        self.assertEqual(out[0]["outcome"], "success")

    def test_password_found_without_p_in_startup(self):
        s = make_session(5432)
        s.client_buf.extend(pg_startup(b"user\x00bob\x00") + pg_password(b"pw"))
        s.server_buf.extend(PG_AUTH_CLEARTEXT + PG_AUTH_OK)
        out = postgres.detect_stream(s, TS)
        self.assertEqual([f["creds"] for f in out], ["bob:pw"])

    def test_ssl_request_before_startup(self):
        s = make_session(5432)
        ssl_request = struct.pack(">II", 8, 80877103)
        s.client_buf.extend(ssl_request + PG_STARTUP_P + pg_password(b"pw2"))
        s.server_buf.extend(PG_AUTH_CLEARTEXT + PG_AUTH_OK)
        out = postgres.detect_stream(s, TS)
        self.assertEqual([f["creds"] for f in out], ["postgres:pw2"])

    def test_truncated_password_message_waits_then_completes(self):
        s = make_session(5432)
        msg = pg_password(b"longerpassword")
        s.client_buf.extend(PG_STARTUP_P + msg[:8])
        s.server_buf.extend(PG_AUTH_CLEARTEXT + PG_AUTH_OK)
        self.assertEqual(postgres.detect_stream(s, TS), [])
        s.client_buf.extend(msg[8:])
        out = postgres.detect_stream(s, TS)
        self.assertEqual([f["creds"] for f in out], ["postgres:longerpassword"])

    def test_pending_then_resolved(self):
        s = make_session(5432)
        s.client_buf.extend(PG_STARTUP_P + pg_password(b"pw"))
        s.server_buf.extend(PG_AUTH_CLEARTEXT)
        self.assertEqual(postgres.detect_stream(s, TS), [])
        self.assertEqual(len(s.pending), 1)
        s.server_buf.extend(PG_AUTH_OK)
        done = resolve_pending(s)
        self.assertEqual([f["outcome"] for f in done], ["success"])


# --------------------------------------------------------------------------
# #2 HTTP Basic
# --------------------------------------------------------------------------

REQ_NOAUTH = b"GET /admin HTTP/1.1\r\nHost: example.test\r\n\r\n"
REQ_AUTH = (b"GET /admin HTTP/1.1\r\nHost: example.test\r\n"
            b"Authorization: Basic YWxpY2U6aHVudGVyMg==\r\n\r\n")  # alice:hunter2
RSP_401 = b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n"
RSP_200 = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"


class HttpBasicTests(unittest.TestCase):
    def test_browser_flow_retry_gets_its_own_response(self):
        """no-auth request -> 401 -> retry with credentials -> 200."""
        s = make_session(80)
        s.client_buf.extend(REQ_NOAUTH)
        self.assertEqual(http_basic.detect_stream(s, TS), [])
        s.server_buf.extend(RSP_401)
        self.assertEqual(http_basic.detect_stream(s, TS), [])
        s.client_buf.extend(REQ_AUTH)
        # The 200 has not arrived: must NOT resolve against the stale 401.
        self.assertEqual(http_basic.detect_stream(s, TS), [])
        self.assertEqual(len(s.pending), 1)
        s.server_buf.extend(RSP_200)
        done = resolve_pending(s)
        self.assertEqual([(f["status"], f["outcome"]) for f in done],
                         [(200, "success")])
        self.assertEqual(done[0]["creds"], "alice:hunter2")
        self.assertNotIn("_rsp_index", done[0])

    def test_browser_flow_both_responses_already_buffered(self):
        s = make_session(80)
        s.client_buf.extend(REQ_NOAUTH + REQ_AUTH)
        s.server_buf.extend(RSP_401 + RSP_200)
        out = http_basic.detect_stream(s, TS)
        self.assertEqual([(f["status"], f["outcome"]) for f in out],
                         [(200, "success")])
        self.assertNotIn("_rsp_index", out[0])

    def test_responses_arrive_after_both_requests(self):
        s = make_session(80)
        s.client_buf.extend(REQ_NOAUTH + REQ_AUTH)
        self.assertEqual(http_basic.detect_stream(s, TS), [])
        s.server_buf.extend(RSP_401)
        self.assertEqual(resolve_pending(s), [])   # 401 belongs to request 0
        s.server_buf.extend(RSP_200)
        done = resolve_pending(s)
        self.assertEqual([f["outcome"] for f in done], ["success"])

    def test_credentialed_first_request_still_fails_on_401(self):
        s = make_session(80)
        s.client_buf.extend(REQ_AUTH)
        s.server_buf.extend(RSP_401)
        out = http_basic.detect_stream(s, TS)
        self.assertEqual([(f["status"], f["outcome"]) for f in out],
                         [(401, "failed")])

    def test_two_credentialed_requests_keep_alive(self):
        s = make_session(80)
        s.client_buf.extend(REQ_AUTH)
        s.server_buf.extend(RSP_401)
        first = http_basic.detect_stream(s, TS)
        s.client_buf.extend(REQ_AUTH)
        s.server_buf.extend(RSP_200)
        second = http_basic.detect_stream(s, TS)
        self.assertEqual([f["outcome"] for f in first], ["failed"])
        self.assertEqual([f["outcome"] for f in second], ["success"])


# --------------------------------------------------------------------------
# #3 IRC
# --------------------------------------------------------------------------

class IrcTests(unittest.TestCase):
    def _run(self, client: bytes):
        s = make_session(6667)
        s.client_buf.extend(client)
        return s, irc.detect_stream(s, TS)

    def test_single_arg_identify_followed_by_join(self):
        s, out = self._run(b"PRIVMSG NickServ :IDENTIFY hunter2\r\nJOIN #chan\r\n")
        self.assertEqual(out, [])
        self.assertEqual(len(s.pending), 1)
        self.assertEqual(s.pending[0].finding["creds"], ":hunter2")
        self.assertEqual(s.pending[0].finding["nick"], "")

    def test_two_arg_identify_followed_by_join(self):
        s, _ = self._run(b"PRIVMSG NickServ :IDENTIFY bob hunter2\r\nJOIN #chan\r\n")
        self.assertEqual(s.pending[0].finding["creds"], "bob:hunter2")

    def test_single_arg_identify_alone(self):
        s, _ = self._run(b"PRIVMSG NickServ :IDENTIFY hunter2\r\n")
        self.assertEqual(s.pending[0].finding["creds"], ":hunter2")

    def test_id_alias_and_resolution(self):
        s = make_session(6667)
        s.client_buf.extend(b"PRIVMSG NickServ :ID hunter2\r\nJOIN #x\r\n")
        s.server_buf.extend(
            b":NickServ!NickServ@svc NOTICE me :Password accepted - you are now recognized.\r\n")
        out = irc.detect_stream(s, TS)
        self.assertEqual([(f["creds"], f["outcome"]) for f in out],
                         [(":hunter2", "success")])


if __name__ == "__main__":
    unittest.main()
