"""
Tests for TODO.md #56: every protocol's response parsing lives in one place.

Detectors only find credentials and park them with session.add_pending();
tscan_ng.resolve owns all response correlation through a per-detector
resolver registry. These tests check the registry is complete, that no
detector consumes server_buf itself, and that a login whose response is
already buffered is still resolved on the same packet (pipeline.py runs
resolve_pending() straight after the detectors).

Run from /opt/tscan:
    PYTHONDONTWRITEBYTECODE=1 venv/bin/python -m unittest discover -s tests -t . -v
"""

import base64
import inspect
import re
import struct
import unittest

from tscan_ng import resolve
from tscan_ng.detectors import DETECTOR_MODULES, STREAM_DETECTORS
from tscan_ng.session import Session

TS = 1000.0


def make_session(dport: int) -> Session:
    """A client 10.0.0.2:50000 talking to server 10.0.0.9:<dport>."""
    s = Session("10.0.0.2", "10.0.0.9", 50000, dport)
    s.last_ts = TS
    return s


def process(session: Session) -> tuple[list, list]:
    """One packet's worth of work, as pipeline.py does it: (detector output, resolved)."""
    immediate = [f for det in STREAM_DETECTORS for f in det(session, TS)]
    return immediate, resolve.resolve_pending(session, TS + 1)


def ber(tag: int, body: bytes) -> bytes:
    """Minimal BER TLV (short or one-byte long form, enough for these tests)."""
    if len(body) < 0x80:
        return bytes([tag, len(body)]) + body
    return bytes([tag, 0x81, len(body)]) + body


def ber_int(n: int) -> bytes:
    return ber(0x02, n.to_bytes(4, "big") if n > 127 else bytes([n]))


class RegistryTests(unittest.TestCase):
    def test_every_detector_module_has_types_and_a_resolver(self):
        types = set()
        for mod in DETECTOR_MODULES:
            with self.subTest(module=mod.__name__):
                self.assertTrue(mod.FINDING_TYPES)
                self.assertTrue(callable(mod.resolve))
                for t in mod.FINDING_TYPES:
                    self.assertIs(resolve.RESOLVERS[t], mod.resolve)
                types.update(mod.FINDING_TYPES)
        self.assertEqual(set(resolve.RESOLVERS), types)
        self.assertEqual(len(types), 13)  # 12 detectors; ftp has two types

    def test_stream_detectors_match_modules(self):
        self.assertEqual(STREAM_DETECTORS, [m.detect_stream for m in DETECTOR_MODULES])

    def test_no_detector_consumes_server_buf(self):
        pattern = re.compile(r"del\s+session\.server_buf")
        for mod in DETECTOR_MODULES:
            with self.subTest(module=mod.__name__):
                self.assertIsNone(pattern.search(inspect.getsource(mod.detect_stream)))

    def test_unknown_type_stays_pending(self):
        s = make_session(80)
        s.add_pending({"type": "nope"}, TS)
        self.assertEqual(resolve.resolve_pending(s, TS), [])
        self.assertEqual(len(s.pending), 1)


class AlreadyBufferedTests(unittest.TestCase):
    """Credentials and the server's answer both buffered before detection.

    Only for protocols that match the reply by tag, id, content or an
    explicit prompt floor. The positional ones (ftp, pop3, smtp, redis) take
    the first reply after the floor set when the credential was seen (#14),
    so for them the reply must arrive after detection; see
    ReplyAfterDetectionTests. In the pipeline it always does: each frame is
    processed on arrival and the reply frame follows the command frame.
    """

    def check(self, dport, client, server, outcome, **fields):
        s = make_session(dport)
        s.client_buf.extend(client)
        s.server_buf.extend(server)
        immediate, done = process(s)
        self.assertEqual(immediate, [])
        self.assertEqual([f["outcome"] for f in done], [outcome])
        self.assertEqual(s.pending, [])
        self.assertEqual(done[0]["ts_start"], TS)
        self.assertEqual(done[0]["ts_end"], TS + 1)
        for key, value in fields.items():
            self.assertEqual(done[0][key], value)
        return s, done[0]

    def test_imap_consumes_tagged_response(self):
        # The old immediate path left the tagged response in server_buf, so a
        # reused tag could match it again.
        s, _ = self.check(143, b"a1 LOGIN bob pw1\r\n", b"* OK hi\r\na1 OK done\r\n",
                          "success", creds="bob:pw1", status="OK")
        self.assertNotIn(b"a1 OK", bytes(s.server_buf))

    def test_irc(self):
        self.check(6667, b"PRIVMSG NickServ :IDENTIFY pw1\r\n",
                   b":NickServ!NickServ@svc NOTICE me :Password accepted - "
                   b"you are now recognized.\r\n", "success", creds=":pw1")

    def test_http(self):
        self.check(80, b"GET / HTTP/1.1\r\nHost: x\r\nAuthorization: Basic "
                   + base64.b64encode(b"bob:pw1") + b"\r\n\r\n",
                   b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n", "success",
                   status=200, status_text="OK")

    def test_telnet_searches_only_after_password_prompt(self):
        self.check(23, b"admin\r\npw1\r\n",
                   b"Welcome to box\r\nlogin: Password: \r\nLogin incorrect\r\n", "failed")

    def test_postgres(self):
        startup = struct.pack(">I", 0x00030000) + b"user\x00bob\x00\x00"
        startup = struct.pack(">I", 4 + len(startup)) + startup
        password = b"p" + struct.pack(">I", 4 + 4) + b"pw1\x00"
        self.check(5432, startup + password,
                   b"R" + struct.pack(">II", 8, 3) + b"R" + struct.pack(">II", 8, 0),
                   "success", creds="bob:pw1")

    def test_ldap(self):
        bind = ber(0x30, ber_int(1) + ber(0x60, ber_int(3) + ber(0x04, b"cn=bob")
                                          + ber(0x80, b"pw1")))
        rsp = ber(0x30, ber_int(1) + ber(0x61, ber(0x0A, b"\x00") + ber(0x04, b"")
                                         + ber(0x04, b"")))
        self.check(389, bind, rsp, "success", creds="cn=bob:pw1", status="0")

    def test_snmp_matches_request_id(self):
        def pdu(tag, req_id, err):
            return ber(0x30, ber_int(1) + ber(0x04, b"public")
                       + ber(tag, ber_int(req_id) + ber_int(err) + ber_int(0) + ber(0x30, b"")))
        self.check(161, pdu(0xA0, 4242, 0), pdu(0xA2, 4242, 0), "success",
                   creds="public", status="0")


class ReplyAfterDetectionTests(unittest.TestCase):
    """Positional protocols in pipeline order: command, detect, reply, resolve."""

    def check(self, dport, client, server_before, reply, outcome, **fields):
        s = make_session(dport)
        s.server_buf.extend(server_before)
        s.client_buf.extend(client)
        immediate, done = process(s)
        self.assertEqual((immediate, done), ([], []))
        self.assertEqual(len(s.pending), 1)
        s.server_buf.extend(reply)
        done = resolve.resolve_pending(s, TS + 1)
        self.assertEqual([f["outcome"] for f in done], [outcome])
        self.assertEqual(s.pending, [])
        for key, value in fields.items():
            self.assertEqual(done[0][key], value)
        return s

    def test_ftp(self):
        s = self.check(21, b"USER bob\r\nPASS pw1\r\n", b"220 hi\r\n331 pw?\r\n",
                       b"230 in\r\n", "success", creds="bob:pw1", status="230")
        self.assertNotIn(b"230", bytes(s.server_buf))  # the reply was consumed

    def test_pop3(self):
        self.check(110, b"USER bob\r\nPASS pw1\r\n", b"+OK ready\r\n+OK user\r\n",
                   b"+OK in\r\n", "success", creds="bob:pw1")

    def test_smtp_plain(self):
        blob = base64.b64encode(b"\x00bob\x00pw1")
        self.check(25, b"AUTH PLAIN " + blob + b"\r\n", b"220 mail\r\n", b"235 ok\r\n",
                   "success", creds="bob:pw1")

    def test_redis(self):
        self.check(6379, b"*2\r\n$4\r\nAUTH\r\n$3\r\npw1\r\n", b"", b"+OK\r\n",
                   "success")


if __name__ == "__main__":
    unittest.main()
