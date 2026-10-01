"""
Tests for TODO.md #16: the scan window must advance even when nothing matches.

Every stream detector scans only the first _MAX_SCAN_CLIENT bytes of client_buf
and consumes bytes only when it matches a credential. Before this fix, once that
many bytes of non-credential traffic (other commands, searches, pipelined
requests, unanswered datagrams) piled up at the front of client_buf, a real
credential arriving behind them never entered the scan window and was missed for
the life of the flow. detectors.common.advance_scan_window() now drops the
scanned-but-unmatched prefix (keeping a tail for a straddling credential) on the
detector's no-match path, so the window moves forward.

Each test drives the detector the way the pipeline does: a first packet of junk
larger than the window (detect_stream parks nothing and trims), then a second
packet carrying the credential, which now fits in the window and is parked as a
pending finding. Without the fix the second step finds nothing.

http_basic (consumes every complete header block, TODO.md #2) and telnet (clears
its whole window once it has a login) do not need advancing and are not covered.

Run from /opt/tscan:
    PYTHONDONTWRITEBYTECODE=1 venv/bin/python -m unittest discover -s tests -t . -v
"""

import base64
import struct
import unittest

from tscan_ng.detectors import (common, ftp, pop3, imap, smtp, irc, redis,
                                 ldap, snmp, postgres, smb)
from tscan_ng.session import Session
from tests.test_smb_reauth import (smb2, session_setup_request,
                                   session_setup_response, ntlm_challenge,
                                   ntlm_authenticate, NT_RESPONSE)

TS = 1000.0


def make_session(dport: int) -> Session:
    s = Session("10.0.0.2", "10.0.0.9", 50000, dport)
    s.last_ts = TS
    return s


def line_junk(line: bytes, over: int) -> bytes:
    """Repeat *line* until the total is a little over *over* bytes."""
    return line * (over // len(line) + 1)


def binary_junk(over: int) -> bytes:
    """Non-credential bytes a little over *over*, with no protocol marker."""
    return b"\x00" * (over + 100)


# --------------------------------------------------------------------------
# The shared helper
# --------------------------------------------------------------------------
class AdvanceScanWindowTests(unittest.TestCase):
    def _session_with(self, data: bytes) -> Session:
        s = make_session(21)
        s.client_buf.extend(data)
        return s

    def test_no_trim_when_within_window(self):
        s = self._session_with(b"x" * 100)
        self.assertEqual(common.advance_scan_window(s, 4096, line_oriented=True), 0)
        self.assertEqual(len(s.client_buf), 100)

    def test_line_oriented_cuts_on_newline_and_keeps_tail(self):
        s = self._session_with(b"NOOP\r\n" * 800)        # 4800 bytes > 4096
        removed = common.advance_scan_window(s, 4096, line_oriented=True, keep_tail=1024)
        self.assertGreater(removed, 0)
        # Cut lands on a newline boundary, so the remainder starts a fresh line.
        self.assertTrue(bytes(s.client_buf).startswith(b"NOOP\r\n"))
        # At least keep_tail of the scanned window is retained.
        self.assertGreaterEqual(len(s.client_buf), 1024)

    def test_binary_cuts_on_byte_boundary(self):
        s = self._session_with(b"\x00" * 5000)
        removed = common.advance_scan_window(s, 4096, line_oriented=False, keep_tail=1024)
        self.assertEqual(removed, 4096 - 1024)
        self.assertEqual(len(s.client_buf), 5000 - (4096 - 1024))

    def test_line_oriented_no_newline_does_not_trim(self):
        # A single huge line with no newline in the drop region: nothing is cut
        # (that stall is TODO.md #22, not #16).
        s = self._session_with(b"A" * 5000)
        self.assertEqual(common.advance_scan_window(s, 4096, line_oriented=True), 0)
        self.assertEqual(len(s.client_buf), 5000)

    def test_keep_tail_larger_than_window_trims_nothing(self):
        s = self._session_with(b"\x00" * 5000)
        self.assertEqual(
            common.advance_scan_window(s, 4096, line_oriented=False, keep_tail=4096), 0)


# --------------------------------------------------------------------------
# Per-detector: junk packet (trims, parks nothing) then credential packet
# --------------------------------------------------------------------------
class DetectorAdvanceTests(unittest.TestCase):
    def _run(self, s, module, junk, creds):
        s.client_buf.extend(junk)
        module.detect_stream(s, TS)
        self.assertEqual(s.pending, [], "junk alone must not park a finding")
        self.assertLess(len(s.client_buf), len(junk), "window did not advance")
        s.client_buf.extend(creds)
        module.detect_stream(s, TS)

    def test_ftp(self):
        s = make_session(21)
        self._run(s, ftp, line_junk(b"NOOP\r\n", ftp._MAX_SCAN_CLIENT),
                  b"USER bob\r\nPASS pw1\r\n")
        self.assertEqual(len(s.pending), 1)
        self.assertEqual(s.pending[0].finding["creds"], "bob:pw1")

    def test_ftp_user_without_pass_then_pass(self):
        # USER is in the window but PASS has not arrived: the junk before USER is
        # dropped so USER stays the anchor and the window can reach the PASS.
        s = make_session(21)
        s.client_buf.extend(line_junk(b"NOOP\r\n", 3000) + b"USER bob\r\n")
        ftp.detect_stream(s, TS)
        self.assertEqual(s.pending, [])
        self.assertTrue(bytes(s.client_buf).startswith(b"USER bob\r\n"))
        s.client_buf.extend(b"PASS pw1\r\n")
        ftp.detect_stream(s, TS)
        self.assertEqual(len(s.pending), 1)
        self.assertEqual(s.pending[0].finding["creds"], "bob:pw1")

    def test_pop3(self):
        s = make_session(110)
        self._run(s, pop3, line_junk(b"NOOP\r\n", pop3._MAX_SCAN_CLIENT),
                  b"USER bob\r\nPASS pw1\r\n")
        self.assertEqual(len(s.pending), 1)
        self.assertEqual(s.pending[0].finding["creds"], "bob:pw1")

    def test_imap(self):
        s = make_session(143)
        self._run(s, imap, line_junk(b"a0 NOOP\r\n", imap._MAX_SCAN_CLIENT),
                  b"a1 LOGIN bob pw1\r\n")
        self.assertEqual(len(s.pending), 1)
        self.assertEqual(s.pending[0].finding["creds"], "bob:pw1")

    def test_smtp(self):
        s = make_session(25)
        blob = base64.b64encode(b"\x00bob\x00pw1")
        self._run(s, smtp, line_junk(b"NOOP\r\n", smtp._MAX_SCAN_CLIENT),
                  b"AUTH PLAIN " + blob + b"\r\n")
        self.assertEqual(len(s.pending), 1)
        self.assertEqual(s.pending[0].finding["creds"], "bob:pw1")

    def test_irc(self):
        s = make_session(6667)
        self._run(s, irc, line_junk(b"PING :srv\r\n", irc._MAX_SCAN_CLIENT),
                  b"PRIVMSG NickServ :IDENTIFY s3cret\r\n")
        self.assertEqual(len(s.pending), 1)
        self.assertEqual(s.pending[0].finding["creds"], ":s3cret")

    def test_redis(self):
        s = make_session(6379)
        auth = b"*2\r\n$4\r\nAUTH\r\n$6\r\ns3cret\r\n"
        self._run(s, redis, binary_junk(redis._MAX_SCAN_CLIENT), auth)
        self.assertEqual(len(s.pending), 1)
        self.assertEqual(s.pending[0].finding["creds"], ":s3cret")

    def test_ldap(self):
        bind = _ber(0x30, _ber_int(1) + _ber(0x60, _ber_int(3) + _ber(0x04, b"cn=bob")
                                             + _ber(0x80, b"pw1")))
        s = make_session(389)
        self._run(s, ldap, binary_junk(ldap._MAX_SCAN_CLIENT), bind)
        self.assertEqual(len(s.pending), 1)
        self.assertEqual(s.pending[0].finding["creds"], "cn=bob:pw1")

    def test_snmp(self):
        req = _ber(0x30, _ber_int(0) + _ber(0x04, b"public")
                   + _ber(0xA0, _ber_int(4242) + _ber_int(0) + _ber_int(0) + _ber(0x30, b"")))
        s = make_session(161)
        self._run(s, snmp, binary_junk(snmp._MAX_SCAN_CLIENT), req)
        self.assertEqual(len(s.pending), 1)
        self.assertEqual(s.pending[0].finding["creds"], "public")

    def test_postgres(self):
        startup = struct.pack(">I", 0x00030000) + b"user\x00bob\x00\x00"
        startup = struct.pack(">I", 4 + len(startup)) + startup
        password = b"p" + struct.pack(">I", 4 + 4) + b"pw1\x00"
        s = make_session(5432)
        s.server_buf.extend(b"R" + struct.pack(">II", 8, 3))   # cleartext request
        # Startup is sent first, then a wall of junk, then the password.
        s.client_buf.extend(startup + binary_junk(postgres._MAX_SCAN_CLIENT))
        postgres.detect_stream(s, TS)
        self.assertEqual(s.pending, [])
        s.client_buf.extend(password)
        postgres.detect_stream(s, TS)
        self.assertEqual(len(s.pending), 1)
        self.assertTrue(s.pending[0].finding["creds"].endswith(":pw1"))

    def test_smb(self):
        s = make_session(445)
        challenge = smb2(1, True, 0, 0x1111, smb._STATUS_MORE_PROCESSING_REQUIRED,
                         session_setup_response(ntlm_challenge(b"AAAAAAAA")))
        s.server_buf.extend(challenge)
        junk = binary_junk(smb._MAX_SCAN_CLIENT)
        s.client_buf.extend(junk)
        smb.detect_stream(s, TS)
        self.assertEqual(s.pending, [])
        self.assertLess(len(s.client_buf), len(junk))
        auth = smb2(1, False, 1, 0x1111, 0,
                    session_setup_request(ntlm_authenticate("DOM", "bob", "WS", NT_RESPONSE)))
        s.client_buf.extend(auth)
        smb.detect_stream(s, TS)
        self.assertEqual(len(s.pending), 1)
        self.assertEqual(s.pending[0].finding["username"], "bob")


# --------------------------------------------------------------------------
# BER / SMB builders (mirrors tests/test_resolve.py and test_smb_reauth.py)
# --------------------------------------------------------------------------
def _ber(tag, body):
    if len(body) < 0x80:
        return bytes([tag, len(body)]) + body
    return bytes([tag, 0x81, len(body)]) + body


def _ber_int(n):
    return _ber(0x02, n.to_bytes(4, "big") if n > 127 else bytes([n]))


if __name__ == "__main__":
    unittest.main()
