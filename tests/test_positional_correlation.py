"""
Tests for TODO.md #14: positional response correlation must not pair a
credential with an unrelated server response.

ftp/pop3/smtp/redis resolve against the first response at or after the
pending finding's server_buf_floor (the server bytes seen when the
credential was recorded), so a stale reply from before the credential
(an earlier failed attempt, a CAPA/SETNAME reply, a -NOAUTH to a pre-auth
command) is skipped. ldap correlates by messageID, the way snmp does by
request-id.

Each test drives the detector in realistic packet order: the credential
command is buffered and detect_stream() parks it as pending BEFORE the
server's reply arrives, exactly as the packet-by-packet pipeline does.

Run from /opt/tscan:
    PYTHONDONTWRITEBYTECODE=1 venv/bin/python -m unittest discover -s tests -t . -v
"""

import struct
import unittest

from tscan_ng import resolve
from tscan_ng.detectors import ftp, pop3, smtp, redis, ldap
from tscan_ng.session import Session

TS = 1000.0


def make_session(dport: int) -> Session:
    s = Session("10.0.0.2", "10.0.0.9", 50000, dport)
    s.last_ts = TS
    return s


def redis_auth(*args: bytes) -> bytes:
    out = b"*%d\r\n" % len(args)
    for a in args:
        out += b"$%d\r\n%s\r\n" % (len(a), a)
    return out


def ber(tag, body):
    if len(body) < 0x80:
        return bytes([tag, len(body)]) + body
    return bytes([tag, 0x81, len(body)]) + body


def ber_int(n):
    return ber(0x02, n.to_bytes(4, "big") if n > 127 else bytes([n]))


def ldap_bind(msgid, dn, pw):
    return ber(0x30, ber_int(msgid) + ber(0x60, ber_int(3) + ber(0x04, dn) + ber(0x80, pw)))


def ldap_bind_response(msgid, result_code):
    return ber(0x30, ber_int(msgid) + ber(0x61, ber(0x0A, bytes([result_code]))
                                          + ber(0x04, b"") + ber(0x04, b"")))


class FtpTests(unittest.TestCase):
    def test_stale_530_before_pass_is_skipped(self):
        s = make_session(21)
        # A 530 from a pre-login command sits in server_buf already.
        s.server_buf.extend(b"220 ready\r\n530 Please login with USER and PASS\r\n")
        s.client_buf.extend(b"USER bob\r\nPASS pw\r\n")
        ftp.detect_stream(s, TS)                       # parks pending, floor set
        self.assertEqual(resolve.resolve_pending(s, TS), [])   # 530 is stale
        s.server_buf.extend(b"230 Login successful\r\n")
        done = resolve.resolve_pending(s, TS + 1)
        self.assertEqual([(f["status"], f["outcome"]) for f in done], [("230", "success")])


class Pop3Tests(unittest.TestCase):
    def test_err_to_capa_before_login_is_not_a_failure(self):
        s = make_session(110)
        s.server_buf.extend(b"+OK POP3 ready\r\n-ERR unknown command CAPA\r\n")
        s.client_buf.extend(b"USER bob\r\nPASS pw\r\n")
        ftp_pending = pop3.detect_stream(s, TS)
        self.assertEqual(resolve.resolve_pending(s, TS), [])   # -ERR was to CAPA
        s.server_buf.extend(b"+OK logged in\r\n")
        done = resolve.resolve_pending(s, TS + 1)
        self.assertEqual([f["outcome"] for f in done], ["success"])

    def test_retry_after_failed_attempt_resolves(self):
        # First attempt fails; a successful retry on the same connection must
        # still resolve (the old "need 3 responses from position 0" logic
        # never reached 3 again after the banner was consumed).
        s = make_session(110)
        s.server_buf.extend(b"+OK ready\r\n+OK user ok\r\n")
        s.client_buf.extend(b"USER bob\r\nPASS wrong\r\n")
        pop3.detect_stream(s, TS)
        s.server_buf.extend(b"-ERR auth failed\r\n")
        self.assertEqual([f["outcome"] for f in resolve.resolve_pending(s, TS + 1)], ["failed"])
        # retry
        s.client_buf.extend(b"USER bob\r\nPASS right\r\n")
        pop3.detect_stream(s, TS + 2)
        s.server_buf.extend(b"+OK logged in\r\n")
        self.assertEqual([f["outcome"] for f in resolve.resolve_pending(s, TS + 3)], ["success"])


class SmtpTests(unittest.TestCase):
    def test_stale_535_before_auth_is_skipped(self):
        s = make_session(25)
        s.server_buf.extend(b"220 mail\r\n535 5.7.8 earlier attempt\r\n")
        s.client_buf.extend(b"AUTH PLAIN AGJvYgBwdw==\r\n")   # \0bob\0pw
        smtp.detect_stream(s, TS)
        self.assertEqual(resolve.resolve_pending(s, TS), [])
        s.server_buf.extend(b"235 2.7.0 accepted\r\n")
        self.assertEqual([f["outcome"] for f in resolve.resolve_pending(s, TS + 1)], ["success"])


class RedisTests(unittest.TestCase):
    def test_noauth_before_auth_is_skipped(self):
        s = make_session(6379)
        s.server_buf.extend(b"-NOAUTH Authentication required.\r\n")
        s.client_buf.extend(redis_auth(b"AUTH", b"pw"))
        redis.detect_stream(s, TS)
        self.assertEqual(resolve.resolve_pending(s, TS), [])   # -NOAUTH is stale
        s.server_buf.extend(b"+OK\r\n")
        self.assertEqual([f["outcome"] for f in resolve.resolve_pending(s, TS + 1)], ["success"])

    def test_stale_ok_from_setname_is_skipped(self):
        s = make_session(6379)
        s.server_buf.extend(b"+OK\r\n")                        # reply to CLIENT SETNAME
        s.client_buf.extend(redis_auth(b"AUTH", b"wrong"))
        redis.detect_stream(s, TS)
        self.assertEqual(resolve.resolve_pending(s, TS), [])
        s.server_buf.extend(b"-ERR invalid password\r\n")
        self.assertEqual([f["outcome"] for f in resolve.resolve_pending(s, TS + 1)], ["failed"])


class LdapTests(unittest.TestCase):
    def test_response_matched_by_message_id(self):
        s = make_session(389)
        s.client_buf.extend(ldap_bind(2, b"cn=bob", b"pw"))
        self.assertEqual(ldap.detect_stream(s, TS), [])
        self.assertEqual(s.pending[0].finding.get("_message_id"), 2)
        # A BindResponse for a DIFFERENT messageID must not resolve it.
        s.server_buf.extend(ldap_bind_response(1, 0))
        self.assertEqual(resolve.resolve_pending(s, TS), [])
        s.server_buf.extend(ldap_bind_response(2, 49))
        done = resolve.resolve_pending(s, TS + 1)
        self.assertEqual([(f["status"], f["outcome"]) for f in done], [("49", "failed")])

    def test_message_id_is_not_emitted(self):
        s = make_session(389)
        s.client_buf.extend(ldap_bind(5, b"cn=bob", b"pw"))
        ldap.detect_stream(s, TS)
        s.server_buf.extend(ldap_bind_response(5, 0))
        done = resolve.resolve_pending(s, TS + 1)
        self.assertNotIn("_message_id", done[0])
        self.assertEqual(done[0]["outcome"], "success")


if __name__ == "__main__":
    unittest.main()
