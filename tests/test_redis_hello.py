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
Tests for TODO.md #24: the RESP3 `HELLO <ver> AUTH <user> <pass>` handshake.

Redis 6+ clients authenticate in the HELLO handshake rather than a separate
AUTH command. The detector only recognised AUTH, so those logins were
missed. HELLO AUTH is now detected in both RESP-array and inline form, and
its reply (a RESP3 map on success, an error on failure) is correlated.

Pure byte parsing; no live Redis.

Run from /opt/tscan:
    PYTHONDONTWRITEBYTECODE=1 venv/bin/python -m unittest discover -s tests -t . -v
"""

import unittest

from tscan_ng.detectors import redis
from tscan_ng import resolve
from tscan_ng.session import Session

TS = 1000.0


def make_session() -> Session:
    s = Session("10.0.0.2", "10.0.0.9", 50000, 6379)
    s.last_ts = TS
    return s


def resp_array(*parts: bytes) -> bytes:
    out = b"*%d\r\n" % len(parts)
    for p in parts:
        out += b"$%d\r\n%s\r\n" % (len(p), p)
    return out


# A minimal RESP3 map reply, as a server answers HELLO: %1 {server: redis}.
HELLO_MAP_REPLY = b"%1\r\n$6\r\nserver\r\n$5\r\nredis\r\n"


class FindHelloTests(unittest.TestCase):
    def test_resp_array_hello_with_auth(self):
        data = resp_array(b"HELLO", b"3", b"AUTH", b"alice", b"s3cret")
        self.assertEqual(redis._find_auth_command(data), ("alice", "s3cret", True, len(data)))

    def test_resp_array_hello_auth_then_setname(self):
        data = resp_array(b"HELLO", b"3", b"AUTH", b"bob", b"pw", b"SETNAME", b"app")
        self.assertEqual(redis._find_auth_command(data), ("bob", "pw", True, len(data)))

    def test_inline_hello_with_auth(self):
        data = b"HELLO 3 AUTH carol pw1\r\n"
        self.assertEqual(redis._find_auth_command(data), ("carol", "pw1", True, len(data)))

    def test_hello_without_auth_is_not_a_match(self):
        self.assertEqual(redis._find_auth_command(resp_array(b"HELLO", b"3")),
                         (None, None, None, None))
        self.assertEqual(redis._find_auth_command(b"HELLO 3\r\n"), (None, None, None, None))

    def test_plain_auth_still_works(self):
        data = resp_array(b"AUTH", b"dave", b"pw2")
        self.assertEqual(redis._find_auth_command(data), ("dave", "pw2", False, len(data)))


class HelloResolveTests(unittest.TestCase):
    def detect(self, client: bytes):
        s = make_session()
        s.client_buf.extend(client)
        redis.detect_stream(s, TS)
        return s

    def test_hello_auth_is_recorded(self):
        s = self.detect(resp_array(b"HELLO", b"3", b"AUTH", b"alice", b"s3cret"))
        self.assertEqual(len(s.pending), 1)
        self.assertEqual(s.pending[0].finding["creds"], "alice:s3cret")

    def test_hello_success_map_reply_resolves_success(self):
        s = self.detect(resp_array(b"HELLO", b"3", b"AUTH", b"alice", b"s3cret"))
        s.server_buf.extend(HELLO_MAP_REPLY)
        done = resolve.resolve_pending(s, TS + 1)
        self.assertEqual([f["outcome"] for f in done], ["success"])
        self.assertNotIn(b"server", bytes(s.server_buf))   # whole map consumed

    def test_hello_failure_resolves_failed(self):
        s = self.detect(resp_array(b"HELLO", b"3", b"AUTH", b"alice", b"wrong"))
        s.server_buf.extend(b"-WRONGPASS invalid username-password pair\r\n")
        done = resolve.resolve_pending(s, TS + 1)
        self.assertEqual([f["outcome"] for f in done], ["failed"])

    def test_plain_auth_reply_unchanged(self):
        s = self.detect(resp_array(b"AUTH", b"dave", b"pw2"))
        s.server_buf.extend(b"+OK\r\n")
        done = resolve.resolve_pending(s, TS + 1)
        self.assertEqual([f["outcome"] for f in done], ["success"])


if __name__ == "__main__":
    unittest.main()
