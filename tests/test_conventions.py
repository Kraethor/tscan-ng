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
Tests for TODO.md #61: one convention per detector, not one per author.

    - Undecodable bytes are decoded with errors="replace" everywhere, so a
      credential with a non-UTF-8 byte shows U+FFFD instead of silently
      losing the byte.
    - "status" in a resolved finding is always a str.
    - The scan-window constants are named _MAX_SCAN_CLIENT / _MAX_SCAN_SERVER
      in every detector module.

Run from /opt/tscan:
    PYTHONDONTWRITEBYTECODE=1 venv/bin/python -m unittest discover -s tests -t . -v
"""

import base64
import inspect
import re
import unittest

from tscan_ng import resolve
from tscan_ng.detectors import DETECTOR_MODULES, STREAM_DETECTORS, common
from tscan_ng.session import Session

TS = 1000.0

_SCAN_NAME_RE = re.compile(r"^_MAX_\w*SCAN\w*$")
_ALLOWED_SCAN_NAMES = {"_MAX_SCAN_CLIENT", "_MAX_SCAN_SERVER"}
_DECODE_IGNORE_RE = re.compile(r"""\.decode\([^)]*["']ignore["']""")


def make_session(dport: int) -> Session:
    """A client 10.0.0.2:50000 talking to server 10.0.0.9:<dport>."""
    s = Session("10.0.0.2", "10.0.0.9", 50000, dport)
    s.last_ts = TS
    return s


def login(dport: int, client: bytes, server: bytes) -> dict:
    """Detect *client*, then deliver *server* and return the one resolved finding."""
    s = make_session(dport)
    s.client_buf.extend(client)
    for det in STREAM_DETECTORS:
        det(s, TS)
    s.server_buf.extend(server)
    done = resolve.resolve_pending(s, TS + 1)
    assert len(done) == 1, done
    return done[0]


class DecodeErrorsTests(unittest.TestCase):
    def test_no_detector_decodes_with_ignore(self):
        for mod in DETECTOR_MODULES + [common]:
            with self.subTest(module=mod.__name__):
                self.assertIsNone(_DECODE_IGNORE_RE.search(inspect.getsource(mod)))

    def test_ftp_non_utf8_byte_is_marked_not_dropped(self):
        f = login(21, b"USER bob\r\nPASS pw\xff1\r\n", b"230 ok\r\n")
        self.assertEqual(f["creds"], "bob:pw�1")

    def test_http_basic_non_utf8_byte_is_marked_not_dropped(self):
        f = login(80, b"GET / HTTP/1.1\r\nHost: x\r\nAuthorization: Basic "
                  + base64.b64encode(b"bob:pw\xff1") + b"\r\n\r\n",
                  b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
        self.assertEqual(f["creds"], "bob:pw�1")


class StatusTypeTests(unittest.TestCase):
    def test_http_status_is_a_string(self):
        f = login(80, b"GET / HTTP/1.1\r\nHost: x\r\nAuthorization: Basic "
                  + base64.b64encode(b"bob:pw1") + b"\r\n\r\n",
                  b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n")
        self.assertEqual((f["status"], f["outcome"]), ("401", "failed"))

    def test_other_protocols_status_is_a_string(self):
        cases = {
            "ftp":   (21,   b"USER bob\r\nPASS pw1\r\n", b"230 ok\r\n"),
            "pop3":  (110,  b"USER bob\r\nPASS pw1\r\n", b"+OK in\r\n"),
            "imap":  (143,  b"a1 LOGIN bob pw1\r\n", b"a1 OK done\r\n"),
            "redis": (6379, b"*2\r\n$4\r\nAUTH\r\n$3\r\npw1\r\n", b"+OK\r\n"),
            "irc":   (6667, b"PRIVMSG NickServ :IDENTIFY pw1\r\n",
                      b":NickServ!NickServ@svc NOTICE me :Password accepted - "
                      b"you are now recognized.\r\n"),
        }
        for name, (dport, client, server) in cases.items():
            with self.subTest(protocol=name):
                self.assertIsInstance(login(dport, client, server)["status"], str)


class ScanLimitNameTests(unittest.TestCase):
    def test_scan_limits_use_the_two_standard_names(self):
        for mod in DETECTOR_MODULES:
            with self.subTest(module=mod.__name__):
                names = {n for n in vars(mod) if _SCAN_NAME_RE.match(n)}
                self.assertTrue(names, "no scan limit defined")
                self.assertLessEqual(names, _ALLOWED_SCAN_NAMES)
                self.assertIn("_MAX_SCAN_CLIENT", names)


if __name__ == "__main__":
    unittest.main()
