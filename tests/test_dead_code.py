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
Tests for TODO.md #55 (dead code and config): the removed legacy settings
must not block startup any more, and common.decode_b64 must accept tokens
without "=" padding instead of silently dropping the credential.

Run from /opt/tscan:
    PYTHONDONTWRITEBYTECODE=1 venv/bin/python -m unittest discover -s tests -t . -v
"""

import os
import tempfile
import unittest

from tscan_ng.config import Config
from tscan_ng.detectors import http_basic
from tscan_ng.detectors.common import decode_b64
from tscan_ng.resolve import resolve_pending
from tscan_ng.session import Session


def conf(extra: str = "") -> Config:
    """Config from a temp file using iface 'lo', a temp output file and *extra* INI text."""
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "t.conf")
        with open(path, "w") as f:
            f.write("[capture]\niface = lo\n"
                    f"[dispatcher]\nout = {os.path.join(d, 'results.jsonl')}\n" + extra)
        return Config(path)


class LegacyConfigTests(unittest.TestCase):
    def test_bad_legacy_socket_no_longer_blocks_startup(self):
        # Was validated (absolute path required) though nothing used it.
        cfg = conf("socket = relative/tscan.sock\nno_immediate = true\n")
        self.assertFalse(hasattr(cfg, "socket_path"))
        self.assertFalse(hasattr(cfg, "no_immediate"))


class DecodeB64Tests(unittest.TestCase):
    def test_padded_token(self):
        self.assertEqual(decode_b64(b"dXNlcjpwYXNzMQ=="), "user:pass1")

    def test_missing_padding_is_tolerated(self):
        self.assertEqual(decode_b64(b"dXNlcjpwYXNzMQ"), "user:pass1")
        self.assertEqual(decode_b64(b"dXNlcjpwYXNzMTI"), "user:pass12")

    def test_undecodable_length_is_empty(self):
        # 4n+1 significant characters cannot be valid base64 at any padding.
        self.assertEqual(decode_b64(b"dXNlc"), "")

    def test_http_basic_unpadded_token_is_reported(self):
        s = Session("10.0.0.2", "10.0.0.9", 50000, 80)
        s.last_ts = 1000.0
        s.client_buf.extend(b"GET / HTTP/1.1\r\nHost: x\r\n"
                            b"Authorization: Basic dXNlcjpwYXNzMQ\r\n\r\n")
        s.server_buf.extend(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
        http_basic.detect_stream(s, 1000.0)
        out = resolve_pending(s, 1000.0)
        self.assertEqual([f["creds"] for f in out], ["user:pass1"])


if __name__ == "__main__":
    unittest.main()
