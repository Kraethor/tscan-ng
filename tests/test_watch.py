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
Tests for scripts/watch.py (TODO.md #8): fields that come from network
traffic must not reach the operator's terminal as raw control characters
(ANSI escape injection).

Run from /opt/tscan:
    PYTHONDONTWRITEBYTECODE=1 venv/bin/python -m unittest discover -s tests -t . -v
"""

import importlib.util
import json
import os
import unicodedata
import unittest

_SPEC = importlib.util.spec_from_file_location(
    "watch", os.path.join(os.path.dirname(__file__), "..", "scripts", "watch.py"))
watch = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(watch)

# The viewer's own colour codes, which are allowed in the output.
_OWN_CODES = [watch.RESET, watch.BOLD, watch.DIM, watch.WHITE, watch.BRIGHT_RED,
              watch.BRIGHT_GREEN, watch.BRIGHT_YELLOW, watch.BRIGHT_BLUE,
              watch.BRIGHT_MAGENTA, watch.BRIGHT_CYAN, watch.BRIGHT_WHITE]

# Clear screen + set the window title, as a hostile client might send it.
_EVIL = "\x1b[2J\x1b]0;pwned\x07"


def hostile_chars(text: str) -> list[str]:
    """Return control/format characters left after removing the viewer's own codes."""
    for code in sorted(_OWN_CODES, key=len, reverse=True):
        text = text.replace(code, "")
    return [c for c in text if c != "\n"
            and unicodedata.category(c) in ("Cc", "Cf", "Zl", "Zp")]


def decoded(finding: dict) -> dict:
    """Round-trip through JSON, as the viewer receives it from results.jsonl."""
    return json.loads(json.dumps(finding))


class WatchEscapeTests(unittest.TestCase):
    def test_http_fields_are_escaped(self):
        out = watch._format(decoded({
            "type": "http_basic", "outcome": "success", "ts": 1700000000,
            "src": "10.0.0.1", "sport": 5000, "dst": "10.0.0.2", "dport": 80,
            "creds": "admin:" + _EVIL, "host": _EVIL, "method": "GET",
            "uri": "/" + _EVIL, "status": 200, "status_text": "OK" + _EVIL,
        }))
        self.assertEqual(hostile_chars(out), [])
        self.assertIn(r"admin:\x1b[2J\x1b]0;pwned\x07", out)

    def test_other_protocol_extras_are_escaped(self):
        for extra in ({"type": "smb_creds", "domain": _EVIL, "workstation": _EVIL},
                      {"type": "postgres_creds", "user": _EVIL},
                      {"type": "smtp_creds", "mechanism": _EVIL},
                      {"type": "snmp_creds", "version": _EVIL, "pdu_type": _EVIL},
                      {"type": "new_detector" + _EVIL}):
            with self.subTest(type=extra["type"]):
                out = watch._format(decoded({"outcome": "success", "ts": 1700000000,
                                             "creds": "u:p", **extra}))
                self.assertEqual(hostile_chars(out), [])

    def test_c1_bidi_and_line_separators_are_escaped(self):
        out = watch._format({"type": "ftp_creds", "outcome": "success", "ts": 1700000000,
                             "creds": "u:\x9b31m\u202eevil\u2028x"})
        self.assertEqual(hostile_chars(out), [])
        self.assertIn(r"u:\x9b31m\u202eevil\u2028x", out)

    def test_ordinary_credentials_are_unchanged(self):
        creds = "bob:p@ss wörd\\x1b"
        out = watch._format({"type": "ftp_creds", "outcome": "success",
                             "ts": 1700000000, "creds": creds})
        self.assertIn(creds, out)


if __name__ == "__main__":
    unittest.main()
