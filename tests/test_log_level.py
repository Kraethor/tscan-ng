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
Tests for the [logging] level setting (TODO.md #18): workers used to be
hardwired to DEBUG; the default is now INFO and DEBUG is opt-in.

Run from /opt/tscan:
    PYTHONDONTWRITEBYTECODE=1 venv/bin/python -m unittest discover -s tests -t . -v
"""

import os
import tempfile
import unittest

from tscan_ng.config import Config


def conf(extra: str = "") -> Config:
    """Config from a temp file using iface 'lo', a temp output file and *extra* INI text."""
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "t.conf")
        with open(path, "w") as f:
            # Output goes to the temp dir: validation requires a writable output
            # directory, and /var/log/tscan is not writable by non-tscan users (#6).
            f.write("[capture]\niface = lo\n"
                    f"[dispatcher]\nout = {os.path.join(d, 'results.jsonl')}\n" + extra)
        return Config(path)


class LogLevelTests(unittest.TestCase):
    def test_default_is_info(self):
        self.assertEqual(conf().log_level, "INFO")

    def test_debug_opt_in_any_case(self):
        self.assertEqual(conf("[logging]\nlevel = debug\n").log_level, "DEBUG")
        self.assertEqual(conf("[logging]\nlevel = Warning\n").log_level, "WARNING")

    def test_invalid_level_rejected(self):
        with self.assertRaises(ValueError) as ctx:
            conf("[logging]\nlevel = chatty\n")
        self.assertIn("logging.level", str(ctx.exception))

    def test_blank_value_falls_back_to_info(self):
        self.assertEqual(conf("[logging]\nlevel =\n").log_level, "INFO")


if __name__ == "__main__":
    unittest.main()
