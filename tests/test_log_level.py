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
    """Config from a temp file using iface 'lo' plus *extra* INI text."""
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "t.conf")
        with open(path, "w") as f:
            f.write("[capture]\niface = lo\n" + extra)
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
