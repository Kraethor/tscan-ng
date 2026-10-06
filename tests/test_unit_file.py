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
Tests for systemd/tscan-pipeline.service (TODO.md #6, #7): the unit is the
only thing enforcing the log directory permissions and the sandbox, so a
dropped line would silently re-expose the credential logs.

This checks the repo copy; `systemd-analyze security tscan-pipeline` checks
the installed one.

Run from /opt/tscan:
    PYTHONDONTWRITEBYTECODE=1 venv/bin/python -m unittest discover -s tests -t . -v
"""

import os
import unittest

_UNIT = os.path.join(os.path.dirname(__file__), "..", "systemd", "tscan-pipeline.service")


def service_settings() -> dict[str, list[str]]:
    """Return {key: [values...]} from the unit's [Service] section."""
    settings: dict[str, list[str]] = {}
    section = None
    with open(_UNIT) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("["):
                section = line
            elif section == "[Service]":
                key, _, value = line.partition("=")
                settings.setdefault(key, []).append(value)
    return settings


class UnitFileTests(unittest.TestCase):
    def setUp(self):
        self.s = service_settings()

    def test_log_directory_is_private(self):
        self.assertEqual(self.s.get("LogsDirectory"), ["tscan"])
        self.assertEqual(self.s.get("LogsDirectoryMode"), ["0750"])
        self.assertEqual(self.s.get("UMask"), ["0027"])

    def test_filesystem_is_read_only_and_deploy_key_hidden(self):
        self.assertEqual(self.s.get("ProtectSystem"), ["strict"])
        self.assertEqual(self.s.get("ProtectHome"), ["yes"])
        self.assertIn("-/opt/tscan/.ssh", self.s.get("InaccessiblePaths", []))
        self.assertNotIn("ReadWritePaths", self.s)

    def test_privilege_limits(self):
        self.assertEqual(self.s.get("NoNewPrivileges"), ["yes"])
        self.assertEqual(self.s.get("CapabilityBoundingSet"), ["CAP_NET_RAW CAP_NET_ADMIN"])
        self.assertIn("AF_PACKET", self.s.get("RestrictAddressFamilies", [""])[0].split())
        self.assertNotIn("PrivateUsers", self.s)  # would break capture, see the unit comment


if __name__ == "__main__":
    unittest.main()
