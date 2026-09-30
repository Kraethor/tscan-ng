"""
Tests for DiscordSink alert suppression (which findings reach the webhook).

The webhook is a dummy string and threading.Thread is replaced, so nothing
is sent and no network is used.

Run from /opt/tscan:
    PYTHONDONTWRITEBYTECODE=1 venv/bin/python -m unittest discover -s tests -t . -v
"""

import unittest
from unittest import mock

from tscan_ng.sinks import discord


def alerts_for(finding: dict, webhook: str = "https://example.invalid/hook") -> int:
    """Return how many background alert threads write(finding) started."""
    with mock.patch.object(discord.threading, "Thread") as thread:
        discord.DiscordSink(webhook).write(finding)
        return thread.call_count


class DiscordSuppressionTests(unittest.TestCase):
    def test_snmp_no_response_is_not_alerted(self):
        self.assertEqual(alerts_for({"type": "snmp_creds", "outcome": "no_response"}), 0)

    def test_snmp_success_is_alerted(self):
        self.assertEqual(alerts_for({"type": "snmp_creds", "outcome": "success"}), 1)

    def test_other_protocol_no_response_is_still_alerted(self):
        self.assertEqual(alerts_for({"type": "http_basic", "outcome": "no_response"}), 1)
        self.assertEqual(alerts_for({"type": "ftp_creds", "outcome": "no_response"}), 1)

    def test_failed_and_pending_still_suppressed(self):
        self.assertEqual(alerts_for({"type": "http_basic", "outcome": "failed"}), 0)
        self.assertEqual(alerts_for({"type": "snmp_creds", "outcome": "pending"}), 0)

    def test_no_webhook_means_no_alert(self):
        self.assertEqual(alerts_for({"type": "http_basic", "outcome": "success"}, webhook=""), 0)


if __name__ == "__main__":
    unittest.main()
