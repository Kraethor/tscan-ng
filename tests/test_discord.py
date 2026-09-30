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


def payload_for(finding: dict) -> str:
    """Return the Discord message text _send_finding would post for *finding*."""
    with mock.patch.object(discord, "_post") as post:
        discord._send_finding("https://example.invalid/hook", finding)
        return post.call_args[0][1]["content"]


class DiscordContentTests(unittest.TestCase):
    def test_snmp_community_string_is_not_sent(self):
        text = payload_for({"type": "snmp_creds", "outcome": "success",
                            "creds": "s3cr3t-community", "session_id": "abcd1234"})
        self.assertNotIn("s3cr3t-community", text)
        self.assertIn("snmp_creds", text)
        self.assertIn("abcd1234", text)

    def test_username_still_sent_but_not_password(self):
        text = payload_for({"type": "ftp_creds", "outcome": "success",
                            "creds": "alice:hunter2", "session_id": "s1"})
        self.assertIn("alice", text)
        self.assertNotIn("hunter2", text)

    def test_password_only_creds_render_as_unknown(self):
        text = payload_for({"type": "irc_creds", "outcome": "success",
                            "creds": ":hunter2", "session_id": "s1"})
        self.assertNotIn("hunter2", text)


if __name__ == "__main__":
    unittest.main()
