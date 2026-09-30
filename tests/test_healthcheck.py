"""
Tests for scripts/pipeline_healthcheck.py (TODO.md #4): the watchdog must
still alert when the pipeline is down because the capture NIC vanished, i.e.
exactly when tscan_ng.config.Config() validation fails.

systemctl, the Discord sink and the state directory are all replaced; nothing
is sent and no real service is touched.

Run from /opt/tscan:
    PYTHONDONTWRITEBYTECODE=1 venv/bin/python -m unittest discover -s tests -t . -v
"""

import importlib.util
import os
import tempfile
import unittest
from unittest import mock

from tscan_ng.config import Config

_SPEC = importlib.util.spec_from_file_location(
    "pipeline_healthcheck",
    os.path.join(os.path.dirname(__file__), "..", "scripts", "pipeline_healthcheck.py"))
hc = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(hc)

WEBHOOK = "https://example.invalid/hook"


def write_conf(directory: str, iface: str, webhook: str = WEBHOOK) -> str:
    """Write a minimal config whose capture.iface is *iface*; return its path."""
    path = os.path.join(directory, "tscan_ng.conf")
    with open(path, "w") as f:
        f.write(f"[capture]\niface = {iface}\n[discord]\ndiscord_webhook = {webhook}\n")
    return path


class ConfigValidateFlagTests(unittest.TestCase):
    def test_missing_nic_fails_validation_by_default(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(ValueError):
                Config(write_conf(d, "nonexistent-nic0"))

    def test_validate_false_still_reads_webhook(self):
        with tempfile.TemporaryDirectory() as d:
            cfg = Config(write_conf(d, "nonexistent-nic0"), validate=False)
            self.assertEqual(cfg.discord_webhook, WEBHOOK)


class HealthcheckMainTests(unittest.TestCase):
    def _run(self, conf_path, active: bool, marker_exists: bool = False):
        """Run main() against a temp state dir; return (sink_cls, marker_path)."""
        state = tempfile.mkdtemp()
        marker = os.path.join(state, "down")
        if marker_exists:
            open(marker, "w").close()
        with mock.patch.object(hc, "STATE_DIR", state), \
             mock.patch.object(hc, "DOWN_MARKER", marker), \
             mock.patch.object(hc, "_is_active", return_value=active), \
             mock.patch.object(hc, "_active_duration", return_value=9999.0), \
             mock.patch.object(hc, "CONFIG_PATH", conf_path), \
             mock.patch.object(hc, "DiscordSink") as sink_cls:
            hc.main()
        return sink_cls, marker

    def test_down_alert_sent_when_capture_nic_missing(self):
        with tempfile.TemporaryDirectory() as d:
            sink_cls, marker = self._run(write_conf(d, "nonexistent-nic0"), active=False)
            self.assertTrue(os.path.exists(marker))
            self.assertEqual(sink_cls.call_args[0][0], WEBHOOK)
            notify = sink_cls.return_value.notify
            self.assertEqual(notify.call_count, 1)
            self.assertIn("DOWN", notify.call_args[0][0])

    def test_down_alert_sent_when_config_unreadable(self):
        """Even a config that cannot be parsed must not stop the marker/alert path."""
        with tempfile.TemporaryDirectory() as d:
            bad = os.path.join(d, "tscan_ng.conf")
            with open(bad, "w") as f:
                f.write("[capture\nthis is not ini\n")
            sink_cls, marker = self._run(bad, active=False)
            self.assertTrue(os.path.exists(marker))
            self.assertEqual(sink_cls.call_args[0][0], "")

    def test_recovered_alert_when_active_again(self):
        with tempfile.TemporaryDirectory() as d:
            sink_cls, marker = self._run(write_conf(d, "lo"), active=True, marker_exists=True)
            self.assertFalse(os.path.exists(marker))
            self.assertIn("RECOVERED", sink_cls.return_value.notify.call_args[0][0])

    def test_healthy_and_quiet(self):
        with tempfile.TemporaryDirectory() as d:
            sink_cls, marker = self._run(write_conf(d, "lo"), active=True)
            self.assertEqual(sink_cls.return_value.notify.call_count, 0)


if __name__ == "__main__":
    unittest.main()
