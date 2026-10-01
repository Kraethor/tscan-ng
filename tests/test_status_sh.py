"""
Tests for TODO.md #45: scripts/status.sh counts the pipeline's workers.

The workers are spawn children of the service's main process; their
command lines do not mention tscan_ng, so the old pgrep pattern only ever
counted the main process. status.sh now asks systemd for the MainPID and
counts that process's multiprocessing.spawn children (the resource tracker,
also a child, is not a worker). It also calls sudo only for journalctl:
`systemctl status` and `ip link show` work for any user.

The script runs against stubs placed first on PATH (sudo, systemctl, ip,
journalctl, pgrep); each logs its arguments, so nothing on the host is
queried and the real process table is not involved. The real pgrep
behaviour is checked live (see TODO.md #45).

Run from /opt/tscan:
    PYTHONDONTWRITEBYTECODE=1 venv/bin/python -m unittest discover -s tests -t . -v
"""

import os
import subprocess
import tempfile
import unittest

SCRIPT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                      "scripts", "status.sh")

# Each stub appends "<name> <args>" to $STUB_LOG.
STUBS = {
    "sudo": 'echo "sudo $*" >> "$STUB_LOG"; exec "$@"\n',
    "systemctl": (
        'echo "systemctl $*" >> "$STUB_LOG"\n'
        'case "$1" in\n'
        '  show) echo "$STUB_MAINPID" ;;\n'
        '  *) echo "status of $2" ;;\n'
        'esac\n'),
    "ip": 'echo "ip $*" >> "$STUB_LOG"; echo "link up"\n',
    "journalctl": 'echo "journalctl $*" >> "$STUB_LOG"; echo "log line"\n',
    "pgrep": ('echo "pgrep $*" >> "$STUB_LOG"; echo "$STUB_WORKERS"\n'
              '[ "$STUB_WORKERS" -gt 0 ]\n'),
}


class StatusShTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        for name, body in STUBS.items():
            path = os.path.join(self.tmp.name, name)
            with open(path, "w") as f:
                f.write("#!/usr/bin/env bash\n" + body)
            os.chmod(path, 0o755)
        self.log = os.path.join(self.tmp.name, "calls.log")

    def run_status(self, main_pid: str, workers: str = "0") -> str:
        env = dict(os.environ,
                   PATH=f"{self.tmp.name}:{os.environ['PATH']}",
                   STUB_LOG=self.log, STUB_MAINPID=main_pid, STUB_WORKERS=workers)
        out = subprocess.run(["bash", SCRIPT], env=env, capture_output=True,
                             text=True, timeout=30)
        return out.stdout

    def calls(self) -> list[str]:
        with open(self.log) as f:
            return f.read().splitlines()

    def test_counts_spawn_children_of_the_main_pid(self):
        out = self.run_status("4242", workers="12")
        self.assertIn("main PID 4242, 12 worker process(es)", out)
        self.assertIn(r"pgrep -c -P 4242 -f multiprocessing\.spawn", self.calls())

    def test_not_running(self):
        out = self.run_status("0")
        self.assertIn("pipeline not running", out)
        self.assertFalse(any(c.startswith("pgrep") for c in self.calls()))

    def test_sudo_only_for_journalctl(self):
        self.run_status("4242", workers="12")
        sudo_calls = [c for c in self.calls() if c.startswith("sudo ")]
        self.assertTrue(sudo_calls)
        for call in sudo_calls:
            with self.subTest(call=call):
                self.assertTrue(call.startswith("sudo journalctl "))


if __name__ == "__main__":
    unittest.main()
