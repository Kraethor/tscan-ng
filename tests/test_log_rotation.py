"""
Tests for TODO.md #47: results.jsonl is rotated by rename, and nothing that
writes or reads it loses lines.

logrotate used copytruncate, which drops lines written between its copy and
its truncate. It now renames the file and creates a new one (create +
delaycompress), so:
    - JSONLSink reopens the path when the file it holds is no longer the one
      at the path (rotated away or deleted). A line written by a worker
      that has not noticed yet lands in the rotated file, which
      delaycompress leaves uncompressed until the next rotation.
    - scripts/watch.py and the dashboard's FindingsTailer finish the old
      file, then read the new one from its start.
The repo's logrotate config is also run for real (as this user, against a
temp dir) to check the whole sequence.

Temp dirs only; /var/log/tscan is not touched.

Run from /opt/tscan:
    PYTHONDONTWRITEBYTECODE=1 venv/bin/python -m unittest discover -s tests -t . -v
"""

import importlib.util
import json
import os
import re
import shutil
import subprocess
import tempfile
import threading
import time
import unittest

from tscan_ng.sinks.jsonl import JSONLSink

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOGROTATE_CONF = os.path.join(REPO, "logrotate", "tscan")


def load_script(name: str):
    spec = importlib.util.spec_from_file_location(
        f"{name}_for_rotation_test", os.path.join(REPO, "scripts", f"{name}.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def lines(path: str) -> list[dict]:
    with open(path) as f:
        return [json.loads(line) for line in f]


class TempDirTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = os.path.join(self.tmp.name, "results.jsonl")


class JSONLSinkRotationTests(TempDirTest):
    def test_reopens_after_rename(self):
        sink = JSONLSink(self.path)
        sink.write({"n": 1})
        os.rename(self.path, self.path + ".1")
        sink.write({"n": 2})
        self.assertEqual(lines(self.path + ".1"), [{"n": 1}])
        self.assertEqual(lines(self.path), [{"n": 2}])

    def test_reopens_after_rename_and_create(self):
        sink = JSONLSink(self.path)
        sink.write({"n": 1})
        os.rename(self.path, self.path + ".1")
        open(self.path, "x").close()             # logrotate's "create"
        sink.write({"n": 2})
        self.assertEqual(lines(self.path), [{"n": 2}])

    def test_reopens_after_delete(self):
        sink = JSONLSink(self.path)
        sink.write({"n": 1})
        os.unlink(self.path)
        sink.write({"n": 2})
        self.assertEqual(lines(self.path), [{"n": 2}])

    def test_several_writers_all_follow(self):
        sinks = [JSONLSink(self.path) for _ in range(3)]
        for i, s in enumerate(sinks):
            s.write({"before": i})
        os.rename(self.path, self.path + ".1")
        for i, s in enumerate(sinks):
            s.write({"after": i})
        self.assertEqual(len(lines(self.path + ".1")), 3)
        self.assertEqual(lines(self.path), [{"after": i} for i in range(3)])

    def test_same_file_is_not_reopened(self):
        sink = JSONLSink(self.path)
        sink.write({"n": 1})
        handle = sink._fd
        sink.write({"n": 2})
        self.assertIs(sink._fd, handle)
        self.assertEqual(lines(self.path), [{"n": 1}, {"n": 2}])


class LogrotateConfigTests(TempDirTest):
    def test_config_rotates_by_rename(self):
        with open(LOGROTATE_CONF) as f:
            directives = [l.strip() for l in f if l.strip() and not l.lstrip().startswith("#")]
        self.assertNotIn("copytruncate", directives)
        for wanted in ("create 0640 tscan tscan", "delaycompress", "su tscan tscan"):
            with self.subTest(directive=wanted):
                self.assertIn(wanted, directives)
        self.assertTrue(any(re.fullmatch(r"maxsize \d+[kMG]?", d) for d in directives))

    @unittest.skipUnless(shutil.which("logrotate") or os.path.exists("/usr/sbin/logrotate"),
                         "logrotate not installed")
    def test_real_logrotate_run_with_a_live_sink(self):
        # The repo config, pointed at the temp dir and without the parts
        # that need root (su, ownership in create).
        with open(LOGROTATE_CONF) as f:
            conf = f.read()
        conf = conf.replace("/var/log/tscan/*.jsonl", os.path.join(self.tmp.name, "*.jsonl"))
        conf = re.sub(r"^\s*su .*$", "", conf, flags=re.M)
        conf = conf.replace("create 0640 tscan tscan", "create 0640")
        conf_path = os.path.join(self.tmp.name, "logrotate.conf")
        with open(conf_path, "w") as f:
            f.write(conf)
        logrotate = shutil.which("logrotate") or "/usr/sbin/logrotate"

        sink = JSONLSink(self.path)
        sink.write({"n": 1})
        subprocess.run([logrotate, "-f", "-s", os.path.join(self.tmp.name, "state"), conf_path],
                       check=True, capture_output=True, timeout=30)
        sink.write({"n": 2})

        self.assertEqual(lines(self.path + ".1"), [{"n": 1}])   # delaycompress: not yet .gz
        self.assertEqual(lines(self.path), [{"n": 2}])
        self.assertEqual(os.stat(self.path).st_mode & 0o777, 0o640)


class WatchTailTests(TempDirTest):
    # _tail() opens the file (at its end) on the first next(), so each test
    # starts a reader thread, lets it open the file, then writes. Every read
    # is in a daemon thread with a timeout so a regression fails, not hangs.

    def start_reader(self, tail, n: int, got: list) -> threading.Thread:
        def reader():
            for _ in range(n):
                got.append(next(tail).strip())
        t = threading.Thread(target=reader, daemon=True)
        t.start()
        time.sleep(0.5)
        return t

    def test_follows_rename_without_losing_lines(self):
        watch = load_script("watch")
        open(self.path, "w").close()
        got = []
        t = self.start_reader(watch._tail(self.path), 3, got)
        with open(self.path, "a") as f:
            f.write("a\n")
        time.sleep(0.5)
        # Rotation: one more line reaches the old file (a worker that has not
        # reopened yet), then the new file gets a line before watch notices.
        os.rename(self.path, self.path + ".1")
        with open(self.path + ".1", "a") as f:
            f.write("b\n")
        with open(self.path, "w") as f:
            f.write("c\n")
        t.join(timeout=10)
        self.assertEqual(got, ["a", "b", "c"])

    def test_follows_truncation(self):
        watch = load_script("watch")
        with open(self.path, "w") as f:
            f.write("old line one\nold line two\n")
        got = []
        t = self.start_reader(watch._tail(self.path), 1, got)
        with open(self.path, "w") as f:      # truncate in place, then a new line
            f.write("x\n")
        t.join(timeout=10)
        self.assertEqual(got, ["x"])


class DashboardTailerTests(TempDirTest):
    def write_finding(self, path, n):
        with open(path, "a") as f:
            f.write(json.dumps({"type": "http_basic", "outcome": "success", "n": n}) + "\n")

    def test_follows_rename_without_losing_lines(self):
        dashboard = load_script("dashboard")
        self.write_finding(self.path, 1)
        tailer = dashboard.FindingsTailer(self.path)
        self.assertEqual(tailer.total, 1)
        os.rename(self.path, self.path + ".1")
        self.write_finding(self.path + ".1", 2)     # straggler into the old file
        self.write_finding(self.path, 3)            # first line of the new file
        tailer.poll()
        self.assertEqual(tailer.total, 3)
        self.assertEqual(tailer.last_line["n"], 3)
        self.write_finding(self.path, 4)
        tailer.poll()
        self.assertEqual(tailer.total, 4)

    def test_follows_truncation(self):
        dashboard = load_script("dashboard")
        self.write_finding(self.path, 1)
        self.write_finding(self.path, 2)
        tailer = dashboard.FindingsTailer(self.path)
        with open(self.path, "w"):
            pass
        self.write_finding(self.path, 3)
        tailer.poll()
        self.assertEqual(tailer.total, 3)


if __name__ == "__main__":
    unittest.main()
