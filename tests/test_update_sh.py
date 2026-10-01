"""
Tests for scripts/update.sh (TODO.md #20): an update must never leave the
pipeline stopped. The old script stopped the service first, so any failure
(git pull, pip, a bad unit) left it down, and it exited 0 even when the
service did not come back.

The script runs against stubs: `id` (reports root), `sudo`, `git`,
`systemctl` and `sleep` come first on PATH, and TSCAN_APP_DIR /
TSCAN_UNIT_DIR point at a temp tree with a fake venv. Nothing on the host is
touched. The stubs read their behaviour from, and log every call to, a
state directory.

Run from /opt/tscan:
    PYTHONDONTWRITEBYTECODE=1 venv/bin/python -m unittest discover -s tests -t . -v
"""

import os
import pathlib
import subprocess
import tempfile
import textwrap
import unittest

SCRIPT = pathlib.Path(__file__).resolve().parent.parent / "scripts" / "update.sh"
UNITS = ("tscan-pipeline.service", "tscan-pipeline-healthcheck.service",
         "tscan-pipeline-healthcheck.timer")

STUBS = {
    "id": 'echo 0\n',
    "sleep": 'exit 0\n',
    # sudo -u USER -H cmd... -> run cmd
    "sudo": textwrap.dedent('''\
        while [[ "$1" == -* ]]; do
          case "$1" in -u) shift 2 ;; *) shift ;; esac
        done
        exec "$@"
    '''),
    "git": textwrap.dedent('''\
        echo "git $*" >> "$STATE/calls"
        while [[ "$1" == -C ]]; do shift 2; done
        case "$1" in
          rev-parse) cat "$STATE/head" ;;
          pull)
            rc=$(cat "$STATE/pull_rc")
            [[ $rc == 0 ]] && cp "$STATE/new_head" "$STATE/head"
            exit "$rc" ;;
          reset) echo "${@: -1}" > "$STATE/head" ;;
        esac
    '''),
    "systemctl": textwrap.dedent('''\
        echo "systemctl $*" >> "$STATE/calls"
        n=$(cat "$STATE/restarts" 2>/dev/null || echo 0)
        case "$1" in
          restart) echo $((n + 1)) > "$STATE/restarts" ;;
          is-active)
            state=$(cat "$STATE/active_$n" 2>/dev/null || echo active)
            [[ " $* " == *" --quiet "* ]] || echo "$state"
            [[ $state == active ]] ;;
          show)   # NRestarts: 0 right after a restart, then nrestarts_<n>
            k=$(cat "$STATE/shows_$n" 2>/dev/null || echo 0); echo $((k + 1)) > "$STATE/shows_$n"
            if (( k == 0 )); then echo 0; else cat "$STATE/nrestarts_$n" 2>/dev/null || echo 0; fi ;;
        esac
        exit $?
    '''),
}

VENV_PYTHON = textwrap.dedent('''\
    echo "python $*" >> "$STATE/calls"
    case "$*" in
      *unittest*) exit "$(cat "$STATE/tests_rc")" ;;
      *) exit "$(cat "$STATE/config_rc")" ;;
    esac
''')
VENV_PIP = 'echo "pip $*" >> "$STATE/calls"\n'


def write_exec(path: pathlib.Path, body: str):
    path.write_text("#!/usr/bin/env bash\n" + body)
    path.chmod(0o755)


class UpdateShTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = pathlib.Path(self.tmp.name)
        self.state, self.app, self.unitdir, stub_bin = (
            root / "state", root / "app", root / "units", root / "bin")
        for d in (self.state, self.app / "systemd", self.app / "venv" / "bin",
                  self.unitdir, stub_bin):
            d.mkdir(parents=True)
        for name, body in STUBS.items():
            write_exec(stub_bin / name, body)
        write_exec(self.app / "venv" / "bin" / "python", VENV_PYTHON)
        write_exec(self.app / "venv" / "bin" / "pip", VENV_PIP)
        (self.app / "requirements.txt").write_text("dpkt\n")
        for unit in UNITS:
            (self.app / "systemd" / unit).write_text(f"[Unit]\n# {unit} v1\n")
            (self.unitdir / unit).write_text(f"[Unit]\n# {unit} v1\n")
        self.set(head="aaaa", new_head="bbbb", pull_rc=0, tests_rc=0, config_rc=0)
        self.env = {**os.environ, "STATE": str(self.state),
                    "PATH": f"{stub_bin}:{os.environ['PATH']}",
                    "TSCAN_APP_DIR": str(self.app), "TSCAN_UNIT_DIR": str(self.unitdir),
                    "TSCAN_HEALTH_WAIT": "1"}

    def tearDown(self):
        self.tmp.cleanup()

    def set(self, **files):
        for name, value in files.items():
            (self.state / name).write_text(f"{value}\n")

    def run_update(self):
        result = subprocess.run(["bash", str(SCRIPT)], env=self.env,
                                capture_output=True, text=True, timeout=30)
        calls_file = self.state / "calls"
        self.calls = calls_file.read_text().splitlines() if calls_file.exists() else []
        self.output = result.stdout + result.stderr
        return result.returncode

    def head(self):
        return (self.state / "head").read_text().strip()

    def restarts(self):
        return [c for c in self.calls if c.startswith("systemctl restart")]

    def test_success(self):
        self.assertEqual(self.run_update(), 0, self.output)
        self.assertEqual(self.head(), "bbbb")
        self.assertEqual(len(self.restarts()), 1)
        self.assertFalse(any(c.startswith("systemctl stop") for c in self.calls))
        self.assertFalse(any("reset" in c for c in self.calls))
        # Pre-flight ran before the restart.
        idx = {c: i for i, c in enumerate(self.calls)}
        first_python = min(i for c, i in idx.items() if c.startswith("python"))
        self.assertLess(first_python, self.calls.index(self.restarts()[0]))

    def test_unchanged_units_skip_daemon_reload(self):
        self.run_update()
        self.assertNotIn("systemctl daemon-reload", self.calls)

    def test_changed_unit_is_installed(self):
        (self.app / "systemd" / UNITS[0]).write_text("[Unit]\n# v2\n")
        self.assertEqual(self.run_update(), 0, self.output)
        self.assertEqual((self.unitdir / UNITS[0]).read_text(), "[Unit]\n# v2\n")
        self.assertIn("systemctl daemon-reload", self.calls)

    def test_failing_tests_abort_before_restart_and_restore_code(self):
        self.set(tests_rc=1)
        self.assertEqual(self.run_update(), 2, self.output)
        self.assertEqual(self.restarts(), [])
        self.assertEqual(self.head(), "aaaa")

    def test_invalid_config_aborts_before_restart(self):
        self.set(config_rc=1)
        self.assertEqual(self.run_update(), 2, self.output)
        self.assertEqual(self.restarts(), [])
        self.assertEqual(self.head(), "aaaa")

    def test_pull_failure_leaves_service_alone(self):
        self.set(pull_rc=1)
        self.assertEqual(self.run_update(), 2, self.output)
        self.assertEqual(self.restarts(), [])
        self.assertEqual(self.head(), "aaaa")

    def test_service_not_coming_up_is_rolled_back(self):
        (self.app / "systemd" / UNITS[0]).write_text("[Unit]\n# v2\n")
        self.set(active_1="activating")          # after the first restart only
        self.assertEqual(self.run_update(), 3, self.output)
        self.assertEqual(self.head(), "aaaa")
        self.assertEqual(len(self.restarts()), 2)
        self.assertEqual((self.unitdir / UNITS[0]).read_text(), f"[Unit]\n# {UNITS[0]} v1\n")

    def test_unit_install_failure_rolls_back_cleanly(self):
        # The unit dir is not writable: the install fails before any restart.
        # Nothing was replaced, so the rollback must not report the service down.
        (self.app / "systemd" / UNITS[0]).write_text("[Unit]\n# v2\n")
        self.unitdir.chmod(0o555)
        try:
            rc = self.run_update()
        finally:
            self.unitdir.chmod(0o755)
        self.assertEqual(rc, 3, self.output)
        self.assertEqual(self.head(), "aaaa")
        self.assertNotIn("DOWN", self.output)

    def test_restart_loop_counts_as_failure(self):
        self.set(nrestarts_1=2)                  # active, but systemd restarted it twice
        self.assertEqual(self.run_update(), 3, self.output)
        self.assertEqual(self.head(), "aaaa")

    def test_failed_rollback_is_reported(self):
        self.set(active_1="failed", active_2="failed")
        self.assertEqual(self.run_update(), 4, self.output)
        self.assertIn("DOWN", self.output)

    def test_not_root(self):
        write_exec(pathlib.Path(self.env["PATH"].split(":")[0]) / "id", "echo 1000\n")
        self.assertEqual(self.run_update(), 1)
        self.assertEqual(self.calls, [])


if __name__ == "__main__":
    unittest.main()
