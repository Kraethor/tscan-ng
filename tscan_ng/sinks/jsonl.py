"""
sinks/jsonl.py - JSONL output sink for tscan-ng detection findings.

Writes detection findings as newline-delimited JSON (JSONL) to either a file
or stdout. Uses orjson for fast serialization.

Each worker process opens its own file handle. flock() ensures writes from
concurrent worker processes do not interleave.
"""

import os
import fcntl
import orjson as json


class JSONLSink:
    """
    Writes detection findings to a JSONL file or stdout.
    Args:
        path: Filesystem path to the output file, or None to write to stdout.
    """

    def __init__(self, path: str | None):
        """
        Open the output file in binary append mode with no buffering.
        Args:
            path: Output file path, or None for stdout.
        """
        self._fd = None
        if path:
            self._fd = open(path, "ab", buffering=0)

    def write(self, obj: dict):
        """
        Serialize obj to JSON and write it as a single line.
        Args:
            obj: Dictionary to serialize. Must be orjson-serializable.
        """
        line = json.dumps(obj) + b"\n"
        if self._fd:
            fcntl.flock(self._fd, fcntl.LOCK_EX)
            try:
                self._fd.write(line)
            finally:
                fcntl.flock(self._fd, fcntl.LOCK_UN)
        else:
            try:
                os.write(1, line)
            except OSError:
                pass
