"""
sinks/jsonl.py - JSONL output sink for tscan-ng detection findings.

Writes detection findings as newline-delimited JSON (JSONL) to either a file
or stdout. Uses orjson for fast serialization.

Each worker process opens its own file handle. flock() ensures writes from
concurrent worker processes do not interleave, preventing partial-line
corruption in the output file.

Platform notes:
  - fcntl.flock() is Linux/Unix only. This module is not portable to Windows.
  - flock() behaviour is undefined on NFS mounts. The output file must reside
    on a local filesystem (the default /var/log/tscan/ is always local).
  - The file is opened with buffering=0 (unbuffered) so that flock boundaries
    coincide with kernel write boundaries, preventing interleaved lines.
"""

import os
import fcntl
import orjson as json


class JSONLSink:
    """
    Writes detection findings to a JSONL file or stdout.

    File output uses flock() for multi-process write safety. Stdout output
    uses a write loop to handle partial writes, which can occur when stdout
    is connected to a pipe with a full buffer.

    Args:
        path: Filesystem path to the output file, or None to write to stdout.
    """

    def __init__(self, path: str | None):
        """
        Open the output file in binary append mode with no buffering.

        buffering=0 ensures each write() call maps directly to a single
        kernel write syscall, so flock boundaries are meaningful.

        Args:
            path: Output file path, or None for stdout.
        """
        self._fd = None
        if path:
            self._fd = open(path, "ab", buffering=0)

    def write(self, obj: dict):
        """
        Serialize obj to JSON and write it as a single line.

        For file output, an exclusive flock is held for the duration of the
        write to prevent workers from interleaving partial lines.

        For stdout output, a write loop ensures all bytes are written even
        if the underlying fd returns a short write (e.g. stdout connected
        to a full pipe buffer).

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
            # os.write() may return a short count on stdout connected to a
            # pipe; loop until all bytes are written.
            while line:
                written = os.write(1, line)
                line = line[written:]
