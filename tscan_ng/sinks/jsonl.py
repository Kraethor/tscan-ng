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
  - Stdout mode (path=None) takes no lock; concurrent processes writing
    lines larger than PIPE_BUF to a shared pipe could interleave.
  - The file is opened with buffering=0 (unbuffered) so that flock boundaries
    coincide with kernel write boundaries, preventing interleaved lines.

Rotation (TODO.md #47): logrotate renames results.jsonl and creates a new
one (logrotate/tscan). Before each write the sink checks that the file it
holds is still the one at its path (same device and inode) and reopens the
path if not, so every worker moves to the new file on its next finding. A
line written in the moment between the rename and that check still lands in
the rotated file, which delaycompress keeps uncompressed until the next
rotation, so nothing is lost.
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

    The file is reopened when it has been rotated away (renamed or
    deleted) since it was opened; see the module docstring.
    """

    def __init__(self, path: str | None):
        """
        Open the output file in binary append mode with no buffering.

        buffering=0 ensures each write() call maps directly to a single
        kernel write syscall, so flock boundaries are meaningful.

        Args:
            path: Output file path, or None for stdout.

        Raises:
            OSError: If the file cannot be opened for append.
        """
        self._path = path
        self._fd = None
        if path:
            self._fd = open(path, "ab", buffering=0)

    def _reopen_if_rotated(self):
        """
        Reopen self._path if the open file is no longer the one at that path.

        True after logrotate has renamed it (whether or not the new file has
        been created yet) or after it was deleted; the reopen creates the
        file if it is missing. Costs one stat() and one fstat() per write,
        which is negligible at the rate findings are written.

        Raises:
            OSError: If the path cannot be reopened.
        """
        try:
            st = os.stat(self._path)
        except FileNotFoundError:
            st = None
        held = os.fstat(self._fd.fileno())
        if st is not None and (st.st_dev, st.st_ino) == (held.st_dev, held.st_ino):
            return
        old, self._fd = self._fd, open(self._path, "ab", buffering=0)
        old.close()

    def write(self, obj: dict):
        """
        Serialize obj to JSON and write it as a single line.

        For file output, the file is first reopened if it was rotated away
        (TODO.md #47), then an exclusive flock is held for the duration of
        the write to prevent workers from interleaving partial lines.

        For stdout output, a write loop ensures all bytes are written even
        if the underlying fd returns a short write (e.g. stdout connected
        to a full pipe buffer).

        Args:
            obj: Dictionary to serialize. Must be orjson-serializable.

        Raises:
            TypeError: (orjson.JSONEncodeError) if obj is not serializable.
            OSError: On write failure (e.g. disk full).
        """
        line = json.dumps(obj) + b"\n"
        if self._fd:
            self._reopen_if_rotated()
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
