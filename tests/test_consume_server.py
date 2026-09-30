"""
Tests for TODO.md #13: bytes may only leave the front of server_buf through
Session.consume_server(), which also shifts every pending finding's floor.
Several detectors used to `del session.server_buf[:n]` directly without the
shift, leaving other pending findings' floors pointing past their data.

Run from /opt/tscan:
    PYTHONDONTWRITEBYTECODE=1 venv/bin/python -m unittest discover -s tests -t . -v
"""

import pathlib
import re
import unittest

from tscan_ng import resolve
from tscan_ng.detectors import ftp
from tscan_ng.session import Session, SessionTable

PACKAGE = pathlib.Path(__file__).resolve().parent.parent / "tscan_ng"


def make_session() -> Session:
    s = Session("10.0.0.2", "10.0.0.9", 50000, 21)
    s.last_ts = 1000.0
    return s


class ConsumeServerTests(unittest.TestCase):
    def test_deletes_and_shifts_floors(self):
        s = make_session()
        s.server_buf.extend(b"0123456789")
        s.add_pending({"type": "x"}, 1.0)                 # floor 10
        s.add_pending({"type": "x"}, 1.0, floor=3)
        s.consume_server(4)
        self.assertEqual(bytes(s.server_buf), b"456789")
        self.assertEqual([p.server_buf_floor for p in s.pending], [6, 0])

    def test_zero_is_a_no_op(self):
        s = make_session()
        s.server_buf.extend(b"abc")
        s.add_pending({"type": "x"}, 1.0)
        s.consume_server(0)
        self.assertEqual((bytes(s.server_buf), s.pending[0].server_buf_floor), (b"abc", 3))

    def test_only_consume_server_deletes_from_server_buf(self):
        pattern = re.compile(r"del\s+[\w.]*server_buf\[")
        offenders = []
        for path in PACKAGE.rglob("*.py"):
            for n, line in enumerate(path.read_text().splitlines(), 1):
                code = line.split("#", 1)[0]
                if pattern.search(code) and "self.server_buf" not in code:
                    offenders.append(f"{path.relative_to(PACKAGE)}:{n}")
        self.assertEqual(offenders, [])

    def test_resolving_one_finding_keeps_the_next_floor_on_its_data(self):
        # Two FTP logins pending; the first reply is consumed, and the second
        # finding's floor must still point at (not past) its own reply.
        s = make_session()
        s.client_buf.extend(b"USER a\r\nPASS 1\r\n")
        ftp.detect_stream(s, 1.0)
        s.server_buf.extend(b"530 no\r\n")
        s.client_buf.extend(b"USER a\r\nPASS 2\r\n")
        ftp.detect_stream(s, 2.0)
        second = s.pending[1]
        self.assertEqual(second.server_buf_floor, 8)
        s.server_buf.extend(b"230 ok\r\n")
        done = resolve.resolve_pending(s, 3.0)
        self.assertEqual([f["outcome"] for f in done], ["failed", "success"])

    def test_trim_shifts_floors(self):
        table = SessionTable(max_buf=16)
        pkt = {"src": "10.0.0.9", "dst": "10.0.0.2", "sport": 21, "dport": 50000,
               "payload": b"x" * 20}
        s, _ = table.add_packet({**pkt, "src": "10.0.0.2", "dst": "10.0.0.9",
                                 "sport": 50000, "dport": 21, "payload": b"hi"}, 1.0)
        s.add_pending({"type": "ftp_creds"}, 1.0, floor=10)
        table.add_packet(pkt, 2.0)
        self.assertEqual(len(s.server_buf), 16)
        self.assertEqual(s.pending[0].server_buf_floor, 6)


if __name__ == "__main__":
    unittest.main()
