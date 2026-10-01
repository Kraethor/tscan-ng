"""
Tests for TODO.md #22: HTTP request framing.

(a) A request body (POST/PUT payload) is skipped using Content-Length, so it is
    not glued onto the next request's header block. Before the fix the body
    bytes parsed as the next request: a fake request line in the body became the
    reported method/URI, and a CRLFCRLF in the body was counted as an extra
    request, shifting the response-correlation index.

(b) A header block larger than the scan window with no CRLFCRLF no longer stalls
    the connection: the scanned prefix is dropped (advance_scan_window(), the
    same mechanism as #16) so later requests on the connection are recovered.

Each test drives http_basic.detect_stream()/resolve() the way the pipeline does.

Run from /opt/tscan:
    PYTHONDONTWRITEBYTECODE=1 venv/bin/python -m unittest discover -s tests -t . -v
"""

import base64
import unittest

from tscan_ng.detectors import http_basic
from tscan_ng import resolve
from tscan_ng.session import Session

TS = 1000.0
TOKEN = base64.b64encode(b"user:pass")       # dXNlcjpwYXNz


def make_session() -> Session:
    s = Session("10.0.0.2", "10.0.0.9", 50000, 80)
    s.last_ts = TS
    return s


def cred_get(path=b"/secret") -> bytes:
    return (b"GET " + path + b" HTTP/1.1\r\nHost: h\r\n"
            b"Authorization: Basic " + TOKEN + b"\r\n\r\n")


class PostBodySkipTests(unittest.TestCase):
    def test_body_not_parsed_as_next_request_line(self):
        # A POST body that itself looks like a request line must not become the
        # reported method/URI of the following credentialed GET.
        body = b"GET /evil HTTP/1.1\r\n"          # 20 bytes, a decoy request line
        post = (b"POST /up HTTP/1.1\r\nHost: h\r\nContent-Length: %d\r\n\r\n"
                % len(body)) + body
        s = make_session()
        s.client_buf.extend(post + cred_get(b"/secret"))
        http_basic.detect_stream(s, TS)
        self.assertEqual(len(s.pending), 1)
        f = s.pending[0].finding
        self.assertEqual(f["creds"], "user:pass")
        self.assertEqual(f["method"], "GET")
        self.assertEqual(f["uri"], "/secret")

    def test_body_with_crlfcrlf_does_not_shift_response_index(self):
        # A body containing a blank line must not be counted as an extra request
        # (which would pair the GET's credentials with the wrong response).
        body = b"a\r\n\r\nb"                       # contains CRLFCRLF
        post = (b"POST /up HTTP/1.1\r\nHost: h\r\nContent-Length: %d\r\n\r\n"
                % len(body)) + body
        s = make_session()
        s.client_buf.extend(post + cred_get(b"/secret"))
        http_basic.detect_stream(s, TS)
        self.assertEqual(len(s.pending), 1)
        self.assertEqual(s.pending[0].finding["_rsp_index"], 1)   # POST=0, GET=1
        # Responses in request order: POST's 204, then GET's 200.
        s.server_buf.extend(b"HTTP/1.1 204 No Content\r\n\r\n"
                            b"HTTP/1.1 200 OK\r\n\r\n")
        done = resolve.resolve_pending(s, TS + 1)
        self.assertEqual([(d["status"], d["outcome"]) for d in done],
                         [("200", "success")])

    def test_body_split_across_packets(self):
        body = b"x" * 100
        post = (b"POST /up HTTP/1.1\r\nHost: h\r\nContent-Length: 100\r\n\r\n")
        s = make_session()
        # Packet 1: POST headers + first 40 body bytes.
        s.client_buf.extend(post + body[:40])
        http_basic.detect_stream(s, TS)
        self.assertEqual(s.pending, [])
        self.assertEqual(s.http_body_remaining, 60)
        # Packet 2: rest of the body + the credentialed GET.
        s.client_buf.extend(body[40:] + cred_get(b"/secret"))
        http_basic.detect_stream(s, TS)
        self.assertEqual(s.http_body_remaining, 0)
        self.assertEqual(len(s.pending), 1)
        self.assertEqual(s.pending[0].finding["uri"], "/secret")

    def test_plain_get_still_works(self):
        s = make_session()
        s.client_buf.extend(cred_get(b"/x"))
        http_basic.detect_stream(s, TS)
        self.assertEqual(len(s.pending), 1)
        self.assertEqual(s.pending[0].finding["creds"], "user:pass")


class OversizedHeaderTests(unittest.TestCase):
    def test_header_block_over_window_does_not_stall(self):
        # A header block larger than the window with no blank line: the prefix is
        # dropped so a later request is reached, instead of stalling forever.
        junk = b"GET /big HTTP/1.1\r\n" + b"X-H: v\r\n" * 3000   # ~24 KB, no CRLFCRLF
        s = make_session()
        s.client_buf.extend(junk)
        http_basic.detect_stream(s, TS)
        self.assertEqual(s.pending, [])
        self.assertLess(len(s.client_buf), len(junk))            # window advanced
        # A real credentialed request now fits and is detected.
        s.client_buf.extend(cred_get(b"/secret"))
        http_basic.detect_stream(s, TS)
        self.assertEqual(len(s.pending), 1)
        self.assertEqual(s.pending[0].finding["creds"], "user:pass")


if __name__ == "__main__":
    unittest.main()
