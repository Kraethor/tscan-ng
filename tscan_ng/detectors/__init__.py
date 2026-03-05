"""
detectors/__init__.py - Detector registry for tscan-ng.

Exports two detector lists consumed by worker processes in run.py:

    DETECTORS:        Per-packet detectors. Receive a normalized pkt dict
                      and return a list of finding dicts.

    STREAM_DETECTORS: Stream-aware detectors. Receive a Session object and
                      the current packet timestamp, and return a list of
                      resolved finding dicts. Pending findings are registered
                      directly on the session for later resolution.

To add a new detector:
    - Per-packet:    implement detect(pkt) and append to DETECTORS
    - Stream-aware:  implement detect_stream(session, ts) and append to
                     STREAM_DETECTORS

Each per-packet detector must implement:
    def detect(pkt: dict) -> list[dict]

Each stream detector must implement:
    def detect_stream(session: Session, ts: float) -> list[dict]
"""

from tscan_ng.detectors import http_basic, ftp, pop3, imap, smtp

DETECTORS = [
    pop3.detect,
]

STREAM_DETECTORS = [
    http_basic.detect_stream,
    imap.detect_stream,
    ftp.detect_stream,
    smtp.detect_stream,
]
