"""
detectors/__init__.py - Detector registry for tscan-ng.

Exports the DETECTORS list consumed by worker processes in run.py.
To add a new detector, import it here and append its detect function.

Each detector must implement:
    def detect(pkt: dict) -> list[dict]

Where pkt is the normalized packet dict from parsing.net.parse_basic,
and each returned dict contains at minimum: type, src, dst, creds.
"""

from tscan_ng.detectors import http_basic, ftp, pop3, imap, smtp

DETECTORS = [
    http_basic.detect,
    ftp.detect,
    pop3.detect,
    imap.detect,
    smtp.detect,
]
