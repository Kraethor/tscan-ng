"""
detectors/http_basic.py - HTTP Basic Auth credential detector for tscan-ng.

Detects credentials submitted via HTTP Basic Authentication by scanning
raw TCP payloads for Authorization: Basic headers.

Note: This is a naive MVP implementation that operates on raw TCP payloads
and does not perform full HTTP request reassembly.
"""

from tscan_ng.detectors.common import decode_b64


def detect(pkt: dict) -> list[dict]:
    """
    Detect HTTP Basic Auth credentials in a TCP packet.
    Scans the raw TCP payload for an Authorization: Basic header and
    decodes the base64-encoded credentials if found.
    Args:
        pkt: Normalized packet dict from parsing.net.parse_basic.
    Returns:
        List of finding dicts, empty if no credentials found.
    """
    if not pkt["tcp"]:
        return []
    p = pkt["payload"]
    if not p or b"Authorization:" not in p or b"Basic " not in p:
        return []
    try:
        line = next(l for l in p.split(b"\r\n") if b"Authorization:" in l and b"Basic " in l)
        b64 = line.split(b"Basic ", 1)[1].strip()
        userpass = decode_b64(b64)
        src, dst = pkt["src"], pkt["dst"]
        return [{"type": "http_basic", "src": src, "dst": dst, "creds": userpass}]
    except Exception:
        return []
