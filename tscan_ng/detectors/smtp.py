"""
detectors/smtp.py - SMTP credential detector for tscan-ng.

Detects cleartext credentials submitted via SMTP AUTH PLAIN and AUTH LOGIN
mechanisms. Handles both inline and challenge-response variants of each.

AUTH PLAIN: credentials are base64-encoded in the format \\x00user\\x00pass
AUTH LOGIN: credentials are exchanged as separate base64-encoded responses
            to server 334 challenges.
"""

import re
from tscan_ng.detectors.common import decode_b64

_SMTP_RESPONSE_RE = re.compile(rb"^\d{3}[ -]")


def _next_client_tokens(lines: list[bytes], start_idx: int, count: int) -> list[bytes]:
    """
    Collect the next `count` client-originated tokens from a list of SMTP lines.
    Skips any line that matches a 3-digit SMTP server response code (e.g.
    334, 235, 535), consuming only client-sent base64 tokens.
    Args:
        lines:     All lines from the TCP payload split on CRLF.
        start_idx: Line index to start scanning from.
        count:     Maximum number of client tokens to collect.
    Returns:
        List of raw token bytes (not yet decoded).
    """
    tokens = []
    idx = start_idx
    while idx < len(lines) and len(tokens) < count:
        token = lines[idx].strip()
        if token and not _SMTP_RESPONSE_RE.match(token):
            tokens.append(token)
        idx += 1
    return tokens


def _find_auth_plain(lines: list[bytes], src: str, dst: str) -> list[dict]:
    """
    Detect credentials from SMTP AUTH PLAIN exchanges.
    AUTH PLAIN credentials are a single base64 token encoding:
        \\x00username\\x00password
    The token may appear inline on the AUTH PLAIN line, or on the
    following line after a 334 server challenge.
    Args:
        lines: SMTP payload lines split on CRLF.
        src:   Source IP address.
        dst:   Destination IP address.
    Returns:
        List of finding dicts with keys: type, src, dst, creds.
    """
    findings = []
    for idx, line in enumerate(lines):
        upper = line.upper()
        if b"AUTH PLAIN" not in upper:
            continue
        token = line.split(b"AUTH PLAIN", 1)[1].strip()
        if not token and idx + 1 < len(lines):
            token = lines[idx + 1].strip()
        if not token:
            continue
        decoded = decode_b64(token)
        parts = decoded.split("\x00")
        if len(parts) >= 3:
            user = parts[-2]
            passwd = parts[-1]
            findings.append({"type": "smtp_plain_creds", "src": src, "dst": dst,
                             "creds": f"{user}:{passwd}"})
    return findings


def _find_auth_login(lines: list[bytes], src: str, dst: str) -> list[dict]:
    """
    Detect credentials from SMTP AUTH LOGIN exchanges.
    AUTH LOGIN exchanges username and password as separate base64-encoded
    responses to server 334 challenges. The username may appear inline on
    the AUTH LOGIN line, or as the first challenge response.
    Args:
        lines: SMTP payload lines split on CRLF.
        src:   Source IP address.
        dst:   Destination IP address.
    Returns:
        List of finding dicts with keys: type, src, dst, creds.
    """
    findings = []
    for idx, line in enumerate(lines):
        upper = line.upper()
        if b"AUTH LOGIN" not in upper:
            continue
        parts = line.split(b"AUTH LOGIN", 1)[1].strip()
        user = decode_b64(parts) if parts else ""
        needed = 2 if not user else 1
        tokens = _next_client_tokens(lines, idx + 1, needed)
        passwd = ""
        if user:
            if tokens:
                passwd = decode_b64(tokens[0])
        elif len(tokens) >= 2:
            user = decode_b64(tokens[0])
            passwd = decode_b64(tokens[1])
        elif len(tokens) == 1:
            user = decode_b64(tokens[0])
        if user or passwd:
            findings.append({"type": "smtp_login_creds", "src": src, "dst": dst,
                             "creds": f"{user}:{passwd}"})
    return findings


def detect(pkt: dict) -> list[dict]:
    """
    Detect SMTP AUTH LOGIN and AUTH PLAIN credentials in a TCP packet.
    Args:
        pkt: Normalized packet dict from parsing.net.parse_basic.
    Returns:
        List of finding dicts, empty if no credentials found.
    """
    if not pkt["tcp"]:
        return []
    payload = pkt["payload"]
    if not payload:
        return []
    lines = payload.split(b"\r\n")
    src, dst = pkt["src"], pkt["dst"]
    findings = []
    findings.extend(_find_auth_plain(lines, src, dst))
    findings.extend(_find_auth_login(lines, src, dst))
    return findings
