"""
detectors/common.py - Shared utilities for tscan-ng detectors.

Provides base64 decoding and a reusable USER/PASS detection helper
used by protocol detectors such as FTP and POP3.
"""

import base64


def decode_b64(token: bytes) -> str:
    """
    Decode a base64-encoded token to a UTF-8 string.
    Tolerates padding errors and non-UTF-8 bytes.
    Args:
        token: Raw base64-encoded bytes.
    Returns:
        Decoded string, or empty string on any error.
    """
    try:
        return base64.b64decode(token, validate=False).decode("utf-8", "ignore")
    except Exception:
        return ""


def detect_user_pass(payload: bytes, finding_type: str, src: str, dst: str,
                     reset_prefixes: tuple[bytes, ...]) -> list[dict]:
    """
    Generic USER/PASS credential detector for line-oriented cleartext protocols.
    Scans payload lines for USER and PASS commands. Pairs them into credential
    findings. Resets pending state on protocol-specific error or quit responses.
    Used by FTP and POP3 detectors which share this exact pattern.
    Args:
        payload:         Raw TCP payload bytes.
        finding_type:    Finding type string written to the output (e.g. "ftp_creds").
        src:             Source IP address string.
        dst:             Destination IP address string.
        reset_prefixes:  Tuple of byte prefixes that reset pending user state
                         (e.g. (b"530", b"QUIT") for FTP).
    Returns:
        List of finding dicts with keys: type, src, dst, creds.
    """
    lines = payload.split(b"\r\n")
    findings = []
    pending_user = None
    for line in lines:
        upper = line.upper()
        if upper.startswith(b"USER "):
            pending_user = line[5:].strip().decode("utf-8", "ignore")
            continue
        if upper.startswith(b"PASS ") and pending_user:
            passwd = line[5:].strip().decode("utf-8", "ignore")
            findings.append({"type": finding_type, "src": src, "dst": dst,
                             "creds": f"{pending_user}:{passwd}"})
            pending_user = None
            continue
        if any(upper.startswith(p) for p in reset_prefixes):
            pending_user = None
    return findings
