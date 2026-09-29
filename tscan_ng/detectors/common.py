"""
detectors/common.py - Shared utilities for tscan-ng detectors.

Provides:
    decode_b64()       - lenient base64 -> str helper. Currently imported by
                         http_basic.py (Authorization: Basic token) and
                         smtp.py (AUTH LOGIN username/password lines).
    detect_user_pass() - a generic packet-payload USER/PASS pairing helper.
                         NOTE: this is legacy code from the pre-stream
                         (per-packet) detector design. Nothing in the package
                         imports or calls it any more -- ftp.py and pop3.py
                         each carry their own stream-aware USER/PASS logic
                         (regex over session.client_buf, response correlation
                         via the session's pending list). It is retained
                         unchanged; do not use it for new detectors, which
                         must follow the stream-aware detect_stream(session,
                         ts) contract described in detectors/__init__.py.

Module-level state: none. Both functions are pure (no session access, no I/O).
"""

import base64


def decode_b64(token: bytes) -> str:
    """
    Decode a base64-encoded token to a UTF-8 string.

    Non-UTF-8 bytes in the decoded data are silently dropped ("ignore"), and
    characters outside the base64 alphabet are discarded (validate=False)
    rather than rejected. Incorrect padding is NOT tolerated: base64.b64decode
    raises binascii.Error for a token with missing/extra "=" padding, which is
    caught below and reported as the empty string, so callers cannot tell
    "bad token" apart from "token that decodes to nothing".

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

    Operates on a SINGLE packet payload (not a reassembled stream): splits it
    on CRLF, remembers the most recent "USER <name>" line, and when a later
    "PASS <pw>" line arrives emits a finding pairing the two. Matching is
    case-insensitive and anchored at the start of each line. The pending user
    is cleared after a pairing, and also when a line starts with one of
    reset_prefixes.

    Legacy/unused: no detector in the package calls this any more (see the
    module docstring). Because it works per packet and never looks at the
    server side, it produces no outcome/status and cannot correlate a
    response. The findings it returns lack session_id, ports, filter and
    outcome, so they are not compatible with the current sinks.

    Args:
        payload:         Raw TCP payload bytes.
        finding_type:    Finding type string written to the output (e.g. "ftp_creds").
        src:             Source IP address string.
        dst:             Destination IP address string.
                         (e.g. (b"530", b"QUIT") for FTP). Compared against the
                         upper-cased line, so prefixes must be given in upper case.

    Returns:
        List of finding dicts with keys: type, src, dst, creds.
    """
    lines = payload.split(b"\r\n")
    findings = []
    pending_user = None
    for line in lines:
        # Upper-case once for case-insensitive command matching; the original
        # `line` is kept for slicing out the user/password so their case is
        # preserved.
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
