"""
detectors/ftp.py - FTP credential detector for tscan-ng.

Stream-aware detector that operates on reassembled TCP streams rather than
individual packets. Parses FTP USER and PASS commands from the client buffer
and correlates them with server response codes.

Handles the standard FTP authentication flow:
    CLIENT: USER username
    SERVER: 331 Password required
    CLIENT: PASS password
    SERVER: 230 Login successful  (or 530 Login incorrect)

Also detects anonymous FTP logins and flags them separately.

Finding outcomes:
    success      - Server responded with 230 Login successful
    failed       - Server responded with 530 Login incorrect
    server_error - Server responded with 421 Service unavailable
    no_response  - Session expired before a server response was seen
                   (emitted by SessionTable.expire())
"""

import re
from tscan_ng.session import _make_filter

# Matches FTP USER command
_FTP_USER_RE = re.compile(
    rb"^USER\s+(\S+)",
    re.IGNORECASE | re.MULTILINE
)

# Matches FTP PASS command
_FTP_PASS_RE = re.compile(
    rb"^PASS\s+(\S+)",
    re.IGNORECASE | re.MULTILINE
)

# Matches FTP server response codes we care about.
# Handles both single-line (230 ) and multi-line (230-) responses.
_FTP_RESPONSE_RE = re.compile(
    rb"^(230|530|421)[ -]",
    re.MULTILINE
)

# Response codes that reset pending state without a successful login
_FTP_RESET_CODES = {b"530", b"421"}


def _outcome(code: bytes) -> str:
    """
    Map an FTP response code to a human-readable outcome string.

    Args:
        code: FTP 3-digit response code bytes.

    Returns:
        One of: success, failed, server_error.
    """
    if code == b"230":
        return "success"
    elif code == b"530":
        return "failed"
    elif code == b"421":
        return "server_error"
    return "unknown"


def detect(pkt: dict) -> list[dict]:
    """
    Per-packet interface — disabled in favour of stream detection.

    Retained so the detector remains a valid entry in DETECTORS for
    per-packet fallback if needed. Always returns empty in this phase.

    Args:
        pkt: Normalized packet dict from parsing.net.parse_basic.

    Returns:
        Empty list.
    """
    return []


def detect_stream(session, ts: float) -> list[dict]:
    """
    Stream-aware FTP credential detector.

    Scans the session's client buffer for FTP USER and PASS commands.
    Pairs them into credential findings and attempts to correlate with
    server response codes in the server buffer.

    Handles anonymous FTP logins by flagging them with type
    "ftp_anonymous" instead of "ftp_creds".

    Emits a finding with outcome "pending" if no server response is
    available yet, and registers it on the session for later resolution.
    Consumes matched commands from the client buffer to avoid re-detection
    on subsequent packets.

    Args:
        session: Session object from session.SessionTable.
        ts:      Unix timestamp of the current packet.

    Returns:
        List of resolved finding dicts. Pending findings are registered on
        the session and not returned until resolved.
    """
    findings = []
    client_bytes = bytes(session.client_buf)

    # Find USER command
    user_match = _FTP_USER_RE.search(client_bytes)
    if not user_match:
        return []

    # Find PASS command after USER
    pass_match = _FTP_PASS_RE.search(client_bytes, user_match.end())
    if not pass_match:
        return []

    user   = user_match.group(1).decode("utf-8", "ignore")
    passwd = pass_match.group(1).decode("utf-8", "ignore")

    is_anonymous = user.lower() == "anonymous"

    base = {
        "type":       "ftp_anonymous" if is_anonymous else "ftp_creds",
        "session_id": session.session_id,
        "src":        session.src,
        "dst":        session.dst,
        "sport":      session.sport,
        "dport":      session.dport,
        "creds":      f"{user}:{passwd}",
        "filter":     _make_filter(session.src, session.dst,
                                   session.sport, session.dport),
    }

    # Attempt to correlate with a server response
    response = _FTP_RESPONSE_RE.search(bytes(session.server_buf))
    if response:
        code = response.group(1)
        findings.append({
            **base,
            "ts_start": ts,
            "ts_end":   session.last_ts,
            "status":   code.decode("utf-8", "ignore"),
            "outcome":  _outcome(code),
        })
        # Consume the matched response from server_buf
        del session.server_buf[:response.end()]
    else:
        session.add_pending(base, ts_start=ts)

    # Consume processed USER and PASS from client_buf
    del session.client_buf[:pass_match.end()]

    return findings
