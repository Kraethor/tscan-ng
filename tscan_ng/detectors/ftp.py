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

FTP is a server-initiated protocol — the server sends a 220 banner before
the client sends USER. This means the session may be created with the server
as the canonical src, causing client and server buffers to be inverted.
The detector handles this by checking both buffers for USER/PASS commands.

Finding outcomes:
    success      - Server responded with 230 Login successful
    failed       - Server responded with 530 Login incorrect
    server_error - Server responded with 421 Service unavailable
    no_response  - Session expired before a server response was seen
                   (emitted by SessionTable.expire())
"""

import re
import sys
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
# Only matches terminating response lines (space after code, not hyphen).
# Multi-line responses use 230- for continuation and 230 for termination.
_FTP_RESPONSE_RE = re.compile(
    rb"^(230|530|421) ",
    re.MULTILINE
)


def _outcome(code: bytes) -> str:
    """
    Map an FTP response code to a human-readable outcome string.

    Args:
        code: FTP 3-digit response code bytes.

    Returns:
        One of: success, failed, server_error, unknown.
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

    Handles the case where session direction is inverted for server-initiated
    protocols like FTP, where the server sends the 220 banner before the
    client sends USER. In this case the session may be created with the
    server as the canonical src, so we check both buffers for USER/PASS.

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
    # Only process FTP control connections
    if session.dport != 21 and session.sport != 21:
        return []

    # FTP is server-initiated (220 banner comes before USER) so the session
    # may be created with the server as canonical src. Check both buffers
    # for USER/PASS and use whichever contains the client commands.
    if _FTP_USER_RE.search(bytes(session.client_buf)):
        client_bytes = bytes(session.client_buf)
        server_bytes = bytes(session.server_buf)
        client_is_client = True
    elif _FTP_USER_RE.search(bytes(session.server_buf)):
        client_bytes = bytes(session.server_buf)
        server_bytes = bytes(session.client_buf)
        client_is_client = False
    else:
        return []

    findings = []

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
        "type":              "ftp_anonymous" if is_anonymous else "ftp_creds",
        "session_id":        session.session_id,
        "src":               session.src,
        "dst":               session.dst,
        "sport":             session.sport,
        "dport":             session.dport,
        "creds":             f"{user}:{passwd}",
        "filter":            _make_filter(session.src, session.dst,
                                          session.sport, session.dport),
        "_client_is_client": client_is_client,
    }

    # Attempt to correlate with a server response
    response = _FTP_RESPONSE_RE.search(server_bytes)
    if response:
        code = response.group(1)
        findings.append({
            **{k: v for k, v in base.items() if not k.startswith("_")},
            "ts_start": ts,
            "ts_end":   session.last_ts,
            "status":   code.decode("utf-8", "ignore"),
            "outcome":  _outcome(code),
        })
        # Consume the matched response from the correct buffer
        if client_is_client:
            del session.server_buf[:response.end()]
        else:
            del session.client_buf[:response.end()]
    else:
        session.add_pending(base, ts_start=ts)

    # Consume processed USER and PASS from the correct buffer
    if client_is_client:
        del session.client_buf[:pass_match.end()]
    else:
        del session.server_buf[:pass_match.end()]

    return findings
