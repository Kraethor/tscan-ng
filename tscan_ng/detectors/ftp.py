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

Because session direction is normalised at creation time (see session.py),
client_buf always contains client-originated bytes and server_buf always
contains server-originated bytes. No direction sniffing is required here.

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


def detect(pkt: dict) -> list:
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


def detect_stream(session, ts: float) -> list:
    """
    Stream-aware FTP credential detector.

    Scans session.client_buf for FTP USER and PASS commands and
    session.server_buf for response codes.  Session direction is always
    normalised to the client perspective by the session layer, so
    client_buf reliably contains the USER/PASS commands.

    Handles anonymous FTP logins by flagging them with type
    "ftp_anonymous" instead of "ftp_creds".

    Registers a pending finding if no server response is available yet,
    and consumes the matched commands from the client buffer to avoid
    re-detection on subsequent packets.

    Args:
        session: Session object from session.SessionTable.
        ts:      Unix timestamp of the current packet.

    Returns:
        List of resolved finding dicts. Pending findings are registered on
        the session and not returned until resolved.
    """
    if session.dport != 21 and session.sport != 21:
        return []

    # -------------------------------------------------------------------------
    # Resolution pass: if a previous call registered a pending FTP finding,
    # check whether the server response has arrived since then and emit it now
    # rather than waiting for session expiry.  USER+PASS and the 230/530
    # response frequently arrive in separate TCP segments, so the pending path
    # is the common case, not the exception.
    # -------------------------------------------------------------------------
    findings = []
    ftp_pending = [p for p in session.pending
                   if p.finding.get("type") in ("ftp_creds", "ftp_anonymous")]
    if ftp_pending:
        server_bytes = bytes(session.server_buf)
        response = _FTP_RESPONSE_RE.search(server_bytes)
        if response:
            code = response.group(1)
            for p in ftp_pending:
                findings.append({
                    **p.finding,
                    "ts_start": p.ts_start,
                    "ts_end":   session.last_ts,
                    "status":   code.decode("utf-8", "ignore"),
                    "outcome":  _outcome(code),
                })
            session.pending = [p for p in session.pending
                               if p not in ftp_pending]
            del session.server_buf[:response.end()]
            return findings

    client_bytes = bytes(session.client_buf)

    user_match = _FTP_USER_RE.search(client_bytes)
    if not user_match:
        return []

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

    server_bytes = bytes(session.server_buf)
    response = _FTP_RESPONSE_RE.search(server_bytes)

    if response:
        code = response.group(1)
        findings.append({
            **base,
            "ts_start": ts,
            "ts_end":   session.last_ts,
            "status":   code.decode("utf-8", "ignore"),
            "outcome":  _outcome(code),
        })
        del session.server_buf[:response.end()]
    else:
        session.add_pending(base, ts_start=ts)

    # Consume USER and PASS from client buffer
    del session.client_buf[:pass_match.end()]

    return findings
