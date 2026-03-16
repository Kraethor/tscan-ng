"""
detectors/pop3.py - POP3 credential detector for tscan-ng.

Stream-aware detector that operates on reassembled TCP streams rather than
individual packets. Parses POP3 USER and PASS commands from the client buffer
and correlates them with server +OK / -ERR responses.

Handles the standard POP3 authentication flow:
    CLIENT: USER username
    SERVER: +OK
    CLIENT: PASS password
    SERVER: +OK Logged in  (or -ERR Authentication failed)

Because session direction is normalised at creation time (see session.py),
client_buf always contains client-originated bytes and server_buf always
contains server-originated bytes.

Finding outcomes:
    success     - Server responded with +OK after PASS
    failed      - Server responded with -ERR after PASS
    no_response - Session expired before a server response was seen
                  (emitted by SessionTable.expire())
"""

import re
from tscan_ng.session import _make_filter

# Matches POP3 USER command
_POP3_USER_RE = re.compile(
    rb"^USER\s+(\S+)",
    re.IGNORECASE | re.MULTILINE
)

# Matches POP3 PASS command
_POP3_PASS_RE = re.compile(
    rb"^PASS\s+(\S+)",
    re.IGNORECASE | re.MULTILINE
)

# Matches a POP3 server response line (+OK or -ERR)
_POP3_RESPONSE_RE = re.compile(
    rb"^(\+OK|-ERR)\b",
    re.MULTILINE
)

# POP3 port
_POP3_PORT = 110


def _outcome(status: bytes) -> str:
    """
    Map a POP3 response token to a human-readable outcome string.

    Args:
        status: b'+OK' or b'-ERR'.

    Returns:
        One of: success, failed.
    """
    if status.upper() == b"+OK":
        return "success"
    return "failed"


def detect(pkt: dict) -> list:
    """
    Per-packet interface — retained for API compatibility, always returns [].

    Args:
        pkt: Normalized packet dict from parsing.net.parse_basic.

    Returns:
        Empty list.
    """
    return []


def detect_stream(session, ts: float) -> list:
    """
    Stream-aware POP3 USER/PASS credential detector.

    Scans session.client_buf for POP3 USER and PASS commands and
    session.server_buf for +OK / -ERR responses.  Session direction is
    always normalised to the client perspective by the session layer.

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
    if session.dport != _POP3_PORT and session.sport != _POP3_PORT:
        return []

    client_bytes = bytes(session.client_buf)

    user_match = _POP3_USER_RE.search(client_bytes)
    if not user_match:
        return []

    pass_match = _POP3_PASS_RE.search(client_bytes, user_match.end())
    if not pass_match:
        return []

    user   = user_match.group(1).decode("utf-8", "ignore")
    passwd = pass_match.group(1).decode("utf-8", "ignore")

    base = {
        "type":       "pop3_creds",
        "session_id": session.session_id,
        "src":        session.src,
        "dst":        session.dst,
        "sport":      session.sport,
        "dport":      session.dport,
        "creds":      f"{user}:{passwd}",
        "filter":     _make_filter(session.src, session.dst,
                                   session.sport, session.dport),
    }

    findings = []
    server_bytes = bytes(session.server_buf)

    # POP3 session response sequence (normal):
    #   responses[0] - server greeting banner (+OK)
    #   responses[1] - reply to USER (+OK or -ERR)
    #   responses[2] - reply to PASS (+OK or -ERR)   <- we want this one
    #
    # We require all three to be present before resolving, because two
    # +OK responses are ambiguous (banner + USER reply, still waiting for
    # PASS reply).  A -ERR at any position is an unambiguous failure
    # and can be resolved immediately.
    responses = list(_POP3_RESPONSE_RE.finditer(server_bytes))

    # Find the first -ERR if any — it's an unambiguous authentication failure
    err_response = next((r for r in responses if r.group(1).upper() == b"-ERR"), None)
    if err_response:
        code = err_response.group(1)
        findings.append({
            **base,
            "ts_start": ts,
            "ts_end":   session.last_ts,
            "status":   code.decode("utf-8", "ignore"),
            "outcome":  "failed",
        })
        del session.server_buf[:err_response.end()]
        del session.client_buf[:pass_match.end()]
    elif len(responses) >= 3:
        # banner + USER reply + PASS reply — take the third as PASS result
        pass_response = responses[2]
        code = pass_response.group(1)
        findings.append({
            **base,
            "ts_start": ts,
            "ts_end":   session.last_ts,
            "status":   code.decode("utf-8", "ignore"),
            "outcome":  _outcome(code),
        })
        del session.server_buf[:pass_response.end()]
        del session.client_buf[:pass_match.end()]
    else:
        # Not enough server data yet — register as pending
        session.add_pending(base, ts_start=ts)
        del session.client_buf[:pass_match.end()]

    return findings
