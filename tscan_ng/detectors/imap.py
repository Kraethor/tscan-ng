"""
detectors/imap.py - IMAP credential detector for tscan-ng.

Stream-aware detector that operates on reassembled TCP streams rather than
individual packets. Parses IMAP LOGIN commands from the client buffer and
correlates them with tagged server responses.

Handles both quoted (allowing spaces) and unquoted username/password forms.
Correctly handles optional response codes in square brackets such as
[CAPABILITY ...] and [AUTHENTICATIONFAILED] between the status word and
human-readable text.

Finding outcomes:
    success      - Server responded with tagged OK
    failed       - Server responded with tagged NO
    bad_command  - Server responded with tagged BAD
    no_response  - Session expired before a server response was seen
                   (emitted by SessionTable.expire())
"""

import re
from tscan_ng.session import _make_filter

# Matches IMAP LOGIN command with optional tag:
#   a001 LOGIN user password
#   a001 LOGIN "user name" "pass word"
_IMAP_LOGIN_RE = re.compile(
    r'^(\S+)\s+LOGIN\s+'
    r'(?:"([^"]*?)"|(\S+))'    # username: quoted or unquoted
    r'\s+'
    r'(?:"([^"]*?)"|(\S+))',   # password: quoted or unquoted
    re.IGNORECASE | re.MULTILINE
)

# Matches a tagged server response:
#   a001 OK [CAPABILITY ...] Welcome
#   a001 NO [AUTHENTICATIONFAILED] Invalid credentials
#   a001 BAD Command unknown
_IMAP_RESPONSE_RE = re.compile(
    r'^(\S+)\s+(OK|NO|BAD)\s+',
    re.IGNORECASE | re.MULTILINE
)


def _outcome(status: str) -> str:
    """
    Map an IMAP response status word to a human-readable outcome string.

    Args:
        status: IMAP status word (OK, NO, or BAD).

    Returns:
        One of: success, failed, bad_command.
    """
    status = status.upper()
    if status == "OK":
        return "success"
    elif status == "NO":
        return "failed"
    elif status == "BAD":
        return "bad_command"
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
    Stream-aware IMAP LOGIN credential detector.

    Scans the session's client buffer for IMAP LOGIN commands. For each
    one found, records the command tag and attempts to correlate with a
    tagged server response already present in the server buffer.

    Emits a finding with outcome "pending" if no server response is
    available yet, and registers it on the session for later resolution.
    Consumes matched commands from the client buffer to avoid re-detection
    on subsequent packets.

    Correctly handles:
        - Quoted strings containing spaces in username or password
        - Optional response codes in square brackets e.g. [CAPABILITY ...]
        - Tag-based request/response correlation

    Args:
        session: Session object from session.SessionTable.
        ts:      Unix timestamp of the current packet.

    Returns:
        List of resolved finding dicts. Pending findings are registered on
        the session and not returned until resolved.
    """
    findings = []
    client_bytes = bytes(session.client_buf)

    for match in _IMAP_LOGIN_RE.finditer(client_bytes.decode("utf-8", "ignore")):
        tag      = match.group(1)
        user     = match.group(2) or match.group(3)
        passwd   = match.group(4) or match.group(5)

        base = {
            "type":       "imap_creds",
            "session_id": session.session_id,
            "src":        session.src,
            "dst":        session.dst,
            "sport":      session.sport,
            "dport":      session.dport,
            "tag":        tag,
            "creds":      f"{user}:{passwd}",
            "filter":     _make_filter(session.src, session.dst,
                                       session.sport, session.dport),
        }

        # Attempt to correlate with a tagged server response
        server_text = session.server_buf.decode("utf-8", "ignore")
        response = None
        for resp_match in _IMAP_RESPONSE_RE.finditer(server_text):
            if resp_match.group(1).upper() == tag.upper():
                response = resp_match.group(2)
                break

        if response:
            findings.append({
                **base,
                "ts_start":    ts,
                "ts_end":      session.last_ts,
                "status":      response.upper(),
                "outcome":     _outcome(response),
            })
        else:
            session.add_pending(base, ts_start=ts)

    # Consume processed client buffer
    if _IMAP_LOGIN_RE.search(client_bytes.decode("utf-8", "ignore")):
        last_match = None
        for m in _IMAP_LOGIN_RE.finditer(client_bytes.decode("utf-8", "ignore")):
            last_match = m
        if last_match:
            del session.client_buf[:last_match.end()]

    return findings
