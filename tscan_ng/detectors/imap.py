"""
detectors/imap.py - IMAP credential detector for tscan-ng.

Stream-aware detector that operates on reassembled TCP streams rather than
individual packets. Parses IMAP LOGIN commands from the client buffer and
correlates them with tagged server responses.

Handles both quoted (allowing spaces) and unquoted username/password forms.
Correctly handles optional response codes in square brackets such as
[CAPABILITY ...] and [AUTHENTICATIONFAILED] between the status word and
human-readable text.

Port handling:
    The detector gates on _IMAP_PORTS (a frozenset of known IMAP ports).
    Sessions where neither endpoint port is in the set are skipped immediately,
    keeping per-packet overhead negligible for non-IMAP traffic.

    The scan for LOGIN commands is bounded to _MAX_CMD_SCAN bytes so that a
    large client buffer does not cause O(n) work on every arriving packet.

Buffer scanning:
    _IMAP_LOGIN_RE is a bytes regex. This avoids decoding client_buf with
    errors="ignore", which silently drops non-UTF-8 bytes and shifts byte
    positions. Since last_match.end() is used as a bytearray index, correct
    byte positions are required to consume the right number of bytes.

Finding outcomes:
    success      - Server responded with tagged OK
    failed       - Server responded with tagged NO
    bad_command  - Server responded with tagged BAD
    no_response  - Session expired before a server response was seen
                   (emitted by SessionTable.expire())
"""

import logging
import re
from tscan_ng.session import _make_filter

# Well-known IMAP ports.
# Sessions whose dport or sport is in this set are scanned for credentials.
_IMAP_PORTS: frozenset = frozenset({
    143,   # IMAP (RFC 3501)
    993,   # IMAPS (still seen in cleartext on internal networks)
    1430,  # Non-standard IMAP port (site-specific)
})

# Maximum bytes of the client buffer to scan for LOGIN commands per call.
# IMAP LOGIN lines are short; 4 KB is well above any realistic auth exchange.
# Bounding the scan keeps per-packet work O(1) regardless of buffer lifetime.
_MAX_CMD_SCAN = 4096

# Matches IMAP LOGIN command as bytes to avoid UTF-8 decode-with-ignore
# shifting byte positions used for buffer consumption.
#   Group 1: command tag (e.g. a001)
#   Group 2: quoted username (content between double quotes, may be empty)
#   Group 3: unquoted username
#   Group 4: quoted password (content between double quotes, may be empty)
#   Group 5: unquoted password
#
# [ \t]+ is used instead of \s+ between tokens to prevent the regex from
# crossing line boundaries. IMAP LOGIN is a single-line command:
#   tag SP LOGIN SP userid SP password CRLF
# Using \s+ would allow matching across lines, producing false positives by
# treating the next command's tokens as credentials (e.g. "A003 LOGIN\r\n
# A004 LOGOUT" would match with A004 as username and LOGOUT as password).
_IMAP_LOGIN_RE = re.compile(
    rb'^(\S+)[ \t]+LOGIN[ \t]+'
    rb'(?:"([^"]*?)"|(\S+))'    # username: quoted or unquoted
    rb'[ \t]+'
    rb'(?:"([^"]*?)"|(\S+))',   # password: quoted or unquoted
    re.IGNORECASE | re.MULTILINE
)

# Matches a tagged server response (string regex — used by detect_stream
# when server_buf has already been decoded to str):
#   a001 OK [CAPABILITY ...] Welcome
#   a001 NO [AUTHENTICATIONFAILED] Invalid credentials
#   a001 BAD Command unknown
_IMAP_RESPONSE_RE = re.compile(
    r'^(\S+)\s+(OK|NO|BAD)\s+',
    re.IGNORECASE | re.MULTILINE
)

# Bytes version of the same pattern — used by run.py _try_resolve to obtain
# a byte-aligned end offset for slicing server_buf directly.  Searching the
# decoded string and using the character offset would mis-align the slice if
# server_buf contains multi-byte UTF-8 sequences or bytes dropped by "ignore".
_IMAP_RESPONSE_BYTES_RE = re.compile(
    rb'^(\S+)\s+(OK|NO|BAD)\s+',
    re.IGNORECASE | re.MULTILINE
)


def _outcome(status: str) -> str:
    """
    Map an IMAP response status word to a human-readable outcome string.

    Args:
        status: IMAP status word (OK, NO, or BAD).

    Returns:
        One of: success, failed, bad_command, unknown.
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

    Emits a finding immediately if a matching tagged response is available,
    or registers a pending finding on the session for later resolution.
    Consumes matched commands from the client buffer to avoid re-detection
    on subsequent packets.

    The scan is bounded to _MAX_CMD_SCAN bytes per call to keep per-packet
    work O(1). The LOGIN regex runs on raw bytes to ensure last_match.end()
    is a valid bytearray index regardless of the byte content.

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
    # Skip sessions that are not on a known IMAP port.
    if session.dport not in _IMAP_PORTS and session.sport not in _IMAP_PORTS:
        return []

    # Cap the scan to _MAX_CMD_SCAN bytes to bound per-packet CPU cost.
    # The regex runs on raw bytes — no decode needed, no byte positions lost.
    scan = bytes(session.client_buf[:_MAX_CMD_SCAN])

    # Decode server_buf once outside the loop rather than once per LOGIN match.
    server_text = session.server_buf.decode("utf-8", "ignore")

    findings = []
    last_match = None  # Tracks the rightmost match for buffer consumption.

    for match in _IMAP_LOGIN_RE.finditer(scan):
        last_match = match

        tag = match.group(1).decode("utf-8", "ignore")

        # Prefer the quoted group; fall back to unquoted. Use explicit None
        # checks rather than `or` — group(2) can be b"" (empty quoted string)
        # which is falsy and would incorrectly fall through to group(3)=None.
        user_bytes   = match.group(2) if match.group(2) is not None else match.group(3)
        passwd_bytes = match.group(4) if match.group(4) is not None else match.group(5)

        user   = user_bytes.decode("utf-8", "ignore")   if user_bytes   is not None else ""
        passwd = passwd_bytes.decode("utf-8", "ignore") if passwd_bytes is not None else ""

        # Guard against empty credentials — emit nothing rather than noise.
        if not user and not passwd:
            logging.debug(
                "imap: session %s: LOGIN matched but user and password both empty",
                session.session_id)
            continue

        base = {
            "type":       "imap_creds",
            "session_id": session.session_id,
            "src":        session.src,
            "dst":        session.dst,
            "sport":      session.sport,
            "dport":      session.dport,
            "tag":        tag,  # Retained for _try_resolve tag correlation in run.py
            "creds":      f"{user}:{passwd}",
            "filter":     _make_filter(session.src, session.dst,
                                       session.sport, session.dport),
        }

        # Attempt to correlate with a matching tagged response in server_buf.
        response = None
        for resp_match in _IMAP_RESPONSE_RE.finditer(server_text):
            if resp_match.group(1).upper() == tag.upper():
                response = resp_match.group(2)
                break

        if response:
            findings.append({
                **base,
                "ts_start": ts,
                "ts_end":   session.last_ts,
                "status":   response.upper(),
                "outcome":  _outcome(response),
            })
        else:
            session.add_pending(base, ts_start=ts)

    # Consume all processed LOGIN commands from the client buffer in one
    # operation. last_match.end() is a byte position from the bytes regex,
    # guaranteed to align with the bytearray regardless of byte content.
    if last_match is not None:
        del session.client_buf[:last_match.end()]

    return findings
