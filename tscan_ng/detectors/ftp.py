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

Port handling:
    The detector gates on _FTP_PORTS (a frozenset of known FTP control ports).
    Sessions where neither endpoint port is in the set are skipped immediately,
    keeping per-packet overhead negligible for non-FTP traffic.

    The scan for USER and PASS is bounded to _MAX_CMD_SCAN bytes so that a
    large client buffer does not cause O(n) work on every arriving packet.

Finding outcomes:
    success      - Server responded with 230 Login successful
    failed       - Server responded with 530 Login incorrect
    server_error - Server responded with 421 Service unavailable
    no_response  - Session expired before a server response was seen
                   (emitted by SessionTable.expire())

Credentials extracted:
    The first USER argument and the first PASS argument that follows it in
    client_buf, joined as "user:password". Each is a single whitespace-free
    non-whitespace token, so a password containing spaces is truncated at the first
    space. Anonymous logins (user "anonymous", any case) are typed
    "ftp_anonymous"; the "password" is then conventionally an e-mail address.

Response correlation:
    Server replies are matched by code only, not by position: the first
    line in server_buf starting with "230 ", "530 " or "421 " is taken as the
    answer to the PASS. Lines are not consumed unless they are matched, so an
    earlier unrelated 530/421 (e.g. 530 "Please login with USER and PASS" sent
    for a pre-login command) will be attributed to the next credential.
    The matching lives in resolve() below. detect_stream() only parks the
    credentials with session.add_pending(); tscan_ng.resolve calls resolve()
    for them, on the same packet if the reply is already buffered.

Known limitations:
    - USER/PASS lines are matched without requiring the terminating CRLF, so a
      command split across TCP segments can yield a truncated password.
    - Only the first 4 KB of client_buf is scanned and the buffer is only
      consumed on a match, so a USER/PASS that starts beyond 4 KB of earlier
      unmatched client bytes is not seen.
    - FTPS/AUTH TLS sessions are encrypted after the AUTH TLS exchange and
      produce no findings; FTP data connections (passive/active ports) are
      never inspected.
"""

import logging
import re
from tscan_ng.session import _make_filter

# Finding types this detector emits; tscan_ng.resolve maps each to resolve().
FINDING_TYPES = ("ftp_creds", "ftp_anonymous")

# Well-known and commonly-used FTP control ports.
# Sessions whose dport or sport is in this set are scanned for credentials.
# Add site-specific alternate ports here if needed.
_FTP_PORTS: frozenset = frozenset({
    21,    # Standard FTP control port (RFC 959)
    2121,  # Common alternate FTP port
})

# Maximum bytes of the client buffer to scan for USER and PASS commands.
# FTP commands are short; 4 KB is well above any realistic auth exchange.
# Bounding the scan keeps per-packet work O(1) regardless of buffer lifetime.
_MAX_CMD_SCAN = 4096

# Matches FTP USER command at the start of any line (MULTILINE).
#   Group 1: the username token. \s+ is used between verb and argument, so it
#   can cross a line break ("USER\r\nPASS x" would capture "PASS" as the user).
_FTP_USER_RE = re.compile(
    rb"^USER\s+(\S+)",
    re.IGNORECASE | re.MULTILINE
)

# Matches FTP PASS command at the start of any line (MULTILINE).
#   Group 1: the password token (first whitespace-delimited word only).
_FTP_PASS_RE = re.compile(
    rb"^PASS\s+(\S+)",
    re.IGNORECASE | re.MULTILINE
)

# Matches FTP server response codes we care about.
#   230 = User logged in, 530 = Not logged in / login incorrect,
#   421 = Service not available (connection closing).
# Only matches terminating response lines (space after code, not hyphen).
# Multi-line responses use 230- for continuation and 230 for termination.
#   Group 1: the 3-digit code.
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
        One of: success, failed, server_error, unknown. In practice "unknown"
        is unreachable from this module, because _FTP_RESPONSE_RE only ever
        yields 230, 530 or 421; it is kept as a safe default.
    """
    if code == b"230":
        return "success"
    elif code == b"530":
        return "failed"
    elif code == b"421":
        return "server_error"
    return "unknown"


def detect_stream(session, ts: float) -> list:
    """
    Stream-aware FTP credential detector.

    Scans session.client_buf for FTP USER and PASS commands and
    session.server_buf for response codes.  Session direction is always
    normalised to the client perspective by the session layer, so
    client_buf reliably contains the USER/PASS commands.

    Handles anonymous FTP logins by flagging them with type
    "ftp_anonymous" instead of "ftp_creds".

    Registers every credential as a pending finding (resolve() below matches
    the server's reply) and consumes the matched commands from the client
    buffer to avoid re-detection on subsequent packets.

    The scan is bounded to _MAX_CMD_SCAN bytes so that a large client
    buffer does not cause O(n) work on every arriving packet.

    Args:
        session: Session object from session.SessionTable.
        ts:      Unix timestamp of the current packet.

    Returns:
        Always an empty list; findings are registered on the session as
        pending and emitted by tscan_ng.resolve once resolved.
    """
    # Skip sessions that are not on a known FTP control port.
    # Neither dport nor sport in _FTP_PORTS means this is definitely not FTP.
    if session.dport not in _FTP_PORTS and session.sport not in _FTP_PORTS:
        return []

    # Cap the scan to _MAX_CMD_SCAN bytes to bound per-packet CPU cost.
    client_bytes = bytes(session.client_buf[:_MAX_CMD_SCAN])

    user_match = _FTP_USER_RE.search(client_bytes)
    if not user_match:
        return []

    # Search for PASS only within the remaining scan window after USER, so a
    # PASS that precedes the USER (stale/out-of-order data) is never paired.
    # user_match.end() is always within client_bytes, so this is safe.
    pass_match = _FTP_PASS_RE.search(client_bytes, user_match.end())
    if not pass_match:
        return []

    user   = user_match.group(1).decode("utf-8", "ignore")
    passwd = pass_match.group(1).decode("utf-8", "ignore")

    # Defensive guard against empty captures. Both patterns capture (\S+), which
    # cannot be empty, so this branch is currently unreachable; it is kept so a
    # future loosening of the regexes cannot produce findings with blank
    # credentials, which would be noise in the output.
    if not user or not passwd:
        logging.debug(
            "ftp: session %s: USER or PASS matched but captured empty string",
            session.session_id)
        del session.client_buf[:pass_match.end()]
        return []

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

    session.add_pending(base, ts_start=ts)

    # Consume USER and PASS from client buffer
    del session.client_buf[:pass_match.end()]

    return []


def resolve(p, session):
    """
    Match a pending FTP login against the server's reply (see tscan_ng.resolve).

    Takes the first 230/530/421 line in server_buf (see "Response
    correlation" in the module docstring for why that can be a stale line).

    Args:
        p:       PendingFinding for an ftp_creds / ftp_anonymous finding.
        session: Session whose server_buf is searched.

    Returns:
        ({"status", "outcome"}, bytes to consume) or None if no reply yet.
    """
    response = _FTP_RESPONSE_RE.search(bytes(session.server_buf))
    if not response:
        return None
    code = response.group(1)
    return ({"status": code.decode("utf-8", "ignore"), "outcome": _outcome(code)},
            response.end())
