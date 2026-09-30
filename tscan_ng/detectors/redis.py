"""
detectors/redis.py - Redis credential detector for tscan-ng.

Stream-aware detector that operates on reassembled TCP streams. Detects
Redis AUTH commands in the client buffer and correlates them with server
+OK / -ERR responses.

Redis uses the RESP (REdis Serialization Protocol) wire format. AUTH can
appear as:

    RESP array, password only (Redis < 6.0):
        *2\r\n$4\r\nAUTH\r\n$<len>\r\n<password>\r\n

    RESP array, username + password (Redis 6.0+ ACL):
        *3\r\n$4\r\nAUTH\r\n$<len>\r\n<username>\r\n$<len>\r\n<password>\r\n

    Inline command (uncommon, sent by telnet-based clients):
        AUTH <password>\r\n
        AUTH <username> <password>\r\n

Server responses:
    +OK\r\n                      → success
    -ERR invalid password\r\n    → failed (pre-6.0)
    -WRONGPASS ...\r\n           → failed (6.0+)

Port handling:
    Gates on _REDIS_PORTS. Sessions on other ports are skipped immediately.
    6379 — standard Redis
    6380 — common alternate port (the cluster bus itself is 16379, not covered)

Finding type: "redis_creds"
Finding extras:
    "username" — ACL username if present (empty string for password-only AUTH).
    "creds"    — "username:password" or ":password" for display consistency.

Response correlation:
    Positional, no request ids: the first server_buf line that is exactly
    "+OK" (success) or begins with "-" (failure) at or after the pending
    finding's server_buf_floor is taken as the AUTH reply. Replies to
    commands sent before AUTH ("+OK" to CLIENT SETNAME/SELECT, "-NOAUTH" to a
    command that needed auth) sit below the floor and are skipped (#14). The
    matching lives in resolve().

Known limitations:
    - "HELLO <ver> AUTH <user> <pass>" (the RESP3 handshake, whose reply is
      not a simple +OK) is not recognised; only a top-level AUTH array or
      inline AUTH command is.
    - Only the first 4 KB of client_buf is scanned and it is consumed only on
      an AUTH match, so an AUTH arriving after 4 KB of other commands on
      the same connection is not seen.
    - AUTH with an empty password is skipped. Redis over TLS is opaque.
"""

import logging
import re
from tscan_ng.session import _make_filter

# Finding types this detector emits; tscan_ng.resolve maps each to resolve().
FINDING_TYPES = ("redis_creds",)

# Well-known cleartext Redis ports.
_REDIS_PORTS: frozenset = frozenset({
    6379,  # Redis default (IANA assigned)
    6380,  # Common alternate Redis port
})

# Maximum bytes of the client buffer to scan per call.
# Redis AUTH commands are short; 4 KB is well above any realistic exchange.
_MAX_SCAN = 4096

# Regex for inline AUTH commands (fallback for non-RESP clients).
# Captures optional username and mandatory password.
#   Group 1: first argument (the password, or the username if a second
#            argument follows); Group 2: second argument (password) or None.
# Requires a CRLF terminator. \s+ can also span a line break.
_AUTH_INLINE_RE = re.compile(
    rb"^AUTH\s+(\S+)(?:\s+(\S+))?\r\n",
    re.IGNORECASE | re.MULTILINE,
)

# Server +OK response line.
# NOTE: _OK_RE and _ERR_RE are not referenced anywhere in the package;
# _find_auth_response() below does its own line-by-line scan instead.
_OK_RE = re.compile(rb"^\+OK\b", re.MULTILINE)

# Server error response line (any leading '-' response to AUTH).
# (Unused -- see the note above _OK_RE.)
_ERR_RE = re.compile(rb"^-\S+", re.MULTILINE)


def _parse_resp_array(data: bytes, offset: int):
    """
    Parse one complete RESP array starting at *offset* in *data*.

    Reads the element count from the '*N\\r\\n' header, then parses each
    element as a bulk string '$N\\r\\n<data>\\r\\n'. The bulk string length
    prefix is used to correctly handle element data that contains \\r\\n.
    Only bulk-string elements are accepted (other RESP types inside the
    array make the parse fail). A negative bulk length (the RESP null string
    "$-1") is not rejected and mis-advances the offset.

    Args:
        data:   Raw bytes buffer from the client stream.
        offset: Byte position of the '*' character that starts the array.

    Returns:
        (elements, new_offset) where elements is a list of bytes objects and
        new_offset points past the last byte of the parsed array.
        Returns (None, None) if the array is incomplete or malformed
        (callers cannot distinguish "not yet fully received" from "invalid").
    """
    if offset >= len(data) or data[offset:offset + 1] != b'*':
        return None, None

    # Read element count from '*N\r\n'.
    eol = data.find(b'\r\n', offset)
    if eol == -1:
        return None, None
    try:
        count = int(data[offset + 1:eol])
    except ValueError:
        return None, None
    if count < 0:
        return None, None

    pos = eol + 2
    elements = []
    for _ in range(count):
        # Each element is a bulk string: '$N\r\n<data>\r\n'.
        if pos >= len(data) or data[pos:pos + 1] != b'$':
            return None, None
        eol2 = data.find(b'\r\n', pos)
        if eol2 == -1:
            return None, None
        try:
            length = int(data[pos + 1:eol2])
        except ValueError:
            return None, None
        pos = eol2 + 2
        if pos + length + 2 > len(data):
            # Bulk string data not yet fully received.
            return None, None
        elem = data[pos:pos + length]
        pos += length + 2  # skip element data + trailing \r\n
        elements.append(elem)

    return elements, pos


def _find_auth_command(data: bytes):
    """
    Scan *data* for the first Redis AUTH command in RESP or inline format.

    Tries RESP array format first at each position; falls back to the inline
    regex for clients that use raw text commands. Walks the buffer one byte
    at a time (bounded by _MAX_SCAN), so an AUTH does not have to be the first
    command; complete non-AUTH RESP arrays are skipped over whole. An AUTH
    array with an element count other than 2 or 3 is skipped as a non-match.
    Text is decoded with errors="replace" (other detectors use "ignore").

    Args:
        data: Raw bytes from the client stream buffer (bounded to _MAX_SCAN).

    Returns:
        (username, password, end_offset) where username is an empty string for
        password-only AUTH and end_offset points past the last byte of the AUTH
        command.  Returns (None, None, None) if no AUTH command is found.
    """
    i = 0
    while i < len(data):
        if data[i:i + 1] == b'*':
            # Attempt to parse a RESP array at this position.
            elems, end = _parse_resp_array(data, i)
            if elems is not None:
                if len(elems) >= 2 and elems[0].upper() == b'AUTH':
                    if len(elems) == 2:
                        # AUTH <password>
                        username = ""
                        password = elems[1].decode("utf-8", "replace")
                        return username, password, end
                    elif len(elems) == 3:
                        # AUTH <username> <password>
                        username = elems[1].decode("utf-8", "replace")
                        password = elems[2].decode("utf-8", "replace")
                        return username, password, end
                # Valid RESP array but not AUTH — skip past it.
                i = end
                continue
            # Not a valid RESP array at this offset — advance one byte.
            i += 1
            continue

        # Try inline AUTH match at this position.
        m = _AUTH_INLINE_RE.match(data, i)
        if m:
            if m.group(2) is not None:
                # AUTH <username> <password>
                username = m.group(1).decode("utf-8", "replace")
                password = m.group(2).decode("utf-8", "replace")
            else:
                # AUTH <password>
                username = ""
                password = m.group(1).decode("utf-8", "replace")
            return username, password, m.end()

        i += 1

    return None, None, None


def _find_auth_response(data: bytes, start: int = 0):
    """
    Scan *data* from *start* for the first Redis server response to AUTH.

    Looks for '+OK' (success) or any '-<error>' line (failure). resolve()
    passes the pending finding's server_buf_floor as *start*, so replies to
    commands sent before AUTH (a '+OK' to CLIENT SETNAME/SELECT, or a
    '-NOAUTH' to a command that needed auth) are skipped (#14). Lines are
    split on CRLF only; other reply types ('+PONG', ':1', bulk replies) are
    skipped line by line.

    Args:
        data:  Raw bytes from the server stream buffer.
        start: Offset to begin scanning (the pending finding's floor).

    Returns:
        (outcome, end_offset) where outcome is "success" or "failed", and
        end_offset is an absolute offset into *data* past the end of the
        matched response line. Returns (None, None) if no relevant response
        is present yet.
    """
    i = start
    while i < len(data):
        eol = data.find(b'\r\n', i)
        if eol == -1:
            break
        line = data[i:eol]
        if line == b'+OK':
            return "success", eol + 2
        if line[:1] == b'-':
            # Any error line in response to AUTH is a failure.
            return "failed", eol + 2
        i = eol + 2

    return None, None


def _outcome(status: str) -> str:
    """
    Return the outcome string from a Redis server response.

    This is a thin passthrough — _find_auth_response already returns a
    canonical outcome string.  The function exists for symmetry with other
    detector modules.

    Args:
        status: Outcome string from _find_auth_response ("success" or "failed").

    Returns:
        The same string, unchanged.
    """
    return status


def detect_stream(session, ts: float) -> list:
    """
    Stream-aware Redis AUTH credential detector.

    Scans session.client_buf for a Redis AUTH command (RESP or inline format)
    and correlates it with the server response in session.server_buf.  Both
    buffers are consumed up to the end of the matched exchange on resolution
    to prevent re-detection on subsequent AUTH commands in the same connection.
    The client command is consumed when matched and a pending finding is
    registered; resolve() matches the reply (on the same packet if it is
    already buffered).

    The scan is bounded to _MAX_SCAN bytes per call to keep per-packet CPU
    cost O(1) regardless of buffer depth.

    Args:
        session: Session object from session.SessionTable.
        ts:      Unix timestamp of the current packet.

    Returns:
        Always an empty list; findings are registered on the session as
        pending and emitted by tscan_ng.resolve once resolved.
    """
    # Gate: only inspect sessions on known Redis ports.
    if session.dport not in _REDIS_PORTS and session.sport not in _REDIS_PORTS:
        return []

    # Bound the scan to avoid O(n) work on very deep buffers.
    client_bytes = bytes(session.client_buf[:_MAX_SCAN])
    username, password, cmd_end = _find_auth_command(client_bytes)

    if username is None:
        return []

    if not password:
        # AUTH with an empty password is unusual; skip to avoid noise. The
        # command is consumed so it is not re-examined on the next packet.
        logging.debug(
            "redis: session %s: AUTH command with empty password — skipping",
            session.session_id)
        del session.client_buf[:cmd_end]
        return []

    # Password-only AUTH (Redis < 6, or the default user) has no username, so
    # the leading ":" keeps the "user:password" shape sinks split on.
    creds_str = f"{username}:{password}" if username else f":{password}"

    base = {
        "type":       "redis_creds",
        "session_id": session.session_id,
        "src":        session.src,
        "dst":        session.dst,
        "sport":      session.sport,
        "dport":      session.dport,
        "username":   username,
        "creds":      creds_str,
        "filter":     _make_filter(session.src, session.dst,
                                   session.sport, session.dport),
    }

    session.add_pending(base, ts_start=ts)
    del session.client_buf[:cmd_end]
    return []


def resolve(p, session):
    """
    Match a pending Redis AUTH against the server's reply (see tscan_ng.resolve).

    Args:
        p:       PendingFinding for a redis_creds finding.
        session: Session whose server_buf is searched.

    Returns:
        ({"status", "outcome"}, bytes to consume) or None if no reply yet.
    """
    outcome, rsp_end = _find_auth_response(bytes(session.server_buf), p.server_buf_floor)
    if outcome is None:
        return None
    return {"status": outcome, "outcome": outcome}, rsp_end
