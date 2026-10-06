# Copyright (C) 2026 Kraethor
#
# This file is part of tscan-ng.
#
# tscan-ng is free software: you can redistribute it and/or modify it under
# the terms of the GNU General Public License as published by the Free
# Software Foundation, version 3.
#
# tscan-ng is distributed in the hope that it will be useful, but WITHOUT ANY
# WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along with
# tscan-ng. If not, see <https://www.gnu.org/licenses/>.
#
# Additional term under GPLv3 section 7(b): if you convey this work or a
# modified version of it, you must preserve the attribution "Based on tscan-ng
# by Kraethor (https://github.com/Kraethor/tscan-ng)" in the source and in any
# user-facing output or accompanying documentation.
#
# SPDX-License-Identifier: GPL-3.0-only

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

    RESP3 HELLO handshake (Redis 6.0+), AUTH as a keyword argument:
        *5\r\n$5\r\nHELLO\r\n$1\r\n3\r\n$4\r\nAUTH\r\n$<len>\r\n<user>\r\n$<len>\r\n<pass>\r\n
        (an optional SETNAME clause may follow AUTH)

    Inline command (uncommon, sent by telnet-based clients):
        AUTH <password>\r\n
        AUTH <username> <password>\r\n
        HELLO <ver> AUTH <username> <password>\r\n

Server responses:
    AUTH:   +OK\r\n                   → success
            -ERR invalid password\r\n → failed (pre-6.0)
            -WRONGPASS ...\r\n        → failed (6.0+)
    HELLO:  a RESP3 map (%<n>...)     → success
            -NOAUTH / -WRONGPASS ...  → failed

Port handling:
    Gates on _REDIS_PORTS. Sessions on other ports are skipped immediately.
    6379 — standard Redis
    6380 — common alternate port (the cluster bus itself is 16379, not covered)

Finding type: "redis_creds"
Finding extras:
    "username" — ACL username if present (empty string for password-only AUTH).
    "creds"    — "username:password" or ":password" for display consistency.

Response correlation:
    Positional, no request ids, keyed from the pending finding's
    server_buf_floor so replies to commands sent before the credential
    ("+OK" to CLIENT SETNAME/SELECT, "-NOAUTH" to a command that needed
    auth) are skipped (#14). For AUTH, the first line that is exactly "+OK"
    (success) or begins with "-" (failure) is the reply. For HELLO the reply
    at the floor is the handshake answer: a "-" line is failure, any other
    (a RESP3 map on success) is success, consumed whole. The matching lives
    in resolve().

Known limitations:
    - Only the first _MAX_SCAN_CLIENT bytes of client_buf are scanned per call;
      when no AUTH/HELLO is in that window the scanned prefix is dropped
      (advance_scan_window(), TODO.md #16), so an AUTH behind other commands on
      the same connection is reached on a later packet.
    - AUTH with an empty password is skipped. Redis over TLS is opaque.
    - A client that sends another command and AUTH in one burst, before the
      first reply arrives (e.g. SELECT then AUTH pipelined), leaves the floor
      below that command's reply, so AUTH is judged by it. Common clients
      send AUTH first and wait for its reply. (Same limit as POP3 USER/PASS
      pipelining.)
"""

import logging
import re
from tscan_ng.detectors.common import advance_scan_window, base_finding, on_ports

# Finding types this detector emits; tscan_ng.resolve maps each to resolve().
FINDING_TYPES = ("redis_creds",)

# Well-known cleartext Redis ports.
_REDIS_PORTS: frozenset = frozenset({
    6379,  # Redis default (IANA assigned)
    6380,  # Common alternate Redis port
})

# Maximum bytes of the client buffer to scan per call.
# Redis AUTH commands are short; 4 KB is well above any realistic exchange.
_MAX_SCAN_CLIENT = 4096

# Regex for inline AUTH commands (fallback for non-RESP clients).
# Captures optional username and mandatory password.
#   Group 1: first argument (the password, or the username if a second
#            argument follows); Group 2: second argument (password) or None.
# Requires a CRLF terminator. \s+ can also span a line break.
_AUTH_INLINE_RE = re.compile(
    rb"^AUTH\s+(\S+)(?:\s+(\S+))?\r\n",
    re.IGNORECASE | re.MULTILINE,
)

# Inline RESP3 handshake with credentials: HELLO <ver> AUTH <user> <pass> ...
# (SETNAME and the rest of the line, if any, are ignored). Group 1 is the
# username, group 2 the password.
_HELLO_INLINE_RE = re.compile(
    rb"^HELLO[ \t]+\S+[ \t]+AUTH[ \t]+(\S+)[ \t]+(\S+)[^\r\n]*\r\n",
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


def _hello_auth_from_elems(elems: list):
    """
    Pull (username, password) out of a parsed RESP `HELLO` array, or None.

    HELLO's form is `HELLO <protover> [AUTH <user> <pass>] [SETNAME <name>]`,
    so AUTH is an optional keyword followed by two arguments somewhere after
    the version (TODO.md #24). A HELLO with no AUTH clause carries no
    credential.
    """
    for k in range(1, len(elems) - 2):
        if elems[k].upper() == b'AUTH':
            return (elems[k + 1].decode("utf-8", "replace"),
                    elems[k + 2].decode("utf-8", "replace"))
    return None


def _find_auth_command(data: bytes):
    """
    Scan *data* for the first Redis credential command in RESP or inline form.

    Recognises both the AUTH command and the RESP3 `HELLO <ver> AUTH <user>
    <pass>` handshake (TODO.md #24). Tries RESP array format first at each
    position; falls back to the inline regexes for clients that use raw text
    commands. Walks the buffer one byte at a time (bounded by
    _MAX_SCAN_CLIENT), so the command does not have to be first; complete
    non-matching RESP arrays are skipped over whole. An AUTH array with an
    element count other than 2 or 3 is skipped as a non-match.

    Args:
        data: Raw bytes from the client stream buffer (bounded to _MAX_SCAN_CLIENT).

    Returns:
        (username, password, is_hello, end_offset) where username is an empty
        string for password-only AUTH, is_hello is True when the credential
        came from a HELLO handshake (its reply is correlated differently),
        and end_offset points past the last byte of the command. Returns
        (None, None, None, None) if no credential command is found.
    """
    i = 0
    while i < len(data):
        if data[i:i + 1] == b'*':
            # Attempt to parse a RESP array at this position.
            elems, end = _parse_resp_array(data, i)
            if elems is not None:
                if elems and elems[0].upper() == b'AUTH' and len(elems) in (2, 3):
                    if len(elems) == 2:
                        # AUTH <password>
                        return "", elems[1].decode("utf-8", "replace"), False, end
                    # AUTH <username> <password>
                    return (elems[1].decode("utf-8", "replace"),
                            elems[2].decode("utf-8", "replace"), False, end)
                if elems and elems[0].upper() == b'HELLO':
                    creds = _hello_auth_from_elems(elems)
                    if creds is not None:
                        return creds[0], creds[1], True, end
                # Valid RESP array but not a credential command — skip past it.
                i = end
                continue
            # Not a valid RESP array at this offset — advance one byte.
            i += 1
            continue

        # Try inline AUTH, then inline HELLO AUTH, at this position.
        m = _AUTH_INLINE_RE.match(data, i)
        if m:
            if m.group(2) is not None:
                # AUTH <username> <password>
                return (m.group(1).decode("utf-8", "replace"),
                        m.group(2).decode("utf-8", "replace"), False, m.end())
            # AUTH <password>
            return "", m.group(1).decode("utf-8", "replace"), False, m.end()

        hm = _HELLO_INLINE_RE.match(data, i)
        if hm:
            return (hm.group(1).decode("utf-8", "replace"),
                    hm.group(2).decode("utf-8", "replace"), True, hm.end())

        i += 1

    return None, None, None, None


def _skip_resp(data: bytes, i: int, depth: int = 0):
    """
    Return the offset just past one complete RESP value starting at *i*.

    Handles the RESP2 and RESP3 types (simple line, bulk string, array, set,
    push, and the RESP3 map), recursing into aggregates. Used to consume a
    HELLO reply whole (its success form is a map), so floors stay valid
    (TODO.md #24).

    Returns None if the value is not fully buffered yet or is malformed, or
    if nesting is implausibly deep (a guard against hostile input).
    """
    if depth > 32 or i >= len(data):
        return None
    tag = data[i:i + 1]
    eol = data.find(b'\r\n', i)
    if eol == -1:
        return None
    if tag in (b'+', b'-', b':', b'_', b'#', b',', b'('):
        return eol + 2                                  # simple, line-terminated
    if tag in (b'$', b'=', b'!'):                       # bulk string/verbatim/error
        try:
            n = int(data[i + 1:eol])
        except ValueError:
            return None
        if n < 0:
            return eol + 2                              # null bulk ($-1)
        end = eol + 2 + n + 2
        return end if end <= len(data) else None
    if tag in (b'*', b'~', b'>', b'%'):                 # array/set/push/map
        try:
            n = int(data[i + 1:eol])
        except ValueError:
            return None
        if n < 0:
            return eol + 2                              # null array
        count = n * 2 if tag == b'%' else n             # a map has 2 items per entry
        pos = eol + 2
        for _ in range(count):
            pos = _skip_resp(data, pos, depth + 1)
            if pos is None:
                return None
        return pos
    return None


def _find_auth_response(data: bytes, start: int = 0, hello: bool = False):
    """
    Scan *data* from *start* for the server's response to AUTH or HELLO.

    resolve() passes the pending finding's server_buf_floor as *start*, so
    replies to commands sent before the credential (a '+OK' to CLIENT
    SETNAME/SELECT, or a '-NOAUTH' to a command that needed auth) are skipped
    (#14).

    For plain AUTH, '+OK' is success and any '-<error>' line is failure;
    other reply types ('+PONG', ':1', bulk replies) are skipped line by line.
    For HELLO (TODO.md #24) the reply at the floor is the handshake answer: a
    '-<error>' line is failure, and any other (a RESP3 map on success) is
    success, consumed whole with _skip_resp so the floor stays valid.

    Args:
        data:  Raw bytes from the server stream buffer.
        start: Offset to begin scanning (the pending finding's floor).
        hello: True if the pending finding came from a HELLO handshake.

    Returns:
        (outcome, end_offset) where outcome is "success" or "failed", and
        end_offset is an absolute offset into *data* past the end of the
        matched response. Returns (None, None) if no relevant response is
        present yet.
    """
    if hello:
        if start >= len(data):
            return None, None
        eol = data.find(b'\r\n', start)
        if eol == -1:
            return None, None
        if data[start:start + 1] == b'-':
            return "failed", eol + 2
        end = _skip_resp(data, start)
        if end is None:
            return None, None                           # map not fully buffered yet
        return "success", end

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

    The scan is bounded to _MAX_SCAN_CLIENT bytes per call to keep per-packet CPU
    cost O(1) regardless of buffer depth.

    Args:
        session: Session object from session.SessionTable.
        ts:      Unix timestamp of the current packet.

    Returns:
        Always an empty list; findings are registered on the session as
        pending and emitted by tscan_ng.resolve once resolved.
    """
    # Gate: only inspect sessions on known Redis ports.
    if not on_ports(session, _REDIS_PORTS):
        return []

    # Bound the scan to avoid O(n) work on very deep buffers.
    client_bytes = bytes(session.client_buf[:_MAX_SCAN_CLIENT])
    username, password, is_hello, cmd_end = _find_auth_command(client_bytes)

    if username is None:
        # No AUTH/HELLO command in the window: drop scanned non-auth commands so
        # an AUTH behind them is reached on a later packet (TODO.md #16). RESP is
        # byte-framed, so the cut is byte-aligned; _find_auth_command() resyncs.
        advance_scan_window(session, _MAX_SCAN_CLIENT, line_oriented=False)
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

    base = base_finding(session, "redis_creds", creds_str, username=username)

    # _hello (private, stripped before output) tells resolve() the reply is a
    # HELLO handshake answer (a RESP3 map on success), not a plain +OK.
    session.add_pending({**base, "_hello": is_hello}, ts_start=ts)
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
    # Pass the server_buf bytearray directly (already scanned from the floor),
    # so nothing is copied per packet (TODO.md #23).
    outcome, rsp_end = _find_auth_response(
        session.server_buf, p.server_buf_floor, p.finding.get("_hello", False))
    if outcome is None:
        return None
    return {"status": outcome, "outcome": outcome}, rsp_end
