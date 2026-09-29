"""
detectors/smtp.py - SMTP credential detector for tscan-ng.

Stream-aware detector that operates on reassembled TCP streams rather than
individual packets. Parses SMTP AUTH PLAIN and AUTH LOGIN commands from the
client buffer and correlates them with server response codes.

Because session direction is normalised at creation time (see session.py),
client_buf always contains client-originated bytes and server_buf always
contains server-originated bytes. No direction sniffing is required here.

Handles two SMTP authentication mechanisms:

AUTH PLAIN:
    CLIENT: AUTH PLAIN <base64(\x00username\x00password)>
    SERVER: 235 Authentication successful
    or split:
    CLIENT: AUTH PLAIN
    SERVER: 334
    CLIENT: <base64(\x00username\x00password)>
    SERVER: 235 Authentication successful

AUTH LOGIN:
    CLIENT: AUTH LOGIN
    SERVER: 334 VXNlcm5hbWU6  (base64 "Username:")
    CLIENT: <base64 username>
    SERVER: 334 UGFzc3dvcmQ6  (base64 "Password:")
    CLIENT: <base64 password>
    SERVER: 235 Authentication successful

For AUTH LOGIN the credentials arrive across multiple packets.  The client
buffer is not consumed until both base64 lines are present so that AUTH LOGIN
remains as a stable anchor across successive detect_stream calls.

Port handling:
    The detector gates on _SMTP_PORTS (a frozenset of known SMTP ports).
    Sessions where neither endpoint port is in the set are skipped immediately.

    The scan for AUTH commands is bounded to _MAX_CMD_SCAN bytes so that a
    large client buffer does not cause O(n) work on every arriving packet.

Finding outcomes:
    success      - Server responded with 235 Authentication successful
    failed       - Server responded with 535 or 534 Authentication failed
    server_error - Server responded with 432
    no_response  - Session expired before a server response was seen
                   (emitted by SessionTable.expire())

Finding type: "smtp_creds"; extra "mechanism" is "PLAIN" or "LOGIN";
"creds" is "user:password" (decoded from base64).

Response correlation:
    Positional, by code: the first server_buf line starting "235", "535",
    "534" or "432" followed by a space or hyphen is taken as the answer. No
    command tags exist in SMTP. Matched lines are consumed only when used, so
    a stale 535/534/432 left by an earlier attempt that this module did not
    detect (e.g. an unsupported mechanism such as CRAM-MD5 or XOAUTH2) will be
    attributed to the next captured credential. run.py's _try_resolve()
    repeats the same matching for pending findings.

Known limitations:
    - Only AUTH PLAIN and AUTH LOGIN are parsed. An initial response given
      on the AUTH LOGIN line itself ("AUTH LOGIN <base64 user>") is not
      matched by _SMTP_AUTH_LOGIN_RE.
    - STARTTLS-protected sessions are opaque; 465 (SMTPS) is normally TLS.
    - Only the first 4 KB of client_buf is scanned. AUTH LOGIN leaves its
      anchor in the buffer until both credential lines arrive, so an
      abandoned AUTH LOGIN can cause later bare-word lines (for example
      message body text that is pure base64 alphabet) to be decoded as
      credentials.
    - The AUTH LOGIN path does not skip empty/undecodable credentials the way
      the AUTH PLAIN path does (decode_b64 returns "" on bad input).
"""

import logging
import re
import base64
from tscan_ng.detectors.common import decode_b64 as _decode_b64
from tscan_ng.session import _make_filter

# Matches SMTP AUTH PLAIN with optional inline credentials, on a line of its
# own (anchored ^...$ per line; the optional CR tolerates CRLF endings since
# MULTILINE $ only matches before "\n").
#   Group 1: the inline base64 blob, or the empty bytes if absent (the client
#   then sends the blob on the next line after the server's 334).
_SMTP_AUTH_PLAIN_RE = re.compile(
    rb"^AUTH PLAIN ?([A-Za-z0-9+/=]*)\r?$",
    re.IGNORECASE | re.MULTILINE
)

# Matches SMTP AUTH LOGIN (no inline initial response) on a line of its own.
_SMTP_AUTH_LOGIN_RE = re.compile(
    rb"^AUTH LOGIN\r?$",
    re.IGNORECASE | re.MULTILINE
)

# Matches a bare base64 line (response to a 334 challenge).
#   Group 1: the base64 text including any trailing "=" padding.
# SMTP verbs that are pure [A-Za-z0-9] strings (RSET, DATA, QUIT, NOOP, etc.)
# would otherwise match; they are excluded by _SMTP_VERBS below.
_BASE64_LINE_RE = re.compile(
    rb"^([A-Za-z0-9+/]+=*)\r?$",
    re.MULTILINE
)

# SMTP command words that are pure base64-alphabet strings and must not be
# misread as AUTH LOGIN credential lines.
_SMTP_VERBS: frozenset = frozenset({
    b"RSET", b"DATA", b"QUIT", b"NOOP", b"HELP",
    b"VRFY", b"EXPN", b"EHLO", b"HELO", b"STARTTLS",
})

# Matches SMTP server response codes we care about, at the start of a line:
#   235 = authentication successful
#   535 = authentication credentials invalid
#   534 = authentication mechanism too weak
#   432 = a password transition is needed
# The [ -] accepts both final ("235 ") and continuation ("235-") lines.
#   Group 1: the 3-digit code.
_SMTP_RESPONSE_RE = re.compile(
    rb"^(235|535|534|432)[ -]",
    re.MULTILINE
)

# Well-known SMTP control ports (standard and submission variants).
# Sessions whose dport or sport is in this set are scanned for credentials.
_SMTP_PORTS: frozenset = frozenset({
    25,    # SMTP (RFC 5321)
    587,   # SMTP submission (RFC 6409)
    465,   # SMTPS (legacy; still widely used)
    2525,  # Common alternate SMTP port
})

# Maximum bytes of the client buffer to scan for AUTH commands per call.
# SMTP auth exchanges are short; 4 KB is well above any realistic exchange.
# Bounding the scan keeps per-packet work O(1) regardless of buffer lifetime.
_MAX_CMD_SCAN = 4096


def _outcome(code: bytes) -> str:
    """
    Map an SMTP response code to a human-readable outcome string.

    Args:
        code: SMTP 3-digit response code bytes.

    Returns:
        One of: success, failed, server_error, unknown. ("unknown" is
        unreachable via _SMTP_RESPONSE_RE, which only yields the four
        codes handled here.)
    """
    if code == b"235":
        return "success"
    elif code in (b"535", b"534"):
        return "failed"
    elif code == b"432":
        return "server_error"
    return "unknown"


def _decode_plain(blob: bytes) -> tuple | None:
    """
    Decode an AUTH PLAIN base64 blob into (username, password).

    AUTH PLAIN format after base64 decode: \x00username\x00password
    or: authzid\x00username\x00password (with optional authorization id)
    (RFC 4616: authzid NUL authcid NUL passwd). The authzid is discarded.
    imap.py carries an identical copy of this function.

    Args:
        blob: Raw base64 encoded bytes.

    Returns:
        (username, password) tuple, or None if decoding fails or the decoded
        payload does not split into two or three NUL-separated fields.
    """
    try:
        decoded = base64.b64decode(blob)
        parts = decoded.split(b"\x00")
        if len(parts) == 3:
            return parts[1].decode("utf-8", "ignore"), parts[2].decode("utf-8", "ignore")
        elif len(parts) == 2:
            return parts[0].decode("utf-8", "ignore"), parts[1].decode("utf-8", "ignore")
    except Exception:
        pass
    return None


def detect_stream(session, ts: float) -> list:
    """
    Stream-aware SMTP AUTH credential detector.

    Scans session.client_buf for SMTP AUTH PLAIN and AUTH LOGIN commands
    and session.server_buf for response codes.  Session direction is always
    normalised to the client perspective by the session layer, so no
    direction sniffing is needed here.

    AUTH PLAIN: credentials may be inline or on the next line after a 334
    challenge.  The client buffer is consumed once credentials are extracted.
    If the split-form blob line has not arrived yet, nothing is emitted or
    consumed, so the bare "AUTH PLAIN" line stays in client_buf as an anchor
    for the next call. A blob that fails to decode is not consumed either.

    AUTH LOGIN: credentials arrive across multiple client packets interleaved
    with server 334 challenges.  The client buffer is NOT consumed until both
    base64 lines are present, keeping AUTH LOGIN as a stable anchor for
    successive calls.  Once complete, a pending finding is registered (or
    resolved immediately if the 235 response is already in server_buf), and
    the consumed portion of client_buf is removed.

    Args:
        session: Session object from session.SessionTable.
        ts:      Unix timestamp of the current packet.

    Returns:
        List of resolved finding dicts. Pending findings are registered on
        the session and not returned until resolved.
    """
    # Skip sessions that are not on a known SMTP port.
    if session.sport not in _SMTP_PORTS and session.dport not in _SMTP_PORTS:
        return []

    # Cap the scan to _MAX_CMD_SCAN bytes to bound per-packet CPU cost.
    client_bytes = bytes(session.client_buf[:_MAX_CMD_SCAN])
    server_bytes = bytes(session.server_buf)

    findings = []

    # -----------------------------------------------------------------------
    # AUTH LOGIN
    # -----------------------------------------------------------------------
    login_match = _SMTP_AUTH_LOGIN_RE.search(client_bytes)
    if login_match:
        # Filter out bare SMTP verbs (RSET, DATA, QUIT, etc.) that consist
        # entirely of base64-alphabet characters and would otherwise be
        # misread as credential lines.
        b64_matches = [
            m for m in _BASE64_LINE_RE.finditer(client_bytes, login_match.end())
            if m.group(1).upper() not in _SMTP_VERBS
        ]

        # The first bare-base64 line after AUTH LOGIN is the username, the second
        # the password (each answers a 334 challenge from the server).
        if len(b64_matches) >= 2:
            user   = _decode_b64(b64_matches[0].group(1))
            passwd = _decode_b64(b64_matches[1].group(1))

            base = {
                "type":       "smtp_creds",
                "mechanism":  "LOGIN",
                "session_id": session.session_id,
                "src":        session.src,
                "dst":        session.dst,
                "sport":      session.sport,
                "dport":      session.dport,
                "creds":      f"{user}:{passwd}",
                "filter":     _make_filter(session.src, session.dst,
                                           session.sport, session.dport),
            }

            response = _SMTP_RESPONSE_RE.search(server_bytes)
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

            # Consume AUTH LOGIN + both credential lines from client buffer.
            # Returns immediately: AUTH PLAIN below is not examined in the
            # same call.
            del session.client_buf[:b64_matches[1].end()]
            return findings

        # Fewer than 2 credential lines present — leave the buffer intact so
        # AUTH LOGIN remains an anchor for the next packet.  Fall through to
        # check AUTH PLAIN in case the client cancelled AUTH LOGIN and retried.

    # -----------------------------------------------------------------------
    # AUTH PLAIN
    # -----------------------------------------------------------------------
    plain_match = _SMTP_AUTH_PLAIN_RE.search(client_bytes)
    if plain_match:
        blob = plain_match.group(1)

        if blob:
            # Credentials inline on the AUTH PLAIN line
            result = _decode_plain(blob)
            end = plain_match.end()
        else:
            # Credentials on the next line (after server 334 challenge)
            next_line = _BASE64_LINE_RE.search(client_bytes, plain_match.end())
            result = _decode_plain(next_line.group(1)) if next_line else None
            end = next_line.end() if next_line else plain_match.end()

        # Use `is not None` rather than truthiness: a valid result is always a
        # 2-tuple, but an explicit None check is more robust if _decode_plain()
        # is ever extended to return other falsy values. (When the inline blob
        # exists but fails to decode, result is None and nothing is consumed,
        # so the same line is re-examined on every subsequent packet.)
        if result is not None:
            user, passwd = result
            # Guard against empty captures — emit nothing rather than
            # a finding with blank credentials.
            if not user and not passwd:
                logging.debug(
                    "smtp: session %s: AUTH PLAIN decoded empty credentials",
                    session.session_id)
                del session.client_buf[:end]
                return findings
            base = {
                "type":       "smtp_creds",
                "mechanism":  "PLAIN",
                "session_id": session.session_id,
                "src":        session.src,
                "dst":        session.dst,
                "sport":      session.sport,
                "dport":      session.dport,
                "creds":      f"{user}:{passwd}",
                "filter":     _make_filter(session.src, session.dst,
                                           session.sport, session.dport),
            }

            response = _SMTP_RESPONSE_RE.search(server_bytes)
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

            del session.client_buf[:end]

    return findings
