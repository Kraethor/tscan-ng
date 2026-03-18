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
"""

import logging
import re
import base64
from tscan_ng.session import _make_filter

# Matches SMTP AUTH PLAIN with optional inline credentials
_SMTP_AUTH_PLAIN_RE = re.compile(
    rb"^AUTH PLAIN ?([A-Za-z0-9+/=]*)\r?$",
    re.IGNORECASE | re.MULTILINE
)

# Matches SMTP AUTH LOGIN
_SMTP_AUTH_LOGIN_RE = re.compile(
    rb"^AUTH LOGIN\r?$",
    re.IGNORECASE | re.MULTILINE
)

# Matches a bare base64 line (response to a 334 challenge)
_BASE64_LINE_RE = re.compile(
    rb"^([A-Za-z0-9+/]+=*)\r?$",
    re.MULTILINE
)

# Matches SMTP server response codes we care about
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
        One of: success, failed, server_error, unknown.
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

    Args:
        blob: Raw base64 encoded bytes.

    Returns:
        (username, password) tuple, or None if decoding fails.
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


def _decode_b64(blob: bytes) -> str:
    """
    Decode a base64 blob to a UTF-8 string.

    Args:
        blob: Raw base64 encoded bytes.

    Returns:
        Decoded string, or empty string on failure.
    """
    try:
        return base64.b64decode(blob).decode("utf-8", "ignore")
    except Exception:
        return ""


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
    Stream-aware SMTP AUTH credential detector.

    Scans session.client_buf for SMTP AUTH PLAIN and AUTH LOGIN commands
    and session.server_buf for response codes.  Session direction is always
    normalised to the client perspective by the session layer, so no
    direction sniffing is needed here.

    AUTH PLAIN: credentials may be inline or on the next line after a 334
    challenge.  The client buffer is consumed once credentials are extracted.

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
        b64_matches = list(_BASE64_LINE_RE.finditer(client_bytes, login_match.end()))

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

            # Consume AUTH LOGIN + both credential lines from client buffer
            del session.client_buf[:b64_matches[1].end()]

        # If fewer than 2 base64 lines are present, do nothing: leave the
        # buffer intact so AUTH LOGIN remains an anchor for the next packet.
        return findings

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
        # is ever extended to return other falsy values.
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
