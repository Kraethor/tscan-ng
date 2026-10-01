"""
detectors/imap.py - IMAP credential detector for tscan-ng.

Stream-aware detector that operates on reassembled TCP streams rather than
individual packets. Parses IMAP LOGIN commands and AUTHENTICATE PLAIN
exchanges from the client buffer and correlates them with tagged server
responses.

Handles both quoted (allowing spaces) and unquoted username/password forms
for LOGIN, and both the inline (SASL-IR, RFC 4959) and split forms of
AUTHENTICATE PLAIN.

Correctly handles optional response codes in square brackets such as
[CAPABILITY ...] and [AUTHENTICATIONFAILED] between the status word and
human-readable text.

Port handling:
    The detector gates on _IMAP_PORTS (a frozenset of known IMAP ports).
    Sessions where neither endpoint port is in the set are skipped immediately,
    keeping per-packet overhead negligible for non-IMAP traffic.

    The scan for LOGIN/AUTHENTICATE commands is bounded to _MAX_SCAN_CLIENT bytes
    so that a large client buffer does not cause O(n) work on every arriving
    packet.

Buffer scanning:
    _IMAP_LOGIN_RE and _IMAP_AUTH_PLAIN_RE are bytes regexes. This avoids
    decoding client_buf with errors="ignore", which silently drops non-UTF-8
    bytes and shifts byte positions. Buffer consumption below relies on byte
    offsets staying aligned with client_buf.

Finding outcomes:
    success      - Server responded with tagged OK
    failed       - Server responded with tagged NO
    bad_command  - Server responded with tagged BAD
    no_response  - Session expired before a server response was seen
                   (emitted by SessionTable.expire())

Finding type: "imap_creds"
Finding extras:
    "tag"       - the client's command tag (e.g. "a001"). Used to pair the
                  request with its tagged server response in resolve().
    "mechanism" - "AUTHENTICATE_PLAIN" for SASL PLAIN; absent for LOGIN.
    "creds"     - "user:password".

Response correlation (tag-based, unlike FTP/POP3/SMTP):
    server_buf is searched for the first "<tag> OK|NO|BAD " line whose tag
    equals the request's tag (case-insensitive). Because of this, unrelated
    untagged ("* ...") or differently-tagged responses cannot be mistaken for
    the answer. resolve() consumes server_buf up to and including the
    matched line, so a reused tag cannot match a stale response.

Known limitations:
    - LOGIN arguments given as IMAP literals ("LOGIN {5}<CRLF>alice ...") are
      not handled, and backslash-escaped quotes inside quoted strings end the
      string early.
    - AUTHENTICATE mechanisms other than PLAIN (LOGIN, XOAUTH2, CRAM-MD5, ...)
      are ignored. STARTTLS upgrades make everything after them opaque.
    - Only the first 4 KB of client_buf is scanned, and the buffer is
      consumed only when a LOGIN/AUTHENTICATE is matched.
    - LOGIN is matched without requiring the terminating CRLF, so a command
      split across TCP segments can be captured truncated.
    - 993 (IMAPS) is normally TLS; it only yields findings if the traffic on
      that port is actually cleartext.
"""

import base64
import logging
import re
from tscan_ng.session import _make_filter

# Finding types this detector emits; tscan_ng.resolve maps each to resolve().
FINDING_TYPES = ("imap_creds",)

# Well-known IMAP ports.
# Sessions whose dport or sport is in this set are scanned for credentials.
_IMAP_PORTS: frozenset = frozenset({
    143,   # IMAP (RFC 3501)
    993,   # IMAPS (still seen in cleartext on internal networks)
    1430,  # Non-standard IMAP port (site-specific)
})

# Maximum bytes of the client buffer to scan for LOGIN/AUTHENTICATE commands
# per call. IMAP auth exchanges are short; 4 KB is well above any realistic
# auth exchange. Bounding the scan keeps per-packet work O(1) regardless of
# buffer lifetime.
_MAX_SCAN_CLIENT = 4096

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

# Matches IMAP AUTHENTICATE PLAIN, with an optional inline SASL-IR initial
# response (RFC 4959):
#   tag AUTHENTICATE PLAIN                    (server then sends "+", client
#                                               follows with a bare base64 line)
#   tag AUTHENTICATE PLAIN <base64>           (inline initial response)
#   Group 1: command tag (e.g. A002)
#   Group 2: inline base64 blob, or None if not present on this line
_IMAP_AUTH_PLAIN_RE = re.compile(
    rb'^(\S+)[ \t]+AUTHENTICATE[ \t]+PLAIN(?:[ \t]+([A-Za-z0-9+/=]+))?\r?$',
    re.IGNORECASE | re.MULTILINE
)

# Matches a bare base64 line — the client's response to the server's "+"
# SASL continuation prompt. IMAP commands always carry a tag (RFC 3501:
# "tag SP command"), so a real command line always contains a space and
# cannot match this tag-less, whole-line pattern; no verb denylist is
# needed here the way detectors/smtp.py needs one for tag-less SMTP verbs.
# The exceptions are the few tag-less client lines IMAP does have -- "DONE"
# (ends IDLE) is pure alphabet and would match -- but they only matter if
# they follow an AUTHENTICATE PLAIN line that has no inline blob.
#   Group 1: the base64 text, with any trailing "=" padding.
_BASE64_LINE_RE = re.compile(
    rb'^([A-Za-z0-9+/]+=*)\r?$',
    re.MULTILINE
)

# Matches a tagged server response, on raw bytes so match.end() is a byte
# offset for consuming server_buf (a decoded string's character offsets
# would mis-align if server_buf holds multi-byte UTF-8 or undecodable bytes).
# The trailing \s+ means the status must be followed by at least one
# whitespace character (a bare "a1 OK" with nothing after it, or split at
# the segment boundary, is not matched).
#   Group 1: tag, Group 2: OK / NO / BAD.
#   a001 OK [CAPABILITY ...] Welcome
#   a001 NO [AUTHENTICATIONFAILED] Invalid credentials
#   a001 BAD Command unknown
_IMAP_RESPONSE_RE = re.compile(
    rb'^(\S+)\s+(OK|NO|BAD)\s+',
    re.IGNORECASE | re.MULTILINE
)


def _outcome(status: str) -> str:
    """
    Map an IMAP response status word to a human-readable outcome string.

    Args:
        status: IMAP status word (OK, NO, or BAD).

    Returns:
        One of: success, failed, bad_command, unknown. ("unknown" is
        unreachable from this module's own callers, which pass only the
        OK/NO/BAD group captured by the response regexes.)
    """
    status = status.upper()
    if status == "OK":
        return "success"
    elif status == "NO":
        return "failed"
    elif status == "BAD":
        return "bad_command"
    return "unknown"


def _decode_plain(blob: bytes) -> tuple | None:
    """
    Decode a SASL PLAIN base64 blob into (username, password).

    SASL PLAIN format after base64 decode: \x00username\x00password
    or: authzid\x00username\x00password (with optional authorization id).
    Same mechanism and wire format as SMTP/POP3 AUTH PLAIN — see
    detectors/smtp.py's _decode_plain for the shared rationale. This is a
    byte-for-byte copy of smtp._decode_plain (each detector is kept
    self-contained). Only two- or three-field payloads are accepted; the
    authorization id in the three-field form is discarded.

    Args:
        blob: Raw base64 encoded bytes.

    Returns:
        (username, password) tuple, or None if decoding fails.
    """
    try:
        decoded = base64.b64decode(blob)
        parts = decoded.split(b"\x00")
        if len(parts) == 3:
            return parts[1].decode("utf-8", "replace"), parts[2].decode("utf-8", "replace")
        elif len(parts) == 2:
            return parts[0].decode("utf-8", "replace"), parts[1].decode("utf-8", "replace")
    except Exception:
        pass
    return None


def detect_stream(session, ts: float) -> list[dict]:
    """
    Stream-aware IMAP credential detector — LOGIN and AUTHENTICATE PLAIN.

    Scans the session's client buffer for IMAP LOGIN commands and for
    AUTHENTICATE PLAIN exchanges (inline SASL-IR or split across the
    server's "+" continuation). For each one found, records the command
    tag and registers a pending finding; resolve() below pairs it with the
    tagged server response (on the same packet if it is already buffered).
    Both mechanisms resolve identically, since resolution only depends on
    the "tag" field matching a tagged OK/NO/BAD response. LOGIN is scanned
    with finditer,
    so several LOGIN commands in one buffer each produce a finding;
    AUTHENTICATE PLAIN uses search, so only the first such command per call
    is handled.

    Both mechanisms are scanned against the same immutable buffer snapshot
    and consumed from session.client_buf in a single operation at the end,
    so an AUTHENTICATE PLAIN command with no continuation line yet (still
    waiting on more data) does not disturb LOGIN's buffer offsets or vice
    versa.

    Correctly handles:
        - Quoted strings containing spaces in username or password (LOGIN)
        - Optional response codes in square brackets e.g. [CAPABILITY ...]
        - Tag-based request/response correlation
        - AUTHENTICATE PLAIN with or without an inline initial response

    Args:
        session: Session object from session.SessionTable.
        ts:      Unix timestamp of the current packet.

    Returns:
        Always an empty list; findings are registered on the session as
        pending and emitted by tscan_ng.resolve once resolved.
    """
    # Skip sessions that are not on a known IMAP port.
    if session.dport not in _IMAP_PORTS and session.sport not in _IMAP_PORTS:
        return []

    # Cap the scan to _MAX_SCAN_CLIENT bytes to bound per-packet CPU cost.
    # The regexes run on raw bytes — no decode needed, no byte positions lost.
    # This snapshot is not mutated until the single consumption point at the
    # end, so offsets computed against it stay valid for both mechanisms.
    scan = bytes(session.client_buf[:_MAX_SCAN_CLIENT])

    consume_end = None  # Furthest offset into `scan` consumed by either mechanism.

    # -----------------------------------------------------------------------
    # LOGIN
    #   tag LOGIN userid password
    # -----------------------------------------------------------------------
    # Track the last LOGIN match so consumption can cover all of them.
    login_last_match = None

    for match in _IMAP_LOGIN_RE.finditer(scan):
        login_last_match = match

        tag = match.group(1).decode("utf-8", "replace")

        # Prefer the quoted group; fall back to unquoted. Use explicit None
        # checks rather than `or` — group(2) can be b"" (empty quoted string)
        # which is falsy and would incorrectly fall through to group(3)=None.
        user_bytes   = match.group(2) if match.group(2) is not None else match.group(3)
        passwd_bytes = match.group(4) if match.group(4) is not None else match.group(5)

        user   = user_bytes.decode("utf-8", "replace")   if user_bytes   is not None else ""
        passwd = passwd_bytes.decode("utf-8", "replace") if passwd_bytes is not None else ""

        # Guard against empty credentials — emit nothing rather than noise.
        # (Only both-empty is dropped; e.g. LOGIN "" secret is still reported.)
        if not user and not passwd:
            logging.debug(
                "imap: session %s: LOGIN matched but user and password both empty",
                session.session_id)
            continue

        session.add_pending({
            "type":       "imap_creds",
            "session_id": session.session_id,
            "src":        session.src,
            "dst":        session.dst,
            "sport":      session.sport,
            "dport":      session.dport,
            "tag":        tag,  # Pairs the request with its response in resolve()
                                # (unlike snmp's "_request_id" it is NOT
                                # underscore-prefixed, so it is also emitted.)
            "creds":      f"{user}:{passwd}",
            "filter":     _make_filter(session.src, session.dst,
                                       session.sport, session.dport),
        }, ts_start=ts)

    if login_last_match is not None:
        consume_end = login_last_match.end()

    # -----------------------------------------------------------------------
    # AUTHENTICATE PLAIN (RFC 3501 SASL; inline form is RFC 4959 SASL-IR)
    #   tag AUTHENTICATE PLAIN [base64]        -> credentials inline, or
    #   S: + (continuation)   C: base64        -> credentials on the next line
    # -----------------------------------------------------------------------
    auth_match = _IMAP_AUTH_PLAIN_RE.search(scan)
    if auth_match:
        tag = auth_match.group(1).decode("utf-8", "replace")
        inline_blob = auth_match.group(2)

        if inline_blob:
            result = _decode_plain(inline_blob)
            auth_end = auth_match.end()
        else:
            # No inline response — credentials are on the next line, sent
            # after the server's "+" continuation prompt. If that line
            # hasn't arrived yet, leave the buffer untouched (auth_end stays
            # None) so this command remains a stable anchor for the next
            # call, the same way detectors/smtp.py's AUTH LOGIN handling
            # waits for both base64 lines before consuming anything.
            next_line = _BASE64_LINE_RE.search(scan, auth_match.end())
            result = _decode_plain(next_line.group(1)) if next_line else None
            auth_end = next_line.end() if next_line else None

        # auth_end is None only when the continuation line has not arrived yet.
        # A result of None with auth_end set means the blob did not decode
        # (bad base64 / wrong field count); it is consumed and ignored.
        if auth_end is not None:
            if result is not None:
                user, passwd = result
                if user or passwd:
                    session.add_pending({
                        "type":       "imap_creds",
                        "mechanism":  "AUTHENTICATE_PLAIN",
                        "session_id": session.session_id,
                        "src":        session.src,
                        "dst":        session.dst,
                        "sport":      session.sport,
                        "dport":      session.dport,
                        "tag":        tag,
                        "creds":      f"{user}:{passwd}",
                        "filter":     _make_filter(session.src, session.dst,
                                                   session.sport, session.dport),
                    }, ts_start=ts)
                else:
                    logging.debug(
                        "imap: session %s: AUTHENTICATE PLAIN decoded empty credentials",
                        session.session_id)

            if consume_end is None or auth_end > consume_end:
                consume_end = auth_end

    # Consume everything processed by either mechanism in one operation
    # (up to whichever of the LOGIN / AUTHENTICATE ends is furthest).
    # Both offsets were computed against the same immutable `scan` snapshot
    # taken at the top of this call, so they remain valid together.
    if consume_end is not None:
        del session.client_buf[:consume_end]

    return []


def resolve(p, session):
    """
    Match a pending IMAP login against its tagged reply (see tscan_ng.resolve).

    Looks for the first "<tag> OK|NO|BAD " line in server_buf whose tag
    equals the finding's "tag" (case-insensitive); untagged and differently
    tagged lines are skipped.

    Args:
        p:       PendingFinding for an imap_creds finding.
        session: Session whose server_buf is searched.

    Returns:
        ({"status", "outcome"}, bytes to consume) or None if no reply yet.
    """
    tag = p.finding.get("tag", "").upper().encode("utf-8", "ignore")
    for match in _IMAP_RESPONSE_RE.finditer(bytes(session.server_buf)):
        if match.group(1).upper() == tag:
            status = match.group(2).upper().decode("utf-8", "replace")
            return {"status": status, "outcome": _outcome(status)}, match.end()
    return None
