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

Port handling:
    The detector gates on _POP3_PORTS (a frozenset of known POP3 ports).
    Sessions where neither endpoint port is in the set are skipped immediately,
    keeping per-packet overhead negligible for non-POP3 traffic.

    The scan for USER and PASS is bounded to _MAX_CMD_SCAN bytes so that a
    large client buffer does not cause O(n) work on every arriving packet.

Finding outcomes:
    success     - Server responded with +OK after PASS
    failed      - Server responded with -ERR after PASS
    no_response - Session expired before a server response was seen
                  (emitted by SessionTable.expire())

Credentials extracted:
    The first USER argument and the first PASS argument that follows it,
    joined as "user:password". Each is a single non-whitespace token, so a
    password containing spaces is truncated at the first space. APOP and
    AUTH (SASL) exchanges are not handled; only the USER/PASS pair.

Response correlation (positional, not tagged -- POP3 has no command tags):
    Server lines beginning "+OK" or "-ERR" are collected in order from
    server_buf. The greeting banner is assumed to be the first one, the USER
    reply the second and the PASS reply the third. Rules applied by resolve()
    below:
      - any "-ERR" anywhere in server_buf resolves immediately as failed;
      - otherwise, once three responses are present, the third decides;
      - otherwise the finding is parked as pending.
    This is an approximation: it assumes the capture saw the banner and that
    no other +OK/-ERR replies (CAPA, STAT, a previous attempt's replies that
    were not consumed, ...) precede the PASS reply.

Known limitations:
    - After a resolved attempt the consumed server_buf no longer contains a
      banner, so a second USER/PASS attempt on the same connection needs three
      fresh +OK lines and will normally stay pending (no_response) on success.
    - A CAPA (or any other +OK-answered command) before login shifts the
      "third response" to the USER reply.
    - Commands are matched without requiring the terminating CRLF, so a line
      split across TCP segments can produce a truncated user or password.
    - Only the first 4 KB of client_buf is scanned; it is consumed only on a
      match.
    - 995 (POP3S) is normally TLS and yields nothing unless traffic on that
      port is actually cleartext.
"""

import logging
import re
from tscan_ng.session import _make_filter

# Finding types this detector emits; tscan_ng.resolve maps each to resolve().
FINDING_TYPES = ("pop3_creds",)

# Well-known POP3 ports.
# Sessions whose dport or sport is in this set are scanned for credentials.
_POP3_PORTS: frozenset = frozenset({
    110,   # POP3 (RFC 1939)
    995,   # POP3S (still seen in cleartext on internal networks)
    1100,  # Non-standard POP3 port (site-specific)
})

# Maximum bytes of the client buffer to scan for USER and PASS commands.
# POP3 commands are short; 4 KB is well above any realistic auth exchange.
# Bounding the scan keeps per-packet work O(1) regardless of buffer lifetime.
_MAX_CMD_SCAN = 4096

# Matches POP3 USER command at the start of any line (MULTILINE).
#   Group 1: username token. \s+ can cross a line break ("USER\r\nPASS x").
_POP3_USER_RE = re.compile(
    rb"^USER\s+(\S+)",
    re.IGNORECASE | re.MULTILINE
)

# Matches POP3 PASS command at the start of any line (MULTILINE).
#   Group 1: password token (first whitespace-delimited word only).
_POP3_PASS_RE = re.compile(
    rb"^PASS\s+(\S+)",
    re.IGNORECASE | re.MULTILINE
)

# Matches a POP3 server response line (+OK or -ERR) at the start of a line.
# \b after the status keeps "+OKAY"-style junk from matching. Case-sensitive
# (no IGNORECASE); RFC 1939 status indicators are upper case.
#   Group 1: "+OK" or "-ERR".
_POP3_RESPONSE_RE = re.compile(
    rb"^(\+OK|-ERR)\b",
    re.MULTILINE
)



def _outcome(status: bytes) -> str:
    """
    Map a POP3 response token to a human-readable outcome string.

    Args:
        status: b'+OK' or b'-ERR'.

    Returns:
        One of: success, failed. Anything that is not "+OK" (case-insensitive)
        maps to failed.
    """
    if status.upper() == b"+OK":
        return "success"
    return "failed"


def detect_stream(session, ts: float) -> list:
    """
    Stream-aware POP3 USER/PASS credential detector.

    Scans session.client_buf for POP3 USER and PASS commands and
    session.server_buf for +OK / -ERR responses.  Session direction is
    always normalised to the client perspective by the session layer.

    Registers every credential as a pending finding (resolve() below matches
    the server's reply) and consumes the matched commands from the client
    buffer to avoid re-detection on subsequent packets.

    The scan is bounded to _MAX_CMD_SCAN bytes per call to keep per-packet
    work O(1) regardless of buffer lifetime.

    Args:
        session: Session object from session.SessionTable.
        ts:      Unix timestamp of the current packet.

    Returns:
        Always an empty list; findings are registered on the session as
        pending and emitted by tscan_ng.resolve once resolved.
    """
    # Skip sessions that are not on a known POP3 port.
    if session.dport not in _POP3_PORTS and session.sport not in _POP3_PORTS:
        return []

    # Cap the scan to _MAX_CMD_SCAN bytes to bound per-packet CPU cost.
    client_bytes = bytes(session.client_buf[:_MAX_CMD_SCAN])

    user_match = _POP3_USER_RE.search(client_bytes)
    if not user_match:
        return []

    pass_match = _POP3_PASS_RE.search(client_bytes, user_match.end())
    if not pass_match:
        return []

    user   = user_match.group(1).decode("utf-8", "ignore")
    passwd = pass_match.group(1).decode("utf-8", "ignore")

    # Defensive guard against empty captures. Both patterns capture (\S+),
    # which cannot be empty, so this branch is currently unreachable; it stops
    # a future regex change from emitting findings with blank credentials.
    if not user or not passwd:
        logging.debug(
            "pop3: session %s: USER or PASS matched but captured empty string",
            session.session_id)
        del session.client_buf[:pass_match.end()]
        return []

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

    session.add_pending(base, ts_start=ts)
    del session.client_buf[:pass_match.end()]
    return []


def resolve(p, session):
    """
    Match a pending POP3 login against the server's replies (see tscan_ng.resolve).

    POP3 session response sequence (normal):
        responses[0] - server greeting banner (+OK)
        responses[1] - reply to USER (+OK or -ERR)
        responses[2] - reply to PASS (+OK or -ERR)   <- the one wanted

    All three must be present before a success is declared, because two +OK
    lines are ambiguous (banner + USER reply, PASS reply still to come). The
    first -ERR anywhere is taken as the failure straight away. (It is not
    strictly unambiguous: an -ERR to CAPA/STAT etc. also matches.)

    Args:
        p:       PendingFinding for a pop3_creds finding.
        session: Session whose server_buf is searched.

    Returns:
        ({"status", "outcome"}, bytes to consume) or None if undecided yet.
    """
    responses = list(_POP3_RESPONSE_RE.finditer(bytes(session.server_buf)))
    decisive = next((r for r in responses if r.group(1).upper() == b"-ERR"), None)
    if decisive is None and len(responses) >= 3:
        decisive = responses[2]
    if decisive is None:
        return None
    code = decisive.group(1)
    return ({"status": code.decode("utf-8", "ignore"), "outcome": _outcome(code)},
            decisive.end())
