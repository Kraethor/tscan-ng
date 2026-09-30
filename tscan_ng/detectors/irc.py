"""
detectors/irc.py - IRC NickServ IDENTIFY credential detector for tscan-ng.

Stream-aware detector that operates on reassembled TCP streams. IRC has no
built-in login concept for the wire itself (a bare NICK/USER handshake
carries no password) -- the credential that matters is the one sent to the
network's NickServ services bot to claim a registered nickname, sent as an
ordinary chat message:

    PRIVMSG NickServ :IDENTIFY <password>
    PRIVMSG NickServ :IDENTIFY <nick> <password>
    PRIVMSG NickServ :ID <password>              -- common short alias

This is the plaintext-credential-over-chat pattern this detector targets --
functionally identical in spirit to FTP/Telnet's cleartext password, just
carried inside an application-level PRIVMSG instead of a dedicated auth
command.

Response correlation: NickServ replies via NOTICE, e.g.

    :NickServ!NickServ@services.example.net NOTICE mynick :Password accepted - you are now recognized.
    :NickServ!NickServ@services.example.net NOTICE mynick :Password incorrect.

Exact wording is services-daemon-specific (Atheme, Anope, and others all
phrase this slightly differently) and not standardized by any IRC RFC;
_ACCEPT_RE/_REJECT_RE recognize the common phrasings from the widely
deployed daemons. A NickServ NOTICE that matches neither pattern is
skipped in place (scanning continues for a later, recognizable one) rather
than treated as failure -- getting the wording wrong should never manufacture
a false "failed" outcome.

Explicit non-goals:
    - SASL PLAIN authentication (the CAP REQ :sasl / AUTHENTICATE multi-step
      exchange most modern clients now prefer for services login) is not
      handled -- it's a different, more structurally complex correlation
      (capability negotiation, then a base64 challenge/response) than the
      single PRIVMSG this module targets. The PRIVMSG IDENTIFY pattern
      remains extremely common (default/fallback behavior for most clients,
      and the only option on networks/bots that don't support SASL).
    - IRCv3 message tags (a leading "@tag=value ..." prefix some modern
      clients prepend) are not parsed; a tagged IDENTIFY line will not
      match _IDENTIFY_RE.
    - ChanServ channel-registration IDENTIFY (same command, different
      target) is not covered, though it is a straightforward addition to
      _IDENTIFY_RE's target alternation should it be wanted.

Port handling:
    Gates on _IRC_PORTS. Sessions on other ports are skipped immediately.
    6667 — standard plaintext IRC
    6666, 6668, 6669 — common alternates in the classic 666x range

Finding type: "irc_creds"
Finding extras:
    "nick"  — the nickname argument to IDENTIFY, if given (empty string for
              the single-argument "IDENTIFY <password>" form).
    "creds" — formatted as "nick:password", or ":password" if no nick was
              given, for display consistency with every other detector
              that has an optional username component (e.g. redis_creds).

Known limitations:
    - Only the first 4 KB of client_buf is scanned; it is consumed only on
      a match.
    - IRC over TLS (6697) is opaque and not in the default port set.
    - No debug log is emitted for skipped empty captures (unlike most
      detectors); logging is not imported.
"""

import re
from tscan_ng.session import _make_filter

# Finding types this detector emits; tscan_ng.resolve maps each to resolve().
FINDING_TYPES = ("irc_creds",)

# Common plaintext (non-TLS) IRC ports.
_IRC_PORTS: frozenset = frozenset({
    6667,  # Standard plaintext IRC
    6666,
    6668,
    6669,
})

# Maximum bytes of client_buf to scan per call. An IDENTIFY line is a single
# short line; well-behaved IRC clients also send NICK/USER/CAP lines first,
# so a generous-but-bounded window keeps this robust to a bit of preceding
# chatter. (resolve() searches all of server_buf for NickServ's reply.)
_MAX_SCAN_CLIENT = 4096

# Matches the client's NickServ identify line (client -> server):
#   PRIVMSG NickServ :IDENTIFY [nick] password
#   PRIVMSG NickServ@services.host :ID [nick] password
#   Group 1: optional first argument (the account nick) -- the optional group
#            is greedy, so with two words it captures the first as the nick.
#   Group 2: the password (the last word before the end of line, or the only
#            word). [^\r\n]* then swallows any further trailing text.
# Requires CRLF. Separators are spaces/tabs only ([ \t]+, never \s+): \s also
# matches CR/LF, which let the optional nick group run across the line break
# and swallow the first word of the NEXT line as the password when commands
# were pipelined in one segment (TODO.md #3).
_IDENTIFY_RE = re.compile(
    rb"^PRIVMSG[ \t]+NickServ(?:@\S+)?[ \t]+:(?:IDENTIFY|ID)[ \t]+(?:(\S+)[ \t]+)?(\S+)[^\r\n]*\r\n",
    re.IGNORECASE | re.MULTILINE,
)

# Matches any server NOTICE line: ":prefix NOTICE target :text\r\n".
#   Group 1: message prefix ("nick!user@host" or a server name),
#   Group 2: the trailing text. The sender is filtered to NickServ in code.
_NOTICE_RE = re.compile(
    rb"^:(\S+)\s+NOTICE\s+\S+\s+:([^\r\n]*)\r\n",
    re.IGNORECASE | re.MULTILINE,
)

# Common phrasings across widely-deployed services daemons (Atheme, Anope).
# Matched anywhere in the NOTICE text, case-insensitively. Not exhaustive:
# unrecognised wording (e.g. "You are now logged in as ...") is treated as
# "no verdict yet" rather than as a failure.
_ACCEPT_RE = re.compile(
    rb"password accepted|you are now (?:identified|recognized)|"
    rb"you are successfully identified",
    re.IGNORECASE,
)
_REJECT_RE = re.compile(
    rb"password incorrect|invalid password|access denied|authentication fail",
    re.IGNORECASE,
)


def _find_identify(data: bytes):
    """
    Scan *data* for a "PRIVMSG NickServ :IDENTIFY ..." (or "ID ...") line.

    Only the first matching line is returned (regex .search); later IDENTIFY
    lines are found on subsequent calls once this one has been consumed.

    Args:
        data: Raw bytes from the client stream buffer (bounded to
              _MAX_SCAN_CLIENT by the caller).

    Returns:
        (nick, password, end_offset) where nick is an empty string if the
        single-argument form was used, and end_offset points past the
        matched line (including its trailing \\r\\n). Returns
        (None, None, None) if no IDENTIFY line is present.
    """
    m = _IDENTIFY_RE.search(data)
    if not m:
        return None, None, None
    nick = m.group(1)
    password = m.group(2)
    nick_str = nick.decode("utf-8", "replace") if nick else ""
    password_str = password.decode("utf-8", "replace")
    return nick_str, password_str, m.end()


def _find_identify_response(data: bytes):
    """
    Scan *data* for a NickServ NOTICE accepting or rejecting an IDENTIFY.

    Args:
        data: Raw bytes from the server stream buffer.

    Returns:
        ("success" | "failed", end_offset) for the first NickServ NOTICE
        whose text matches a recognized accept/reject phrasing, where
        end_offset points past that NOTICE line. A NickServ NOTICE with
        unrecognized wording is skipped (not treated as either outcome) so
        scanning can continue to a later, recognizable reply. Returns
        (None, None) if no matching NOTICE is present yet.
    """
    for m in _NOTICE_RE.finditer(data):
        prefix = m.group(1)
        nick = prefix.split(b"!", 1)[0]
        if nick.lower() != b"nickserv":
            continue
        text = m.group(2)
        if _ACCEPT_RE.search(text):
            return "success", m.end()
        if _REJECT_RE.search(text):
            return "failed", m.end()
    return None, None


def _outcome(status: str) -> str:
    """
    Return the outcome string from a NickServ NOTICE.

    This is a thin passthrough -- _find_identify_response already returns
    a canonical outcome string. The function exists for symmetry with
    other detector modules.

    Args:
        status: Outcome string from _find_identify_response.

    Returns:
        The same string, unchanged.
    """
    return status


def detect_stream(session, ts: float) -> list:
    """
    Stream-aware IRC NickServ IDENTIFY credential detector.

    Scans session.client_buf for an IDENTIFY line and correlates it with a
    NickServ NOTICE in session.server_buf. Both buffers are consumed up to
    the end of the matched line/message on resolution to prevent
    re-detection.

    Args:
        session: Session object from session.SessionTable.
        ts:      Unix timestamp of the current packet.

    Returns:
        Always an empty list; findings are registered on the session as
        pending and emitted by tscan_ng.resolve once resolved.
    """
    if session.dport not in _IRC_PORTS and session.sport not in _IRC_PORTS:
        return []

    client_bytes = bytes(session.client_buf[:_MAX_SCAN_CLIENT])
    nick, password, req_end = _find_identify(client_bytes)

    if password is None:
        return []

    # Defensive: the regex's (\S+) cannot capture an empty password, so this
    # is currently unreachable.
    if not password:
        del session.client_buf[:req_end]
        return []

    creds_str = f"{nick}:{password}" if nick else f":{password}"

    base = {
        "type":       "irc_creds",
        "session_id": session.session_id,
        "src":        session.src,
        "dst":        session.dst,
        "sport":      session.sport,
        "dport":      session.dport,
        "nick":       nick,
        "creds":      creds_str,
        "filter":     _make_filter(session.src, session.dst,
                                   session.sport, session.dport),
    }

    del session.client_buf[:req_end]
    session.add_pending(base, ts_start=ts)
    return []


def resolve(p, session):
    """
    Match a pending NickServ IDENTIFY against NickServ's NOTICE (see tscan_ng.resolve).

    Args:
        p:       PendingFinding for a irc_creds finding.
        session: Session whose server_buf is searched.

    Returns:
        ({"status", "outcome"}, bytes to consume) or None if no reply yet.
    """
    outcome, rsp_end = _find_identify_response(bytes(session.server_buf))
    if outcome is None:
        return None
    return {"status": outcome, "outcome": _outcome(outcome)}, rsp_end
