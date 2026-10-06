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

    The scan for USER and PASS is bounded to _MAX_SCAN_CLIENT bytes so that a
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
    - Only the first _MAX_SCAN_CLIENT bytes of client_buf are scanned per call.
      When no USER is in that window the scanned prefix is dropped
      (advance_scan_window(), TODO.md #16), so a USER/PASS behind a backlog of
      other commands is reached on a later packet; a credential line longer than
      the window still cannot be matched.
    - FTPS/AUTH TLS sessions are encrypted after the AUTH TLS exchange and
      produce no findings; FTP data connections (passive/active ports) are
      never inspected.
"""

import logging
import re
from tscan_ng.detectors.common import advance_scan_window, base_finding, on_ports

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
_MAX_SCAN_CLIENT = 4096

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

    The scan is bounded to _MAX_SCAN_CLIENT bytes so that a large client
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
    if not on_ports(session, _FTP_PORTS):
        return []

    # Cap the scan to _MAX_SCAN_CLIENT bytes to bound per-packet CPU cost.
    client_bytes = bytes(session.client_buf[:_MAX_SCAN_CLIENT])

    user_match = _FTP_USER_RE.search(client_bytes)
    if not user_match:
        # No USER anchor in the window: drop scanned junk so a USER behind it is
        # reached on a later packet (TODO.md #16).
        advance_scan_window(session, _MAX_SCAN_CLIENT, line_oriented=True)
        return []

    # Search for PASS only within the remaining scan window after USER, so a
    # PASS that precedes the USER (stale/out-of-order data) is never paired.
    # user_match.end() is always within client_bytes, so this is safe.
    pass_match = _FTP_PASS_RE.search(client_bytes, user_match.end())
    if not pass_match:
        # USER is parked but PASS has not arrived (or is past the window). Drop
        # only the junk before USER (a line boundary) so the window can extend
        # to reach the PASS, keeping the USER anchor itself (TODO.md #16).
        if user_match.start() > 0:
            del session.client_buf[:user_match.start()]
        return []

    user   = user_match.group(1).decode("utf-8", "replace")
    passwd = pass_match.group(1).decode("utf-8", "replace")

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

    base = base_finding(session, "ftp_anonymous" if is_anonymous else "ftp_creds",
                        f"{user}:{passwd}")

    session.add_pending(base, ts_start=ts)

    # Consume USER and PASS from client buffer
    del session.client_buf[:pass_match.end()]

    return []


def resolve(p, session):
    """
    Match a pending FTP login against the server's reply (see tscan_ng.resolve).

    Takes the first 230/530/421 line at or after the finding's
    server_buf_floor (the server bytes already seen when the PASS was
    recorded), so a stale 530/421 from before this login is skipped (#14).

    Args:
        p:       PendingFinding for an ftp_creds / ftp_anonymous finding.
        session: Session whose server_buf is searched.

    Returns:
        ({"status", "outcome"}, bytes to consume) or None if no reply yet.
    """
    # Scan the server_buf bytearray directly from the floor (re accepts a
    # bytearray and a start pos), so nothing is copied per packet (TODO.md #23).
    for response in _FTP_RESPONSE_RE.finditer(session.server_buf, p.server_buf_floor):
        code = response.group(1)
        return ({"status": code.decode("utf-8", "replace"), "outcome": _outcome(code)},
                response.end())
    return None
