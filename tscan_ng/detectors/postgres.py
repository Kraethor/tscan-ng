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
detectors/postgres.py - PostgreSQL cleartext password credential detector
for tscan-ng.

Stream-aware detector that operates on reassembled TCP streams. Parses the
PostgreSQL frontend/backend wire protocol (v3.0) startup/auth exchange:

    CLIENT -> SERVER: StartupMessage (no leading message-type byte, unlike
                       every other message in the protocol) -- carries
                       connection parameters as null-terminated key/value
                       pairs, including "user".
    SERVER -> CLIENT: AuthenticationCleartextPassword ('R', auth-code 3)
    CLIENT -> SERVER: PasswordMessage ('p') -- the raw cleartext password,
                       null-terminated. This is the actual plaintext
                       credential, same shape as FTP/Telnet's, just carried
                       inside this protocol's own PasswordMessage instead
                       of a dedicated command line.
    SERVER -> CLIENT: AuthenticationOk ('R', auth-code 0) on success, or
                       ErrorResponse ('E') on failure.

Every PostgreSQL protocol message except the initial StartupMessage is
framed as: 1-byte type + Int32 length (big-endian, includes itself but not
the type byte) + payload. This module locates messages by searching for
the type byte directly (matching every other detector's "search for the
marker" style) but additionally validates the message length wherever the
spec pins it to an exact value -- both AuthenticationCleartextPassword and
AuthenticationOk are always exactly 8 bytes of length (a bare 4-byte
auth-code, no further payload) -- which meaningfully cuts the false-positive
rate of a single-byte-magic search ('R' and 'p' are common bytes) beyond
what port-gating alone provides.

Explicit non-goals:
    - AuthenticationMD5Password (auth-code 5): the PasswordMessage in this
      flow carries "md5" + a salted double-MD5 hex digest, not a plaintext
      password. Structurally similar in spirit to SMB's NTLMv2 capture, but
      out of scope for this first pass -- flag for a future addition if
      MD5 auth turns out to still be common in practice.
    - AuthenticationSASL / SCRAM-SHA-256 (auth-code 10, the modern default
      in current PostgreSQL releases) is out of scope entirely -- SCRAM is
      specifically designed so the wire exchange never carries anything
      password-equivalent.
    - Kerberos/GSS/SSPI (auth-codes 2/7/9) are out of scope.
    - The StartupMessage's "user" parameter is extracted on a best-effort
      basis (see _find_startup_user) purely for context; failure to find
      it never blocks capturing the actual password.

Port handling:
    Gates on _POSTGRES_PORTS. Sessions on other ports are skipped
    immediately.
    5432 — PostgreSQL default

Finding type: "postgres_creds"
Finding extras:
    "user"  — the "user" connection parameter from the StartupMessage, if
              found (empty string otherwise).
    "creds" — formatted as "user:password", or ":password" if no user was
              found, for display consistency with every other detector
              that has an optional username component.
    "status" — "0" (AuthenticationOk), or the SQLSTATE of the ErrorResponse
              (e.g. "28P01" invalid_password), or "" if the error carried no
              SQLSTATE field.

Outcomes: success (AuthenticationOk), failed (ErrorResponse with SQLSTATE
28P01), server_error (any other ErrorResponse, e.g. 28000
invalid_authorization_specification or 3D000 invalid_catalog_name).

Message framing (v3.0): after the StartupMessage, every message is
Byte1(type) Int32(length) payload, where length counts itself and the payload
but not the type byte. Multi-byte integers are big-endian.

Known limitations:
    - The message search is still a raw single-byte find for 'p', but it now
      starts after the StartupMessage (and any SSLRequest before it) instead of
      at the front of client_buf, and a candidate 'p' whose length field is
      larger than the whole scan window is skipped rather than treated as a
      truncated message (TODO.md #1). See _find_password_message.
    - Only the first _MAX_SCAN_CLIENT/_MAX_SCAN_SERVER bytes of each buffer are
      examined. When the cleartext request is present but no PasswordMessage is
      in the client window, the scanned prefix is dropped (advance_scan_window(),
      TODO.md #16); if that cut reaches past the StartupMessage the username
      falls back to "" but the password is still captured.
    - TLS negotiated via SSLRequest ('S' response) makes the rest opaque.
"""

import struct
from tscan_ng.detectors.common import advance_scan_window, base_finding, on_ports

# Finding types this detector emits; tscan_ng.resolve maps each to resolve().
FINDING_TYPES = ("postgres_creds",)

# PostgreSQL default port.
_POSTGRES_PORTS: frozenset = frozenset({5432})

# Maximum bytes to scan per call. StartupMessage + PasswordMessage together
# are typically well under a kilobyte; server_bytes_bounded only needs to
# reach the initial AuthenticationCleartextPassword request, which arrives
# immediately after StartupMessage.
_MAX_SCAN_CLIENT = 4096
_MAX_SCAN_SERVER = 4096

# StartupMessage protocol version: major 3 in the high 16 bits, minor 0 in the
# low 16 bits (Int32 0x00030000).
_PG_PROTOCOL_VERSION_3_0 = 0x00030000

# 'R' (Authentication) message sub-codes, from the Int32 following the length.
_AUTH_TYPE_OK = 0
_AUTH_TYPE_CLEARTEXT = 3

# SQLSTATE for invalid_password (PostgreSQL Errors Appendix A.1).
_SQLSTATE_INVALID_PASSWORD = b"28P01"


def _find_startup_user(data: bytes) -> str:
    """
    Best-effort scan for the "user" parameter in a StartupMessage.

    StartupMessage layout: Int32 length, Int32 protocol version, then
    null-terminated key/value string pairs, ended by an extra NUL.

    Locates the message by searching for the literal 4-byte big-endian
    protocol version 0x00030000 and backing up 4 bytes for the presumed
    length field, rather than assuming the StartupMessage is the very
    first thing in the buffer -- a client that first sends an SSLRequest
    probe (a distinct, 8-byte "please confirm SSL support" message) would
    push the real StartupMessage a little further in, and this scan finds
    it either way.

    Args:
        data: Raw bytes from the client stream buffer.

    Returns:
        The decoded "user" value, or "" if not found (never raises; a
        missing username never blocks capturing the actual password).
    """
    version_bytes = struct.pack(">I", _PG_PROTOCOL_VERSION_3_0)
    idx = data.find(version_bytes)
    if idx < 4:
        return ""
    msg_start = idx - 4
    length = struct.unpack_from(">I", data, msg_start)[0]
    msg_end = msg_start + length
    if length < 8 or msg_end > len(data):
        return ""
    params = data[idx + 4:msg_end]
    # "user\0alice\0database\0db\0\0" splits into alternating key, value, ...
    # (plus trailing empty strings from the terminators).
    parts = params.split(b"\x00")
    for i in range(0, len(parts) - 1, 2):
        if parts[i].lower() == b"user":
            return parts[i + 1].decode("utf-8", "replace")
    return ""


def _find_cleartext_auth_request(data: bytes):
    """
    Scan *data* (server_buf) for an AuthenticationCleartextPassword message.

    Args:
        data: Raw bytes from the server stream buffer (bounded to
              _MAX_SCAN_SERVER by the caller).

    Wire form: 'R' Int32(8) Int32(3), i.e. 9 bytes. Any 'R' with a different
    length (or auth code) is skipped and the search continues. If fewer than
    9 bytes follow a candidate 'R', the search stops and reports "not present"
    (waits for more data) rather than trying later candidates.

    Returns:
        End offset past the matched message, or None if not present.
    """
    i = 0
    while True:
        idx = data.find(b"R", i)
        if idx == -1:
            return None
        if idx + 9 > len(data):
            return None  # Not enough bytes yet to confirm -- wait for more.
        length = struct.unpack_from(">I", data, idx + 1)[0]
        if length != 8:
            # AuthenticationCleartextPassword is always exactly an 8-byte
            # length (4-byte length field + 4-byte auth-code, no further
            # payload) -- anything else isn't this message.
            i = idx + 1
            continue
        auth_type = struct.unpack_from(">I", data, idx + 5)[0]
        if auth_type == _AUTH_TYPE_CLEARTEXT:
            return idx + 1 + length
        i = idx + 1


def _startup_end(data: bytes) -> int:
    """
    Return the offset just past the StartupMessage in *data*, or 0 if none.

    client_buf begins with the StartupMessage (optionally preceded by an
    8-byte SSLRequest), and that message is plain text that routinely
    contains the letter 'p' ("postgres", "application_name", "psql"). The
    PasswordMessage search must start after it, or those bytes are mistaken
    for a message type. Located the same way _find_startup_user does: search
    for the protocol-version bytes and back up 4 bytes for the length field.

    If the StartupMessage is present but not fully buffered yet, returns
    len(data) so the caller waits for more data rather than searching inside
    it.

    Args:
        data: Raw bytes from the client stream buffer.

    Returns:
        Offset of the first byte after the StartupMessage, len(data) if it is
        incomplete, or 0 if no StartupMessage is present in *data*.
    """
    idx = data.find(struct.pack(">I", _PG_PROTOCOL_VERSION_3_0))
    if idx < 4:
        return 0
    msg_start = idx - 4
    length = struct.unpack_from(">I", data, msg_start)[0]
    if length < 8:
        return 0
    msg_end = msg_start + length
    return msg_end if msg_end <= len(data) else len(data)


def _find_password_message(data: bytes):
    """
    Scan *data* (client_buf) for a PasswordMessage: 'p' Int32(length)
    password NUL.

    The search starts after the StartupMessage (see _startup_end) so its
    parameter text cannot be mistaken for a message. Within the remaining
    bytes, a candidate 'p' is handled by its length field:
        - below 5: cannot hold even an empty null-terminated string; skip.
        - larger than _MAX_SCAN_CLIENT: could never fit in the scan window,
          so it is not a real PasswordMessage; skip and keep looking.
        - larger than the bytes buffered so far (but within the window): a
          genuine message that is still arriving; stop and wait for more data.

    Args:
        data: Raw bytes from the client stream buffer (bounded to
              _MAX_SCAN_CLIENT by the caller).

    Returns:
        (password, end_offset) if found, where end_offset points past the
        matched message. Returns (None, None) if not present.
    """
    i = _startup_end(data)
    while True:
        idx = data.find(b"p", i)
        if idx == -1:
            return None, None
        if idx + 5 > len(data):
            return None, None
        length = struct.unpack_from(">I", data, idx + 1)[0]
        if length < 5 or length > _MAX_SCAN_CLIENT:
            i = idx + 1
            continue
        msg_end = idx + 1 + length
        if msg_end > len(data):
            return None, None  # Truncated -- wait for more data.
        payload = data[idx + 5:msg_end]
        password = payload.split(b"\x00", 1)[0]
        return password.decode("utf-8", "replace"), msg_end


def _extract_error_field(payload: bytes, field_type: bytes):
    """
    Extract one field from an ErrorResponse payload. Field type codes are
    single ASCII letters, e.g. b"S" severity, b"C" SQLSTATE, b"M" message.

    ErrorResponse payload is a sequence of (1-byte field type, null-
    terminated string) pairs, terminated by a final zero byte.

    Args:
        payload:    The ErrorResponse message payload (after the length field).
        field_type: Single-byte field type to look for (e.g. b"C" for SQLSTATE).

    Returns:
        The field's bytes value, or None if not present.
    """
    i = 0
    while i < len(payload):
        ft = payload[i:i + 1]
        if ft == b"\x00":
            break
        j = payload.find(b"\x00", i + 1)
        if j == -1:
            break
        if ft == field_type:
            return payload[i + 1:j]
        i = j + 1
    return None


def _find_auth_outcome(data):
    """
    Scan *data* (server_buf) for the final AuthenticationOk or ErrorResponse
    following a PasswordMessage.

    Candidates are the earliest 'R' or 'E' byte. 'R' must be an 8-byte-length
    AuthenticationOk (code 0) to count; other 'R' messages (including the
    earlier AuthenticationCleartextPassword) are skipped. The first 'E'
    candidate with a complete, plausible length (>= 4) is taken as an
    ErrorResponse. A candidate whose declared length runs past the buffered
    data stops the scan (treated as truncated). Called by resolve().

    Args:
        data: Server stream buffer (a bytes or bytearray; not copied).

    Returns:
        (outcome, status, end_offset) if found, where outcome is one of
        "success"/"failed"/"server_error" and status is a short string
        (SQLSTATE code for errors, "0" for success). Returns
        (None, None, None) if not yet present.
    """
    i = 0
    while True:
        idx_r = data.find(b"R", i)
        idx_e = data.find(b"E", i)
        candidates = [x for x in (idx_r, idx_e) if x != -1]
        if not candidates:
            return None, None, None
        idx = min(candidates)
        msg_type = data[idx:idx + 1]
        if idx + 5 > len(data):
            return None, None, None
        length = struct.unpack_from(">I", data, idx + 1)[0]
        if length < 4:
            i = idx + 1
            continue
        msg_end = idx + 1 + length
        if msg_end > len(data):
            return None, None, None  # Truncated -- wait for more data.

        if msg_type == b"R":
            if length != 8:
                i = idx + 1
                continue
            auth_type = struct.unpack_from(">I", data, idx + 5)[0]
            if auth_type == _AUTH_TYPE_OK:
                return "success", "0", msg_end
            i = idx + 1
            continue
        else:  # b"E" ErrorResponse
            payload = data[idx + 5:msg_end]
            sqlstate = _extract_error_field(payload, b"C")
            if sqlstate == _SQLSTATE_INVALID_PASSWORD:
                return "failed", sqlstate.decode("ascii", "replace"), msg_end
            return ("server_error",
                    sqlstate.decode("ascii", "replace") if sqlstate else "",
                    msg_end)


def detect_stream(session, ts: float) -> list:
    """
    Stream-aware PostgreSQL cleartext password credential detector.

    Requires an AuthenticationCleartextPassword request already present in
    session.server_buf before a PasswordMessage in session.client_buf is
    treated as a capture, mirroring smb.py's "server precondition, then
    client credential" shape rather than the simpler single
    request/response pair most other detectors use.

    The server's cleartext-password request is NOT consumed (only the final
    AuthenticationOk/ErrorResponse and everything before it is, on
    resolution), and the client's StartupMessage is not consumed either
    (only up to the end of the PasswordMessage). Every password is
    registered as pending; resolve() matches the outcome (on the same packet
    if it is already buffered). An empty password is consumed and ignored.

    Args:
        session: Session object from session.SessionTable.
        ts:      Unix timestamp of the current packet.

    Returns:
        Always an empty list; findings are registered on the session as
        pending and emitted by tscan_ng.resolve once resolved.
    """
    if not on_ports(session, _POSTGRES_PORTS):
        return []

    server_bytes_bounded = bytes(session.server_buf[:_MAX_SCAN_SERVER])
    auth_req_end = _find_cleartext_auth_request(server_bytes_bounded)
    if auth_req_end is None:
        return []

    client_bytes = bytes(session.client_buf[:_MAX_SCAN_CLIENT])
    password, req_end = _find_password_message(client_bytes)
    if password is None:
        # Server asked for a cleartext password but no PasswordMessage is in the
        # window yet. Drop scanned junk so a PasswordMessage behind it is reached
        # on a later packet (TODO.md #16). The protocol is byte-framed, so the cut
        # is byte-aligned and _find_password_message() resyncs. In the rare case
        # where >_MAX_SCAN_CLIENT bytes precede the password the StartupMessage
        # may be trimmed too, so the username falls back to "" (creds ":pw"); the
        # password itself is still captured.
        advance_scan_window(session, _MAX_SCAN_CLIENT, line_oriented=False)
        return []

    if not password:
        del session.client_buf[:req_end]
        return []

    # Best-effort: look for the StartupMessage in the same client window.
    user = _find_startup_user(client_bytes)
    creds_str = f"{user}:{password}" if user else f":{password}"

    base = base_finding(session, "postgres_creds", creds_str, user=user)

    del session.client_buf[:req_end]
    session.add_pending(base, ts_start=ts)
    return []


def resolve(p, session):
    """
    Match a pending PostgreSQL password against AuthenticationOk/ErrorResponse (see tscan_ng.resolve).

    Consumes server_buf up to the end of that message, which includes the
    earlier cleartext-password request.

    Args:
        p:       PendingFinding for a postgres_creds finding.
        session: Session whose server_buf is searched.

    Returns:
        ({"status", "outcome"}, bytes to consume) or None if no reply yet.
    """
    # Scan the server_buf bytearray directly, no per-packet copy (TODO.md #23).
    # The scan starts at 0 and skips the earlier cleartext-password request
    # (_find_auth_outcome); consume removes it along with the final message.
    outcome, status, rsp_end = _find_auth_outcome(session.server_buf)
    if outcome is None:
        return None
    return {"status": status, "outcome": outcome}, rsp_end
