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
"""

import struct
from tscan_ng.session import _make_filter

# PostgreSQL default port.
_POSTGRES_PORTS: frozenset = frozenset({5432})

# Maximum bytes to scan per call. StartupMessage + PasswordMessage together
# are typically well under a kilobyte; server_bytes_bounded only needs to
# reach the initial AuthenticationCleartextPassword request, which arrives
# immediately after StartupMessage.
_MAX_SCAN_CLIENT = 4096
_MAX_SCAN_SERVER = 4096

_PG_PROTOCOL_VERSION_3_0 = 0x00030000

_AUTH_TYPE_OK = 0
_AUTH_TYPE_CLEARTEXT = 3

# SQLSTATE for invalid_password (PostgreSQL Errors Appendix A.1).
_SQLSTATE_INVALID_PASSWORD = b"28P01"


def _find_startup_user(data: bytes) -> str:
    """
    Best-effort scan for the "user" parameter in a StartupMessage.

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


def _find_password_message(data: bytes):
    """
    Scan *data* (client_buf) for a PasswordMessage.

    Args:
        data: Raw bytes from the client stream buffer (bounded to
              _MAX_SCAN_CLIENT by the caller).

    Returns:
        (password, end_offset) if found, where end_offset points past the
        matched message. Returns (None, None) if not present.
    """
    i = 0
    while True:
        idx = data.find(b"p", i)
        if idx == -1:
            return None, None
        if idx + 5 > len(data):
            return None, None
        length = struct.unpack_from(">I", data, idx + 1)[0]
        if length < 5:
            # Too short to hold even an empty null-terminated string.
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
    Extract one field from an ErrorResponse payload.

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


def _find_auth_outcome(data: bytes):
    """
    Scan *data* (server_buf) for the final AuthenticationOk or ErrorResponse
    following a PasswordMessage.

    Args:
        data: Raw bytes from the server stream buffer.

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

    Args:
        session: Session object from session.SessionTable.
        ts:      Unix timestamp of the current packet.

    Returns:
        List of resolved finding dicts. A pending finding is registered on
        the session if the final AuthenticationOk/ErrorResponse has not yet
        arrived.
    """
    if session.dport not in _POSTGRES_PORTS and session.sport not in _POSTGRES_PORTS:
        return []

    server_bytes_bounded = bytes(session.server_buf[:_MAX_SCAN_SERVER])
    auth_req_end = _find_cleartext_auth_request(server_bytes_bounded)
    if auth_req_end is None:
        return []

    client_bytes = bytes(session.client_buf[:_MAX_SCAN_CLIENT])
    password, req_end = _find_password_message(client_bytes)
    if password is None:
        return []

    if not password:
        del session.client_buf[:req_end]
        return []

    user = _find_startup_user(client_bytes)
    creds_str = f"{user}:{password}" if user else f":{password}"

    base = {
        "type":       "postgres_creds",
        "session_id": session.session_id,
        "src":        session.src,
        "dst":        session.dst,
        "sport":      session.sport,
        "dport":      session.dport,
        "user":       user,
        "creds":      creds_str,
        "filter":     _make_filter(session.src, session.dst,
                                   session.sport, session.dport),
    }

    server_bytes_full = bytes(session.server_buf)
    outcome, status, rsp_end = _find_auth_outcome(server_bytes_full)

    del session.client_buf[:req_end]

    if outcome is not None:
        del session.server_buf[:rsp_end]
        return [{
            **base,
            "ts_start": ts,
            "ts_end":   session.last_ts,
            "status":   status,
            "outcome":  outcome,
        }]
    else:
        session.add_pending(base, ts_start=ts)
        return []
