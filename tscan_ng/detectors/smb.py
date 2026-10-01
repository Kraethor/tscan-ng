"""
detectors/smb.py - SMB2/3 NTLMv2 credential detector for tscan-ng.

Stream-aware detector that operates on reassembled TCP streams. Unlike
every other credential detector in this package, SMB authentication never
puts a plaintext password on the wire — NTLM authentication is a
challenge/response exchange, and the artifact worth capturing is the
NTLMv2 challenge-response itself, in the exact format hashcat (-m 5600)
and John (--format=netntlmv2) expect for offline cracking. This is the
same technique tools like Responder use.

Exchange (MS-SMB2 §3.2.4.1.5 / MS-NLMP), all inside SESSION_SETUP
requests/responses:

    CLIENT -> SERVER: SESSION_SETUP request, NTLMSSP NEGOTIATE (type 1)
    SERVER -> CLIENT: SESSION_SETUP response, status=STATUS_MORE_PROCESSING_REQUIRED,
                       NTLMSSP CHALLENGE (type 2) — carries an 8-byte ServerChallenge
    CLIENT -> SERVER: SESSION_SETUP request, NTLMSSP AUTHENTICATE (type 3) — carries
                       domain/username/workstation and the NTLMv2 NTChallengeResponse
                       (16-byte NTProofStr + variable "temp" blob)
    SERVER -> CLIENT: SESSION_SETUP response, final status (SUCCESS / LOGON_FAILURE / ...)

The NEGOTIATE message carries no useful data and is ignored. The finding
requires correlating a CHALLENGE already seen in server_buf with an
AUTHENTICATE seen in client_buf, then optionally a *second*, later
server_buf response for the final outcome — a three-way correlation, unlike
every other detector here which is a single request/response pair. See
_find_ntlm_challenge / _find_ntlm_authenticate / _find_final_status.

Message framing: every SMB2 PDU on the wire (both port 445 direct-TCP and
port 139 NetBIOS-Session, once the underlying NBSS session is established)
is prefixed with a 4-byte NetBIOS Session Service header, then the SMB2
message itself starting with the 4-byte magic b"\\xfeSMB". Rather than
parse NBSS framing or SMB2 message chaining (NextCommand) explicitly, this
scans directly for the b"\\xfeSMB" magic at each position — the same
"search for the marker, ignore surrounding framing" approach ldap.py and
redis.py use for their own wire formats.

NTLMSSP messages (NEGOTIATE/CHALLENGE/AUTHENTICATE) are carried inside a
GSS-API SPNEGO ASN.1 wrapper in the SESSION_SETUP security buffer. Rather
than implement an ASN.1/SPNEGO parser, this searches directly for the
b"NTLMSSP\\x00" signature within the security buffer — the NTLMSSP message
bytes appear verbatim inside the SPNEGO OCTET STRING, unencoded, so a
substring search reliably locates it regardless of the wrapper.

Explicit non-goals:
    - SMB1/CIFS (b"\\xffSMB" magic) is not supported — modern Windows has
      shipped with SMB1 disabled by default for years, so it should not
      appear on general-purpose traffic in 2026. The scanner simply never
      matches SMB1 frames; it does not misparse them.
    - Kerberos authentication (the default on domain-joined Windows talking
      to a domain member/DC) is out of scope — only NTLM/NTLMSSP is parsed.
    - NTLMv1 (a bare 24-byte NTChallengeResponse, no extended blob) is not
      extracted, only NTLMv2 (NTProofStr + variable blob). NTLMv1 is
      deprecated and rare on modern clients.
    - Re-authentication on one connection is handled: each AUTHENTICATE is
      paired with the CHALLENGE and final response of its own SMB2 SessionId
      (TODO.md #25), so several SESSION_SETUP exchanges on a connection are
      tracked independently.

Outcome semantics — a deliberate departure from every other detector here:
    Every other detector's "outcome" answers "was the submitted password
    correct". For SMB, the captured NTLMv2 hash is equally crackable
    (equally valuable) whether or not that specific logon attempt
    succeeded on that specific server — unlike a plaintext password, a
    "failed" capture is not a wasted one. This detector still maps outcome
    from the real SMB2 status code for consistency with the rest of the
    codebase, but that means a captured hash tied to a failed logon shows
    up in the JSONL log with outcome="failed" and will NOT trigger a
    Discord alert (DiscordSink._SUPPRESSED_OUTCOMES suppresses "failed"
    for every detector, not just SMB) even though the hash itself is just
    as usable. outcome="server_error" is a separate case and DOES alert,
    same as every other detector — only "failed" is suppressed. Worth revisiting (e.g. alerting on any complete capture
    regardless of outcome) if failed-but-crackable captures turn out to be
    common enough to matter in practice.

Port handling:
    Gates on _SMB_PORTS. Sessions on other ports are skipped immediately.
    445 — SMB direct-TCP transport (the modern default)
    139 — NetBIOS Session Service (legacy; identical SMB2 framing once the
          underlying NBSS session is up)

Finding type: "smb_creds"
Finding extras:
    "domain"      — NTLM domain from the AUTHENTICATE message.
    "username"    — NTLM username from the AUTHENTICATE message.
    "workstation" — Client workstation name from the AUTHENTICATE message.
    "creds"       — The full NetNTLMv2 hash string in hashcat -m 5600 /
                    John netntlmv2 format:
                        username::domain:serverchallenge:ntproofstr:blob
                    Chosen deliberately so DiscordSink's naive
                    creds.split(":", 1)[0] still yields just the username,
                    same as every other detector, while the full field
                    remains directly hashcat/John-ready.
    "status"      — the SMB2 NTSTATUS of the final SESSION_SETUP response,
                    as a decimal string (e.g. "0" for success,
                    "3221225581" for 0xC000006D LOGON_FAILURE).

Correlation caveats:
    - The ServerChallenge is taken from the CHALLENGE whose SMB2 SessionId
      matches the AUTHENTICATE being processed, and the final status from
      the SESSION_SETUP response with that same SessionId and the
      AUTHENTICATE's MessageId (TODO.md #25), so a re-authentication on the
      same connection no longer pairs an AUTHENTICATE with a stale challenge
      or reads another exchange's status. The CHALLENGE must be within the
      first 4 KB of server_buf and is consumed only when the final status
      is.
    - Encrypted (SMB 3 transform header) or signed-and-sealed traffic hides
      later exchanges, but SESSION_SETUP itself is always in the clear.
"""

import struct
from tscan_ng.detectors.common import base_finding, on_ports

# Finding types this detector emits; tscan_ng.resolve maps each to resolve().
FINDING_TYPES = ("smb_creds",)

# Well-known SMB ports.
_SMB_PORTS: frozenset = frozenset({
    445,  # SMB direct-TCP transport
    139,  # NetBIOS Session Service
})

# Maximum bytes of each buffer to scan per call. SESSION_SETUP always
# happens immediately after TCP connect + SMB2 NEGOTIATE, well within these
# bounds for realistic traffic; keeps per-packet cost O(1) regardless of
# how much file-I/O traffic follows on the same long-lived SMB connection.
_MAX_SCAN_SERVER = 4096
_MAX_SCAN_CLIENT = 8192

# SMB2 packet header (MS-SMB2 §2.2.1.2), all fields little-endian:
#   0  ProtocolId (4)   = 0xFE 'S' 'M' 'B'
#   4  StructureSize(2) = 64
#   6  CreditCharge (2)
#   8  Status (4)        (ChannelSequence+Reserved in requests)
#   12 Command (2)
#   14 CreditRequest/Response (2)
#   16 Flags (4)
#   20 NextCommand (4), 24 MessageId (8), 32 ProcessId/Reserved (4),
#   36 TreeId (4), 40 SessionId (8), 48 Signature (16)
_SMB2_MAGIC = b"\xfeSMB"
_SMB2_HEADER_LEN = 64
_CMD_SESSION_SETUP = 0x0001
_FLAG_SERVER_TO_REDIR = 0x00000001  # set on responses, clear on requests

# NTSTATUS values. MORE_PROCESSING_REQUIRED is the *intermediate* status that
# accompanies the NTLM CHALLENGE; it is not a login verdict.
_STATUS_MORE_PROCESSING_REQUIRED = 0xC0000016
_STATUS_SUCCESS = 0x00000000
# SMB2 status codes that unambiguously mean "the credentials were rejected"
# (as opposed to some other server-side error). Anything else non-success
# falls through to "server_error".
_STATUS_FAILED_CODES = frozenset({
    0xC000006D,  # STATUS_LOGON_FAILURE
    0xC000006A,  # STATUS_WRONG_PASSWORD
    0xC0000064,  # STATUS_NO_SUCH_USER
    0xC0000234,  # STATUS_ACCOUNT_LOCKED_OUT
    0xC0000072,  # STATUS_ACCOUNT_DISABLED
    0xC0000193,  # STATUS_ACCOUNT_EXPIRED
    0xC0000071,  # STATUS_PASSWORD_EXPIRED
    0xC0000224,  # STATUS_PASSWORD_MUST_CHANGE
})

# NTLMSSP message header (MS-NLMP §2.2.1): 8-byte signature "NTLMSSP\0"
# followed by a 4-byte little-endian MessageType (1=NEGOTIATE, 2=CHALLENGE,
# 3=AUTHENTICATE).
_NTLMSSP_SIG = b"NTLMSSP\x00"
_NTLM_TYPE_CHALLENGE = 2
_NTLM_TYPE_AUTHENTICATE = 3


def _iter_smb2_messages(data: bytes):
    """
    Yield one tuple per SMB2 message found in *data*.

    Locates each message by searching for the b"\\xfeSMB" magic directly
    (see module docstring re: not parsing NBSS/NextCommand framing).

    Args:
        data: Raw bytes buffer to scan.

    Yields:
        (header_start, is_response, command, status, message_id,
         session_id, payload_start):
            header_start:  Byte offset of the SMB2 magic (start of header).
            is_response:    True if SMB2_FLAGS_SERVER_TO_REDIR is set.
            command:        Command code (e.g. _CMD_SESSION_SETUP).
            status:         Header's Status field. Only meaningful when
                            is_response is True — for requests this is
                            ChannelSequence+Reserved or plain Reserved,
                            not a real status.
            message_id:     Header's MessageId (offset 24); pairs a request
                            with its response within a connection.
            session_id:     Header's SessionId (offset 40). The server
                            assigns it in the CHALLENGE response and the
                            client echoes it, so one NTLM exchange's
                            CHALLENGE, AUTHENTICATE and final response all
                            share it (TODO.md #25).
            payload_start:  Byte offset immediately after the fixed header,
                            where the command-specific structure begins.
    """
    i = 0
    while True:
        idx = data.find(_SMB2_MAGIC, i)
        if idx == -1:
            return
        if idx + _SMB2_HEADER_LEN > len(data):
            return  # Header truncated — wait for more data.
        # Field offsets are from the header layout above the constants.
        status = struct.unpack_from("<I", data, idx + 8)[0]
        command = struct.unpack_from("<H", data, idx + 12)[0]
        flags = struct.unpack_from("<I", data, idx + 16)[0]
        is_response = bool(flags & _FLAG_SERVER_TO_REDIR)
        message_id = struct.unpack_from("<Q", data, idx + 24)[0]
        session_id = struct.unpack_from("<Q", data, idx + 40)[0]
        payload_start = idx + _SMB2_HEADER_LEN
        yield idx, is_response, command, status, message_id, session_id, payload_start
        i = idx + 4  # Advance past this magic; next find() picks up the rest.


def _extract_security_buffer(data: bytes, header_start: int,
                             payload_start: int, is_response: bool):
    """
    Extract the SESSION_SETUP security buffer (GSS-API/SPNEGO token) bytes.

    Field layout differs between request and response (MS-SMB2 §2.2.5/2.2.6);
    SecurityBufferOffset in both is relative to header_start, not payload_start.

    Args:
        data:          The buffer containing the message.
        header_start:  Byte offset of this message's SMB2 header.
        payload_start: Byte offset of the command-specific structure.
        is_response:   True for a SESSION_SETUP response, False for a request.

    Returns:
        (security_buffer_bytes, buf_end) where buf_end is the absolute byte
        offset immediately past the security buffer — i.e. the end of this
        entire SMB2 message, since the security buffer is always its last
        field. Returns (None, None) if the structure is truncated, empty,
        or malformed.
    """
    # Offsets below are relative to payload_start (the end of the 64-byte
    # header). Response (MS-SMB2 §2.2.6): StructureSize(2) SessionFlags(2)
    # SecurityBufferOffset(2) SecurityBufferLength(2). Request (§2.2.5):
    # StructureSize(2) Flags(1) SecurityMode(1) Capabilities(4) Channel(4)
    # SecurityBufferOffset(2) SecurityBufferLength(2) PreviousSessionId(8).
    if is_response:
        fixed_len = 8  # StructureSize, SessionFlags, SecBufOffset, SecBufLen
        off_field, len_field = 4, 6
    else:
        fixed_len = 16  # up through SecurityBufferOffset/Length
        off_field, len_field = 12, 14
    if payload_start + fixed_len > len(data):
        return None, None
    sec_off = struct.unpack_from("<H", data, payload_start + off_field)[0]
    sec_len = struct.unpack_from("<H", data, payload_start + len_field)[0]
    buf_start = header_start + sec_off
    buf_end = buf_start + sec_len
    # Reject empty buffers, offsets pointing back into the header, and buffers
    # that extend past the data received so far (truncated: wait for more).
    if sec_len == 0 or buf_start < payload_start or buf_end > len(data):
        return None, None
    return data[buf_start:buf_end], buf_end


def _find_ntlm_challenge(data: bytes, session_id: int):
    """
    Scan *data* (server_buf) for the SESSION_SETUP response of session
    *session_id* carrying an NTLMSSP CHALLENGE, and extract its
    ServerChallenge.

    Matching the SessionId (rather than taking the first CHALLENGE in the
    buffer) pairs the challenge with the AUTHENTICATE of the same exchange,
    so a second authentication over one connection is not hashed against
    the first exchange's challenge (TODO.md #25).

    Args:
        data:       Raw bytes from the server stream buffer (bounded to
                    _MAX_SCAN_SERVER by the caller).
        session_id: SMB2 SessionId of the AUTHENTICATE to pair with.

    Returns:
        8-byte ServerChallenge, or None if no matching CHALLENGE is present.
    """
    for header_start, is_response, command, _status, _msg_id, sess_id, payload_start in _iter_smb2_messages(data):
        if not is_response or command != _CMD_SESSION_SETUP or sess_id != session_id:
            continue
        sec_buf, _buf_end = _extract_security_buffer(data, header_start, payload_start, True)
        if not sec_buf:
            continue
        # The NTLMSSP message sits verbatim inside the SPNEGO wrapper.
        idx = sec_buf.find(_NTLMSSP_SIG)
        if idx == -1 or idx + 32 > len(sec_buf):
            continue
        msg_type = struct.unpack_from("<I", sec_buf, idx + 8)[0]
        if msg_type != _NTLM_TYPE_CHALLENGE:
            continue
        # CHALLENGE layout (MS-NLMP §2.2.1.2): signature(8) type(4)
        # TargetNameFields(8) NegotiateFlags(4) ServerChallenge(8) ...
        # so the 8-byte challenge is at message offset 24.
        return bytes(sec_buf[idx + 24:idx + 32])  # ServerChallenge, fixed offset
    return None


def _find_ntlm_authenticate(data: bytes):
    """
    Scan *data* (client_buf) for a SESSION_SETUP request carrying an
    NTLMSSP AUTHENTICATE message, and extract its credential fields.

    Args:
        data: Raw bytes from the client stream buffer (bounded to
              _MAX_SCAN_CLIENT by the caller).

    Returns:
        (domain, username, workstation, nt_response, session_id,
        message_id, end_offset) if an
        AUTHENTICATE message is found, where nt_response is the raw
        NtChallengeResponse bytes (NTLMv2: 16-byte NTProofStr + variable
        blob) and end_offset points past this entire SMB2 message
        (header + SESSION_SETUP request structure + security buffer, which
        is always the structure's last field); session_id/message_id come
        from this request's SMB2 header (TODO.md #25). Returns a 7-tuple of
        None if no AUTHENTICATE message is present.
    """
    for header_start, is_response, command, _status, msg_id, sess_id, payload_start in _iter_smb2_messages(data):
        if is_response or command != _CMD_SESSION_SETUP:
            continue
        sec_buf, buf_end = _extract_security_buffer(data, header_start, payload_start, False)
        if not sec_buf:
            continue
        idx = sec_buf.find(_NTLMSSP_SIG)
        # 64 = size of the fixed AUTHENTICATE header up to NegotiateFlags
        # (through offset 63); NEGOTIATE (type 1) is skipped by the type test.
        if idx == -1 or idx + 64 > len(sec_buf):
            continue
        msg_type = struct.unpack_from("<I", sec_buf, idx + 8)[0]
        if msg_type != _NTLM_TYPE_AUTHENTICATE:
            continue
        msg = sec_buf[idx:]

        def field(off):
            """Read one NTLM AUTHENTICATE field: a (length, max_length,
            offset) triplet at *off*, where length/offset describe the
            actual field bytes located at msg[offset:offset+length]."""
            length = struct.unpack_from("<H", msg, off)[0]
            offset = struct.unpack_from("<I", msg, off + 4)[0]
            # (offset is an unsigned 32-bit value, so "offset < 0" can never be
            # true; the upper-bound test is the effective bounds check.)
            if length == 0 or offset < 0 or offset + length > len(msg):
                return b""
            return bytes(msg[offset:offset + length])

        # AUTHENTICATE fixed header (MS-NLMP §2.2.1.3), each "Fields" entry is
        # Len(2) MaxLen(2) BufferOffset(4), offsets relative to the message:
        #   12 LmChallengeResponse (unused)   20 NtChallengeResponse
        #   28 DomainName                     36 UserName
        #   44 Workstation                    52 EncryptedRandomSessionKey
        #   60 NegotiateFlags
        nt_response = field(20)
        domain_raw = field(28)
        user_raw = field(36)
        workstation_raw = field(44)

        # NTLMSSP_NEGOTIATE_UNICODE (bit 0) selects UTF-16LE vs OEM (the code
        # page is unknown here, so latin-1 is used as a byte-preserving guess).
        neg_flags = struct.unpack_from("<I", msg, 60)[0]
        unicode = bool(neg_flags & 0x00000001)
        enc = "utf-16-le" if unicode else "latin-1"

        return (
            domain_raw.decode(enc, "replace"),
            user_raw.decode(enc, "replace"),
            workstation_raw.decode(enc, "replace"),
            nt_response,
            sess_id,
            msg_id,
            buf_end,
        )
    return None, None, None, None, None, None, None


def _find_final_status(data: bytes, session_id: int, message_id: int):
    """
    Scan *data* (server_buf) for the SESSION_SETUP response that answers the
    AUTHENTICATE of (session_id, message_id): same SessionId and MessageId,
    and a status other than STATUS_MORE_PROCESSING_REQUIRED (that status is
    the CHALLENGE, not the final reply).

    Matching both ids (rather than the first non-more-processing response)
    keeps a second authentication over the same connection from reading the
    first exchange's final status (TODO.md #25).

    Args:
        data:       Raw bytes from the server stream buffer.
        session_id: SMB2 SessionId of the AUTHENTICATE being resolved.
        message_id: SMB2 MessageId of the AUTHENTICATE being resolved.

    Returns:
        (status, end_offset) if found, where end_offset points past this
        entire response message (including its trailing security buffer,
        if any — e.g. a final SPNEGO accept-completed token on success).
        Falls back to just past the fixed 8-byte response structure if
        there's no security buffer (sec_len == 0 is a normal, valid case
        for a straightforward failure response). Returns (None, None) if
        not yet present.
    """
    for header_start, is_response, command, status, msg_id, sess_id, payload_start in _iter_smb2_messages(data):
        if (is_response and command == _CMD_SESSION_SETUP
                and sess_id == session_id and msg_id == message_id
                and status != _STATUS_MORE_PROCESSING_REQUIRED):
            _sec_buf, buf_end = _extract_security_buffer(data, header_start, payload_start, True)
            return status, (buf_end if buf_end is not None else payload_start + 8)
    return None, None


def _outcome(status: int) -> str:
    """
    Map an SMB2 SESSION_SETUP final status code to a finding outcome string.

    Args:
        status: Integer NTSTATUS value from the SMB2 header's Status field.

    Returns:
        One of: "success", "failed", "server_error".
    """
    if status == _STATUS_SUCCESS:
        return "success"
    if status in _STATUS_FAILED_CODES:
        return "failed"
    return "server_error"


def detect_stream(session, ts: float) -> list:
    """
    Stream-aware SMB2/3 NTLMv2 credential detector.

    Only the first 4 KB of server_buf and 8 KB of client_buf are examined for
    the CHALLENGE and AUTHENTICATE respectively.

    Requires an AUTHENTICATE in session.client_buf and the CHALLENGE of its
    own SMB2 SessionId in session.server_buf before anything can be detected
    — unlike every other detector here, the "request" alone (AUTHENTICATE)
    is not self-contained; it only becomes a usable credential once combined
    with that exchange's ServerChallenge (TODO.md #25). If the matching
    CHALLENGE hasn't been seen yet, this returns without consuming the
    AUTHENTICATE, so it naturally retries once the CHALLENGE arrives.

    Args:
        session: Session object from session.SessionTable.
        ts:      Unix timestamp of the current packet.

    Returns:
        Always an empty list; findings are registered on the session as
        pending and emitted by tscan_ng.resolve once resolved.
    """
    if not on_ports(session, _SMB_PORTS):
        return []

    client_bytes = bytes(session.client_buf[:_MAX_SCAN_CLIENT])
    (domain, username, workstation, nt_response,
     session_id, message_id, req_end) = _find_ntlm_authenticate(client_bytes)
    if username is None:
        return []

    # NTLMv2: NTProofStr (16 bytes) + a variable-length "temp" blob. A bare
    # 24-byte response is classic NTLMv1, which this detector doesn't
    # extract (see module docstring).
    if not username or not nt_response or len(nt_response) <= 24:
        # Anonymous/NULL-session or NTLMv1 AUTHENTICATE: consume it so it is
        # not re-parsed on every subsequent packet, and emit nothing.
        del session.client_buf[:req_end]
        return []

    # Pair with the CHALLENGE of this AUTHENTICATE's own SMB2 session, not
    # the first one in the buffer (TODO.md #25). If it has not been seen
    # yet, leave the AUTHENTICATE in client_buf and retry once it arrives.
    challenge = _find_ntlm_challenge(
        bytes(session.server_buf[:_MAX_SCAN_SERVER]), session_id)
    if challenge is None:
        return []

    # hashcat -m 5600 / John netntlmv2 line format:
    #   USER::DOMAIN:ServerChallenge:NTProofStr:blob   (all hex except names)
    ntproofstr_hex = nt_response[:16].hex()
    blob_hex = nt_response[16:].hex()
    server_challenge_hex = challenge.hex()
    creds_hash = f"{username}::{domain}:{server_challenge_hex}:{ntproofstr_hex}:{blob_hex}"

    base = base_finding(session, "smb_creds", creds_hash,
                        domain=domain,
                        username=username,
                        workstation=workstation)

    # _session_id/_message_id (private, stripped before output) let
    # resolve() match the final response of this exact exchange.
    del session.client_buf[:req_end]
    session.add_pending({**base, "_session_id": session_id, "_message_id": message_id},
                        ts_start=ts)
    return []


def resolve(p, session):
    """
    Match a pending NTLM SESSION_SETUP against its final response (see tscan_ng.resolve).

    Consumes server_buf up to the end of that response, which includes the
    earlier CHALLENGE.

    Args:
        p:       PendingFinding for a smb_creds finding.
        session: Session whose server_buf is searched.

    Returns:
        ({"status", "outcome"}, bytes to consume) or None if no reply yet.
    """
    status, rsp_end = _find_final_status(
        bytes(session.server_buf),
        p.finding.get("_session_id"), p.finding.get("_message_id"))
    if status is None:
        return None
    return {"status": str(status), "outcome": _outcome(status)}, rsp_end
