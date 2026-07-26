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
    - Only the first NTLM auth attempt per TCP connection is tracked;
      SESSION_SETUP re-authentication later on the same connection is not
      handled specially (see _find_final_status).

Outcome semantics — a deliberate departure from every other detector here:
    Every other detector's "outcome" answers "was the submitted password
    correct". For SMB, the captured NTLMv2 hash is equally crackable
    (equally valuable) whether or not that specific logon attempt
    succeeded on that specific server — unlike a plaintext password, a
    "failed" capture is not a wasted one. This detector still maps outcome
    from the real SMB2 status code for consistency with the rest of the
    codebase (and because DiscordSink only alerts on outcome == "success"),
    but that means a captured hash tied to a failed logon will show up in
    the JSONL log with outcome="failed"/"server_error" and will NOT trigger
    a Discord alert even though the hash itself is just as usable. Worth
    revisiting (e.g. alerting on any complete capture regardless of
    outcome) if failed-but-crackable captures turn out to be common enough
    to matter in practice.

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
"""

import struct
from tscan_ng.session import _make_filter

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

_SMB2_MAGIC = b"\xfeSMB"
_SMB2_HEADER_LEN = 64
_CMD_SESSION_SETUP = 0x0001
_FLAG_SERVER_TO_REDIR = 0x00000001  # set on responses, clear on requests

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
        (header_start, is_response, command, status, payload_start):
            header_start:  Byte offset of the SMB2 magic (start of header).
            is_response:    True if SMB2_FLAGS_SERVER_TO_REDIR is set.
            command:        Command code (e.g. _CMD_SESSION_SETUP).
            status:         Header's Status field. Only meaningful when
                            is_response is True — for requests this is
                            ChannelSequence+Reserved or plain Reserved,
                            not a real status.
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
        status = struct.unpack_from("<I", data, idx + 8)[0]
        command = struct.unpack_from("<H", data, idx + 12)[0]
        flags = struct.unpack_from("<I", data, idx + 16)[0]
        is_response = bool(flags & _FLAG_SERVER_TO_REDIR)
        payload_start = idx + _SMB2_HEADER_LEN
        yield idx, is_response, command, status, payload_start
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
    if sec_len == 0 or buf_start < payload_start or buf_end > len(data):
        return None, None
    return data[buf_start:buf_end], buf_end


def _find_ntlm_challenge(data: bytes):
    """
    Scan *data* (server_buf) for a SESSION_SETUP response carrying an
    NTLMSSP CHALLENGE message, and extract its ServerChallenge.

    Args:
        data: Raw bytes from the server stream buffer (bounded to
              _MAX_SCAN_SERVER by the caller).

    Returns:
        8-byte ServerChallenge, or None if no CHALLENGE message is present.
    """
    for header_start, is_response, command, _status, payload_start in _iter_smb2_messages(data):
        if not is_response or command != _CMD_SESSION_SETUP:
            continue
        sec_buf, _buf_end = _extract_security_buffer(data, header_start, payload_start, True)
        if not sec_buf:
            continue
        idx = sec_buf.find(_NTLMSSP_SIG)
        if idx == -1 or idx + 32 > len(sec_buf):
            continue
        msg_type = struct.unpack_from("<I", sec_buf, idx + 8)[0]
        if msg_type != _NTLM_TYPE_CHALLENGE:
            continue
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
        (domain, username, workstation, nt_response, end_offset) if an
        AUTHENTICATE message is found, where nt_response is the raw
        NtChallengeResponse bytes (NTLMv2: 16-byte NTProofStr + variable
        blob) and end_offset points past this entire SMB2 message
        (header + SESSION_SETUP request structure + security buffer, which
        is always the structure's last field). Returns (None, None, None,
        None, None) if no AUTHENTICATE message is present.
    """
    for header_start, is_response, command, _status, payload_start in _iter_smb2_messages(data):
        if is_response or command != _CMD_SESSION_SETUP:
            continue
        sec_buf, buf_end = _extract_security_buffer(data, header_start, payload_start, False)
        if not sec_buf:
            continue
        idx = sec_buf.find(_NTLMSSP_SIG)
        if idx == -1 or idx + 64 > len(sec_buf):
            continue
        msg_type = struct.unpack_from("<I", sec_buf, idx + 8)[0]
        if msg_type != _NTLM_TYPE_AUTHENTICATE:
            continue
        msg = sec_buf[idx:]

        def field(off):
            length = struct.unpack_from("<H", msg, off)[0]
            offset = struct.unpack_from("<I", msg, off + 4)[0]
            if length == 0 or offset < 0 or offset + length > len(msg):
                return b""
            return bytes(msg[offset:offset + length])

        nt_response = field(20)
        domain_raw = field(28)
        user_raw = field(36)
        workstation_raw = field(44)

        neg_flags = struct.unpack_from("<I", msg, 60)[0]
        unicode = bool(neg_flags & 0x00000001)
        enc = "utf-16-le" if unicode else "latin-1"

        return (
            domain_raw.decode(enc, "replace"),
            user_raw.decode(enc, "replace"),
            workstation_raw.decode(enc, "replace"),
            nt_response,
            buf_end,
        )
    return None, None, None, None, None


def _find_final_status(data: bytes):
    """
    Scan *data* (server_buf) for the first SESSION_SETUP response whose
    status is not STATUS_MORE_PROCESSING_REQUIRED — i.e. the response to
    the AUTHENTICATE message, not the earlier CHALLENGE.

    Only the first NTLM auth attempt per connection is tracked (see module
    docstring); a connection that re-authenticates would have multiple
    CHALLENGE/final-status pairs, and this returns whichever non-more-
    processing status appears first without trying to match it to a
    specific AUTHENTICATE.

    Args:
        data: Raw bytes from the server stream buffer.

    Returns:
        (status, end_offset) if found, where end_offset points past this
        entire response message (including its trailing security buffer,
        if any — e.g. a final SPNEGO accept-completed token on success).
        Falls back to just past the fixed 8-byte response structure if
        there's no security buffer (sec_len == 0 is a normal, valid case
        for a straightforward failure response). Returns (None, None) if
        not yet present.
    """
    for header_start, is_response, command, status, payload_start in _iter_smb2_messages(data):
        if is_response and command == _CMD_SESSION_SETUP and status != _STATUS_MORE_PROCESSING_REQUIRED:
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


def detect(pkt: dict) -> list:
    """
    Per-packet interface — retained for API compatibility, always returns [].

    Args:
        pkt: Normalized packet dict from parsing.net.parse_basic.

    Returns:
        Empty list.
    """
    return []


def detect_stream(session, ts: float) -> list:
    """
    Stream-aware SMB2/3 NTLMv2 credential detector.

    Requires both a CHALLENGE already present in session.server_buf and an
    AUTHENTICATE present in session.client_buf before anything can be
    detected — unlike every other detector here, the "request" alone
    (AUTHENTICATE) is not self-contained; it only becomes a usable
    credential once combined with the ServerChallenge from the earlier
    CHALLENGE. If the CHALLENGE hasn't been seen yet, this returns
    immediately without consuming anything, so it naturally retries on the
    next packet once the CHALLENGE arrives.

    Args:
        session: Session object from session.SessionTable.
        ts:      Unix timestamp of the current packet.

    Returns:
        List of resolved finding dicts. A pending finding is registered on
        the session if the final SESSION_SETUP response has not yet arrived.
    """
    if session.dport not in _SMB_PORTS and session.sport not in _SMB_PORTS:
        return []

    challenge = _find_ntlm_challenge(bytes(session.server_buf[:_MAX_SCAN_SERVER]))
    if challenge is None:
        return []

    client_bytes = bytes(session.client_buf[:_MAX_SCAN_CLIENT])
    domain, username, workstation, nt_response, req_end = _find_ntlm_authenticate(client_bytes)
    if username is None:
        return []

    # NTLMv2: NTProofStr (16 bytes) + a variable-length "temp" blob. A bare
    # 24-byte response is classic NTLMv1, which this detector doesn't
    # extract (see module docstring).
    if not username or not nt_response or len(nt_response) <= 24:
        del session.client_buf[:req_end]
        return []

    ntproofstr_hex = nt_response[:16].hex()
    blob_hex = nt_response[16:].hex()
    server_challenge_hex = challenge.hex()
    creds_hash = f"{username}::{domain}:{server_challenge_hex}:{ntproofstr_hex}:{blob_hex}"

    base = {
        "type":        "smb_creds",
        "session_id":  session.session_id,
        "src":         session.src,
        "dst":         session.dst,
        "sport":       session.sport,
        "dport":       session.dport,
        "domain":      domain,
        "username":    username,
        "workstation": workstation,
        "creds":       creds_hash,
        "filter":      _make_filter(session.src, session.dst,
                                    session.sport, session.dport),
    }

    server_bytes = bytes(session.server_buf)
    status, rsp_end = _find_final_status(server_bytes)

    del session.client_buf[:req_end]

    if status is not None:
        # Final response already in server_buf — resolve immediately.
        del session.server_buf[:rsp_end]
        return [{
            **base,
            "ts_start": ts,
            "ts_end":   session.last_ts,
            "status":   str(status),
            "outcome":  _outcome(status),
        }]
    else:
        # Server has not sent the final response yet — register as pending.
        session.add_pending(base, ts_start=ts)
        return []
