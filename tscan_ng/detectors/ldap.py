"""
detectors/ldap.py - LDAP credential detector for tscan-ng.

Stream-aware detector that operates on reassembled TCP streams. Parses
LDAPMessage / BindRequest frames from the client buffer and correlates
them with BindResponse result codes from the server buffer.

Handles LDAP simple-bind authentication only (RFC 4511 §4.2):

    CLIENT: LDAPMessage { messageID, BindRequest { version, name=<DN>, simple=<pw> } }
    SERVER: LDAPMessage { messageID, BindResponse { resultCode, matchedDN, ... } }

Result codes (RFC 4511 §4.1.9):
    0  (success)             → outcome "success"
    49 (invalidCredentials)  → outcome "failed"
    other                    → outcome "server_error"

SASL binds (multi-step challenge/response) are not supported.
Anonymous binds (empty DN and password) are silently skipped.
TLS-wrapped sessions (LDAPS on 636, GC+TLS on 3269) are out of scope.

Port handling:
    Gates on _LDAP_PORTS. Sessions on other ports are skipped immediately.
    389  — standard LDAP (RFC 4511)
    3268 — Microsoft Global Catalog (also cleartext LDAP)

Finding type: "ldap_creds"
Finding extras:
    "dn" — raw Distinguished Name string from the BindRequest name field.
    "creds" — formatted as "dn:password" for display consistency.
"""

import logging
from tscan_ng.session import _make_filter

# Well-known cleartext LDAP ports.
# Sessions whose dport or sport is in this set are scanned for credentials.
_LDAP_PORTS: frozenset = frozenset({
    389,   # LDAP (RFC 4511)
    3268,  # Microsoft Global Catalog (also cleartext LDAP)
})

# Maximum bytes of the client buffer to scan per call.
# LDAP BindRequests are modest in size; 8 KB covers any realistic auth exchange.
_MAX_SCAN = 8192

# BER/ASN.1 tag constants used in LDAPMessage (RFC 4511).
_TAG_INTEGER  = 0x02   # Universal primitive: INTEGER
_TAG_ENUM     = 0x0A   # Universal primitive: ENUMERATED (resultCode)
_TAG_OCTET    = 0x04   # Universal primitive: OCTET STRING (DN, password)
_TAG_SEQUENCE = 0x30   # Universal constructed: SEQUENCE (LDAPMessage wrapper)
_TAG_BIND_REQ = 0x60   # Application[0] constructed: BindRequest
_TAG_BIND_RSP = 0x61   # Application[1] constructed: BindResponse
_TAG_SIMPLE   = 0x80   # Context[0] primitive: simple authentication password


def _parse_ber_len(data: bytes, offset: int):
    """
    Parse a BER-encoded length value starting at *offset* in *data*.

    Supports short form (single byte, high bit clear) and definite long form
    (high bit set; low 7 bits give the count of subsequent length bytes).
    Indefinite form (first byte == 0x80) is not used by LDAP and is treated
    as an error.

    Args:
        data:   Raw bytes buffer containing the BER stream.
        offset: Byte position of the first length byte.

    Returns:
        (length, new_offset) where length is the decoded integer length and
        new_offset points to the first byte of the value field.
        Returns (None, None) on any error or if data is truncated.
    """
    if offset >= len(data):
        return None, None
    first = data[offset]
    offset += 1
    if first & 0x80 == 0:
        # Short form: the byte itself is the length.
        return first, offset
    num_bytes = first & 0x7F
    if num_bytes == 0 or num_bytes > 4 or offset + num_bytes > len(data):
        # Indefinite form (num_bytes==0), oversized, or truncated.
        return None, None
    length = 0
    for _ in range(num_bytes):
        length = (length << 8) | data[offset]
        offset += 1
    return length, offset


def _parse_ber_tlv(data: bytes, offset: int):
    """
    Parse one BER TLV (tag-length-value) triple at *offset* in *data*.

    Multi-byte tags (low 5 bits all set in the first tag byte, i.e. 0x1F)
    are not supported — standard LDAP v3 messages do not use them.

    Args:
        data:   Raw bytes buffer containing the BER stream.
        offset: Byte position of the tag byte.

    Returns:
        (tag, value_bytes, new_offset) on success, where value_bytes is a
        bytes slice of the TLV value field and new_offset points past the end
        of this TLV.  Returns (None, None, None) on any error or if the data
        is truncated (value extends beyond available bytes).
    """
    if offset >= len(data):
        return None, None, None
    tag = data[offset]
    offset += 1
    # Multi-byte tags are not used in standard LDAPv3 messages.
    if (tag & 0x1F) == 0x1F:
        return None, None, None
    length, offset = _parse_ber_len(data, offset)
    if length is None:
        return None, None, None
    if offset + length > len(data):
        # Value not yet fully received — wait for more data.
        return None, None, None
    value = data[offset:offset + length]
    return tag, value, offset + length


def _find_bind_request(data: bytes):
    """
    Scan *data* for the first complete LDAPMessage containing a simple BindRequest.

    Expected structure (simplified from RFC 4511):
        SEQUENCE {                        -- LDAPMessage
            messageID  INTEGER,
            BindRequest [APPLICATION 0] {
                version        INTEGER,
                name           OCTET STRING,  -- Distinguished Name
                authentication [0] OCTET STRING  -- simple password
            }
        }

    SASL binds carry a different authentication tag and are skipped silently.
    Anonymous binds (both name and password empty) are also skipped since
    they carry no exploitable credentials.

    Args:
        data: Raw bytes from the client stream buffer (bounded to _MAX_SCAN).

    Returns:
        (dn, password, end_offset) if a simple BindRequest is found, where
        end_offset points past the last byte of the matched LDAPMessage.
        Returns (None, None, None) if no valid simple BindRequest is present.
    """
    i = 0
    while i < len(data):
        # LDAPMessage always starts with a SEQUENCE tag.
        if data[i] != _TAG_SEQUENCE:
            i += 1
            continue

        outer_tag, msg_value, msg_end = _parse_ber_tlv(data, i)
        if outer_tag is None:
            # Data is truncated — wait for more bytes.
            break

        # Parse the first field: messageID INTEGER.
        off = 0
        id_tag, _id_val, off = _parse_ber_tlv(msg_value, off)
        if id_tag != _TAG_INTEGER:
            i += 1
            continue

        # Parse the second field: BindRequest APPLICATION[0].
        req_tag, req_value, off = _parse_ber_tlv(msg_value, off)
        if req_tag != _TAG_BIND_REQ:
            # Not a BindRequest (could be any other LDAP operation) — skip.
            i = msg_end
            continue

        # Inside the BindRequest: version, name, authentication.
        roff = 0

        # version INTEGER (always 3 for LDAPv3; we accept any value).
        v_tag, _v_val, roff = _parse_ber_tlv(req_value, roff)
        if v_tag != _TAG_INTEGER:
            i += 1
            continue

        # name OCTET STRING — the Distinguished Name of the binding entity.
        n_tag, n_val, roff = _parse_ber_tlv(req_value, roff)
        if n_tag != _TAG_OCTET:
            i += 1
            continue

        # authentication CHOICE — expect [0] (simple password).
        a_tag, a_val, roff = _parse_ber_tlv(req_value, roff)
        if a_tag != _TAG_SIMPLE:
            # SASL or other mechanism — not supported; skip this message.
            i = msg_end
            continue

        dn       = (n_val or b"").decode("utf-8", "replace")
        password = (a_val or b"").decode("utf-8", "replace")

        # Skip anonymous binds (RFC 4511 §4.2): empty DN and empty password.
        if not dn and not password:
            i = msg_end
            continue

        return dn, password, msg_end

    return None, None, None


def _find_bind_response(data: bytes):
    """
    Scan *data* for the first complete LDAPMessage containing a BindResponse.

    Expected structure (simplified from RFC 4511):
        SEQUENCE {                          -- LDAPMessage
            messageID  INTEGER,
            BindResponse [APPLICATION 1] {
                resultCode ENUMERATED,      -- 0=success, 49=invalidCredentials
                matchedDN  OCTET STRING,
                ...
            }
        }

    Args:
        data: Raw bytes from the server stream buffer.

    Returns:
        (result_code, end_offset) if a BindResponse is found, where result_code
        is the integer LDAP result code and end_offset points past the last byte
        of the matched LDAPMessage.
        Returns (None, None) if no valid BindResponse is present.
    """
    i = 0
    while i < len(data):
        if data[i] != _TAG_SEQUENCE:
            i += 1
            continue

        outer_tag, msg_value, msg_end = _parse_ber_tlv(data, i)
        if outer_tag is None:
            # Truncated — wait for more bytes.
            break

        off = 0
        id_tag, _id_val, off = _parse_ber_tlv(msg_value, off)
        if id_tag != _TAG_INTEGER:
            i += 1
            continue

        rsp_tag, rsp_value, off = _parse_ber_tlv(msg_value, off)
        if rsp_tag != _TAG_BIND_RSP:
            # Not a BindResponse — skip to next message.
            i = msg_end
            continue

        # First field inside BindResponse is always the resultCode ENUMERATED.
        roff = 0
        rc_tag, rc_val, roff = _parse_ber_tlv(rsp_value, roff)
        if rc_tag != _TAG_ENUM or not rc_val:
            i += 1
            continue

        result_code = rc_val[0]
        return result_code, msg_end

    return None, None


def _outcome(result_code: int) -> str:
    """
    Map an LDAP BindResponse result code to a finding outcome string.

    Result codes are defined in RFC 4511 §4.1.9. Only the two codes
    that are directly relevant to authentication are mapped to specific
    outcomes; all others fall through to "server_error".

    Args:
        result_code: Integer result code from the BindResponse ENUMERATED field.

    Returns:
        One of: "success", "failed", "server_error".
    """
    if result_code == 0:
        return "success"
    if result_code == 49:
        # invalidCredentials — the server rejected the supplied DN/password.
        return "failed"
    return "server_error"


def detect_stream(session, ts: float) -> list:
    """
    Stream-aware LDAP simple-bind credential detector.

    Scans session.client_buf for a complete LDAPMessage containing a simple
    BindRequest, then looks for the corresponding BindResponse in
    session.server_buf.  Both buffers are consumed up to the end of the
    matched message on resolution to prevent re-detection.

    Only simple-bind (password as plaintext in the [0] CHOICE) is detected.
    SASL, anonymous, and TLS-wrapped sessions are out of scope.

    The scan is bounded to _MAX_SCAN bytes per call to keep per-packet CPU
    cost O(1) regardless of buffer depth.

    Args:
        session: Session object from session.SessionTable.
        ts:      Unix timestamp of the current packet.

    Returns:
        List of resolved finding dicts. A pending finding is registered on
        the session if the BindResponse has not yet arrived.
    """
    # Gate: only inspect sessions on known LDAP ports.
    if session.dport not in _LDAP_PORTS and session.sport not in _LDAP_PORTS:
        return []

    # Bound the scan to avoid O(n) work on very deep buffers.
    client_bytes = bytes(session.client_buf[:_MAX_SCAN])
    dn, password, req_end = _find_bind_request(client_bytes)

    if dn is None:
        return []

    if not password:
        # Non-empty DN with empty password is an unauthenticated bind
        # (RFC 4511 §4.2).  Skip — no exploitable credential to record.
        logging.debug(
            "ldap: session %s: unauthenticated bind (non-empty DN, empty password)"
            " — skipping",
            session.session_id)
        del session.client_buf[:req_end]
        return []

    base = {
        "type":       "ldap_creds",
        "session_id": session.session_id,
        "src":        session.src,
        "dst":        session.dst,
        "sport":      session.sport,
        "dport":      session.dport,
        "dn":         dn,
        "creds":      f"{dn}:{password}",
        "filter":     _make_filter(session.src, session.dst,
                                   session.sport, session.dport),
    }

    server_bytes = bytes(session.server_buf)
    result_code, rsp_end = _find_bind_response(server_bytes)

    if result_code is not None:
        # BindResponse already in server_buf — resolve immediately.
        outcome = _outcome(result_code)
        del session.server_buf[:rsp_end]
        del session.client_buf[:req_end]
        return [{
            **base,
            "ts_start": ts,
            "ts_end":   session.last_ts,
            "status":   str(result_code),
            "outcome":  outcome,
        }]
    else:
        # Server has not responded yet — register as pending.
        session.add_pending(base, ts_start=ts)
        del session.client_buf[:req_end]
        return []
