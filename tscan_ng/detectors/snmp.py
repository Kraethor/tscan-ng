"""
detectors/snmp.py - SNMPv1/v2c community string detector for tscan-ng.

Stream-aware detector, but unlike every other detector in this package the
underlying transport is UDP, not TCP -- SNMP is virtually always deployed
over UDP in practice (RFC 3430's TCP transport mapping is not used in the
wild). This is the first UDP-carried protocol tscan-ng supports; see
capture._build_port_filter for the BPF-level change that lets SNMP traffic
reach userspace at all (previously the filter was unconditionally
"tcp and (...)").

Nothing else needed to change for UDP to work: parsing.net.parse_basic()
already parses UDP payloads (it just wasn't consumed anywhere), and
Session/SessionTable's flow model is protocol-agnostic -- a UDP "session"
here is just packets sharing a 4-tuple, exactly like TCP, with no SYN/FIN
concept required by any of this pipeline's logic. Each captured UDP
datagram is exactly one complete SNMP message (IP fragmentation of a
message this small is not handled).

Message format (RFC 1157 / RFC 1901), BER/ASN.1 like LDAP:

    SNMP Message ::= SEQUENCE {
        version    INTEGER {version-1(0), version-2c(1)},
        community  OCTET STRING,
        data       PDU          -- CHOICE, tag identifies the PDU type
    }
    PDU ::= [APPLICATION n] IMPLICIT SEQUENCE {
        request-id   INTEGER,
        error-status INTEGER,   -- 0 = noError (Response-PDU only)
        error-index  INTEGER,
        variable-bindings SEQUENCE OF VarBind
    }

The community string is present in *every* message, request or response --
there is no separate auth handshake to correlate the way every other
detector here has one. This module still registers a pending finding and
waits for a Response-PDU with a matching request-id, purely to populate
"outcome" for consistency with the rest of the codebase (see below for why
that's a much weaker signal here than elsewhere).

BER parsing is a minimal, self-contained duplicate of the same technique
ldap.py uses for its own BER/ASN.1 message (short-form and definite long-
form lengths only; SNMP doesn't use indefinite form or multi-byte tags
either) -- kept independent rather than imported, matching every other
detector module's self-contained style in this package.

Outcome semantics -- weaker than every other detector here:
    SNMPv1/v2c's PDU error-status field (RFC 1157/1901) has no
    "authenticationFailure" value -- community-string validation happens
    before a Response-PDU is even generated, and a rejected community
    typically causes the agent to *silently drop* the request (or, on some
    devices, emit an snmpv2-Trap authenticationFailure notification to a
    configured trap receiver -- not back to the requester). That means:
    any Response-PDU we see at all, regardless of its error-status value
    (noSuchName, genErr, etc. are about the queried OID, not the
    community), is treated as outcome="success" -- it implies the
    community string was at least accepted for processing. The absence of
    any response is emitted as the usual "no_response" via session/pending
    expiry, but that is a genuinely ambiguous signal here (could mean a
    rejected community, or could just as easily mean a dropped UDP
    datagram, a firewalled agent, or a slow/unreachable device) -- unlike
    every TCP-based detector's "no_response", which is a comparatively
    reliable capture-vs-timeout signal.

Explicit non-goals:
    - SNMPv3 (USM security model: HMAC-based auth, no community string
      concept at all) is out of scope entirely.
    - SNMP traps (port 162, agent-initiated, no response to correlate) are
      not parsed -- only agent-directed requests on port 161.
    - Variable-binding OID/value contents are not decoded; only version,
      community, PDU type, and request-id are extracted.

Port handling:
    Gates on _SNMP_PORTS. Sessions on other ports are skipped immediately.
    161 — SNMP agent (GetRequest/GetNextRequest/SetRequest/GetBulkRequest
          arrive here; Response-PDUs come back from the same port)

Finding type: "snmp_creds"
Finding extras:
    "version"  — "v1" or "v2c" (or the raw integer, stringified, for any
                 other value).
    "pdu_type" — "GetRequest", "GetNextRequest", "SetRequest", or
                 "GetBulkRequest".
    "creds"    — the community string itself. No colon-separated
                 username:password shape (SNMPv1/v2c has no username
                 concept), so it is withheld from Discord alerts
                 (DiscordSink._NO_USERNAME_TYPES) and appears only in the
                 JSONL log.
    "status"   — the Response-PDU's error-status integer, stringified.

Alerting: an "no_response" snmp_creds finding (an unanswered request, the
normal result of internet scans of UDP 161) is written to the JSONL log but
does not alert on Discord -- see DiscordSink._SUPPRESSED_TYPE_OUTCOMES.

Direction: the flow's client/server orientation comes from session.py's
_normalize_direction(), which only knows the TCP server ports in
session._SERVER_PORTS (161 is not among them). A flow is therefore oriented
by whichever datagram was seen first: if that is a Response from port 161
(e.g. capture started mid-exchange), the session's client/server roles are
inverted for its lifetime and requests will land in server_buf, where this
module does not look.

Known limitations:
    - Requests are matched to responses by request-id only (not by source
      address or community), and only within one 4-tuple session, so a poller
      that reuses one source port sends many requests down one session.
    - Only the first 2 KB of client_buf is scanned; client_buf is consumed
      only when a request with a non-empty community is matched (or an empty
      one is discarded), so unmatched datagrams accumulate at the front.
    - A datagram whose community is empty is dropped silently (no log).
"""

from tscan_ng.session import _make_filter

# Finding types this detector emits; tscan_ng.resolve maps each to resolve().
FINDING_TYPES = ("snmp_creds",)

# SNMP agent port. 162 (traps) deliberately excluded -- see module docstring.
_SNMP_PORTS: frozenset = frozenset({161})

# Maximum bytes to scan per call. SNMP GetRequest/SetRequest messages for a
# handful of OIDs are well under a few hundred bytes; this is generous
# headroom while still bounding worst-case scan cost.
_MAX_SCAN_CLIENT = 2048

# BER tag bytes. A PDU tag is Context-specific, constructed (0xA0 | n), where
# n is the PDU type from RFC 1157 / RFC 3416 (n=4, the v1 Trap, is 0xA4 and
# is ignored, as is n=6 InformRequest / n=7 SNMPv2-Trap).
_TAG_INTEGER = 0x02
_TAG_OCTET = 0x04
_TAG_SEQUENCE = 0x30

_PDU_GET_REQUEST = 0xA0
_PDU_GET_NEXT_REQUEST = 0xA1
_PDU_GET_RESPONSE = 0xA2
_PDU_SET_REQUEST = 0xA3
_PDU_GET_BULK_REQUEST = 0xA5

# Request PDU tag -> name recorded in the "pdu_type" field.
_REQUEST_PDU_NAMES = {
    _PDU_GET_REQUEST: "GetRequest",
    _PDU_GET_NEXT_REQUEST: "GetNextRequest",
    _PDU_SET_REQUEST: "SetRequest",
    _PDU_GET_BULK_REQUEST: "GetBulkRequest",
}

# Wire value of the message's version INTEGER -> label. (SNMPv3 is 3 and has a
# different message structure; it would not parse as the SEQUENCE layout used
# here and would be reported by its raw number only if it did.)
_VERSION_NAMES = {0: "v1", 1: "v2c"}


def _parse_ber_len(data: bytes, offset: int):
    """
    Parse a BER-encoded length value starting at *offset* in *data*.

    Supports short form and definite long form only, identical to
    ldap._parse_ber_len -- see that module for the full rationale.

    Args:
        data:   Raw bytes buffer containing the BER stream.
        offset: Byte position of the first length byte.

    Returns:
        (length, new_offset), or (None, None) on error or truncation.
    """
    if offset >= len(data):
        return None, None
    first = data[offset]
    offset += 1
    if first & 0x80 == 0:
        return first, offset
    num_bytes = first & 0x7F
    if num_bytes == 0 or num_bytes > 4 or offset + num_bytes > len(data):
        return None, None
    length = 0
    for _ in range(num_bytes):
        length = (length << 8) | data[offset]
        offset += 1
    return length, offset


def _parse_ber_tlv(data: bytes, offset: int):
    """
    Parse one BER TLV (tag-length-value) triple at *offset* in *data*.

    Identical approach to ldap._parse_ber_tlv -- see that module for the
    full rationale (multi-byte tags not supported; not needed for SNMP).

    Args:
        data:   Raw bytes buffer containing the BER stream.
        offset: Byte position of the tag byte.

    Returns:
        (tag, value_bytes, new_offset), or (None, None, None) on error or
        truncation (value extends beyond available bytes).
    """
    if offset >= len(data):
        return None, None, None
    tag = data[offset]
    offset += 1
    if (tag & 0x1F) == 0x1F:
        return None, None, None
    length, offset = _parse_ber_len(data, offset)
    if length is None:
        return None, None, None
    if offset + length > len(data):
        return None, None, None
    value = data[offset:offset + length]
    return tag, value, offset + length


def _parse_ber_integer(value: bytes) -> int:
    """
    Decode a BER INTEGER value (big-endian, two's complement) to a Python int.

    Args:
        value: Raw value bytes of an INTEGER TLV.

    Returns:
        Decoded integer. Returns 0 for an empty value (malformed, but
        harmless to treat as zero rather than raising).
    """
    if not value:
        return 0
    return int.from_bytes(value, byteorder="big", signed=True)


def _find_snmp_request(data: bytes):
    """
    Scan *data* for the first complete SNMP message carrying a request PDU
    (GetRequest, GetNextRequest, SetRequest, or GetBulkRequest).

    Locates a message by finding a SEQUENCE tag (0x30) and parsing
    version / community / PDU outward from there. Non-request messages
    (Responses, Traps) are skipped by their full length; structural
    mismatches advance one byte. An incomplete message stops the scan.

    Args:
        data: Raw bytes from the client stream buffer (bounded to
              _MAX_SCAN_CLIENT by the caller).

    Returns:
        (version, community, request_id, pdu_name, end_offset) if found,
        where end_offset points past the matched SNMP message. Returns
        (None, None, None, None, None) if no request PDU is present yet.
    """
    i = 0
    while i < len(data):
        if data[i] != _TAG_SEQUENCE:
            i += 1
            continue

        outer_tag, msg_value, msg_end = _parse_ber_tlv(data, i)
        if outer_tag is None:
            break  # Truncated -- wait for more data.

        off = 0
        ver_tag, ver_val, off = _parse_ber_tlv(msg_value, off)
        if ver_tag != _TAG_INTEGER:
            i += 1
            continue

        comm_tag, comm_val, off = _parse_ber_tlv(msg_value, off)
        if comm_tag != _TAG_OCTET:
            i += 1
            continue

        # The PDU is the third element of the message; its tag selects the type.
        pdu_tag, pdu_val, _pdu_end = _parse_ber_tlv(msg_value, off)
        pdu_name = _REQUEST_PDU_NAMES.get(pdu_tag)
        if pdu_name is None:
            # Not a request PDU we track (Response-PDU, Trap, etc.) -- skip.
            i = msg_end
            continue

        # First field of every PDU body is request-id INTEGER.
        rid_tag, rid_val, _ = _parse_ber_tlv(pdu_val, 0)
        if rid_tag != _TAG_INTEGER:
            i += 1
            continue

        version = _parse_ber_integer(ver_val)
        community = (comm_val or b"").decode("utf-8", "replace")
        request_id = _parse_ber_integer(rid_val)
        return version, community, request_id, pdu_name, msg_end

    return None, None, None, None, None


def _find_snmp_response(data: bytes, request_id: int):
    """
    Scan *data* for a Response-PDU (GetResponse) matching *request_id*.

    Same scanning approach as _find_snmp_request(). Responses with a different
    request-id are skipped by their full length (and not consumed). Called by
    resolve().

    Args:
        data:       Raw bytes from the server stream buffer.
        request_id: The request-id to match against (the SNMP request-id
                    INTEGER, which may be negative).

    Returns:
        (error_status, end_offset) if a matching response is found, where
        end_offset points past the matched SNMP message. Returns
        (None, None) if not yet present.
    """
    i = 0
    while i < len(data):
        if data[i] != _TAG_SEQUENCE:
            i += 1
            continue

        outer_tag, msg_value, msg_end = _parse_ber_tlv(data, i)
        if outer_tag is None:
            break

        off = 0
        ver_tag, _ver_val, off = _parse_ber_tlv(msg_value, off)
        if ver_tag != _TAG_INTEGER:
            i += 1
            continue

        comm_tag, _comm_val, off = _parse_ber_tlv(msg_value, off)
        if comm_tag != _TAG_OCTET:
            i += 1
            continue

        pdu_tag, pdu_val, _ = _parse_ber_tlv(msg_value, off)
        if pdu_tag != _PDU_GET_RESPONSE:
            i = msg_end
            continue

        poff = 0
        rid_tag, rid_val, poff = _parse_ber_tlv(pdu_val, poff)
        if rid_tag != _TAG_INTEGER:
            i = msg_end
            continue
        if _parse_ber_integer(rid_val) != request_id:
            i = msg_end
            continue

        # Second field is error-status INTEGER (poff is now just past request-id).
        err_tag, err_val, _ = _parse_ber_tlv(pdu_val, poff)
        if err_tag != _TAG_INTEGER:
            i = msg_end
            continue

        return _parse_ber_integer(err_val), msg_end

    return None, None


def _outcome(error_status: int) -> str:
    """
    Map a Response-PDU's arrival to a finding outcome.

    Always "success" regardless of the actual error-status value -- see
    the module docstring's "Outcome semantics" section for why SNMPv1/v2c
    gives us no error-status value that actually means "bad community".
    Kept as a function (rather than inlining the constant) purely for
    interface consistency with every other detector's _outcome().

    Args:
        error_status: The Response-PDU's error-status integer. Unused;
                      retained in the signature for symmetry with other
                      detectors and clarity at call sites.

    Returns:
        Always "success".
    """
    return "success"


def detect_stream(session, ts: float) -> list:
    """
    Stream-aware SNMPv1/v2c community string detector.

    Scans session.client_buf for a request PDU and correlates it with a
    Response-PDU (matched by request-id) in session.server_buf. Both
    buffers are consumed up to the end of the matched message on
    resolution to prevent re-detection. The client request is consumed when
    matched and a pending finding carrying the private "_request_id" is
    registered; resolve() matches the Response-PDU with that request-id (on
    the same packet if it is already buffered).

    Args:
        session: Session object from session.SessionTable.
        ts:      Unix timestamp of the current packet.

    Returns:
        Always an empty list; findings are registered on the session as
        pending and emitted by tscan_ng.resolve once resolved.
    """
    if session.dport not in _SNMP_PORTS and session.sport not in _SNMP_PORTS:
        return []

    client_bytes = bytes(session.client_buf[:_MAX_SCAN_CLIENT])
    version, community, request_id, pdu_name, req_end = _find_snmp_request(client_bytes)

    if community is None:
        return []

    if not community:
        # Empty community string -- no exploitable credential. Consumed so it
        # is not re-parsed on every packet.
        del session.client_buf[:req_end]
        return []

    base = {
        "type":       "snmp_creds",
        "session_id": session.session_id,
        "src":        session.src,
        "dst":        session.dst,
        "sport":      session.sport,
        "dport":      session.dport,
        "version":    _VERSION_NAMES.get(version, str(version)),
        "pdu_type":   pdu_name,
        "creds":      community,
        "filter":     _make_filter(session.src, session.dst,
                                   session.sport, session.dport),
    }

    del session.client_buf[:req_end]
    # _request_id is private (stripped before output by tscan_ng.resolve and
    # session._close_finding, like every other "_"-prefixed field) -- needed
    # only to match this finding against the right Response-PDU.
    session.add_pending({**base, "_request_id": request_id}, ts_start=ts)
    return []


def resolve(p, session):
    """
    Match a pending SNMP request against the Response-PDU with its request-id (see tscan_ng.resolve).

    Args:
        p:       PendingFinding for a snmp_creds finding.
        session: Session whose server_buf is searched.

    Returns:
        ({"status", "outcome"}, bytes to consume) or None if no reply yet.
    """
    error_status, rsp_end = _find_snmp_response(bytes(session.server_buf),
                                                p.finding.get("_request_id"))
    if error_status is None:
        return None
    return {"status": str(error_status), "outcome": _outcome(error_status)}, rsp_end
