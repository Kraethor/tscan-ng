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
    "status" — the numeric resultCode, stringified.

BER framing (all of LDAP is BER, X.690): every element is Tag, Length, Value.
Length is one byte if < 128, otherwise 0x80|n followed by n big-endian length
bytes. Both directions are located by scanning for a SEQUENCE tag (0x30) and
parsing outward from there rather than by tracking message boundaries.

Response correlation:
    Keyed on messageID (#14): the BindRequest's messageID is carried on the
    pending finding as the private "_message_id", and resolve() takes the
    BindResponse with the same messageID, skipping answers to other binds
    (anonymous, unauthenticated or SASL binds this module ignores, or earlier
    simple binds). Consuming up to the matched response also discards those
    skipped answers. SASL multi-step binds answer with resultCode 14
    (saslBindInProgress), which maps to "server_error".

Known limitations:
    - Only the first _MAX_SCAN_CLIENT bytes of client_buf are scanned per call.
      When no simple bind is in that window the scanned prefix is dropped
      (advance_scan_window(), TODO.md #16; the byte-aligned cut resyncs on the
      next 0x30 SEQUENCE), so a simple bind behind a backlog of searches is
      reached on a later packet.
    - A message whose declared length exceeds the scan window (or is bogus)
      stops the scan for that call, since it is indistinguishable from a
      message still being received.
    - resultCode is read from a single byte, so values above 127 (two-byte
      ENUMERATED) would be misread; standard codes are all below 128.
"""

import logging
from tscan_ng.detectors.common import advance_scan_window, base_finding, on_ports, parse_ber_len, parse_ber_tlv

# Finding types this detector emits; tscan_ng.resolve maps each to resolve().
FINDING_TYPES = ("ldap_creds",)

# Well-known cleartext LDAP ports.
# Sessions whose dport or sport is in this set are scanned for credentials.
_LDAP_PORTS: frozenset = frozenset({
    389,   # LDAP (RFC 4511)
    3268,  # Microsoft Global Catalog (also cleartext LDAP)
})

# Maximum bytes of the client buffer to scan per call.
# LDAP BindRequests are modest in size; 8 KB covers any realistic auth exchange.
_MAX_SCAN_CLIENT = 8192

# BER/ASN.1 tag constants used in LDAPMessage (RFC 4511). A tag byte is
# class (top 2 bits) | constructed flag (0x20) | tag number (low 5 bits), so
# e.g. 0x60 = Application class, constructed, number 0; 0x80 = context-specific
# class, primitive, number 0.
_TAG_INTEGER  = 0x02   # Universal primitive: INTEGER
_TAG_ENUM     = 0x0A   # Universal primitive: ENUMERATED (resultCode)
_TAG_OCTET    = 0x04   # Universal primitive: OCTET STRING (DN, password)
_TAG_SEQUENCE = 0x30   # Universal constructed: SEQUENCE (LDAPMessage wrapper)
_TAG_BIND_REQ = 0x60   # Application[0] constructed: BindRequest
_TAG_BIND_RSP = 0x61   # Application[1] constructed: BindResponse
_TAG_SIMPLE   = 0x80   # Context[0] primitive: simple authentication password


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

    SASL binds carry a different authentication tag ([3]) and are skipped
    silently. Anonymous binds (both name and password empty) are also skipped
    since they carry no exploitable credentials. A non-empty DN with an empty
    password is returned (the caller discards it as an unauthenticated bind).

    Skipped messages advance the scan by their full length (i = msg_end);
    structural mismatches advance one byte so a false 0x30 in the middle of
    other data does not hide a real message. No bytes are consumed from the
    buffer here; the caller deletes up to end_offset only on a match.

    Args:
        data: Raw bytes from the client stream buffer (bounded to _MAX_SCAN_CLIENT).

    Returns:
        (dn, password, message_id, end_offset) if a simple BindRequest is
        found, where message_id is the LDAPMessage messageID (used by
        resolve() to pick the matching BindResponse) and end_offset points
        past the last byte of the matched LDAPMessage.
        Returns (None, None, None, None) if no valid simple BindRequest is
        present.
    """
    i = 0
    while i < len(data):
        # LDAPMessage always starts with a SEQUENCE tag (0x30).
        if data[i] != _TAG_SEQUENCE:
            i += 1
            continue

        outer_tag, msg_value, msg_end = parse_ber_tlv(data, i)
        if outer_tag is None:
            # Data is truncated — wait for more bytes.
            break

        # Parse the first field: messageID INTEGER. (Offsets from here on are
        # relative to msg_value / req_value, not to the whole buffer.) The
        # value is kept so resolve() can match the BindResponse by it.
        off = 0
        id_tag, id_val, off = parse_ber_tlv(msg_value, off)
        if id_tag != _TAG_INTEGER:
            i += 1
            continue

        # Parse the second field: BindRequest APPLICATION[0].
        req_tag, req_value, off = parse_ber_tlv(msg_value, off)
        if req_tag != _TAG_BIND_REQ:
            # Not a BindRequest (could be any other LDAP operation) — skip.
            i = msg_end
            continue

        # Inside the BindRequest: version, name, authentication.
        roff = 0

        # version INTEGER (always 3 for LDAPv3; we accept any value).
        v_tag, _v_val, roff = parse_ber_tlv(req_value, roff)
        if v_tag != _TAG_INTEGER:
            i += 1
            continue

        # name OCTET STRING — the Distinguished Name of the binding entity.
        n_tag, n_val, roff = parse_ber_tlv(req_value, roff)
        if n_tag != _TAG_OCTET:
            i += 1
            continue

        # authentication CHOICE — expect [0] (simple password).
        a_tag, a_val, roff = parse_ber_tlv(req_value, roff)
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

        return dn, password, int.from_bytes(id_val or b"", "big"), msg_end

    return None, None, None, None


def _find_bind_response(data, message_id: int | None = None):
    """
    Scan *data* for the BindResponse answering the bind with *message_id*.

    Expected structure (simplified from RFC 4511):
        SEQUENCE {                          -- LDAPMessage
            messageID  INTEGER,
            BindResponse [APPLICATION 1] {
                resultCode ENUMERATED,      -- 0=success, 49=invalidCredentials
                matchedDN  OCTET STRING,
                ...
            }
        }

    A BindResponse whose messageID differs from *message_id* (the answer to
    some other bind on the connection) is skipped by its full length, the
    way snmp._find_snmp_response() skips other request-ids (#14). None
    matches the first BindResponse (for a finding recorded without an id).
    Called by resolve(). The result code is taken from the first byte of the
    ENUMERATED value only.

    Args:
        data:       Server stream buffer (a bytes or bytearray; not copied).
        message_id: messageID of the BindRequest being answered, or None.

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

        outer_tag, msg_value, msg_end = parse_ber_tlv(data, i)
        if outer_tag is None:
            # Truncated — wait for more bytes.
            break

        off = 0
        id_tag, id_val, off = parse_ber_tlv(msg_value, off)
        if id_tag != _TAG_INTEGER:
            i += 1
            continue

        rsp_tag, rsp_value, off = parse_ber_tlv(msg_value, off)
        if rsp_tag != _TAG_BIND_RSP:
            # Not a BindResponse — skip to next message.
            i = msg_end
            continue

        if message_id is not None and int.from_bytes(id_val or b"", "big") != message_id:
            # The answer to a different bind — skip it whole.
            i = msg_end
            continue

        # First field inside BindResponse is always the resultCode ENUMERATED
        # (LDAPResult: resultCode, matchedDN, diagnosticMessage, referral...).
        roff = 0
        rc_tag, rc_val, roff = parse_ber_tlv(rsp_value, roff)
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
    outcomes; all others fall through to "server_error" (this includes, for
    example, 14 saslBindInProgress, 48 inappropriateAuthentication and
    53 unwillingToPerform, none of which are a credential verdict).

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
    SASL, anonymous, and TLS-wrapped sessions are out of scope. A non-empty DN
    with an empty password (unauthenticated bind) is consumed and ignored.
    Every simple bind is registered as pending; resolve() matches the
    BindResponse (on the same packet if it is already buffered).

    The scan is bounded to _MAX_SCAN_CLIENT bytes per call to keep per-packet CPU
    cost O(1) regardless of buffer depth.

    Args:
        session: Session object from session.SessionTable.
        ts:      Unix timestamp of the current packet.

    Returns:
        Always an empty list; findings are registered on the session as
        pending and emitted by tscan_ng.resolve once resolved.
    """
    # Gate: only inspect sessions on known LDAP ports.
    if not on_ports(session, _LDAP_PORTS):
        return []

    # Bound the scan to avoid O(n) work on very deep buffers.
    client_bytes = bytes(session.client_buf[:_MAX_SCAN_CLIENT])
    dn, password, message_id, req_end = _find_bind_request(client_bytes)

    if dn is None:
        # No simple BindRequest in the window: drop scanned non-bind messages
        # (searches, SASL binds) so a bind behind them is reached on a later
        # packet (TODO.md #16). BER is byte-framed; _find_bind_request() resyncs
        # on the next 0x30 SEQUENCE tag, so a byte-aligned cut is recovered.
        advance_scan_window(session, _MAX_SCAN_CLIENT, line_oriented=False)
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

    base = base_finding(session, "ldap_creds", f"{dn}:{password}", dn=dn)

    # "_message_id" is private (stripped before output, like snmp's
    # "_request_id"); resolve() matches the BindResponse on it.
    session.add_pending({**base, "_message_id": message_id}, ts_start=ts)
    del session.client_buf[:req_end]
    return []


def resolve(p, session):
    """
    Match a pending LDAP simple bind against its BindResponse (see tscan_ng.resolve).

    Takes the BindResponse whose messageID equals the request's
    ("_message_id"), skipping answers to other binds (#14).

    Args:
        p:       PendingFinding for a ldap_creds finding.
        session: Session whose server_buf is searched.

    Returns:
        ({"status", "outcome"}, bytes to consume) or None if no reply yet.
    """
    # Scan the server_buf bytearray directly, no per-packet copy (TODO.md #23).
    # Correlation is by messageID (not a byte floor), so the scan starts at 0.
    result_code, rsp_end = _find_bind_response(session.server_buf,
                                               p.finding.get("_message_id"))
    if result_code is None:
        return None
    return {"status": str(result_code), "outcome": _outcome(result_code)}, rsp_end
