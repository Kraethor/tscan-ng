"""
detectors/common.py - Shared utilities for tscan-ng detectors.

Provides (TODO.md #57 moved the last four here from per-module copies):
    decode_b64()        - lenient base64 -> str helper. Used by http_basic.py
                          (Authorization: Basic token) and smtp.py (AUTH
                          LOGIN username/password lines).
    decode_sasl_plain() - SASL PLAIN blob -> (user, password). smtp.py, imap.py.
    parse_ber_len(), parse_ber_tlv()
                        - minimal BER reader. ldap.py, snmp.py.
    base_finding()      - the fields every finding starts with. All detectors.
    on_ports()          - "is this flow on my ports" gate. All detectors.

Module-level state: none. The functions are pure (base_finding() and
on_ports() read the session they are given; nothing is modified, no I/O).

(detect_user_pass(), a per-packet USER/PASS helper from the pre-stream
detector design, was removed in TODO.md #55; it had no callers.)
"""

import base64
import re

from tscan_ng.session import _make_filter

# Everything outside the standard base64 alphabet, including "=" padding and
# whitespace. Stripped before decoding so padding can be recomputed.
_NON_B64_RE = re.compile(rb"[^A-Za-z0-9+/]")


def decode_b64(token: bytes) -> str:
    """
    Decode a base64-encoded token to a UTF-8 string.

    Lenient on purpose, since the input is whatever a client sent:
    characters outside the base64 alphabet are discarded, and missing or
    extra "=" padding is tolerated (the padding is recomputed from the
    remaining length; some clients omit it). Non-UTF-8 bytes in the decoded
    data become U+FFFD ("replace", the detector-wide convention; see
    detectors/__init__.py).

    A token that cannot be valid base64 at any padding (4n+1 significant
    characters) returns the empty string, so callers cannot tell "bad token"
    apart from "token that decodes to nothing".

    Args:
        token: Raw base64-encoded bytes.

    Returns:
        Decoded string, or empty string on any error.
    """
    data = _NON_B64_RE.sub(b"", token)
    try:
        return base64.b64decode(data + b"=" * (-len(data) % 4)).decode("utf-8", "replace")
    except Exception:
        return ""


def decode_sasl_plain(blob: bytes) -> tuple | None:
    """
    Decode a SASL PLAIN base64 blob into (username, password).

    SASL PLAIN (RFC 4616) after base64 decode is authzid NUL authcid NUL
    passwd; the authzid is usually empty (\x00username\x00password) and is
    discarded. A two-field payload (username NUL password) is accepted too.
    Used for SMTP AUTH PLAIN and IMAP AUTHENTICATE PLAIN, which share the
    wire format.

    Args:
        blob: Raw base64 encoded bytes.

    Returns:
        (username, password) tuple, or None if decoding fails or the decoded
        payload does not split into two or three NUL-separated fields.
    """
    try:
        decoded = base64.b64decode(blob)
        parts = decoded.split(b"\x00")
        if len(parts) == 3:
            return parts[1].decode("utf-8", "replace"), parts[2].decode("utf-8", "replace")
        elif len(parts) == 2:
            return parts[0].decode("utf-8", "replace"), parts[1].decode("utf-8", "replace")
    except Exception:
        pass
    return None


def parse_ber_len(data: bytes, offset: int):
    """
    Parse a BER-encoded length value starting at *offset* in *data*.

    Supports short form (single byte, high bit clear) and definite long form
    (high bit set; low 7 bits give the count of subsequent length bytes).
    Indefinite form (first byte == 0x80) is used by neither LDAP nor SNMP and
    is treated as an error. More than 4 length bytes (lengths above 4 GiB) is
    also treated as an error.

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
    # Long form: low 7 bits = number of length bytes that follow.
    num_bytes = first & 0x7F
    if num_bytes == 0 or num_bytes > 4 or offset + num_bytes > len(data):
        # Indefinite form (num_bytes==0), oversized, or truncated.
        return None, None
    length = 0
    for _ in range(num_bytes):
        length = (length << 8) | data[offset]
        offset += 1
    return length, offset


def parse_ber_tlv(data: bytes, offset: int):
    """
    Parse one BER TLV (tag-length-value) triple at *offset* in *data*.

    Multi-byte tags (low 5 bits all set in the first tag byte, i.e. 0x1F)
    are not supported: standard LDAPv3 and SNMP v1/v2c messages do not use
    them.

    Args:
        data:   Raw bytes buffer containing the BER stream.
        offset: Byte position of the tag byte.

    Returns:
        (tag, value_bytes, new_offset) on success, where value_bytes is a
        bytes slice of the TLV value field and new_offset points past the end
        of this TLV.  Returns (None, None, None) on any error or if the data
        is truncated (value extends beyond available bytes). Malformed and
        merely-incomplete input are indistinguishable to the caller.
    """
    if offset >= len(data):
        return None, None, None
    tag = data[offset]
    offset += 1
    if (tag & 0x1F) == 0x1F:
        return None, None, None
    length, offset = parse_ber_len(data, offset)
    if length is None:
        return None, None, None
    if offset + length > len(data):
        # Value not yet fully received — wait for more data.
        return None, None, None
    value = data[offset:offset + length]
    return tag, value, offset + length


def base_finding(session, ftype: str, creds: str, **extra) -> dict:
    """
    Build the fields every finding starts with, in the standard key order.

    Args:
        session: Session the credential was seen on (client perspective:
                 session.src/sport is the client).
        ftype:   Finding type, one of the module's FINDING_TYPES.
        creds:   Credential string as the detector formats it (usually
                 "user:password").
        **extra: Protocol-specific fields (e.g. nick=, tag=, mechanism=),
                 placed after the endpoint fields and before "creds", in the
                 order given.

    Returns:
        {"type", "session_id", "src", "dst", "sport", "dport", <extra...>,
        "creds", "filter"}. Private "_"-prefixed fields are added by the
        caller ({**base, "_request_id": ...}).
    """
    return {
        "type":       ftype,
        "session_id": session.session_id,
        "src":        session.src,
        "dst":        session.dst,
        "sport":      session.sport,
        "dport":      session.dport,
        **extra,
        "creds":      creds,
        "filter":     _make_filter(session.src, session.dst,
                                   session.sport, session.dport),
    }


def on_ports(session, ports) -> bool:
    """
    True if either endpoint of *session* is on one of *ports*.

    Every detector's first check. Both endpoints are tested because a flow
    first seen from the server side may be stored with client and server
    swapped (see session._normalize_direction). The caller passes its own
    module-level port set (rebound by detectors.configure_all()), so it must
    be looked up at call time, not captured.

    Args:
        session: Session to test.
        ports:   Set of port numbers the detector handles.

    Returns:
        bool.
    """
    return session.dport in ports or session.sport in ports
