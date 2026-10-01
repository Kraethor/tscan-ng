"""
detectors/common.py - Shared utilities for tscan-ng detectors.

Provides:
    decode_b64() - lenient base64 -> str helper. Currently imported by
                   http_basic.py (Authorization: Basic token) and smtp.py
                   (AUTH LOGIN username/password lines).

Module-level state: none. The function is pure (no session access, no I/O).

(detect_user_pass(), a per-packet USER/PASS helper from the pre-stream
detector design, was removed in TODO.md #55; it had no callers.)
"""

import base64
import re

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
