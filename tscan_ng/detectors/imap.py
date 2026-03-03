"""
detectors/imap.py - IMAP credential detector for tscan-ng.

Detects cleartext IMAP credentials submitted via the LOGIN command.
Handles both quoted (allowing spaces) and unquoted username/password forms.
"""

import re

_IMAP_LOGIN_RE = re.compile(
    r'\bLOGIN\s+'
    r'(?:"([^"]*?)"|(\S+))'   # username: quoted or unquoted
    r'\s+'
    r'(?:"([^"]*?)"|(\S+))',   # password: quoted or unquoted
    re.IGNORECASE
)


def detect(pkt: dict) -> list[dict]:
    """
    Detect IMAP LOGIN credentials in a TCP packet.
    Handles both quoted string credentials (which may contain spaces) and
    plain unquoted credentials.
    Args:
        pkt: Normalized packet dict from parsing.net.parse_basic.
    Returns:
        List of finding dicts, empty if no credentials found.
    """
    if not pkt["tcp"]:
        return []
    payload = pkt["payload"]
    if not payload:
        return []
    text = payload.decode("utf-8", "ignore")
    src, dst = pkt["src"], pkt["dst"]
    findings = []
    for line in text.splitlines():
        match = _IMAP_LOGIN_RE.search(line)
        if match:
            user = match.group(1) or match.group(2)
            passwd = match.group(3) or match.group(4)
            findings.append({"type": "imap_creds", "src": src, "dst": dst,
                             "creds": f"{user}:{passwd}"})
    return findings
