import re

_IMAP_LOGIN_RE = re.compile(
    r'\bLOGIN\s+'
    r'(?:"([^"]*?)"|(\S+))'   # username: quoted or unquoted
    r'\s+'
    r'(?:"([^"]*?)"|(\S+))',   # password: quoted or unquoted
    re.IGNORECASE
)


def detect(pkt):
    """Detect IMAP LOGIN credentials in cleartext."""
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
            findings.append({"type": "imap_creds", "src": src, "dst": dst, "creds": f"{user}:{passwd}"})
    return findings
