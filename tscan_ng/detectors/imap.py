import re

_IMAP_LOGIN_RE = re.compile(r"\bLOGIN\s+\"?([^\s\"]+)\"?\s+\"?([^\s\"]+)\"?", re.IGNORECASE)


def detect(pkt):
    """Detect IMAP LOGIN credentials in cleartext."""
    if not pkt["tcp"]:
        return []
    payload = pkt["payload"]
    if not payload:
        return []
    text = payload.decode("utf-8", "ignore")
    findings = []
    for line in text.splitlines():
        match = _IMAP_LOGIN_RE.search(line)
        if match:
            user, passwd = match.groups()
            findings.append({"type": "imap_creds", "creds": f"{user}:{passwd}"})
    return findings
