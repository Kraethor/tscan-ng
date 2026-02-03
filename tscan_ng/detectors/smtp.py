from tscan_ng.detectors.common import decode_b64


def _find_auth_plain(lines: list[bytes]) -> list[dict]:
    findings = []
    for idx, line in enumerate(lines):
        upper = line.upper()
        if b"AUTH PLAIN" not in upper:
            continue
        token = line.split(b"AUTH PLAIN", 1)[1].strip()
        if not token and idx + 1 < len(lines):
            token = lines[idx + 1].strip()
        if not token:
            continue
        decoded = decode_b64(token)
        parts = decoded.split("\x00")
        if len(parts) >= 3:
            user = parts[-2]
            passwd = parts[-1]
            findings.append({"type": "smtp_plain_creds", "creds": f"{user}:{passwd}"})
    return findings


def _find_auth_login(lines: list[bytes]) -> list[dict]:
    findings = []
    for idx, line in enumerate(lines):
        if b"AUTH LOGIN" not in line.upper():
            continue
        if idx + 2 >= len(lines):
            continue
        user = decode_b64(lines[idx + 1].strip())
        passwd = decode_b64(lines[idx + 2].strip())
        if user or passwd:
            findings.append({"type": "smtp_login_creds", "creds": f"{user}:{passwd}"})
    return findings


def detect(pkt):
    """Detect SMTP AUTH LOGIN/PLAIN credentials."""
    if not pkt["tcp"]:
        return []
    payload = pkt["payload"]
    if not payload:
        return []
    lines = payload.split(b"\r\n")
    findings = []
    findings.extend(_find_auth_plain(lines))
    findings.extend(_find_auth_login(lines))
    return findings
