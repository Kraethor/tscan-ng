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


def _next_client_tokens(lines: list[bytes], start_idx: int, count: int) -> list[bytes]:
    tokens = []
    idx = start_idx
    while idx < len(lines) and len(tokens) < count:
        token = lines[idx].strip()
        if token:
            if not token.upper().startswith(b"334 "):
                tokens.append(token)
        idx += 1
    return tokens


def _find_auth_login(lines: list[bytes]) -> list[dict]:
    findings = []
    for idx, line in enumerate(lines):
        upper = line.upper()
        if b"AUTH LOGIN" not in upper:
            continue
        parts = line.split(b"AUTH LOGIN", 1)[1].strip()
        user = decode_b64(parts) if parts else ""
        needed = 2 if not user else 1
        tokens = _next_client_tokens(lines, idx + 1, needed)
        passwd = ""
        if user:
            if tokens:
                passwd = decode_b64(tokens[0])
        elif len(tokens) >= 2:
            user = decode_b64(tokens[0])
            passwd = decode_b64(tokens[1])
        elif len(tokens) == 1:
            user = decode_b64(tokens[0])
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
