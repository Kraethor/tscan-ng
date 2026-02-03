def detect(pkt):
    """Detect FTP USER/PASS credentials in cleartext."""
    if not pkt["tcp"]:
        return []
    payload = pkt["payload"]
    if not payload:
        return []
    lines = payload.split(b"\r\n")
    findings = []
    for idx, line in enumerate(lines):
        if line.upper().startswith(b"USER "):
            user = line[5:].strip().decode("utf-8", "ignore")
            if idx + 1 < len(lines) and lines[idx + 1].upper().startswith(b"PASS "):
                passwd = lines[idx + 1][5:].strip().decode("utf-8", "ignore")
                findings.append({"type": "ftp_creds", "creds": f"{user}:{passwd}"})
    return findings
