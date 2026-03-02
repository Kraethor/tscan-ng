def detect(pkt):
    """Detect POP3 USER/PASS credentials in cleartext."""
    if not pkt["tcp"]:
        return []
    payload = pkt["payload"]
    if not payload:
        return []
    lines = payload.split(b"\r\n")
    src, dst = pkt["src"], pkt["dst"]
    findings = []
    pending_user = None
    for line in lines:
        upper = line.upper()
        if upper.startswith(b"USER "):
            pending_user = line[5:].strip().decode("utf-8", "ignore")
            continue
        if upper.startswith(b"PASS ") and pending_user:
            passwd = line[5:].strip().decode("utf-8", "ignore")
            findings.append({"type": "pop3_creds", "src": src, "dst": dst, "creds": f"{pending_user}:{passwd}"})
            pending_user = None
            continue
        if upper.startswith(b"-ERR") or upper.startswith(b"QUIT"):
            pending_user = None
    return findings
