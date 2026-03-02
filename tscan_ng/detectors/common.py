import base64

def decode_b64(token: bytes) -> str:
    try:
        return base64.b64decode(token, validate=False).decode("utf-8", "ignore")
    except Exception:
        return ""

def detect_user_pass(payload: bytes, finding_type: str, src: str, dst: str,
                     reset_prefixes: tuple[bytes, ...]) -> list[dict]:
    """Shared USER/PASS detector for FTP and POP3."""
    lines = payload.split(b"\r\n")
    findings = []
    pending_user = None
    for line in lines:
        upper = line.upper()
        if upper.startswith(b"USER "):
            pending_user = line[5:].strip().decode("utf-8", "ignore")
            continue
        if upper.startswith(b"PASS ") and pending_user:
            passwd = line[5:].strip().decode("utf-8", "ignore")
            findings.append({"type": finding_type, "src": src, "dst": dst, "creds": f"{pending_user}:{passwd}"})
            pending_user = None
            continue
        if any(upper.startswith(p) for p in reset_prefixes):
            pending_user = None
    return findings
