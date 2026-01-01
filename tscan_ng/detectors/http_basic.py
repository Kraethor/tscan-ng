import base64

def detect(pkt):
    """Find HTTP Basic creds in raw TCP payload (naive MVP)."""
    if not pkt["tcp"]:
        return []
    p = pkt["payload"]
    if not p or b"Authorization:" not in p or b"Basic " not in p:
        return []
    try:
        line = next(l for l in p.split(b"\r\n") if b"Authorization:" in l and b"Basic " in l)
        b64 = line.split(b"Basic ", 1)[1].strip()
        userpass = base64.b64decode(b64, validate=False).decode("utf-8", "ignore")
        return [{"type": "http_basic", "creds": userpass}]
    except Exception:
        return []
