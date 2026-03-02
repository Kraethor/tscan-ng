from tscan_ng.detectors.common import decode_b64

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
        userpass = decode_b64(b64)
        src, dst = pkt["src"], pkt["dst"]
        return [{"type": "http_basic", "src": src, "dst": dst, "creds": userpass}]
    except Exception:
        return []
