import base64


def decode_b64(token: bytes) -> str:
    try:
        return base64.b64decode(token, validate=False).decode("utf-8", "ignore")
    except Exception:
        return ""
