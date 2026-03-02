from tscan_ng.detectors.common import detect_user_pass

def detect(pkt):
    """Detect POP3 USER/PASS credentials in cleartext."""
    if not pkt["tcp"] or not pkt["payload"]:
        return []
    return detect_user_pass(pkt["payload"], "pop3_creds", pkt["src"], pkt["dst"],
                             reset_prefixes=(b"-ERR", b"QUIT"))
