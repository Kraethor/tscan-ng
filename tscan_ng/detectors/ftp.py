from tscan_ng.detectors.common import detect_user_pass

def detect(pkt):
    """Detect FTP USER/PASS credentials in cleartext."""
    if not pkt["tcp"] or not pkt["payload"]:
        return []
    return detect_user_pass(pkt["payload"], "ftp_creds", pkt["src"], pkt["dst"],
                             reset_prefixes=(b"530", b"QUIT"))
