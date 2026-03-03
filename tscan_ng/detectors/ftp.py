"""
detectors/ftp.py - FTP credential detector for tscan-ng.

Detects cleartext FTP credentials submitted via USER and PASS commands.
Resets pending state on 530 (login failed) or QUIT.
"""

from tscan_ng.detectors.common import detect_user_pass


def detect(pkt: dict) -> list[dict]:
    """
    Detect FTP USER/PASS credentials in a TCP packet.
    Args:
        pkt: Normalized packet dict from parsing.net.parse_basic.
    Returns:
        List of finding dicts, empty if no credentials found.
    """
    if not pkt["tcp"] or not pkt["payload"]:
        return []
    return detect_user_pass(pkt["payload"], "ftp_creds", pkt["src"], pkt["dst"],
                             reset_prefixes=(b"530", b"QUIT"))
