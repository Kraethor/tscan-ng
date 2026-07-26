"""
detectors/__init__.py - Detector registry for tscan-ng.

Exports two detector lists consumed by worker processes in run.py:

    DETECTORS:        Per-packet detectors. Receive a normalized pkt dict
                      and return a list of finding dicts.

    STREAM_DETECTORS: Stream-aware detectors. Receive a Session object and
                      the current packet timestamp, and return a list of
                      resolved finding dicts. Pending findings are registered
                      directly on the session for later resolution.

To add a new detector:
    - Per-packet:    implement detect(pkt) and append to DETECTORS
    - Stream-aware:  implement detect_stream(session, ts) and append to
                     STREAM_DETECTORS

Each per-packet detector must implement:
    def detect(pkt: dict) -> list[dict]

Each stream detector must implement:
    def detect_stream(session: Session, ts: float) -> list[dict]

Call configure_all(cfg) once in each worker process after loading Config to
apply the port sets from the config file to every protocol detector.
"""

from tscan_ng.detectors import http_basic, ftp, pop3, imap, smtp, telnet, ldap, redis, smb

DETECTORS = []

STREAM_DETECTORS = [
    http_basic.detect_stream,
    imap.detect_stream,
    ftp.detect_stream,
    smtp.detect_stream,
    pop3.detect_stream,
    telnet.detect_stream,
    ldap.detect_stream,
    redis.detect_stream,
    smb.detect_stream,
]


def configure_all(cfg) -> None:
    """
    Apply per-protocol port sets from *cfg* to each detector module.

    Each protocol detector gates on a module-level frozenset of ports. This
    function replaces those frozensets with the values loaded from the config
    file, allowing port lists to be changed without editing source code.

    Must be called once per worker process before the packet processing loop.

    Args:
        cfg: Loaded Config object (tscan_ng.config.Config).
    """
    http_basic._HTTP_PORTS = cfg.http_ports
    ftp._FTP_PORTS         = cfg.ftp_ports
    smtp._SMTP_PORTS       = cfg.smtp_ports
    imap._IMAP_PORTS       = cfg.imap_ports
    pop3._POP3_PORTS       = cfg.pop3_ports
    telnet._TELNET_PORTS   = cfg.telnet_ports
    ldap._LDAP_PORTS       = cfg.ldap_ports
    redis._REDIS_PORTS     = cfg.redis_ports
    smb._SMB_PORTS         = cfg.smb_ports
