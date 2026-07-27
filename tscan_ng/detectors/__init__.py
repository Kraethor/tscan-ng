"""
detectors/__init__.py - Detector registry for tscan-ng.

Exports STREAM_DETECTORS, the list of detector functions consumed by each
pipeline_worker() process in pipeline.py, the deployed tscan-pipeline.service
path. Every protocol here needs stream reassembly to correlate a credential
with its server response (see e.g. detectors/ftp.py's module docstring), so
all 12 are stream-aware; there is no per-packet detector mechanism.

To add a new detector: implement detect_stream(session, ts) and append it
to STREAM_DETECTORS. Required signature:
    def detect_stream(session: Session, ts: float) -> list[dict]

Call configure_all(cfg) once in each worker process after loading Config to
apply the port sets from the config file to every protocol detector.
"""

from tscan_ng.detectors import (
    http_basic, ftp, pop3, imap, smtp, telnet, ldap, redis, smb, snmp, irc, postgres,
)

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
    snmp.detect_stream,
    irc.detect_stream,
    postgres.detect_stream,
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
    snmp._SNMP_PORTS       = cfg.snmp_ports
    irc._IRC_PORTS         = cfg.irc_ports
    postgres._POSTGRES_PORTS = cfg.postgres_ports
