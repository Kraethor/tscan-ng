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

How detectors are driven (pipeline.py pipeline_worker(), per captured packet):
    1. SessionTable.add_packet() appends the payload to the flow's
       client_buf/server_buf and returns the Session.
    2. Every function in STREAM_DETECTORS is called with (session, ts), in list
       order. Order has no functional significance: each detector gates on its
       own port set, so at most one does real work for a given flow. Returned
       findings are already resolved and are emitted immediately.
    3. Unresolved credentials are parked with session.add_pending(); then every
       entry in session.pending is offered to run.py's _try_resolve(), which
       dispatches on the finding's "type" and re-runs that protocol's
       response parser against server_buf. So each protocol's response logic
       lives in TWO places (the detector's immediate-resolve path and
       _try_resolve) and must be kept in sync.

Registration checklist for a NEW detector (every place in the current tree
that enumerates the protocols; missing one causes a silent failure):
    1. detectors/<proto>.py: module-level `_<PROTO>_PORTS` frozenset (the
       name configure_all() overwrites), `detect_stream(session, ts)`, an
       `_outcome()` mapper, and a `_find_*_response()` helper that returns an
       end offset into server_buf so the response can be consumed.
    2. This file: import the module, append <proto>.detect_stream to
       STREAM_DETECTORS, and add a `<proto>._<PROTO>_PORTS = cfg.<proto>_ports`
       line to configure_all().
    3. config.py: a `<proto>_ports` property (with default fallback), the
       [ports] example in the module docstring, and the two places that list
       every protocol (the ports summary tuple list and __repr__).
    4. config/tscan_ng.conf: a `<proto> = ...` line under [ports].
    5. capture.py _build_port_filter(): add cfg.<proto>_ports to the TCP port
       union (or, for a UDP protocol, to the udp clause). Without this the
       BPF filter drops the traffic before it reaches any detector.
    6. run.py: import the response parser and add an `elif finding_type ==
       "<proto>_creds"` branch to _try_resolve(); otherwise pending findings
       never resolve and can only end as "no_response".
    7. scripts/watch.py: a colour/label entry (and display branch) for the new
       finding type; docs (README.md, docs/REBUILD.md, docs/test_reference.md)
       and tests.
    Also add cfg.<proto>_ports to the union in Config.server_ports
    (config.py): it tells SessionTable which side of a flow is the server when
    a flow is first seen from the server side; without it such flows are
    stored with client/server swapped. And check whether
    DiscordSink._SUPPRESSED_OUTCOMES (and _SUPPRESSED_TYPE_OUTCOMES) give the
    new outcome values the alerting behaviour you want.
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
    The detectors look the frozenset up as a module global at call time, so
    rebinding it here takes effect immediately. The hard-coded frozensets in
    each module are only the defaults used when configure_all() is never
    called (e.g. in unit tests). Only port gating is configurable; the
    per-detector _MAX_* scan limits are not.

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
