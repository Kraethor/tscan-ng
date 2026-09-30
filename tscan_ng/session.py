"""
session.py - TCP flow session tracking for tscan-ng.

Maintains a per-worker table of active network flows, buffering the payload
bytes of each direction. Buffers are simple arrival-order concatenations of
packet payloads -- there is no TCP sequence-number tracking, so
retransmissions and out-of-order segments are appended as they arrive. Tracks pending credential findings awaiting
server response correlation.

Each session tracks:
    - Client stream: bytes flowing from the initiating host to the server
    - Server stream: bytes flowing from the server back to the client
    - Last seen timestamp: used for session expiry
    - Pending findings: credential detections awaiting response correlation
    - session_id: stable 8-character hex identifier for the lifetime of the flow
    - ts_first/last_ts: wall-clock timestamps of first and last packets seen
      (last_seen/created_at, by contrast, are time.monotonic() values)

Flow identity is based on the canonical 4-tuple:
    (src_ip, dst_ip, sport, dport)

Direction is normalised at session creation time: if the first packet arrives
from a well-known server port (e.g. the server sent the protocol banner first),
the session is created with src/dst/sport/dport swapped so that session.src and
session.sport always refer to the *client* endpoint.  This means client_buf
always contains client-originated bytes and server_buf always contains
server-originated bytes, without any per-detector direction sniffing.

Phase status (historical build plan; Phase 1 is now done by the kernel's
PACKET_FANOUT_HASH in pipeline.py rather than by application code):
    Phase 1 - Flow affinity routing:        COMPLETE
    Phase 2 - Per-worker stream buffering:  COMPLETE
    Phase 3 - Stream-aware detectors:       COMPLETE
    Phase 4 - Response correlation:         COMPLETE
    Phase 5 - Session expiry and cleanup:   COMPLETE
"""

import hashlib
import time
import logging
from dataclasses import dataclass, field

# Ports on which servers are expected to initiate the conversation
# (i.e. the server sends the first data packet — banner, greeting, etc.).
# When a packet arrives whose *source* port is in this set and whose
# *destination* port is not, we treat the packet as server->client and
# store the session from the client's perspective by swapping src/dst.
# This hardcoded list is only the DEFAULT for SessionTable(); the pipeline
# passes Config.server_ports (the union of every detector's configured
# [ports]) instead, so LDAP, Redis, SMB, SNMP, IRC, PostgreSQL and any
# non-default configured port are covered too. Callers that use the default
# get this older, partial list (TODO.md #12).
_SERVER_PORTS: frozenset = frozenset({
    21,    # FTP control
    22,    # SSH
    23,    # Telnet
    25,    # SMTP
    80,    # HTTP
    110,   # POP3
    143,   # IMAP
    443,   # HTTPS
    465,   # SMTPS
    587,   # SMTP submission
    993,   # IMAPS
    995,   # POP3S
    2121,  # FTP alternate
    1430,  # IMAP alternate
    1100,  # POP3 alternate
    2323,  # Telnet alternate
    2525,  # SMTP alternate
})


def _normalize_direction(pkt: dict, server_ports: frozenset = _SERVER_PORTS) -> dict:
    """
    Return a copy of pkt with src/dst/sport/dport normalised to client perspective.

    If the packet's source port is a known server port and the destination
    port is not (i.e. the server sent the first data packet), the addresses
    are swapped so that the client is always represented as the source.

    Args:
        pkt:          Normalized packet dict from parsing.net.parse_basic.
        server_ports: Ports treated as "server side" (default: the module's
                      partial _SERVER_PORTS; the pipeline passes
                      Config.server_ports).

    Returns:
        pkt (the same object, not a copy) unchanged if already client-perspective, or a new dict with
        src/dst and sport/dport swapped if direction was inverted.
    """
    if pkt["sport"] in server_ports and pkt["dport"] not in server_ports:
        return {
            **pkt,
            "src":   pkt["dst"],
            "dst":   pkt["src"],
            "sport": pkt["dport"],
            "dport": pkt["sport"],
        }
    return pkt


def _make_session_id(src: str, dst: str, sport: int, dport: int,
                     created_at: float) -> str:
    """
    Generate a stable 8-character hex session identifier.

    Derived from the flow 4-tuple and creation timestamp. Stable for the
    lifetime of the session so all findings from the same TCP connection
    share the same session_id, making them trivially linkable in log
    analysis tools.

    Args:
        src:        Source IP address string.
        dst:        Destination IP address string.
        sport:      Source port number.
        dport:      Destination port number.
        created_at: Monotonic timestamp when the session was created.
            (Monotonic time is not comparable across processes or
            restarts, so ids are only unique in practice, not guaranteed:
            32 bits of SHA-1.)

    Returns:
        8-character lowercase hex string.
    """
    key = f"{src}|{sport}|{dst}|{dport}|{created_at}".encode()
    return hashlib.sha1(key, usedforsecurity=False).hexdigest()[:8]


def _close_finding(p: "PendingFinding", last_ts: float) -> dict:
    """
    Build a no_response finding dict for a pending finding being force-closed.

    Shared by every path that removes a session or a pending finding
    without a resolved response (idle expiry, age-based expiry, eviction)
    so each closes out its in-flight findings the same way instead of
    silently dropping them.

    Args:
        p:       The PendingFinding being closed.
        last_ts: Unix timestamp to record as ts_end (typically the owning
                 session's last_ts).

    Returns:
        A completed finding dict with outcome="no_response".
    """
    clean = {k: v for k, v in p.finding.items() if not k.startswith("_")}
    return {
        **clean,
        "ts_start":    p.ts_start,
        "ts_end":      last_ts,
        "outcome":     "no_response",
        "status":      None,
        "status_text": None,
    }


def _make_filter(src: str, dst: str, sport: int, dport: int) -> str:
    """
    Build a Wireshark/tcpdump display filter string for this flow.
    Every detector stores it as the finding's "filter" field. It always says
    "tcp port", which is wrong for SNMP (UDP); see TODO.md #28.

    The resulting filter can be used directly with tcpdump -r or as a
    Wireshark display filter to isolate this session in a full pcap
    capture on a corroborating device.

    Args:
        src:   Source IP address string (client).
        dst:   Destination IP address string (server).
        sport: Source port number (client).
        dport: Destination port number (server).

    Returns:
        A tcpdump/Wireshark compatible filter string.
    """
    return f"host {src} and host {dst} and tcp port {sport} and tcp port {dport}"


@dataclass
class PendingFinding:
    """
    A credential finding detected but not yet correlated with a server response.

    Attributes:
        finding:            Partial finding dict. Will be completed with status,
                            status_text, outcome, and ts_end on resolution.
        ts_start:           Unix timestamp when the credentials were observed.
        server_buf_floor:   len(session.server_buf) at the moment this finding
                            was registered. The eventual response can only
                            appear at or after this position — bytes before it
                            predate the credential submission and are safe to
                            trim. Shifted down whenever server_buf is trimmed
                            or consumed (see Session.consume_server()) so
                            it stays valid as an index into the current buffer.
    """
    finding:          dict
    ts_start:         float
    server_buf_floor: int = 0


@dataclass
class Session:
    """
    Represents a single active network flow.

    src/dst/sport/dport are always stored from the *client* perspective:
    session.src is the client IP, session.dst is the server IP, etc.
    This invariant is enforced by SessionTable.get_or_create via
    _normalize_direction().

    Attributes:
        src:        Source IP of the flow initiator (client).
        dst:        Destination IP of the flow target (server).
        sport:      Source port of the flow initiator (ephemeral).
        dport:      Destination port of the flow target (well-known).
        session_id: Stable 8-char hex identifier for this flow.
        client_buf: Concatenated payloads from client to server, in arrival
                    order (not sequence-number reassembled).
        server_buf: Concatenated payloads from server to client, in arrival
                    order (not sequence-number reassembled).
        pending:    Credential findings awaiting response correlation.
        last_seen:  Monotonic timestamp of the most recently processed packet
                    (drives idle expiry and eviction order).
        created_at: Monotonic timestamp when the session was first created.
        ts_first:   Unix timestamp of the first packet seen (for findings).
        last_ts:    Unix timestamp of the most recently processed packet.
        http_req_seen: Number of HTTP request header blocks consumed from
                    client_buf on this flow (credentialed or not). Used by
                    detectors/http_basic.py to pair each credentialed request
                    with the response at the same position in the (in-order)
                    response stream. Unused by other detectors.
        http_rsp_gone: Number of HTTP status lines already removed from the
                    front of server_buf (matched or skipped). Together with
                    http_req_seen this converts "the Nth response on the
                    flow" into an index into the current server_buf.
        _client_trim_warned: True after the first client_buf trim warning has
                    been emitted. Suppresses repeat warnings on the same session
                    to prevent log flooding on high-volume persistent connections.
        _server_trim_warned: Same as above for server_buf.
    """
    src:        str
    dst:        str
    sport:      int
    dport:      int
    session_id: str       = field(init=False)
    client_buf: bytearray = field(default_factory=bytearray)
    server_buf: bytearray = field(default_factory=bytearray)
    pending:    list      = field(default_factory=list)
    last_seen:  float     = field(default_factory=time.monotonic)
    created_at: float     = field(default_factory=time.monotonic)
    ts_first:   float     = 0.0
    last_ts:    float     = 0.0
    http_req_seen: int = 0
    http_rsp_gone: int = 0
    # Trim warning suppression: warn once per direction, then go silent.
    # Prevents log flooding on high-volume persistent connections.
    _client_trim_warned: bool = field(default=False, repr=False)
    _server_trim_warned: bool = field(default=False, repr=False)

    def __post_init__(self):
        """Derive session_id from the flow tuple and created_at (init=False field)."""
        self.session_id = _make_session_id(
            self.src, self.dst, self.sport, self.dport, self.created_at
        )

    def add_packet(self, pkt: dict, ts: float):
        """
        Append a packet's payload to the appropriate directional buffer.

        Because session.src/sport are always normalised to the *client*
        perspective, direction assignment is straightforward: packets
        whose source matches the client endpoint go to client_buf;
        all others go to server_buf.

        pkt is guaranteed to contain the keys src, dst, sport, dport, and
        payload by parsing.net.parse_basic(), which is the only source of
        pkt dicts in this pipeline.

        last_ts is only advanced forward to guard against backward system
        clock adjustments (e.g. NTP step corrections) producing inverted
        ts_start/ts_end timestamps in findings.

        Args:
            pkt: Normalized packet dict from parsing.net.parse_basic.
            ts:  Unix timestamp of this packet.
        """
        self.last_seen = time.monotonic()
        # Only advance last_ts forward — guard against backward clock jumps
        # producing inverted timestamps in emitted findings.
        if ts > self.last_ts:
            self.last_ts = ts
        if self.ts_first == 0.0:
            self.ts_first = ts
        payload = pkt.get("payload", b"")
        if not payload:
            return
        if pkt["src"] == self.src and pkt["sport"] == self.sport:
            self.client_buf.extend(payload)
        else:
            self.server_buf.extend(payload)

    def add_pending(self, finding: dict, ts_start: float, floor: int | None = None):
        """
        Register a credential finding as pending server response correlation.

        Every detector reports credentials this way; tscan_ng.resolve then
        matches the response (possibly on the same packet, if it is already
        buffered).

        Records this finding's floor (see PendingFinding.server_buf_floor) so
        a later buffer trim knows not to discard bytes its response may still
        need. By default the floor is the current server_buf length; a
        detector that knows the response can only follow an earlier point
        (telnet: the password prompt) passes that offset instead.

        Args:
            finding:  Partial finding dict from a stream detector.
            ts_start: Unix timestamp when the credentials were observed.
            floor:    Optional server_buf offset to use as the floor.
        """
        self.pending.append(PendingFinding(
            finding=finding, ts_start=ts_start,
            server_buf_floor=len(self.server_buf) if floor is None else floor))

    def consume_server(self, n: int):
        """
        Remove the first *n* bytes of server_buf and shift pending floors.

        The only way bytes leave server_buf (TODO.md #13): used by
        tscan_ng.resolve when a reply is matched and by SessionTable's size
        trim. Doing the delete and the shift together means no caller can
        forget the shift and leave other pending findings' floors pointing
        past their data. tests/test_consume_server.py checks nothing else in
        the package deletes from server_buf.

        Args:
            n: Number of bytes to remove; 0 or less does nothing.
        """
        if n <= 0:
            return
        del self.server_buf[:n]
        self.shift_pending_floors(n)

    def shift_pending_floors(self, consumed: int):
        """
        Shift all pending findings' server_buf_floor down after *consumed*
        bytes were removed from the front of server_buf.

        Called by consume_server(); use that rather than calling this
        directly. Keeps the remaining pending findings' floors valid indexes
        into the now-shorter buffer. Clamped to 0 rather than going negative.

        Args:
            consumed: Number of bytes removed from the front of server_buf.
        """
        for p in self.pending:
            p.server_buf_floor = max(0, p.server_buf_floor - consumed)

    def expire_pending(self, now: float, max_age: float) -> list:
        """
        Force-close pending findings older than max_age as no_response.

        A pending finding's server_buf_floor (see add_pending) blocks
        server_buf trimming from cutting past it, so a finding that never
        correlates with a response holds that floor — and therefore
        server_buf's growth — in place indefinitely. On a busy session
        that never goes idle long enough to hit is_expired(), this is the
        only thing that bounds server_buf, so it must run independently of
        session-level idle expiry.

        Args:
            now:     Current wall-clock (Unix) timestamp.
            max_age: Maximum age in seconds before a pending finding is
                     force-closed.

        Returns:
            List of no_response finding dicts for any findings force-closed.
            Age is measured in the caller's timestamp domain (packet wall
            time, as passed by SessionTable.add_packet), and the closed
            findings' ts_end is the session's last_ts.

        Side effects:
            Replaces self.pending with the still-pending subset. Does NOT
            shift floors: the surviving findings' floors are unaffected,
            since no buffer bytes are removed.
        """
        expired_findings = []
        still_pending = []
        for p in self.pending:
            if (now - p.ts_start) > max_age:
                expired_findings.append(_close_finding(p, self.last_ts))
            else:
                still_pending.append(p)
        self.pending = still_pending
        return expired_findings

    def is_expired(self, timeout: float) -> bool:
        """
        Check whether this session has been idle longer than the timeout.

        Args:
            timeout: Maximum idle time in seconds before a session expires.

        Returns:
            True if the session should be expired and cleaned up. Uses
            last_seen (monotonic), so it is immune to wall-clock steps.
        """
        return (time.monotonic() - self.last_seen) > timeout


class SessionTable:
    """
    Per-worker table of active network flows.

    Keyed on a canonical flow tuple that is direction-independent —
    both directions of a flow map to the same session entry. The
    canonical form always places the lower (src, sport) pair first
    so that client->server and server->client packets match the same key.

    Sessions are always created with src/sport normalised to the client
    endpoint (see _normalize_direction), so client_buf and server_buf
    reliably contain client-originated and server-originated bytes
    respectively.

    Attributes:
        _sessions:         Dict mapping flow keys to Session objects.
        _max_buf:          Maximum bytes buffered per directional stream
                           before the buffer is trimmed from the front.
        _timeout:          Idle timeout in seconds for session expiry.
        _pending_max_age:  Maximum age in seconds for an unresolved pending
                           finding before it is force-closed (see
                           Session.expire_pending).
        _max_sessions:     Maximum number of concurrent sessions tracked at
                           once. Bounds total memory against a burst of many
                           concurrent flows, independent of per-session
                           buffer limits (see _evict_one).
        _server_ports:     Ports treated as the server side when orienting a
                           new flow from its first packet (see
                           _normalize_direction).
    """

    def __init__(self, max_buf: int = 4 * 1024 * 1024,
                 timeout: float = 60.0, pending_max_age: float = 45.0,
                 max_sessions: int = 2048,
                 server_ports: frozenset | None = None):
        """
        Initialize an empty session table.

        Args:
            max_buf:         Maximum bytes to buffer per directional stream.
            timeout:         Idle timeout in seconds before a session is
                             expired.
            pending_max_age: Maximum age in seconds before an unresolved
                             pending finding is force-closed, releasing the
                             server_buf trim floor it was holding open.
            max_sessions:    Maximum number of concurrent sessions tracked
                             at once, independent of max_buf/timeout.
            server_ports:    Ports on which the far end is the server, used
                             to orient a flow first seen from the server
                             side. None uses the partial module default
                             _SERVER_PORTS; the pipeline passes
                             Config.server_ports.
        """
        self._sessions: dict = {}
        self._max_buf = max_buf
        self._timeout = timeout
        self._pending_max_age = pending_max_age
        self._max_sessions = max_sessions
        self._server_ports = _SERVER_PORTS if server_ports is None else server_ports

    def _make_key(self, src: str, dst: str, sport: int, dport: int) -> tuple:
        """
        Compute a canonical, direction-independent flow key.

        Args:
            src:   Source IP address string.
            dst:   Destination IP address string.
            sport: Source port number.
            dport: Destination port number.

        Returns:
            A tuple suitable for use as a dict key: the two (ip, port)
            endpoints ordered lexicographically, so both directions of a
            flow yield the same key. The key carries no protocol, so a TCP
            and a UDP flow between the same endpoints would share a session.
        """
        a, b = (src, sport), (dst, dport)
        if a > b:
            a, b = b, a
        return (a, b)

    def get_or_create(self, pkt: dict) -> tuple:
        """
        Return the existing session for a packet's flow, or create a new one.

        New sessions are created with src/sport normalised to the client
        perspective via _normalize_direction(), ensuring that client_buf
        always accumulates client bytes and server_buf accumulates server
        bytes regardless of which endpoint sent the first packet.

        If creating a new session would exceed max_sessions, evicts one
        existing session first (see _evict_one) so the table never grows
        past its cap.

        Args:
            pkt: Normalized packet dict from parsing.net.parse_basic.

        Note the returned session is not touched (no last_seen update); the
        caller (add_packet) does that via Session.add_packet.

        Returns:
            Tuple of (session, evicted_findings) — the Session object for
            this flow, and a list of no_response finding dicts for any
            session evicted to make room for it (empty if none).
        """
        key = self._make_key(pkt["src"], pkt["dst"],
                             pkt["sport"], pkt["dport"])
        evicted = []
        if key not in self._sessions:
            if len(self._sessions) >= self._max_sessions:
                evicted = self._evict_one()
            norm = _normalize_direction(pkt, self._server_ports)
            self._sessions[key] = Session(
                src=norm["src"],
                dst=norm["dst"],
                sport=norm["sport"],
                dport=norm["dport"],
            )
        return self._sessions[key], evicted

    def _evict_one(self) -> list:
        """
        Evict one session to make room when the table is at max_sessions.

        Prefers evicting a session with no pending findings — nothing
        credential-related in flight — over one with pending findings.
        Within whichever pool is available, evicts the least-recently-active
        session first. If every session currently has a pending finding,
        falls back to least-recently-active regardless, since an incoming
        new connection must always get a session even if that means giving
        up on one in-flight correlation.

        Cost is O(n) in the number of sessions per eviction (a full scan),
        paid on every new flow once the table is at capacity.

        Returns:
            List of no_response finding dicts for any pending findings the
            evicted session was holding (empty if it had none).
        """
        # "idle" here means "no pending findings", not "inactive".
        idle = [(k, s) for k, s in self._sessions.items() if not s.pending]
        pool = idle if idle else list(self._sessions.items())
        key, victim = min(pool, key=lambda kv: kv[1].last_seen)
        del self._sessions[key]
        return [_close_finding(p, victim.last_ts) for p in victim.pending]

    def add_packet(self, pkt: dict, ts: float) -> tuple:
        """
        Add a packet to its corresponding session, creating one if needed.

        Enforces the per-direction buffer size limit by trimming the oldest
        bytes from the front of the buffer if it exceeds max_buf.  Trimming
        is logged at WARNING level because it can cause partial protocol state
        loss — for example, a USER command trimmed before its PASS arrives will
        prevent credential correlation for that exchange.  If trims are frequent,
        increase session_max_buf in tscan_ng.conf.

        server_buf's trim point additionally respects any pending findings'
        server_buf_floor (see PendingFinding) — it will never cut past the
        earliest floor still outstanding, even if that means temporarily
        exceeding max_buf. Without this, a burst of unrelated server traffic
        could trim away a tagged response a pending finding is still waiting
        to match, silently turning a real outcome into a false "no_response".
        This bends the size cap only as far as outstanding pending findings
        require; once they resolve or expire, normal trimming resumes.

        Because that floor can be held open indefinitely by a finding that
        never correlates with a response, pending findings older than
        _pending_max_age are force-closed as no_response *before* the floor
        is computed below. Without this, a single stuck pending finding on a
        continuously-active session (one that never goes idle long enough to
        hit session-level expiry) lets server_buf grow without bound.

        Args:
            pkt: Normalized packet dict from parsing.net.parse_basic.
            ts:  Unix timestamp of this packet.

        Trimming runs after every packet, so only a freshly grown buffer is
        ever trimmed; the client_buf cut keeps the newest max_buf bytes.

        Returns:
            Tuple of (session, closed_findings) — the updated Session object
            for this flow, and a list of no_response finding dicts for any
            pending findings force-closed by age or by evicting another
            session to make room for this one.
        """
        session, evicted = self.get_or_create(pkt)
        session.add_packet(pkt, ts)
        expired = session.expire_pending(ts, self._pending_max_age)
        closed = evicted + expired

        if len(session.client_buf) > self._max_buf:
            if not session._client_trim_warned:
                logging.warning(
                    "session %s: client_buf trimmed (%d bytes) — "
                    "increase session_max_buf to reduce credential data loss",
                    session.session_id, len(session.client_buf))
                session._client_trim_warned = True
            del session.client_buf[:-self._max_buf]

        # naive_cut: bytes over the cap. The real cut is limited to the
        # lowest outstanding floor (bytes before it are the only ones no
        # pending finding still needs).
        naive_cut = len(session.server_buf) - self._max_buf
        if naive_cut > 0:
            floor = min((p.server_buf_floor for p in session.pending),
                        default=naive_cut)
            cut = min(naive_cut, floor)
            if cut > 0:
                if not session._server_trim_warned:
                    logging.warning(
                        "session %s: server_buf trimmed (%d bytes) — "
                        "increase session_max_buf to reduce credential data loss",
                        session.session_id, len(session.server_buf))
                    session._server_trim_warned = True
                session.consume_server(cut)

        return session, closed

    def expire(self) -> list:
        """
        Remove sessions that have been idle longer than the configured timeout.

        For any session with pending findings, emits a no_response finding
        for each so the output record is closed out rather than silently
        dropped.

        Called periodically (pipeline._maybe_run_periodic). Idleness is
        measured on the monotonic clock via Session.is_expired.

        Returns:
            List of no_response finding dicts for any expired pending findings.
        """
        expired_findings = []
        expired_keys = [k for k, s in self._sessions.items()
                        if s.is_expired(self._timeout)]
        for k in expired_keys:
            session = self._sessions[k]
            expired_findings.extend(
                _close_finding(p, session.last_ts) for p in session.pending)
            del self._sessions[k]
        return expired_findings

    def flush_all(self) -> list:
        """
        Expire all sessions immediately regardless of idle time.

        Called on worker shutdown to ensure all pending findings are
        closed out as no_response before the process exits. Without
        this, pending findings for active sessions at shutdown time
        would be silently lost.

        Returns:
            List of no_response finding dicts for all remaining pending
            findings across all sessions.
        """
        flushed = []
        for session in self._sessions.values():
            flushed.extend(
                _close_finding(p, session.last_ts) for p in session.pending)
        self._sessions.clear()
        return flushed

    def __len__(self) -> int:
        """Return the number of active sessions in the table."""
        return len(self._sessions)
