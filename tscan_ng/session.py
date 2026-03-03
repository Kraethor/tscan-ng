"""
session.py - TCP flow session tracking for tscan-ng.

Maintains a per-worker table of active network flows, buffering reassembled
byte streams in each direction. Tracks pending credential findings awaiting
server response correlation.

Each session tracks:
    - Client stream: bytes flowing from the initiating host to the server
    - Server stream: bytes flowing from the server back to the client
    - Last seen timestamp: used for session expiry in Phase 5
    - Pending findings: credential detections awaiting response correlation
    - session_id: stable 8-character hex identifier for the lifetime of the flow
    - ts_start: timestamp of the first packet seen in the session

Flow identity is based on the canonical 4-tuple:
    (src_ip, dst_ip, sport, dport)

Direction is determined by comparing the packet's src/sport against the
session's canonical src/sport. Packets in the reverse direction are
accumulated in the server stream.

Phase status:
    Phase 1 - Flow affinity routing:        COMPLETE
    Phase 2 - Per-worker stream buffering:  COMPLETE
    Phase 3 - Stream-aware detectors:       COMPLETE
    Phase 4 - Response correlation:         COMPLETE
    Phase 5 - Session expiry and cleanup:   PARTIAL
"""

import time
from dataclasses import dataclass, field


def _make_session_id(src: str, dst: str, sport: int, dport: int, created_at: float) -> str:
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
        created_at: Unix timestamp when the session was created.

    Returns:
        8-character lowercase hex string.
    """
    return format(hash((src, dst, sport, dport, created_at)) & 0xFFFFFFFF, "08x")


def _make_filter(src: str, dst: str, sport: int, dport: int) -> str:
    """
    Build a Wireshark/tcpdump display filter string for this flow.

    The resulting filter can be used directly with tcpdump -r or as a
    Wireshark display filter to isolate this session in a full pcap
    capture on a corroborating device.

    Args:
        src:   Source IP address string.
        dst:   Destination IP address string.
        sport: Source port number.
        dport: Destination port number.

    Returns:
        A tcpdump/Wireshark compatible filter string.
    """
    return f"host {src} and host {dst} and tcp port {sport} and tcp port {dport}"


@dataclass
class PendingFinding:
    """
    A credential finding that has been detected but not yet correlated
    with a server response.

    Attributes:
        finding:    The partial finding dict. Will be completed with
                    status, status_text, outcome, and ts_end on resolution.
        ts_start:   Timestamp of the packet in which credentials were found.
    """
    finding:  dict
    ts_start: float


@dataclass
class Session:
    """
    Represents a single active network flow.

    Attributes:
        src:            Source IP of the flow initiator (client).
        dst:            Destination IP of the flow target (server).
        sport:          Source port of the flow initiator.
        dport:          Destination port of the flow target.
        session_id:     Stable 8-char hex identifier for this flow.
        client_buf:     Reassembled byte stream from client to server.
        server_buf:     Reassembled byte stream from server to client.
        pending:        Credential findings awaiting response correlation.
        last_seen:      Monotonic timestamp of the most recently processed packet.
        created_at:     Monotonic timestamp when the session was first created.
        ts_first:       Unix timestamp of the first packet seen (for findings).
        last_ts:        Unix timestamp of the most recently processed packet.
    """
    src:        str
    dst:        str
    sport:      int
    dport:      int
    session_id: str             = field(init=False)
    client_buf: bytearray       = field(default_factory=bytearray)
    server_buf: bytearray       = field(default_factory=bytearray)
    pending:    list            = field(default_factory=list)
    last_seen:  float           = field(default_factory=time.monotonic)
    created_at: float           = field(default_factory=time.monotonic)
    ts_first:   float           = 0.0
    last_ts:    float           = 0.0

    def __post_init__(self):
        self.session_id = _make_session_id(
            self.src, self.dst, self.sport, self.dport, self.created_at
        )

    def add_packet(self, pkt: dict, ts: float):
        """
        Append a packet's payload to the appropriate directional buffer.

        Determines direction by comparing the packet's src/sport against
        the session's canonical src/sport. Packets originating from the
        session initiator go to client_buf; all others go to server_buf.

        Args:
            pkt: Normalized packet dict from parsing.net.parse_basic.
            ts:  Unix timestamp of this packet.
        """
        self.last_seen = time.monotonic()
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

    def add_pending(self, finding: dict, ts_start: float):
        """
        Register a credential finding as pending server response correlation.

        Args:
            finding:  Partial finding dict from a stream detector.
            ts_start: Unix timestamp when the credentials were observed.
        """
        self.pending.append(PendingFinding(finding=finding, ts_start=ts_start))

    def is_expired(self, timeout: float) -> bool:
        """
        Check whether this session has been idle longer than the timeout.

        Args:
            timeout: Maximum idle time in seconds before a session expires.

        Returns:
            True if the session should be expired and cleaned up.
        """
        return (time.monotonic() - self.last_seen) > timeout


class SessionTable:
    """
    Per-worker table of active network flows.

    Keyed on a canonical flow tuple that is direction-independent —
    both directions of a flow map to the same session entry. The
    canonical form always places the lower (src, sport) pair first
    so that client→server and server→client packets match the same key.

    Attributes:
        _sessions:  Dict mapping flow keys to Session objects.
        _max_buf:   Maximum bytes buffered per directional stream
                    before the buffer is trimmed from the front.
    """

    # Default maximum bytes buffered per directional stream per session.
    DEFAULT_MAX_BUF = 1 * 1024 * 1024  # 1MB per direction

    def __init__(self, max_buf: int = DEFAULT_MAX_BUF):
        """
        Initialize an empty session table.

        Args:
            max_buf: Maximum bytes to buffer per directional stream.
        """
        self._sessions: dict[tuple, Session] = {}
        self._max_buf = max_buf

    def _make_key(self, src: str, dst: str, sport: int, dport: int) -> tuple:
        """
        Compute a canonical, direction-independent flow key.

        Args:
            src:   Source IP address string.
            dst:   Destination IP address string.
            sport: Source port number.
            dport: Destination port number.

        Returns:
            A tuple suitable for use as a dict key.
        """
        a, b = (src, sport), (dst, dport)
        if a > b:
            a, b = b, a
        return (a, b)

    def get_or_create(self, pkt: dict) -> Session:
        """
        Return the existing session for a packet's flow, or create a new one.

        Args:
            pkt: Normalized packet dict from parsing.net.parse_basic.

        Returns:
            The Session object for this flow.
        """
        key = self._make_key(pkt["src"], pkt["dst"], pkt["sport"], pkt["dport"])
        if key not in self._sessions:
            self._sessions[key] = Session(
                src=pkt["src"],
                dst=pkt["dst"],
                sport=pkt["sport"],
                dport=pkt["dport"],
            )
        return self._sessions[key]

    def add_packet(self, pkt: dict, ts: float) -> Session:
        """
        Add a packet to its corresponding session, creating one if needed.

        Enforces the per-direction buffer size limit by trimming the oldest
        bytes from the front of the buffer if it exceeds max_buf.

        Args:
            pkt: Normalized packet dict from parsing.net.parse_basic.
            ts:  Unix timestamp of this packet.

        Returns:
            The updated Session object for this flow.
        """
        session = self.get_or_create(pkt)
        session.add_packet(pkt, ts)

        # Trim buffers if they exceed the maximum size
        if len(session.client_buf) > self._max_buf:
            del session.client_buf[:-self._max_buf]
        if len(session.server_buf) > self._max_buf:
            del session.server_buf[:-self._max_buf]

        return session

    def expire(self, timeout: float = 60.0) -> list[dict]:
        """
        Remove sessions that have been idle longer than the timeout.

        For any session with pending findings, emits a no_response finding
        for each so the output record is closed out rather than silently
        dropped.

        Args:
            timeout: Idle timeout in seconds (default: 60).

        Returns:
            List of no_response finding dicts for any expired pending findings.
        """
        expired_findings = []
        expired_keys = [k for k, s in self._sessions.items() if s.is_expired(timeout)]
        for k in expired_keys:
            session = self._sessions[k]
            for p in session.pending:
                expired_findings.append({
                    **p.finding,
                    "ts_start":   p.ts_start,
                    "ts_end":     session.last_ts,
                    "outcome":    "no_response",
                    "status":     None,
                    "status_text": None,
                })
            del self._sessions[k]
        return expired_findings

    def __len__(self) -> int:
        """Return the number of active sessions in the table."""
        return len(self._sessions)
