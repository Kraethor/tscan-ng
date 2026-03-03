"""
session.py - TCP flow session tracking for tscan-ng.

Maintains a per-worker table of active network flows, buffering reassembled
byte streams in each direction. This is the foundation for stateful stream
reassembly and response correlation in later phases.

Each session tracks:
    - Client stream: bytes flowing from the initiating host to the server
    - Server stream: bytes flowing from the server back to the client
    - Last seen timestamp: used for session expiry in Phase 5

Flow identity is based on the canonical 4-tuple:
    (src_ip, dst_ip, sport, dport)

Direction is determined by comparing the packet's src/sport against the
session's canonical src/sport. Packets in the reverse direction are
accumulated in the server stream.

Note: This phase buffers data but detectors are not yet stream-aware.
      Stream data is available but unused until Phase 3.
"""

import time
from dataclasses import dataclass, field


@dataclass
class Session:
    """
    Represents a single active network flow.

    Attributes:
        src:           Source IP of the flow initiator (client).
        dst:           Destination IP of the flow target (server).
        sport:         Source port of the flow initiator.
        dport:         Destination port of the flow target.
        client_buf:    Reassembled byte stream from client to server.
        server_buf:    Reassembled byte stream from server to client.
        last_seen:     Unix timestamp of the most recently processed packet.
        created_at:    Unix timestamp when the session was first created.
    """
    src:        str
    dst:        str
    sport:      int
    dport:      int
    client_buf: bytearray = field(default_factory=bytearray)
    server_buf: bytearray = field(default_factory=bytearray)
    last_seen:  float = field(default_factory=time.monotonic)
    created_at: float = field(default_factory=time.monotonic)

    def add_packet(self, pkt: dict):
        """
        Append a packet's payload to the appropriate directional buffer.

        Determines direction by comparing the packet's src/sport against
        the session's canonical src/sport. Packets originating from the
        session initiator go to client_buf; all others go to server_buf.

        Args:
            pkt: Normalized packet dict from parsing.net.parse_basic.
        """
        self.last_seen = time.monotonic()
        payload = pkt.get("payload", b"")
        if not payload:
            return
        if pkt["src"] == self.src and pkt["sport"] == self.sport:
            self.client_buf.extend(payload)
        else:
            self.server_buf.extend(payload)

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
        _sessions:      Dict mapping flow keys to Session objects.
        _max_buf:       Maximum bytes buffered per directional stream
                        before the buffer is trimmed from the front.
    """

    # Default maximum bytes buffered per directional stream per session.
    # Prevents unbounded memory growth for long-lived connections.
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

        Sorts the two endpoints so that both directions of a flow
        produce the same key.

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

        On creation, the packet's src/sport are recorded as the canonical
        client endpoint for direction tracking.

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

    def add_packet(self, pkt: dict) -> Session:
        """
        Add a packet to its corresponding session, creating one if needed.

        Enforces the per-direction buffer size limit by trimming the oldest
        bytes from the front of the buffer if it exceeds max_buf.

        Args:
            pkt: Normalized packet dict from parsing.net.parse_basic.

        Returns:
            The updated Session object for this flow.
        """
        session = self.get_or_create(pkt)
        session.add_packet(pkt)

        # Trim buffers if they exceed the maximum size
        if len(session.client_buf) > self._max_buf:
            del session.client_buf[:-self._max_buf]
        if len(session.server_buf) > self._max_buf:
            del session.server_buf[:-self._max_buf]

        return session

    def expire(self, timeout: float = 60.0) -> int:
        """
        Remove sessions that have been idle longer than the timeout.

        Should be called periodically from the worker loop to prevent
        unbounded memory growth from stale sessions.

        Args:
            timeout: Idle timeout in seconds (default: 60).

        Returns:
            Number of sessions expired and removed.
        """
        expired = [k for k, s in self._sessions.items() if s.is_expired(timeout)]
        for k in expired:
            del self._sessions[k]
        return len(expired)

    def __len__(self) -> int:
        """Return the number of active sessions in the table."""
        return len(self._sessions)
