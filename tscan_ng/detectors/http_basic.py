"""
detectors/http_basic.py - HTTP Basic Auth credential detector for tscan-ng.

Stream-aware detector that operates on reassembled TCP streams rather than
individual packets. Parses complete HTTP requests from the client buffer and
correlates them with HTTP responses from the server buffer.

Detects credentials submitted via HTTP Basic Authentication and emits
findings with full request context (method, URI, host) and response
correlation (status code, outcome).

Finding outcomes:
    success      - Server responded with 2xx
    failed       - Server responded with 401
    redirect     - Server responded with 3xx
    server_error - Server responded with 5xx
    pending      - Credentials seen, no server response yet in this packet
    no_response  - Session expired before a server response was seen
                   (emitted by SessionTable.expire())
"""

import re
from tscan_ng.detectors.common import decode_b64

# Matches the HTTP request line e.g. "GET /path HTTP/1.1"
_REQUEST_LINE_RE = re.compile(rb"^([A-Z]+)\s+(\S+)\s+HTTP/\d+\.\d+\r\n", re.MULTILINE)

# Matches the HTTP response status line e.g. "HTTP/1.1 200 OK"
_RESPONSE_LINE_RE = re.compile(rb"^HTTP/\d+\.\d+\s+(\d{3})\s+(.*?)\r\n", re.MULTILINE)

# Matches Authorization: Basic <token> header
_AUTH_HEADER_RE = re.compile(rb"Authorization:\s*Basic\s+(\S+)", re.IGNORECASE)

# Matches Host: header
_HOST_HEADER_RE = re.compile(rb"Host:\s*(\S+)", re.IGNORECASE)


def _outcome(status: int) -> str:
    """
    Map an HTTP status code to a human-readable outcome string.

    Args:
        status: HTTP status code integer.

    Returns:
        One of: success, failed, redirect, server_error, unknown.
    """
    if 200 <= status < 300:
        return "success"
    elif status == 401:
        return "failed"
    elif 300 <= status < 400:
        return "redirect"
    elif 500 <= status < 600:
        return "server_error"
    return "unknown"


def _parse_response(server_buf: bytearray) -> tuple[int, str] | None:
    """
    Extract the HTTP status code and text from the server buffer.

    Args:
        server_buf: Reassembled server-direction byte stream.

    Returns:
        Tuple of (status_code, status_text) if a response line is found,
        otherwise None.
    """
    m = _RESPONSE_LINE_RE.search(bytes(server_buf))
    if not m:
        return None
    return int(m.group(1)), m.group(2).decode("utf-8", "ignore").strip()


def detect(pkt: dict) -> list[dict]:
    """
    Per-packet interface — disabled in favour of stream detection.

    Retained so the detector remains a valid entry in DETECTORS for
    per-packet fallback if needed. Always returns empty in this phase.

    Args:
        pkt: Normalized packet dict from parsing.net.parse_basic.

    Returns:
        Empty list.
    """
    return []


def detect_stream(session, ts: float) -> list[dict]:
    """
    Stream-aware HTTP Basic Auth detector.

    Scans the session's client buffer for complete HTTP requests containing
    an Authorization: Basic header. For each one found, attempts to correlate
    with a server response already present in the server buffer.

    Emits a finding with outcome "pending" if no server response is available
    yet, and registers it on the session for later resolution. Consumes
    matched requests from the client buffer to avoid re-detection on
    subsequent packets.

    Args:
        session: Session object from session.SessionTable.
        ts:      Unix timestamp of the current packet.

    Returns:
        List of resolved finding dicts. Pending findings are registered on
        the session and not returned until resolved.
    """
    findings = []
    client_bytes = bytes(session.client_buf)

    # Find all complete HTTP request headers (terminated by double CRLF)
    while True:
        header_end = client_bytes.find(b"\r\n\r\n")
        if header_end == -1:
            break  # No complete request headers yet

        headers = client_bytes[:header_end + 4]

        # Check for Authorization: Basic header
        auth_match = _AUTH_HEADER_RE.search(headers)
        if not auth_match:
            # No credentials in this request — consume and move on
            client_bytes = client_bytes[header_end + 4:]
            session.client_buf = bytearray(client_bytes)
            continue

        # Extract request line components
        req_match = _REQUEST_LINE_RE.search(headers)
        method = req_match.group(1).decode("utf-8", "ignore") if req_match else ""
        uri    = req_match.group(2).decode("utf-8", "ignore") if req_match else ""

        # Extract Host header
        host_match = _HOST_HEADER_RE.search(headers)
        host = host_match.group(1).decode("utf-8", "ignore") if host_match else ""

        # Decode credentials
        creds = decode_b64(auth_match.group(1))

        # Build the base finding
        base = {
            "type":       "http_basic",
            "session_id": session.session_id,
            "src":        session.src,
            "dst":        session.dst,
            "sport":      session.sport,
            "dport":      session.dport,
            "host":       host,
            "method":     method,
            "uri":        uri,
            "creds":      creds,
            "filter":     _make_filter(session.src, session.dst,
                                       session.sport, session.dport),
        }

        # Attempt to correlate with a server response
        response = _parse_response(session.server_buf)
        if response:
            status, status_text = response
            findings.append({
                **base,
                "ts_start":    ts,
                "ts_end":      session.last_ts,
                "status":      status,
                "status_text": status_text,
                "outcome":     _outcome(status),
            })
            # Consume the response from server_buf
            m = _RESPONSE_LINE_RE.search(bytes(session.server_buf))
            if m:
                del session.server_buf[:m.end()]
        else:
            # No response yet — register as pending
            session.add_pending(base, ts_start=ts)

        # Consume this request from client_buf
        client_bytes = client_bytes[header_end + 4:]
        session.client_buf = bytearray(client_bytes)

    return findings


def _make_filter(src: str, dst: str, sport: int, dport: int) -> str:
    """
    Build a Wireshark/tcpdump display filter string for this flow.

    Args:
        src:   Source IP address string.
        dst:   Destination IP address string.
        sport: Source port number.
        dport: Destination port number.

    Returns:
        A tcpdump/Wireshark compatible filter string.
    """
    return f"host {src} and host {dst} and tcp port {sport} and tcp port {dport}"
