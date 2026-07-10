"""
detectors/http_basic.py - HTTP Basic Auth credential detector for tscan-ng.

Stream-aware detector that operates on reassembled TCP streams rather than
individual packets. Parses complete HTTP requests from the client buffer and
correlates them with HTTP responses from the server buffer.

Detects credentials submitted via HTTP Basic Authentication and emits
findings with full request context (method, URI, host) and response
correlation (status code, outcome).

Port handling:
    The detector gates on _HTTP_PORTS (a frozenset of common HTTP/proxy
    ports). Sessions where neither endpoint port is in the set are skipped
    immediately, keeping per-packet overhead negligible for non-matching
    traffic — the same pattern every other detector in this package uses.

    This is a deliberate coverage/cost tradeoff: Basic Auth on a port
    outside this list will not be detected. Previously this detector had no
    port gate at all and scanned every session on the wire regardless of
    port, which was the single largest per-packet CPU cost in the pipeline
    on a full SPAN/mirror feed (every non-HTTP session — bulk HTTPS, video,
    everything — still paid for a 16 KB buffer scan on every packet). Add
    site-specific alternate ports to ports.http in tscan_ng.conf rather than
    reverting to unconditional scanning.

Buffer handling:
    The scan for HTTP header boundaries is capped at _MAX_HEADER_SCAN bytes
    per call. This keeps per-packet work O(1) regardless of buffer size, and
    avoids O(n²) behaviour at high line speed where detect_stream() is called
    on every arriving packet.

    The client buffer is consumed (via del) before request processing, not
    after. This guarantees the buffer always advances even if an exception
    occurs mid-processing, preventing the same headers from being re-examined
    on every subsequent packet.

Finding outcomes:
    success      - Server responded with 2xx, or 304 (see note below)
    failed       - Server responded with 401
    redirect     - Server responded with 3xx (excluding 304)
    server_error - Server responded with 5xx
    pending      - Credentials seen, no server response yet in this packet
    no_response  - Session expired before a server response was seen
                   (emitted by SessionTable.expire())

Note on 304:
    Per RFC 7232, a server may only return 304 Not Modified for a conditional
    request if that request would otherwise have succeeded — including its
    Authorization header. A server rejects bad credentials with 401, never
    304. So 304 is as strong evidence of valid credentials as 2xx, and is
    classified as "success" rather than lumped in with ordinary 3xx redirects
    (301/302/303/307/308), which carry no such guarantee about auth validity.
"""

import logging
import re
from tscan_ng.detectors.common import decode_b64
from tscan_ng.session import _make_filter

# Well-known and commonly-used HTTP/proxy ports.
# Sessions whose dport or sport is in this set are scanned for Basic Auth.
# Add site-specific alternate ports here if needed.
_HTTP_PORTS: frozenset = frozenset({
    80,    # HTTP
    8080,  # Common HTTP alternate / proxy
    8000,  # Common HTTP alternate
    8008,  # Common HTTP alternate
    8081,  # Common HTTP alternate
    8888,  # Common HTTP alternate
    3128,  # Squid proxy default
})

# Maximum bytes to scan for an HTTP header boundary (\r\n\r\n) per call.
# 16 KB is well above any realistic HTTP request header. Capping the scan
# here bounds per-packet CPU to O(1) rather than O(n) over buffer lifetime.
_MAX_HEADER_SCAN = 16384

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

    304 is classified as "success" rather than "redirect": per RFC 7232, a
    server can only return 304 for a conditional request that would otherwise
    have succeeded (including Authorization), so it's equally strong evidence
    of valid credentials as a 2xx. See the module docstring's "Note on 304".

    Args:
        status: HTTP status code integer.

    Returns:
        One of: success, failed, redirect, server_error, unknown.
    """
    if 200 <= status < 300:
        return "success"
    elif status == 304:
        return "success"
    elif status == 401:
        return "failed"
    elif 300 <= status < 400:
        return "redirect"
    elif 500 <= status < 600:
        return "server_error"
    return "unknown"


def _parse_response(server_buf: bytearray) -> tuple[int, str, int] | None:
    """
    Extract the HTTP status code, text, and byte end-offset from the server buffer.

    Args:
        server_buf: Reassembled server-direction byte stream.

    Returns:
        Tuple of (status_code, status_text, end_offset) if a response line is
        found, otherwise None.  end_offset is the byte position immediately after
        the matched response line, suitable for use with del server_buf[:end_offset].
    """
    m = _RESPONSE_LINE_RE.search(bytes(server_buf))
    if not m:
        return None
    return int(m.group(1)), m.group(2).decode("utf-8", "ignore").strip(), m.end()


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
    an Authorization: Basic header. For each request found, attempts to
    correlate with a server response already present in the server buffer.

    Emits a finding immediately if a server response is available, or
    registers a pending finding on the session for later resolution when the
    response arrives. Consumes matched requests from the client buffer to
    avoid re-detection on subsequent packets.

    The scan is bounded to _MAX_HEADER_SCAN bytes per call to prevent O(n²)
    CPU usage at high line speed. The client buffer is consumed before
    per-request processing so the buffer always advances, even if processing
    raises an exception.

    Args:
        session: Session object from session.SessionTable.
        ts:      Unix timestamp of the current packet.

    Returns:
        List of resolved finding dicts. Pending findings are registered on
        the session and not returned until resolved.
    """
    # Skip sessions that are not on a known HTTP/proxy port.
    # Neither dport nor sport in _HTTP_PORTS means this is definitely not HTTP.
    if session.dport not in _HTTP_PORTS and session.sport not in _HTTP_PORTS:
        return []

    findings = []

    while True:
        # Limit the scan to _MAX_HEADER_SCAN bytes to keep per-packet work
        # O(1). If no complete header is found within this window, wait for
        # more data to arrive.
        scan = bytes(session.client_buf[:_MAX_HEADER_SCAN + 4])
        header_end = scan.find(b"\r\n\r\n")
        if header_end == -1:
            break

        # Consume the request headers from the session buffer NOW, before any
        # processing that could raise. This guarantees the buffer always
        # advances and prevents re-processing the same request on every
        # subsequent packet if an exception occurs below.
        consume = header_end + 4
        headers = bytes(session.client_buf[:consume])
        del session.client_buf[:consume]

        # Skip requests with no Basic Auth credentials
        auth_match = _AUTH_HEADER_RE.search(headers)
        if not auth_match:
            continue

        # Extract request line (method + URI)
        req_match = _REQUEST_LINE_RE.search(headers)
        method = req_match.group(1).decode("utf-8", "ignore") if req_match else ""
        uri    = req_match.group(2).decode("utf-8", "ignore") if req_match else ""

        if not method:
            # Authorization header present but no parseable request line.
            # Still emit the finding — credentials are the primary artifact —
            # but log so anomalous requests are visible during troubleshooting.
            logging.debug(
                "http_basic: session %s: Authorization header with no request line",
                session.session_id)

        # Extract Host header
        host_match = _HOST_HEADER_RE.search(headers)
        host = host_match.group(1).decode("utf-8", "ignore") if host_match else ""

        # Decode Base64 credentials
        creds = decode_b64(auth_match.group(1))

        # Guard against empty captures — some clients (e.g. Zscaler Client
        # Connector's zcc_conn_test probe) send "Authorization: Basic Og=="
        # (base64 for ":") purely as a connectivity check, with no real
        # username or password. Emit nothing rather than a finding with
        # blank credentials, which would be noise in the output.
        _user, _, _passwd = creds.partition(":")
        if not _user and not _passwd:
            logging.debug(
                "http_basic: session %s: Authorization header present but decoded to empty credentials",
                session.session_id)
            continue

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

        # Attempt to correlate with a server response already in server_buf
        response = _parse_response(session.server_buf)
        if response:
            status, status_text, rsp_end = response
            findings.append({
                **base,
                "ts_start":    ts,
                "ts_end":      session.last_ts,
                "status":      status,
                "status_text": status_text,
                "outcome":     _outcome(status),
            })
            del session.server_buf[:rsp_end]
        else:
            # No server response yet — register as pending for later resolution
            session.add_pending(base, ts_start=ts)

    return findings
