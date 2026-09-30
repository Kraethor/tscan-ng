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
    unknown      - Server responded with any other status (e.g. 403, 404,
                   411). Common for Basic Auth: a 403 in particular usually
                   means the credentials *were* accepted and something else
                   (ACL, WAF, path rule) blocked the request, so this is not
                   noise — see _outcome()'s docstring.
    pending      - Not emitted by this module: a credential with no response
                   yet is parked with session.add_pending() and reported
                   later as success/failed/... or no_response. (The word
                   only appears in DiscordSink's suppression list.)
    no_response  - Session expired before a server response was seen
                   (emitted by SessionTable.expire())

Alerting note:
    DiscordSink alerts on every outcome above except "pending" and
    "failed" (see DiscordSink._SUPPRESSED_OUTCOMES) — "unknown" and
    "no_response" both alert, since both represent credentials that were
    actually submitted and are worth a human look, even though neither is
    a confirmed success.

Note on 304:
    Per RFC 7232, a server may only return 304 Not Modified for a conditional
    request if that request would otherwise have succeeded — including its
    Authorization header. A server rejects bad credentials with 401, never
    304. So 304 is as strong evidence of valid credentials as 2xx, and is
    classified as "success" rather than lumped in with ordinary 3xx redirects
    (301/302/303/307/308), which carry no such guarantee about auth validity.

Credentials extracted:
    The base64 token of any "Authorization: Basic <token>" header, decoded
    (common.decode_b64) to "user:password" and emitted verbatim as "creds".
    The header search is a substring match, so "Proxy-Authorization: Basic"
    (sent to a proxy such as Squid on 3128) is captured too; a proxy rejects
    those with 407, which _outcome() reports as "unknown". Also recorded:
    "host" (Host header), "method" and "uri" (request line). Tokens that fail
    to decode, or decode to just ":" / nothing, are dropped.

Request framing:
    A request is delimited only by the first blank line (CRLF CRLF). Request
    bodies are NOT skipped: a POST body remains in client_buf and is treated as
    the start of the next request's header block.

Response correlation:
    HTTP/1.x returns exactly one response per request, in request order. Every
    request header block consumed from client_buf is numbered per session
    (Session.http_req_seen), whether or not it carries credentials; a
    credentialed request remembers its number as "_rsp_index". Its response is
    the status line at that position in the server stream: take_response()
    finds the Nth "HTTP/x.y NNN" line (allowing for lines already removed,
    Session.http_rsp_gone), deletes everything up to and including it, and
    shifts the pending floors. So the 401 a browser receives for its first,
    credential-less request is skipped and the retry is paired with its own
    response (TODO.md #2). run.py's _try_resolve() calls the same function
    for pending findings. Assumes in-order responses (no reordering from
    multi-connection races; SPAN loss shifts the pairing) and no interim
    "100 Continue" responses.

Known limitations:
    - HTTPS is opaque; only cleartext HTTP on the configured ports is seen.
    - A header block longer than _MAX_HEADER_SCAN, or a large body with no
      CRLF CRLF in it, prevents progress: nothing is consumed until enough
      data arrives to find a boundary inside the scan window.
    - Digest, NTLM and Bearer authentication are not handled.
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
# (The scan window is _MAX_HEADER_SCAN + 4 bytes so a boundary that ends
# exactly at the limit is still found.)
_MAX_HEADER_SCAN = 16384

# Matches the HTTP request line e.g. "GET /path HTTP/1.1".
#   Group 1: method (upper-case letters only), Group 2: request target.
# Requires CRLF line ends. Unanchored-by-position: MULTILINE ^ lets it match
# on any line, so it is searched on the already-isolated header block.
_REQUEST_LINE_RE = re.compile(rb"^([A-Z]+)\s+(\S+)\s+HTTP/\d+\.\d+\r\n", re.MULTILINE)

# Matches the HTTP response status line e.g. "HTTP/1.1 200 OK".
#   Group 1: 3-digit status code, Group 2: reason phrase (may be empty; the
#   lazy (.*?) stops at the first CRLF).
_RESPONSE_LINE_RE = re.compile(rb"^HTTP/\d+\.\d+\s+(\d{3})\s+(.*?)\r\n", re.MULTILINE)

# Matches Authorization: Basic <token> header (also matches inside
# "Proxy-Authorization:" since there is no line anchor).
#   Group 1: the still-base64-encoded token (non-whitespace run).
_AUTH_HEADER_RE = re.compile(rb"Authorization:\s*Basic\s+(\S+)", re.IGNORECASE)

# Matches Host: header. Group 1: host[:port] token.
_HOST_HEADER_RE = re.compile(rb"Host:\s*(\S+)", re.IGNORECASE)


def _outcome(status: int) -> str:
    """
    Map an HTTP status code to a human-readable outcome string.

    304 is classified as "success" rather than "redirect": per RFC 7232, a
    server can only return 304 for a conditional request that would otherwise
    have succeeded (including Authorization), so it's equally strong evidence
    of valid credentials as a 2xx. See the module docstring's "Note on 304".

    Everything not explicitly matched below (403, 404, 411, ...) falls
    through to "unknown" — see the module docstring's "Finding outcomes"
    for why that still alerts rather than being treated as noise.

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


def take_response(session, rsp_index: int | None = None):
    """
    Extract, and consume, the HTTP response for one request on *session*.

    Responses arrive in request order, so request number k (see
    Session.http_req_seen) is answered by the k-th status line of the server
    stream. Status lines already deleted from the front of server_buf are
    tracked in Session.http_rsp_gone, so the wanted line is at position
    (rsp_index - http_rsp_gone) among the status lines still buffered. Also
    imported by run.py's _try_resolve(). Copies the whole buffer to bytes on
    each call.

    On success everything up to and including the matched status line is
    deleted from server_buf (which discards earlier, unrelated responses such
    as a 401 challenge), http_rsp_gone is advanced past every status line
    removed, and the pending findings' floors are shifted.

    Args:
        session:   Session whose server_buf is searched.
        rsp_index: Zero-based number of the request whose response is wanted.
                   None means "the first buffered status line" (legacy
                   behaviour, for findings without a recorded index).

    Returns:
        Tuple of (status_code, status_text, end_offset) if that response is
        buffered, otherwise None. end_offset is the number of bytes just
        removed from the front of server_buf. None is also returned if the
        response was already consumed or trimmed away (index below
        http_rsp_gone); the finding then stays pending until it expires.
    """
    want = 0 if rsp_index is None else rsp_index - session.http_rsp_gone
    if want < 0:
        return None
    match = None
    for n, m in enumerate(_RESPONSE_LINE_RE.finditer(bytes(session.server_buf))):
        if n == want:
            match = m
            break
    if match is None:
        return None
    end = match.end()
    del session.server_buf[:end]
    session.shift_pending_floors(end)
    session.http_rsp_gone += want + 1
    return (int(match.group(1)),
            match.group(2).decode("utf-8", "ignore").strip(), end)


def detect_stream(session, ts: float) -> list[dict]:
    """
    Stream-aware HTTP Basic Auth detector.

    Scans the session's client buffer for complete HTTP requests containing
    an Authorization: Basic header. For each request found, attempts to
    correlate with a server response already present in the server buffer.

    Emits a finding immediately if a server response is available, or
    registers a pending finding on the session for later resolution when the
    response arrives. Consumes every scanned request header block (with or
    without credentials) from the client buffer to avoid re-detection on
    subsequent packets. Each request block is numbered (Session.http_req_seen)
    and paired with its own response by take_response(), which also consumes
    the response and shifts the pending floors.

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

        # Number this request (every request gets a slot, credentialed or
        # not) so its response can be found by position later -- the response
        # to an earlier credential-less request must not be paired with it.
        rsp_index = session.http_req_seen
        session.http_req_seen += 1

        # Skip requests with no Basic Auth credentials (their header block has
        # already been consumed above).
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

        # Attempt to correlate with this request's response if already buffered
        response = take_response(session, rsp_index)
        if response:
            status, status_text, _rsp_end = response
            findings.append({
                **base,
                "ts_start":    ts,
                "ts_end":      session.last_ts,
                "status":      status,
                "status_text": status_text,
                "outcome":     _outcome(status),
            })
        else:
            # No server response yet -- register as pending for later
            # resolution. "_rsp_index" (underscore fields are stripped by
            # run.py's _try_resolve) tells it which response to wait for.
            session.add_pending({**base, "_rsp_index": rsp_index}, ts_start=ts)

    return findings
