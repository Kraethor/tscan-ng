# Copyright (C) 2026 Kraethor
#
# This file is part of tscan-ng.
#
# tscan-ng is free software: you can redistribute it and/or modify it under
# the terms of the GNU General Public License as published by the Free
# Software Foundation, version 3.
#
# tscan-ng is distributed in the hope that it will be useful, but WITHOUT ANY
# WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along with
# tscan-ng. If not, see <https://www.gnu.org/licenses/>.
#
# Additional term under GPLv3 section 7(b): if you convey this work or a
# modified version of it, you must preserve the attribution "Based on tscan-ng
# by Kraethor (https://github.com/Kraethor/tscan-ng)" in the source and in any
# user-facing output or accompanying documentation.
#
# SPDX-License-Identifier: GPL-3.0-only

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

    _HTTP_PORTS below is only the default. detectors.configure_all(cfg)
    rebinds this module's _HTTP_PORTS to the configured set once per worker
    process at startup, so the frozenset in this file is what applies only
    when configure_all() is never called (e.g. in unit tests) — editing it
    does not change the gate in a running deployment. The default the
    pipeline actually falls back to is declared in the registry, the "http"
    row of tscan_ng.protocols.PROTOCOLS, which _HTTP_PORTS mirrors; see
    detectors/__init__.py configure_all() for the rebinding.

    To change the ports in a deployment, set ports.http in tscan_ng.conf.
    That one list does double duty: capture._build_port_filter() unions the
    configured ports of every protocol into the BPF filter attached to the
    capture socket, so a port missing from it is never captured at all and
    no detector-side gate can recover it.

    This is a deliberate coverage/cost tradeoff: Basic Auth on a port
    outside the configured list will not be detected. Previously this
    detector had no port gate at all and scanned every session on the wire
    regardless of port, which was the single largest per-packet CPU cost in
    the pipeline on a full SPAN/mirror feed (every non-HTTP session — bulk
    HTTPS, video, everything — still paid for a 16 KB buffer scan on every
    packet). Add site-specific alternate ports to ports.http in
    tscan_ng.conf rather than reverting to unconditional scanning.

Buffer handling:
    The scan for HTTP header boundaries is capped at _MAX_SCAN_CLIENT bytes
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
    no_response  - Session expired before a server response was seen
                   (emitted by SessionTable.expire())

Alerting note:
    DiscordSink alerts on every outcome above except "failed" (see
    DiscordSink._SUPPRESSED_OUTCOMES) — "unknown" and "no_response" both alert, since both represent credentials that were
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
    A request header block is delimited by the first blank line (CRLF CRLF).
    A request body is skipped using its Content-Length (TODO.md #22), so a
    POST/PUT payload is not treated as the start of the next request. The body
    bytes to skip are tracked across packets in Session.http_body_remaining.
    A chunked request body (Transfer-Encoding: chunked, no Content-Length) is
    not skipped; it is uncommon for credentialed requests and is left as a
    known limitation below.

Response correlation:
    HTTP/1.x returns exactly one response per request, in request order. Every
    request header block consumed from client_buf is numbered per session
    (Session.http_req_seen), whether or not it carries credentials; a
    credentialed request remembers its number as "_rsp_index". Its response is
    the status line at that position in the server stream: resolve() finds
    the Nth "HTTP/x.y NNN" line (allowing for lines already removed,
    Session.http_rsp_gone) and tscan_ng.resolve deletes everything up to and
    including it. So the 401 a browser receives for its first,
    credential-less request is skipped and the retry is paired with its own
    response (TODO.md #2). Assumes in-order responses (no reordering from
    multi-connection races; SPAN loss shifts the pairing) and no interim
    "100 Continue" responses.

Known limitations:
    - HTTPS is opaque; only cleartext HTTP on the configured ports is seen.
    - A header block longer than _MAX_SCAN_CLIENT bytes cannot be matched: when
      the buffer grows past the window with no CRLF CRLF in it, the scanned
      prefix is dropped (advance_scan_window(), TODO.md #22b) so the connection
      is not stalled forever; that one oversized request is lost, later ones are
      recovered. (Request bodies no longer cause this since they are skipped by
      Content-Length.)
    - A chunked request body is not skipped (no Content-Length); its bytes can
      still glue onto the following request. Uncommon for credentialed requests.
    - Digest, NTLM and Bearer authentication are not handled.
"""

import logging
import re
from tscan_ng.detectors.common import advance_scan_window, base_finding, decode_b64, on_ports

# Finding types this detector emits; tscan_ng.resolve maps each to resolve().
FINDING_TYPES = ("http_basic",)

# Well-known and commonly-used HTTP/proxy ports — the DEFAULT gate only.
# Sessions whose dport or sport is in this set are scanned for Basic Auth.
# detectors.configure_all() rebinds this name to the configured ports once per
# worker process at startup, so editing this set does NOT change the gate in a
# running deployment and is not how site-specific ports are added: set
# ports.http in tscan_ng.conf instead. That same configured list builds the BPF
# capture filter (capture._build_port_filter), so a port absent from it never
# reaches this detector. These values mirror the "http" row of
# tscan_ng.protocols.PROTOCOLS, the default the config layer falls back to —
# keep the two in step.
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
# (The scan window is _MAX_SCAN_CLIENT + 4 bytes so a boundary that ends
# exactly at the limit is still found.)
_MAX_SCAN_CLIENT = 16384

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

# Matches Content-Length header. Group 1: the decimal length.
_CONTENT_LENGTH_RE = re.compile(rb"^Content-Length:\s*(\d+)", re.IGNORECASE | re.MULTILINE)


def _body_length(headers: bytes) -> int:
    """
    Bytes of request body to skip after this header block (TODO.md #22).

    Reads Content-Length so a request body (a POST/PUT payload) is skipped
    rather than glued onto the next request's header block, which otherwise
    makes the body's bytes parse as the next request (empty/wrong method and
    URI, and a shifted response pairing).

    Args:
        headers: The request header block, including the terminating CRLFCRLF.

    Returns:
        The Content-Length value, or 0 when there is none. A chunked body has
        no Content-Length and returns 0 (not skipped; see the module docstring).
    """
    m = _CONTENT_LENGTH_RE.search(headers)
    if m:
        return int(m.group(1))
    return 0


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


def resolve(p, session):
    """
    Match a pending Basic-auth request against its own response (see tscan_ng.resolve).

    Responses arrive in request order, so request number k (see
    Session.http_req_seen, recorded as the finding's "_rsp_index") is
    answered by the k-th status line of the server stream. Status lines
    already deleted from the front of server_buf are counted in
    Session.http_rsp_gone, so the wanted line is at position
    (_rsp_index - http_rsp_gone) among the status lines still buffered.

    On a match, http_rsp_gone is advanced past every status line that
    tscan_ng.resolve is about to delete (the wanted one and any earlier,
    unrelated ones such as a 401 challenge). A finding whose response was
    already consumed or trimmed away (index below http_rsp_gone) never
    matches and stays pending until it expires. Copies the whole buffer to
    bytes on each call.

    Args:
        p:       PendingFinding for an http_basic finding. A missing
                 "_rsp_index" means "the first buffered status line".
        session: Session whose server_buf is searched.

    Returns:
        ({"status", "status_text", "outcome"}, bytes to consume) or None if
        that response is not buffered yet. "status" is the 3-digit code as a
        str ("200"), like every other detector's status.
    """
    rsp_index = p.finding.get("_rsp_index")
    want = 0 if rsp_index is None else rsp_index - session.http_rsp_gone
    if want < 0:
        return None
    # Scan the server_buf bytearray directly (positional counting uses
    # http_rsp_gone, not a byte floor), so nothing is copied per packet
    # (TODO.md #23).
    for n, match in enumerate(_RESPONSE_LINE_RE.finditer(session.server_buf)):
        if n == want:
            session.http_rsp_gone += want + 1
            status = int(match.group(1))
            return ({"status": str(status),
                     "status_text": match.group(2).decode("utf-8", "replace").strip(),
                     "outcome": _outcome(status)},
                    match.end())
    return None


def detect_stream(session, ts: float) -> list[dict]:
    """
    Stream-aware HTTP Basic Auth detector.

    Scans the session's client buffer for complete HTTP requests containing
    an Authorization: Basic header, and registers each one as a pending
    finding (resolve() pairs it with its response, on the same packet if it
    is already buffered). Consumes every scanned request header block (with
    or without credentials) from the client buffer to avoid re-detection on
    subsequent packets. Each request block is numbered (Session.http_req_seen)
    so resolve() can pick its own response.

    The scan is bounded to _MAX_SCAN_CLIENT bytes per call to prevent O(n²)
    CPU usage at high line speed. The client buffer is consumed before
    per-request processing so the buffer always advances, even if processing
    raises an exception.

    Args:
        session: Session object from session.SessionTable.
        ts:      Unix timestamp of the current packet.

    Returns:
        Always an empty list; findings are registered on the session as
        pending and emitted by tscan_ng.resolve once resolved.
    """
    # Skip sessions that are not on a known HTTP/proxy port.
    # Neither dport nor sport in _HTTP_PORTS means this is definitely not HTTP.
    if not on_ports(session, _HTTP_PORTS):
        return []


    while True:
        # Skip any request body left over from the previous request before
        # looking for the next header block, so a POST/PUT payload is never
        # parsed as the next request (TODO.md #22). Drain whatever has arrived;
        # if the body is not all here yet, wait for more data.
        if session.http_body_remaining:
            drop = min(session.http_body_remaining, len(session.client_buf))
            del session.client_buf[:drop]
            session.http_body_remaining -= drop
            if session.http_body_remaining:
                break

        # Limit the scan to _MAX_SCAN_CLIENT bytes to keep per-packet work
        # O(1). If no complete header is found within this window, wait for
        # more data to arrive.
        scan = bytes(session.client_buf[:_MAX_SCAN_CLIENT + 4])
        header_end = scan.find(b"\r\n\r\n")
        if header_end == -1:
            # No header boundary in the window. If the buffer has grown past the
            # window, drop the scanned prefix so a header block larger than the
            # window (or a bodiless stream with no boundary) cannot stall the
            # session forever (TODO.md #22b, same mechanism as #16). A request
            # whose header block exceeds the window is lost, but later requests
            # on the connection are recovered.
            advance_scan_window(session, _MAX_SCAN_CLIENT, line_oriented=True)
            break

        # Consume the request headers from the session buffer NOW, before any
        # processing that could raise. This guarantees the buffer always
        # advances and prevents re-processing the same request on every
        # subsequent packet if an exception occurs below.
        consume = header_end + 4
        headers = bytes(session.client_buf[:consume])
        del session.client_buf[:consume]

        # Record this request's body length so the next loop iteration skips it
        # before scanning for the following request (TODO.md #22a).
        session.http_body_remaining = _body_length(headers)

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
        method = req_match.group(1).decode("utf-8", "replace") if req_match else ""
        uri    = req_match.group(2).decode("utf-8", "replace") if req_match else ""

        if not method:
            # Authorization header present but no parseable request line.
            # Still emit the finding — credentials are the primary artifact —
            # but log so anomalous requests are visible during troubleshooting.
            logging.debug(
                "http_basic: session %s: Authorization header with no request line",
                session.session_id)

        # Extract Host header
        host_match = _HOST_HEADER_RE.search(headers)
        host = host_match.group(1).decode("utf-8", "replace") if host_match else ""

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

        base = base_finding(session, "http_basic", creds, host=host, method=method, uri=uri)

        # "_rsp_index" (underscore fields are stripped before output) tells
        # resolve() which response belongs to this request.
        session.add_pending({**base, "_rsp_index": rsp_index}, ts_start=ts)

    return []
