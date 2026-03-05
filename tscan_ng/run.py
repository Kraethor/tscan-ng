"""
run.py - Dispatcher and worker entry point for tscan-ng.

Receives raw packets from the capture process via a Unix datagram socket,
dispatches them to a pool of worker processes using flow-affinity routing,
and writes detection findings to a JSONL sink.

Configuration is loaded from /opt/tscan/tscan_ng/config/tscan_ng.conf at
startup. See tscan_ng/config.py for all available settings and their defaults.

Flow affinity ensures all packets belonging to the same TCP/UDP session
(identified by src_ip, dst_ip, sport, dport) are always routed to the same
worker. Each worker maintains a SessionTable that buffers reassembled streams
per flow in both directions.

Per-packet detectors run on every parsed packet. Stream-aware detectors run
after each packet is added to its session, operating on the full reassembled
client and server buffers. Pending findings (credentials seen but no server
response yet) are registered on the session and resolved when the response
arrives, or closed out as no_response on session expiry or shutdown.

Phase status:
    Phase 1 - Flow affinity routing:        COMPLETE
    Phase 2 - Per-worker stream buffering:  COMPLETE
    Phase 3 - Stream-aware detectors:       COMPLETE
    Phase 4 - Response correlation:         COMPLETE
    Phase 5 - Session expiry and cleanup:   COMPLETE
"""

import os, struct, socket, time, multiprocessing as mp
from tscan_ng.config import Config
from tscan_ng.parsing.net import parse_basic
from tscan_ng.detectors import DETECTORS, STREAM_DETECTORS
from tscan_ng.detectors.http_basic import _parse_response, _outcome
from tscan_ng.detectors.imap import _IMAP_RESPONSE_RE, _outcome as _imap_outcome
from tscan_ng.detectors.ftp import _FTP_RESPONSE_RE, _outcome as _ftp_outcome
from tscan_ng.detectors.smtp import _SMTP_RESPONSE_RE, _outcome as _smtp_outcome
from tscan_ng.sinks.jsonl import JSONLSink
from tscan_ng.session import SessionTable

HDR = struct.Struct("!IIIHH")  # sec, usec, caplen, l2type, pad


def _flow_key(src: str, dst: str, sport: int, dport: int) -> int:
    """
    Compute a stable hash for a network flow used to select a worker.

    The hash is symmetric with respect to the direction of the flow —
    both (src->dst) and (dst->src) map to the same worker. This ensures
    that request and response packets for the same session are always
    handled by the same worker process, which is required for stateful
    stream reassembly and response correlation.

    Args:
        src:   Source IP address string.
        dst:   Destination IP address string.
        sport: Source port number.
        dport: Destination port number.

    Returns:
        A stable non-negative integer hash suitable for worker selection
        via modulo.
    """
    a, b = (src, sport), (dst, dport)
    if a > b:
        a, b = b, a
    return hash((a, b)) & 0x7FFFFFFF


def _try_resolve(p, session, ts: float) -> dict | None:
    """
    Attempt to resolve a pending finding against available server buffer data.

    Dispatches to the appropriate resolver based on the finding type.
    Returns a completed finding dict if resolved, or None if still pending.

    For protocols where session direction may be inverted (e.g. FTP, where
    the server sends the first packet), the pending finding stores a
    '_client_is_client' flag set by the detector to indicate which buffer
    contains server responses. Private fields prefixed with '_' are stripped
    from the final emitted finding.

    Args:
        p:       PendingFinding object from the session.
        session: Session object containing server_buf and client_buf.
        ts:      Unix timestamp of the current packet.

    Returns:
        Completed finding dict if resolved, None otherwise.
    """
    finding_type = p.finding.get("type", "")

    # Strip private fields (prefixed with _) from the emitted finding
    clean_finding = {k: v for k, v in p.finding.items() if not k.startswith("_")}

    if finding_type == "http_basic":
        response = _parse_response(session.server_buf)
        if response:
            status, status_text = response
            return {
                **clean_finding,
                "ts":          p.ts_start,
                "ts_start":    p.ts_start,
                "ts_end":      ts,
                "status":      status,
                "status_text": status_text,
                "outcome":     _outcome(status),
            }

    elif finding_type == "imap_creds":
        tag = p.finding.get("tag", "")
        server_text = session.server_buf.decode("utf-8", "ignore")
        for resp_match in _IMAP_RESPONSE_RE.finditer(server_text):
            if resp_match.group(1).upper() == tag.upper():
                status = resp_match.group(2).upper()
                return {
                    **clean_finding,
                    "ts_start":    p.ts_start,
                    "ts_end":      ts,
                    "status":      status,
                    "outcome":     _imap_outcome(status),
                }

    elif finding_type in ("ftp_creds", "ftp_anonymous"):
        client_is_client = p.finding.get("_client_is_client", True)
        server_bytes = (bytes(session.server_buf) if client_is_client
                        else bytes(session.client_buf))
        response = _FTP_RESPONSE_RE.search(server_bytes)
        if response:
            code = response.group(1)
            return {
                **clean_finding,
                "ts_start":    p.ts_start,
                "ts_end":      ts,
                "status":      code.decode("utf-8", "ignore"),
                "outcome":     _ftp_outcome(code),
            }

    elif finding_type == "smtp_creds":
        response = _SMTP_RESPONSE_RE.search(bytes(session.server_buf))
        if not response:
            # Check inverted direction
            response = _SMTP_RESPONSE_RE.search(bytes(session.client_buf))
        if response:
            code = response.group(1)
            return {
                **clean_finding,
                "ts_start":    p.ts_start,
                "ts_end":      ts,
                "status":      code.decode("utf-8", "ignore"),
                "outcome":     _smtp_outcome(code),
            }
    return None


def worker_main(pipe, cfg: Config):
    """
    Worker process entry point.

    Receives (ts, l2type, buf) tuples from the dispatcher via a multiprocessing
    Pipe, parses each packet, accumulates it into the per-flow SessionTable,
    runs per-packet detectors, runs stream-aware detectors, resolves any
    pending findings against newly arrived server responses, and writes all
    findings to the configured JSONLSink.

    Session expiry runs on a wall-clock timer using cfg.expiry_interval.
    On shutdown (None sentinel received), all remaining sessions are flushed
    and any pending findings are emitted as no_response before exit.

    Args:
        pipe: The child end of a multiprocessing.Pipe connection.
        cfg:  Loaded Config object.
    """
    sink = JSONLSink(cfg.out_path or None)
    sessions = SessionTable(
        max_buf=cfg.session_max_buf,
        timeout=cfg.session_timeout,
    )
    last_expiry = time.monotonic()

    while True:
        msg = pipe.recv()
        if msg is None:
            for f in sessions.flush_all():
                sink.write({"ts": f["ts_start"], **f})
            break

        ts, l2type, buf = msg
        pkt = parse_basic(l2type, buf)
        if not pkt:
            continue

        # Accumulate packet into session stream buffers
        session = sessions.add_packet(pkt, ts)

        # Run per-packet detectors
        for det in DETECTORS:
            for f in det(pkt):
                sink.write({"ts": ts, **f})

        # Run stream-aware detectors
        for det in STREAM_DETECTORS:
            for f in det(session, ts):
                sink.write({"ts": ts, **f})

        # Resolve any pending findings if a server response has now arrived
        if session.pending and session.server_buf:
            still_pending = []
            for p in session.pending:
                resolved = _try_resolve(p, session, ts)
                if resolved:
                    sink.write(resolved)
                else:
                    still_pending.append(p)
            session.pending = still_pending

        # Run expiry on wall-clock timer
        now = time.monotonic()
        if now - last_expiry >= cfg.expiry_interval:
            for f in sessions.expire():
                sink.write({"ts": f["ts_start"], **f})
            last_expiry = now


def dispatcher(cfg: Config):
    """
    Main dispatcher loop.

    Binds a Unix datagram socket to receive packets from the capture process,
    spawns a pool of worker processes, and routes packets to workers using
    flow-affinity hashing on (src_ip, dst_ip, sport, dport).

    Flow affinity guarantees that all packets from a given TCP/UDP session
    are handled by the same worker, which is required for stateful stream
    processing. Packets that cannot be parsed for flow key extraction fall
    back to round-robin dispatch.

    Shuts down cleanly on KeyboardInterrupt, sending a None sentinel to each
    worker to signal termination and allow graceful session flushing.

    Args:
        cfg: Loaded Config object.
    """
    parents, procs = [], []
    for _ in range(cfg.workers):
        p_end, c_end = mp.Pipe()
        p = mp.Process(target=worker_main, args=(c_end, cfg), daemon=True)
        p.start(); c_end.close()
        parents.append(p_end); procs.append(p)

    if os.path.exists(cfg.socket_path):
        os.unlink(cfg.socket_path)
    s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    s.bind(cfg.socket_path)
    os.chmod(cfg.socket_path, 0o660)

    rr = 0
    try:
        while True:
            buf = s.recv(65536 + HDR.size)
            if len(buf) < HDR.size:
                continue
            sec, usec, caplen, l2type, _ = HDR.unpack_from(buf, 0)
            payload = memoryview(buf)[HDR.size:HDR.size + caplen].tobytes()
            ts = sec + usec / 1_000_000.0

            pkt = parse_basic(l2type, payload)
            if pkt:
                worker_idx = _flow_key(pkt["src"], pkt["dst"],
                                       pkt["sport"], pkt["dport"]) % cfg.workers
            else:
                worker_idx = rr % cfg.workers
                rr += 1

            parents[worker_idx].send((ts, l2type, payload))

    except KeyboardInterrupt:
        pass
    finally:
        for pe in parents:
            try: pe.send(None)
            except BrokenPipeError: pass
        for p in procs:
            p.join(timeout=5)


if __name__ == "__main__":
    cfg = Config()
    dispatcher(cfg)
