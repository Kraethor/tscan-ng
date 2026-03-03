"""
run.py - Dispatcher and worker entry point for tscan-ng.

Receives raw packets from the capture process via a Unix datagram socket,
dispatches them to a pool of worker processes using flow-affinity routing,
and writes detection findings to a JSONL sink.

Flow affinity ensures all packets belonging to the same TCP/UDP session
(identified by src_ip, dst_ip, sport, dport) are always routed to the same
worker. This is a prerequisite for stateful stream reassembly and response
correlation in later phases.

Usage:
    python -m tscan_ng.run --socket /run/tscan/tscan.sock [--workers N] [--out /path/to/results.jsonl]
"""

import argparse, os, struct, socket, multiprocessing as mp
from tscan_ng.parsing.net import parse_basic
from tscan_ng.detectors import DETECTORS
from tscan_ng.sinks.jsonl import JSONLSink

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
    # Sort src/dst so both directions of a flow hash identically
    a, b = (src, sport), (dst, dport)
    if a > b:
        a, b = b, a
    return hash((a, b)) & 0x7FFFFFFF


def worker_main(pipe, out_path: str | None):
    """
    Worker process entry point.

    Receives (ts, l2type, buf) tuples from the dispatcher via a multiprocessing
    Pipe, parses each packet, runs all detectors, and writes any findings to
    the configured JSONLSink.

    All packets belonging to the same flow are guaranteed to arrive at the
    same worker due to flow-affinity routing in the dispatcher. This makes
    this function the correct place to add per-flow session state in later
    phases.

    Args:
        pipe:     The child end of a multiprocessing.Pipe connection.
        out_path: Path to the JSONL output file, or None to write to stdout.
    """
    sink = JSONLSink(out_path if out_path else None)
    while True:
        msg = pipe.recv()
        if msg is None:
            break
        ts, l2type, buf = msg
        pkt = parse_basic(l2type, buf)
        if not pkt:
            continue
        for det in DETECTORS:
            findings = det(pkt)
            for f in findings:
                sink.write({"ts": ts, **f})


def dispatcher(socket_path: str, nworkers: int, out_path: str | None):
    """
    Main dispatcher loop.

    Binds a Unix datagram socket to receive packets from the capture process,
    spawns a pool of worker processes, and routes packets to workers using
    flow-affinity hashing on (src_ip, dst_ip, sport, dport).

    Flow affinity guarantees that all packets from a given TCP/UDP session
    are handled by the same worker, which is required for future stateful
    processing. Packets that cannot be parsed for flow key extraction fall
    back to round-robin dispatch.

    Shuts down cleanly on KeyboardInterrupt, sending a None sentinel to each
    worker to signal termination.

    Args:
        socket_path: Filesystem path for the Unix datagram socket.
        nworkers:    Number of worker processes to spawn.
        out_path:    Path to the JSONL output file, or None for stdout.
    """
    # Spawn workers
    parents, procs = [], []
    for _ in range(nworkers):
        p_end, c_end = mp.Pipe()
        p = mp.Process(target=worker_main, args=(c_end, out_path), daemon=True)
        p.start(); c_end.close()
        parents.append(p_end); procs.append(p)

    # Bind Unix datagram socket to receive from capture process
    if os.path.exists(socket_path):
        os.unlink(socket_path)
    s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    s.bind(socket_path)
    os.chmod(socket_path, 0o660)

    rr = 0  # round-robin fallback counter for unparseable packets
    try:
        while True:
            buf = s.recv(65536 + HDR.size)
            if len(buf) < HDR.size:
                continue
            sec, usec, caplen, l2type, _ = HDR.unpack_from(buf, 0)
            payload = memoryview(buf)[HDR.size:HDR.size + caplen].tobytes()
            ts = sec + usec / 1_000_000.0

            # Attempt to extract flow key for affinity routing.
            # Fall back to round-robin for non-IP or unparseable packets.
            pkt = parse_basic(l2type, payload)
            if pkt:
                worker_idx = _flow_key(pkt["src"], pkt["dst"],
                                       pkt["sport"], pkt["dport"]) % nworkers
            else:
                worker_idx = rr % nworkers
                rr += 1

            parents[worker_idx].send((ts, l2type, payload))

    except KeyboardInterrupt:
        pass
    finally:
        for pe in parents:
            try: pe.send(None)
            except BrokenPipeError: pass
        for p in procs:
            p.join(timeout=1)


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="tscan-ng dispatcher and worker pool.")
    ap.add_argument("--socket", required=True, help="Path to Unix datagram socket.")
    ap.add_argument("--workers", type=int, default=max(1, os.cpu_count() or 1),
                    help="Number of worker processes (default: CPU count).")
    ap.add_argument("--out", default="/var/log/tscan/results.jsonl",
                    help="Output JSONL file path (default: /var/log/tscan/results.jsonl).")
    args = ap.parse_args()
    dispatcher(args.socket, args.workers, args.out or None)
