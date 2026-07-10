"""
pipeline.py - Fan-out capture+detect pipeline for tscan-ng.

Replaces the capture.py -> Unix socket -> run.py dispatcher ->
multiprocessing.Queue -> worker_main() architecture with N self-contained
processes, each independently capturing from the interface via a raw
AF_PACKET socket joined to a shared PACKET_FANOUT_HASH group.

Why: the old architecture had ONE process (the dispatcher) parsing and
flow-hashing every packet before any of the N workers ever saw it, making
that single process a serial bottleneck upstream of the parallelism the
workers were meant to provide. Confirmed live under sustained load: worker
queues sat at 0 drops the entire time while dispatcher backpressure alone
dropped hundreds of thousands of packets -- the workers were never the
constraint, the single-threaded dispatcher was.

The kernel's PACKET_FANOUT_HASH computes a symmetric 5-tuple hash per
packet and guarantees all packets of a given flow land on the same fanout
member -- the same invariant the old dispatcher's _flow_key() hash provided
by hand in run.py -- so each pipeline process's SessionTable never needs to
coordinate with any other pipeline process.

Each pipeline process is a complete, independent capture-to-finding path:
raw socket recv() -> parse_basic() -> SessionTable -> detectors ->
JSONLSink. JSONLSink already flock()s file writes (see sinks/jsonl.py), so
N processes safely share one output file with no further coordination.

The BPF filter is compiled via libpcap's pcap_open_dead() + pcap_compile()
(see capture.py) rather than reimplementing a BPF compiler, then attached
directly to the raw socket with SO_ATTACH_FILTER -- classic BPF bytecode
is identical whether it ends up driving a pcap handle or a Linux socket
filter, so no translation is needed.
"""

import ctypes, logging, multiprocessing as mp, socket, struct, time
from tscan_ng.config import Config
from tscan_ng.parsing.net import parse_basic, DLT_EN10MB
from tscan_ng.detectors import DETECTORS, STREAM_DETECTORS, configure_all
from tscan_ng.sinks.jsonl import JSONLSink
from tscan_ng.session import SessionTable
from tscan_ng.run import _try_resolve
from tscan_ng.capture import (
    pcap_open_dead, bpf_program, pcap_compile, pcap_freecode, pcap_close,
    PCAP_NETMASK_UNKNOWN, _err, _build_port_filter,
)

# --- Linux AF_PACKET / PACKET_FANOUT constants ---
# Not exposed by Python's socket module (Linux-specific, not POSIX); values
# from linux/if_packet.h and asm-generic/socket.h.
SOL_PACKET = 263
PACKET_ADD_MEMBERSHIP = 1
PACKET_MR_PROMISC = 1
PACKET_FANOUT = 18
PACKET_FANOUT_HASH = 0
PACKET_FANOUT_FLAG_DEFRAG = 0x8000
SO_ATTACH_FILTER = 26
SO_RCVBUFFORCE = 33
ETH_P_ALL = 0x0003
PACKET_STATISTICS = 6

# Arbitrary but fixed group ID shared by every pipeline process so they all
# join the same PACKET_FANOUT group. Fanout groups are scoped per network
# namespace, so collision with an unrelated process on this host is not a
# practical concern.
_FANOUT_GROUP_ID = 0xACE1


class sock_filter(ctypes.Structure):
    """
    Maps to C struct sock_filter (code, jt, jf, k).

    Binary-identical layout to libpcap's bpf_insn -- both are the classic
    BPF instruction format -- so a program compiled by pcap_compile() can
    be handed to SO_ATTACH_FILTER with no translation, just a reinterpret
    of the same bytes.
    """
    _fields_ = [("code", ctypes.c_uint16), ("jt", ctypes.c_uint8),
                ("jf", ctypes.c_uint8), ("k", ctypes.c_uint32)]


class sock_fprog(ctypes.Structure):
    """Maps to C struct sock_fprog, the argument type for SO_ATTACH_FILTER."""
    _fields_ = [("len", ctypes.c_ushort),
                ("filter", ctypes.POINTER(sock_filter))]


def _attach_filter(sock: socket.socket, expr: str, snaplen: int):
    """
    Compile a tcpdump/pcap-filter expression and attach it to an AF_PACKET
    socket via SO_ATTACH_FILTER, so the kernel drops non-matching packets
    before they ever reach userspace.

    Uses pcap_open_dead() to compile against DLT_EN10MB without an
    activated capture handle, and therefore without needing CAP_NET_RAW
    just to compile a filter. All of the pcap-allocated memory backing the
    compiled program (prog.bf_insns) must stay valid until the kernel
    actually reads it during the setsockopt() call -- freeing it any
    earlier would leave the embedded pointer dangling -- so compile,
    attach, and free all happen together in this one function rather than
    being split across a return boundary.

    Args:
        sock:    An already-created AF_PACKET socket (bound or unbound).
        expr:    BPF filter expression, e.g. "tcp and (port 21 or port 25)".
        snaplen: Snapshot length to compile the filter against.

    Raises:
        RuntimeError: If the dead handle can't be opened or the filter
                      fails to compile.
    """
    dead = pcap_open_dead(DLT_EN10MB, snaplen)
    if not dead:
        raise RuntimeError("pcap_open_dead failed")
    try:
        prog = bpf_program()
        if pcap_compile(dead, ctypes.byref(prog), expr.encode(), 1,
                        PCAP_NETMASK_UNKNOWN) != 0:
            raise RuntimeError(f"pcap_compile({expr!r}): {_err(dead)}")
        try:
            insns_ptr = ctypes.cast(ctypes.c_void_p(prog.bf_insns),
                                    ctypes.POINTER(sock_filter))
            fprog = sock_fprog(prog.bf_len, insns_ptr)
            sock.setsockopt(socket.SOL_SOCKET, SO_ATTACH_FILTER, bytes(fprog))
        finally:
            pcap_freecode(ctypes.byref(prog))
    finally:
        pcap_close(dead)


def _open_fanout_socket(iface: str, group_id: int, bpf_filter: str,
                        snaplen: int, buf_bytes: int) -> socket.socket:
    """
    Open an AF_PACKET raw socket bound to iface, filtered, promiscuous, and
    joined to a PACKET_FANOUT group.

    Order matters and follows packet(7): bind() to the interface first,
    then join the fanout group -- a socket must already be bound before it
    can join a fanout group. The filter is attached right after bind() and
    before the fanout join, to minimize the window where unfiltered
    traffic could queue on this socket.

    Args:
        iface:      Interface name to capture from.
        group_id:   Shared fanout group ID -- every pipeline process must
                    be called with the same value to end up in the same
                    group and share the kernel's flow-hash distribution.
        bpf_filter: BPF filter expression attached via SO_ATTACH_FILTER.
        snaplen:    Snapshot length; also used as the recv() buffer size.
        buf_bytes:  Kernel socket receive buffer size in bytes. The old
                    libpcap-based capture explicitly sized its ring buffer
                    to this (capture.buffer_bytes); a plain AF_PACKET
                    socket defaults to whatever net.core.rmem_default is
                    (commonly ~208KB), which is far too small to absorb a
                    traffic burst and would silently regress burst
                    handling versus the old capture path. Set via
                    SO_RCVBUFFORCE (needs CAP_NET_ADMIN, already granted
                    to this service) rather than SO_RCVBUF, since plain
                    SO_RCVBUF is capped at net.core.rmem_max -- which
                    defaults to the same small value as rmem_default and
                    would silently clamp the requested size otherwise.

    Returns:
        A bound, filtered, fanout-joined, promiscuous AF_PACKET socket.
    """
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                         socket.htons(ETH_P_ALL))
    sock.setsockopt(socket.SOL_SOCKET, SO_RCVBUFFORCE, buf_bytes)
    sock.bind((iface, 0))
    _attach_filter(sock, bpf_filter, snaplen)

    # Promiscuous mode scoped to this socket via PACKET_ADD_MEMBERSHIP
    # (dropped automatically when the socket closes) rather than an
    # ip-link-level toggle -- this is the same mechanism libpcap uses under
    # the hood for pcap_set_promisc() on Linux.
    if_index = socket.if_nametoindex(iface)
    mreq = struct.pack("=IHH8s", if_index, PACKET_MR_PROMISC, 0, b"\x00" * 8)
    sock.setsockopt(SOL_PACKET, PACKET_ADD_MEMBERSHIP, mreq)

    mode = PACKET_FANOUT_HASH | PACKET_FANOUT_FLAG_DEFRAG
    # PACKET_FANOUT_FLAG_DEFRAG sets bit 31 once shifted into the high
    # 16 bits, so this value overflows a signed 32-bit int -- Python's
    # setsockopt(level, opt, int) overload can't parse it (silently falls
    # back to demanding a bytes-like object instead). Pack it explicitly
    # as unsigned 32-bit to sidestep that.
    sock.setsockopt(SOL_PACKET, PACKET_FANOUT,
                    struct.pack("=I", group_id | (mode << 16)))

    return sock


def _maybe_run_periodic(sock: socket.socket, sessions: SessionTable, sink: JSONLSink,
                        pipeline_id: int, last_expiry: float,
                        expiry_interval: float) -> float:
    """
    Run session expiry and log kernel-level packet drops, if expiry_interval
    has elapsed since the last run.

    Called from both the recv() timeout branch (quiet periods) and after
    every successfully processed packet, mirroring the old worker's expiry
    timing exactly.

    Also polls PACKET_STATISTICS for drops the kernel made before this
    process ever saw the packet (receive buffer full). This is the only way
    to see those drops -- unlike the old capture.py/dispatcher.py, which
    counted every drop explicitly in application code because backpressure
    happened at a socket send()/queue.put() this code controlled, a kernel-
    level AF_PACKET drop happens silently with nothing in the recv() path
    to observe it. PACKET_STATISTICS is a read-and-clear counter, so
    polling it on this same timer is the only way to catch it.

    Args:
        sock:            The pipeline's fanout socket.
        sessions:        The pipeline's SessionTable.
        sink:            The pipeline's JSONLSink.
        pipeline_id:     0-based index, used only for logging.
        last_expiry:     Monotonic timestamp of the last periodic run.
        expiry_interval: Minimum seconds between periodic runs.

    Returns:
        The new last_expiry timestamp (unchanged if the interval hasn't
        elapsed yet).
    """
    now = time.monotonic()
    if now - last_expiry < expiry_interval:
        return last_expiry
    for f in sessions.expire():
        sink.write({"ts": f["ts_start"], **f})
    _, drops = struct.unpack(
        "=II", sock.getsockopt(SOL_PACKET, PACKET_STATISTICS, 8))
    if drops:
        logging.warning(
            "pipeline[%d]: kernel dropped %d packet(s) -- socket recv buffer "
            "full, increase capture.buffer_bytes", pipeline_id, drops)
    return now


def pipeline_worker(pipeline_id: int, cfg: Config, group_id: int):
    """
    Self-contained capture-to-finding pipeline: one raw AF_PACKET fanout
    socket, one SessionTable, one JSONLSink, all in a single process.

    Architecturally identical to run.py's old worker_main() -- same
    SessionTable usage, same detector loop, same pending-finding
    resolution via _try_resolve(), same expiry-on-timeout pattern -- the
    only thing that changes is where packets come from: a socket this
    process owns and reads directly, instead of a multiprocessing.Queue
    fed by a separate dispatcher process. Every packet this process
    receives is guaranteed by the kernel's PACKET_FANOUT_HASH to belong to
    a flow no other pipeline process is handling, so there is no
    coordination needed between pipeline processes.

    recv() uses a 1-second socket timeout so session expiry runs even
    during quiet periods with no incoming traffic, mirroring the old
    worker's queue.get(timeout=1.0) pattern.

    Packet timestamps use time.time() at the point recv() returns, not a
    kernel capture timestamp -- unlike the old pcap-based path, which had
    an accurate kernel timestamp from pcap_next_ex(), a raw recv() would
    need SO_TIMESTAMP ancillary data via recvmsg() to get one. Findings use
    these timestamps only for correlation/expiry ordering, not forensic
    packet timing, so the small latency skew is an acceptable simplification.

    Args:
        pipeline_id: 0-based index, used only for logging.
        cfg:         Loaded Config object.
        group_id:    Shared PACKET_FANOUT group ID -- every pipeline
                     process must be called with the same value.
    """
    logging.basicConfig(
        level=logging.DEBUG,
        format=f"%(levelname)s pipeline[{pipeline_id}] pid=%(process)d %(message)s")
    configure_all(cfg)

    bpf_filter = cfg.bpf_filter
    if bpf_filter is None:
        bpf_filter = _build_port_filter(cfg)

    sock = _open_fanout_socket(cfg.iface, group_id, bpf_filter, cfg.snaplen,
                               cfg.buffer_bytes)
    sock.settimeout(1.0)

    sink = JSONLSink(cfg.out_path or None)
    sessions = SessionTable(
        max_buf=cfg.session_max_buf,
        timeout=cfg.session_timeout,
        pending_max_age=cfg.pending_max_age,
        max_sessions=cfg.max_sessions,
    )
    last_expiry = time.monotonic()
    logging.info("pipeline started, iface=%s filter=%r", cfg.iface, bpf_filter)

    # Consecutive failure counter — reset to 0 on every successful packet.
    fail_count = 0
    while True:
        try:
            frame = sock.recv(cfg.snaplen)
        except socket.timeout:
            # No packets for 1 second. Run session expiry and loop.
            last_expiry = _maybe_run_periodic(
                sock, sessions, sink, pipeline_id, last_expiry, cfg.expiry_interval)
            continue
        except OSError:
            logging.exception("pipeline[%d]: recv error, exiting", pipeline_id)
            break

        ts = time.time()
        pkt = parse_basic(DLT_EN10MB, frame)
        if not pkt:
            # Expected for non-IP or non-TCP/UDP traffic that still matched
            # the BPF filter's link-layer scope (e.g. ARP is never seen
            # here since the filter is "tcp and (...)", but kept as a
            # cheap guard rather than assuming the filter is infallible).
            continue

        try:
            session, closed = sessions.add_packet(pkt, ts)
            for f in closed:
                sink.write({"ts": f["ts_start"], **f})
            for det in DETECTORS:
                for f in det(pkt):
                    sink.write({"ts": ts, **f})
            for det in STREAM_DETECTORS:
                for f in det(session, ts):
                    sink.write({"ts": ts, **f})
            if session.pending:
                still_pending = []
                for p in session.pending:
                    resolved = _try_resolve(p, session, ts)
                    if resolved:
                        sink.write(resolved)
                    else:
                        still_pending.append(p)
                session.pending = still_pending
            last_expiry = _maybe_run_periodic(
                sock, sessions, sink, pipeline_id, last_expiry, cfg.expiry_interval)
            fail_count = 0  # Reset on success
        except Exception:
            logging.exception(
                "pipeline[%d]: unhandled exception processing packet", pipeline_id)
            fail_count += 1
            if fail_count >= 100:
                logging.error("pipeline[%d]: %d consecutive failures, exiting",
                              pipeline_id, fail_count)
                break

    for f in sessions.flush_all():
        sink.write({"ts": f["ts_start"], **f})
    sock.close()


def main(cfg: Config):
    """
    Spawn cfg.workers pipeline processes sharing one PACKET_FANOUT group.

    Unlike the old dispatcher/worker split, there is no coordinating
    process needed once the pipelines are running -- each is fully
    independent. This process's only job is to start them and wait.

    Shutdown handling mirrors run.py's old dispatcher(): best-effort on
    KeyboardInterrupt (SIGINT), which is the same level of graceful
    shutdown the old code had. Neither the old nor the new code installs a
    custom SIGTERM handler, so `systemctl stop` still terminates pipeline
    processes without flushing pending sessions -- a pre-existing gap, not
    introduced by this change.

    Args:
        cfg: Loaded Config object.
    """
    procs = [mp.Process(target=pipeline_worker, args=(i, cfg, _FANOUT_GROUP_ID),
                        daemon=False)
             for i in range(cfg.workers)]
    for p in procs:
        p.start()

    try:
        for p in procs:
            p.join()
    except KeyboardInterrupt:
        for p in procs:
            p.terminate()
        for p in procs:
            p.join(timeout=5)
            if p.is_alive():
                logging.warning("pipeline: pid=%d did not exit cleanly, killing", p.pid)
                p.kill()
                p.join(timeout=1)


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(levelname)s %(message)s",
    )
    try:
        cfg = Config()
    except ValueError as exc:
        logging.critical("tscan-pipeline: configuration error — %s", exc)
        raise SystemExit(1)
    main(cfg)
