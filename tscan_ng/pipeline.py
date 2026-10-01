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
JSONLSink + DiscordSink. JSONLSink already flock()s file writes (see
sinks/jsonl.py), so N processes safely share one output file with no
further coordination. DiscordSink (see sinks/discord.py) fires a webhook
alert on a background thread for every finding except outcome "failed"
(and unanswered SNMP probes), so alerting is always on -- it does not depend on anything
reading the JSONL log. Repeat findings are collapsed before either sink by
_emit()'s cross-process cooldown.

Entry point: `python -m tscan_ng.pipeline` loads Config() and calls main().
Detectors only park credentials as pending findings; resolve.py's
resolve_pending() matches them with their server responses, right after
the detectors on every packet (TODO.md #56).

The BPF filter is compiled via libpcap's pcap_open_dead() + pcap_compile()
(see capture.py) rather than reimplementing a BPF compiler, then attached
directly to the raw socket with SO_ATTACH_FILTER -- classic BPF bytecode
is identical whether it ends up driving a pcap handle or a Linux socket
filter, so no translation is needed.
"""

import ctypes, hashlib, logging, multiprocessing as mp, multiprocessing.connection, os, signal, socket, struct, sys, time
from tscan_ng.config import Config
from tscan_ng.parsing.net import parse_basic, DLT_EN10MB
from tscan_ng.detectors import STREAM_DETECTORS, configure_all
from tscan_ng.sinks.jsonl import JSONLSink
from tscan_ng.sinks.discord import DiscordSink
from tscan_ng.sinks.cooldown import claim_slot
from tscan_ng.session import SessionTable
from tscan_ng.resolve import resolve_pending
from tscan_ng.capture import (
    pcap_open_dead, bpf_program, pcap_compile, pcap_freecode, pcap_close,
    PCAP_NETMASK_UNKNOWN, _err, _build_port_filter,
)

# Marker directory for _emit()'s per-(dst, dport, creds, outcome) finding cooldown --
# one marker file per key, same cross-process reasoning as DiscordSink's own
# notify() cooldown (see sinks/cooldown.py): all cfg.workers pipeline_worker
# processes must agree on whether a given key was already emitted recently,
# and the only thing they all share is the filesystem. /run/tscan is created
# by tscan-pipeline.service via RuntimeDirectory=tscan.
_FINDING_COOLDOWN_DIR = "/run/tscan/finding_cooldown"

# --- Linux AF_PACKET / PACKET_FANOUT constants ---
# Not exposed by Python's socket module (Linux-specific, not POSIX); values
# from linux/if_packet.h and asm-generic/socket.h.
SOL_PACKET = 263                  # setsockopt level for AF_PACKET options
PACKET_ADD_MEMBERSHIP = 1         # option: join a membership (promisc) on an iface
PACKET_MR_PROMISC = 1             # membership type: promiscuous mode
PACKET_FANOUT = 18                # option: join a fanout group
PACKET_FANOUT_HASH = 0            # fanout mode: flow-hash load balancing
PACKET_FANOUT_FLAG_DEFRAG = 0x8000  # fanout flag: reassemble IP fragments first
SO_ATTACH_FILTER = 26             # attach a classic BPF program to the socket
SO_RCVBUFFORCE = 33               # set rcvbuf ignoring rmem_max (needs CAP_NET_ADMIN)
ETH_P_ALL = 0x0003                # protocol: every EtherType
PACKET_STATISTICS = 6             # option: read-and-clear tp_packets/tp_drops

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
        OSError:      From setsockopt() if the kernel rejects the program.
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

    Raises:
        OSError:      If any socket call fails (e.g. missing CAP_NET_RAW /
                      CAP_NET_ADMIN, unknown interface, group already in
                      use with a different mode).
        RuntimeError: If the BPF filter fails to compile (see
                      _attach_filter).
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


# Set by _main_shutdown_handler() when the parent process receives SIGTERM, so
# main() can tell a requested shutdown (workers exiting cleanly after their own
# SIGTERM) from workers dying unexpectedly.
_shutdown_requested = False


class _StopFlag:
    """
    A stop flag that is safe to set from a signal handler.

    Deliberately NOT a threading.Event: Event.set() takes a non-reentrant
    lock, and each worker receives SIGTERM twice in quick succession (once
    from systemd, once from main()'s terminate()). If the second signal
    lands while the first handler is inside Event.set() -- holding that
    lock -- the nested handler blocks forever on it. That left 1-2 of the
    12 workers hung on most restarts until main() SIGKILLed them after 5 s
    (stack dumps showed _handler -> Event.set -> _handler -> Event.set).
    A plain attribute assignment needs no lock and is atomic in CPython.
    """

    __slots__ = ("_flag",)

    def __init__(self):
        self._flag = False

    def set(self) -> None:
        """Mark the flag set (lock-free; reentrancy-safe)."""
        self._flag = True

    def is_set(self) -> bool:
        """True once set() has been called."""
        return self._flag


def _install_worker_stop_handlers() -> _StopFlag:
    """
    Make SIGTERM and SIGINT stop a worker's capture loop instead of killing it.

    `systemctl stop` sends SIGTERM to every process in the unit's cgroup.
    Python's default action terminates the process on the spot, so pending
    sessions were never flushed and any credential seen but not yet answered
    was lost (TODO.md #21). The handler only sets a flag (a lock-free
    _StopFlag, see its docstring for why not threading.Event); the capture loop
    checks it at the top of every iteration (recv() has a 1 s timeout, so the
    loop notices within about a second), then falls through to its normal
    flush_all() and socket close.

    Returns:
        The _StopFlag that is set once a stop signal has been received.
    """
    stop = _StopFlag()

    def _handler(signum, frame):
        stop.set()

    signal.signal(signal.SIGTERM, _handler)
    signal.signal(signal.SIGINT, _handler)
    return stop


def _main_shutdown_handler(signum, frame):
    """Parent-process SIGTERM handler: note the request and unwind like SIGINT."""
    global _shutdown_requested
    _shutdown_requested = True
    raise KeyboardInterrupt


def _install_main_shutdown_handler() -> None:
    """
    Treat SIGTERM in the parent process as a requested shutdown.

    Without this, SIGTERM killed main() outright and its cleanup (terminating
    and joining the workers) never ran. It is converted into the same
    KeyboardInterrupt path main() already uses for SIGINT, and
    _shutdown_requested is set so that workers which exit cleanly in response
    to the same SIGTERM are not mistaken for unexpected worker deaths.
    """
    signal.signal(signal.SIGTERM, _main_shutdown_handler)


def _stamp_resolved(finding: dict, ts: float) -> dict:
    """
    Return a copy of a pending-then-resolved *finding* with a "ts" field.

    resolve.resolve_pending() returns findings without one; without this
    those records had no top-level timestamp (TODO.md #17). "ts" is set to
    the finding's own ts_start (when the credentials were seen); *ts* (the
    current packet time) is only the fallback if ts_start is missing. An
    existing "ts" is left as is.

    Args:
        finding: Resolved finding dict from resolve.resolve_pending().
        ts:      Unix timestamp of the packet that resolved it.

    Returns:
        New dict; the input is not modified.
    """
    return {"ts": finding.get("ts_start", ts), **finding}


def _emit(sink: JSONLSink, discord: DiscordSink, finding: dict,
          finding_cooldown_sec: float = 0) -> None:
    """
    Write *finding* to the JSONL sink and forward it to Discord alerting,
    unless it's still within its (dst, dport, creds) cooldown window.

    The cooldown is checked once here, upstream of both sinks, rather than
    inside each sink -- so a spammer replaying the same bad credentials at
    the same service produces at most one results.jsonl line *and* at most
    one Discord alert per finding_cooldown_sec window, instead of the two
    sinks disagreeing about what counts as a repeat. The cooldown key is
    (dst, dport, creds, outcome). It deliberately excludes "type" and "src":
    the same attacker (or botnet) replaying the same credentials at the same
    service from many source ports/IPs is exactly the noise this is meant to
    collapse. It includes "outcome" so that a "failed" or "no_response"
    finding does not suppress a later "success" with the same credentials --
    a change of outcome is new information (TODO.md #10); each distinct
    outcome is still limited to one emission per window.

    Both sinks share the same write(finding) interface, so every finding
    site in this module calls through here once instead of duplicating the
    two calls. DiscordSink.write() is itself a further no-op if alerting is
    unconfigured or the finding's outcome is "failed".

    Marker files (one per distinct key, named by the SHA-256 of the key so
    arbitrary credential bytes never reach the filesystem as a name) live
    in _FINDING_COOLDOWN_DIR and are only deleted by this code when a sink
    write raises. The slot is claimed before the sinks are written (so
    concurrent workers cannot both emit the same finding); if a sink write
    raises, the marker is removed again so the failed finding does not
    consume the window, and the exception propagates. If the marker cannot
    be opened, claim_slot() fails open and the finding is emitted.

    Args:
        sink:                 The pipeline's JSONLSink.
        discord:              The pipeline's DiscordSink.
        finding:              Finding dict to write/alert on.
        finding_cooldown_sec: Minimum seconds between emissions sharing the
            same (dst, dport, creds, outcome) key. 0 disables the cooldown (every
            finding is emitted) -- see Config.finding_cooldown.
    """
    marker_path = None
    if finding_cooldown_sec > 0:
        key = (f"{finding.get('dst', '')}:{finding.get('dport', '')}:"
               f"{finding.get('creds', '')}:{finding.get('outcome', '')}")
        marker_path = os.path.join(
            _FINDING_COOLDOWN_DIR, hashlib.sha256(key.encode()).hexdigest())
        if not claim_slot(marker_path, finding_cooldown_sec):
            return
    try:
        sink.write(finding)
        discord.write(finding)
    except Exception:
        # The finding was not recorded: give the slot back so the next
        # occurrence is not suppressed for a whole window (TODO.md #10).
        if marker_path:
            try:
                os.unlink(marker_path)
            except OSError:
                pass
        raise


def _maybe_run_periodic(sock: socket.socket, sessions: SessionTable, sink: JSONLSink,
                        discord: DiscordSink, pipeline_id: int, last_expiry: float,
                        expiry_interval: float, finding_cooldown_sec: float = 0) -> float:
    """
    Run session expiry and log kernel-level packet drops, if expiry_interval
    has elapsed since the last run.

    Called by _capture_loop() at the top of every pass, whatever happens
    to the frame (TODO.md #19), so rejected or failing frames cannot starve
    it. Uses time.monotonic() for the interval; returns early with no work
    otherwise.

    Also polls PACKET_STATISTICS for drops the kernel made before this
    process ever saw the packet (receive buffer full). This is the only way
    to see those drops -- unlike the old capture.py/dispatcher.py, which
    counted every drop explicitly in application code because backpressure
    happened at a socket send()/queue.put() this code controlled, a kernel-
    level AF_PACKET drop happens silently with nothing in the recv() path
    to observe it. PACKET_STATISTICS is a read-and-clear counter, so
    polling it on this same timer is the only way to catch it. Only the
    drop count is used; the packet count is discarded. Drops are logged at
    WARNING per poll, not sent to Discord.

    Args:
        sock:                 The pipeline's fanout socket.
        sessions:             The pipeline's SessionTable.
        sink:                 The pipeline's JSONLSink.
        discord:              The pipeline's DiscordSink.
        pipeline_id:          0-based index, used only for logging.
        last_expiry:          Monotonic timestamp of the last periodic run.
        expiry_interval:      Minimum seconds between periodic runs.
        finding_cooldown_sec: Passed through to _emit() -- see its docstring.

    Returns:
        The new last_expiry timestamp (unchanged if the interval hasn't
        elapsed yet).

    Side effects:
        Emits no_response findings for expired sessions via _emit().
    """
    now = time.monotonic()
    if now - last_expiry < expiry_interval:
        return last_expiry
    for f in sessions.expire():
        _emit(sink, discord, {"ts": f["ts_start"], **f}, finding_cooldown_sec)
    _, drops = struct.unpack(
        "=II", sock.getsockopt(SOL_PACKET, PACKET_STATISTICS, 8))
    if drops:
        logging.warning(
            "pipeline[%d]: kernel dropped %d packet(s) -- socket recv buffer "
            "full, increase capture.buffer_bytes", pipeline_id, drops)
    return now


def _capture_loop(sock, cfg, sessions: SessionTable, sink: JSONLSink, discord: DiscordSink,
                  pipeline_id: int, finding_cooldown_sec: float, stop) -> str | None:
    """
    Receive and process packets until *stop* is set or something goes wrong.

    Split out of pipeline_worker() so it can be driven by tests with a fake
    socket. Per frame: parse_basic() -> SessionTable -> detectors ->
    resolve_pending(), emitting every finding through _emit(), plus periodic
    maintenance (_maybe_run_periodic()).

    Args:
        sock:                 Socket-like object with recv() and getsockopt().
        cfg:                  Anything with .snaplen and .expiry_interval.
        sessions, sink, discord, pipeline_id, finding_cooldown_sec:
                              As in pipeline_worker().
        stop:                 Flag with is_set(), set by the stop handlers.

    Returns:
        None on a normal stop, or a reason string when this process must exit
        abnormally (recv() error, or 100 consecutive processing failures).
    """
    last_expiry = time.monotonic()
    # Consecutive failure counter — reset to 0 on every successfully
    # processed packet; hitting 100 (a persistent bug rather than one bad
    # packet) makes this process give up instead of spinning on logged errors.
    fail_count = 0
    while not stop.is_set():
        # Maintenance is checked on every pass, before the frame is even
        # read, so no kind of traffic can starve it (TODO.md #19): it used to
        # run only after a successfully processed frame or an idle 1 s
        # timeout, so a steady stream of frames that parse_basic() rejects or
        # that raise below stopped sessions from ever expiring. It returns
        # at once unless expiry_interval has passed. A failure here is
        # logged and retried next interval rather than ending the worker.
        try:
            last_expiry = _maybe_run_periodic(
                sock, sessions, sink, discord, pipeline_id, last_expiry, cfg.expiry_interval,
                finding_cooldown_sec)
        except Exception:
            logging.exception("pipeline[%d]: periodic maintenance failed", pipeline_id)
            last_expiry = time.monotonic()

        try:
            frame = sock.recv(cfg.snaplen)
        except socket.timeout:
            continue  # idle link; maintenance runs at the top of the loop
        except OSError as exc:
            logging.exception("pipeline[%d]: recv error, exiting", pipeline_id)
            return f"pipeline[{pipeline_id}] pid={os.getpid()} exiting: recv() error ({exc}) -- capture interface may be down"

        ts = time.time()
        pkt = parse_basic(DLT_EN10MB, frame)
        if not pkt:
            # Expected for non-IP or non-TCP/UDP traffic that still matched
            # the BPF filter's link-layer scope (e.g. ARP is never seen
            # here since the auto-built filter only admits tcp/udp on the
            # configured ports, but an explicit capture.bpf_filter may let
            # anything through, so this stays as a cheap guard rather than
            # assuming the filter is infallible).
            continue

        try:
            session, closed = sessions.add_packet(pkt, ts)
            for f in closed:
                _emit(sink, discord, {"ts": f["ts_start"], **f}, finding_cooldown_sec)
            # Detectors park credentials as pending (they return nothing
            # today; the loop keeps the interface open); resolve_pending()
            # then matches any reply already buffered, on this same packet.
            for det in STREAM_DETECTORS:
                for f in det(session, ts):
                    _emit(sink, discord, {"ts": ts, **f}, finding_cooldown_sec)
            if session.pending:
                for resolved in resolve_pending(session, ts):
                    _emit(sink, discord, _stamp_resolved(resolved, ts),
                          finding_cooldown_sec)
            fail_count = 0  # Reset on success
        except Exception:
            logging.exception(
                "pipeline[%d]: unhandled exception processing packet", pipeline_id)
            fail_count += 1
            if fail_count >= 100:
                logging.error("pipeline[%d]: %d consecutive failures, exiting",
                              pipeline_id, fail_count)
                return f"pipeline[{pipeline_id}] pid={os.getpid()} exiting: {fail_count} consecutive processing failures"

    return None


def pipeline_worker(pipeline_id: int, cfg: Config, group_id: int):
    """
    Self-contained capture-to-finding pipeline: one raw AF_PACKET fanout
    socket, one SessionTable, one JSONLSink, all in a single process.

    Architecturally identical to run.py's old worker_main() -- same
    SessionTable usage, same detector loop, same pending-finding
    resolution (now resolve.resolve_pending()), same expiry-on-timeout
    pattern -- the
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

    Error handling: an exception while processing one packet is logged and
    counted; 100 consecutive failures (fail_count resets on any success) or
    an OSError from recv() ends the loop as an abnormal exit. On any loop
    exit (including a SIGTERM/SIGINT stop request) the session table is
    flushed (pending findings closed as
    no_response), the socket closed, and -- if abnormal -- a Discord
    notify() is sent and the process exits with status 1. Startup errors
    (socket/filter setup) propagate as exceptions and also kill the
    process non-zero, without a Discord alert.

    Args:
        pipeline_id: 0-based index, used only for logging.
        cfg:         Loaded Config object.
        group_id:    Shared PACKET_FANOUT group ID -- every pipeline
                     process must be called with the same value.
    """
    # Root logger level in every worker comes from [logging] level (default
    # INFO). DEBUG also enables DEBUG output from libraries and from
    # parsing.net (one traceback per malformed packet), so it is opt-in;
    # sinks/discord.py pins urllib3 to WARNING regardless, so the webhook URL
    # is never logged.
    logging.basicConfig(
        level=cfg.log_level,
        format=f"%(levelname)s pipeline[{pipeline_id}] pid=%(process)d %(message)s")
    configure_all(cfg)

    bpf_filter = cfg.bpf_filter
    if bpf_filter is None:
        bpf_filter = _build_port_filter(cfg)

    sock = _open_fanout_socket(cfg.iface, group_id, bpf_filter, cfg.snaplen,
                               cfg.buffer_bytes)
    sock.settimeout(1.0)  # bounds how long expiry can be starved on a quiet link

    sink = JSONLSink(cfg.out_path or None)
    discord = DiscordSink(cfg.discord_webhook, cooldown_sec=cfg.discord_notify_cooldown)
    finding_cooldown_sec = cfg.finding_cooldown
    if finding_cooldown_sec > 0:
        # Best-effort: if this fails, _emit()'s os.open() will fail too and
        # claim_slot() fails open (see sinks/cooldown.py), so a missing or
        # unwritable directory means "no dedup", never "no logging".
        try:
            os.makedirs(_FINDING_COOLDOWN_DIR, exist_ok=True)
        except OSError:
            pass
    sessions = SessionTable(
        max_buf=cfg.session_max_buf,
        timeout=cfg.session_timeout,
        pending_max_age=cfg.pending_max_age,
        max_sessions=cfg.max_sessions,
        server_ports=cfg.server_ports,
    )
    logging.info("pipeline started, iface=%s filter=%r", cfg.iface, bpf_filter)

    stop = _install_worker_stop_handlers()
    # _capture_loop() returns a reason string on abnormal exit, checked here to
    # decide this process's exit code. A worker dying is only ever supposed
    # to happen via KeyboardInterrupt/terminate() from main() during
    # shutdown (SIGTERM/SIGINT, see _install_worker_stop_handlers); recv()
    # failing or fail_count maxing out means something is
    # actually wrong (e.g. the capture interface went down), and previously
    # this function just returned normally in both cases -- indistinguishable
    # from a clean shutdown to both systemd (exit code 0 never triggers
    # Restart=on-failure) and to anyone watching (nothing said why). Both
    # get an exit code and a Discord alert now.
    abnormal_exit = _capture_loop(sock, cfg, sessions, sink, discord, pipeline_id,
                                  finding_cooldown_sec, stop)

    if stop.is_set():
        logging.info("pipeline[%d]: stop signal received, flushing sessions", pipeline_id)
    for f in sessions.flush_all():
        _emit(sink, discord, {"ts": f["ts_start"], **f}, finding_cooldown_sec)
    sock.close()

    if abnormal_exit:
        # notify() posts on a background daemon thread (and returns None if
        # alerting is off or the shared cooldown already fired); join it (briefly --
        # matches the HTTP call's own 5s timeout) before exiting, since a
        # daemon thread doesn't get to finish once the process exits and
        # this is the last thing this process does.
        alert_thread = discord.notify(abnormal_exit)
        if alert_thread:
            alert_thread.join(timeout=5)
        # Exit non-zero so the parent's main() (and, transitively,
        # systemd's Restart=on-failure) sees this as a real failure instead
        # of a clean shutdown.
        sys.exit(1)


def main(cfg: Config):
    """
    Spawn cfg.workers pipeline processes sharing one PACKET_FANOUT group.

    Unlike the old dispatcher/worker split, there is no coordinating
    process needed once the pipelines are running -- each is fully
    independent. This process's job is to start them, notice if any of
    them ever exits, and tear the rest down + propagate a real failure if
    so -- every pipeline_worker() is meant to run forever, so any exit
    (short of this process itself being interrupted for shutdown) means
    something is wrong.

    Shutdown handling: SIGTERM (what `systemctl stop` sends, to the parent
    and to every worker at once) is converted here into the same
    KeyboardInterrupt path as SIGINT (_install_main_shutdown_handler), and
    each worker installs its own handlers (_install_worker_stop_handlers) so
    it leaves its capture loop and flushes its pending sessions before
    exiting. A worker that exits cleanly because of the same SIGTERM is not
    treated as an unexpected death (_shutdown_requested). Findings still
    pending at that moment are written as no_response instead of being lost
    (TODO.md #21).

    Blocks until a worker dies or the process is interrupted. Workers are
    non-daemon processes, so they are explicitly terminated (SIGTERM, which
    they handle gracefully; then killed if still alive after a 5s join) on
    the way out.

    Args:
        cfg: Loaded Config object.

    Raises:
        SystemExit(1): if any worker exited on its own (as opposed to this
            process being interrupted for a requested shutdown), so
            systemd's Restart=on-failure actually restarts the service
            instead of treating it as a clean stop. The previous version of
            this function returned normally in that case -- looking
            identical to a deliberate shutdown to both systemd and anyone
            watching -- which is how the pipeline ended up silently dead
            for 10 days after the capture interface dropped (see
            pipeline_worker's docstring for the worker side of this fix).
    """
    _install_main_shutdown_handler()
    # Explicit "spawn" start method (TODO.md #27 and #21). Python 3.14 defaults
    # to "forkserver", whose helper processes deadlock the parent's exit once
    # the parent handles SIGTERM itself: the parent's atexit handler waits for
    # the resource tracker, the tracker waits for the forkserver to drop its
    # pipe, and the forkserver waits for the parent to die. The result was
    # `systemctl stop` hanging for the full 90 s TimeoutStopSec. "spawn" has
    # no such helper and still starts every worker as a fresh interpreter
    # (ambient capabilities survive the exec), and pinning it means a Python
    # upgrade cannot silently change how workers are started.
    ctx = mp.get_context("spawn")
    procs = [ctx.Process(target=pipeline_worker, args=(i, cfg, _FANOUT_GROUP_ID),
                         daemon=False)
             for i in range(cfg.workers)]
    for p in procs:
        p.start()

    failed = False
    try:
        # Wait for the first worker to exit, for any reason, rather than
        # joining them in list order. A plain `for p in procs: p.join()`
        # only notices a worker dying once every *earlier* worker in the
        # list has also already exited -- one bad worker among many
        # healthy ones would hang unnoticed forever, leaving the pipeline
        # silently running at reduced capacity with one fanout member
        # permanently gone. mp.connection.wait() on every process's
        # sentinel wakes up on whichever process exits first, with no
        # polling.
        mp.connection.wait(p.sentinel for p in procs)  # blocks; returns on first exit
    except KeyboardInterrupt:
        pass  # Requested shutdown -- not a failure.
    else:
        if _shutdown_requested:
            pass  # SIGTERM reached a worker before it reached us: still a requested shutdown.
        else:
            dead = {p.pid: p.exitcode for p in procs if not p.is_alive()}
            logging.error("pipeline: worker(s) exited unexpectedly, tearing down: %s", dead)
            failed = True

    for p in procs:
        if p.is_alive():
            p.terminate()
    for p in procs:
        p.join(timeout=5)
        if p.is_alive():
            logging.warning("pipeline: pid=%d did not exit cleanly, killing", p.pid)
            p.kill()
            p.join(timeout=1)

    if failed:
        raise SystemExit(1)


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
