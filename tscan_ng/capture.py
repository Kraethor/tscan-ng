"""
capture.py - Low-level pcap capture process for tscan-ng.

Opens a network interface in promiscuous mode using libpcap via ctypes,
captures packets at line speed, and forwards them to the dispatcher via
a Unix datagram socket.

Configuration is loaded from /opt/tscan/tscan.conf at startup. See
tscan_ng/config.py for all available settings and their defaults.

Each packet is prefixed with a fixed-size header:
    HDR = struct.Struct("!IIIHH")  # sec, usec, caplen, l2type, pad
"""

import os, sys, ctypes, ctypes.util, logging, time
from tscan_ng.config import Config

PCAP_ERRBUF_SIZE = 256

libpcap_path = ctypes.util.find_library('pcap')
if not libpcap_path:
    raise RuntimeError("libpcap not found")
pcap = ctypes.CDLL(libpcap_path)

pcap_t = ctypes.c_void_p


class timeval(ctypes.Structure):
    """Maps to C struct timeval (tv_sec, tv_usec)."""
    _fields_ = [("tv_sec", ctypes.c_long), ("tv_usec", ctypes.c_long)]


class pcap_pkthdr(ctypes.Structure):
    """Maps to C struct pcap_pkthdr (timestamp, capture length, wire length)."""
    _fields_ = [("ts", timeval), ("caplen", ctypes.c_uint32),
                ("len", ctypes.c_uint32)]


class bpf_program(ctypes.Structure):
    """
    Maps to C struct bpf_program (bf_len, bf_insns).

    bf_insns is populated by pcap_compile() with a pointer to a
    libpcap-allocated instruction array. Never dereferenced from Python —
    it is only ever passed by reference to pcap_setfilter()/pcap_freecode(),
    so c_void_p is sufficient here.
    """
    _fields_ = [("bf_len", ctypes.c_uint), ("bf_insns", ctypes.c_void_p)]


# Passed to pcap_compile() when the capture device's network mask is
# unknown/unavailable, which is always true for us (no netmask-relative
# filter terms like "net"/"broadcast" are used).
PCAP_NETMASK_UNKNOWN = 0xffffffff


# libpcap function bindings
pcap_create = pcap.pcap_create
pcap_create.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
pcap_create.restype = pcap_t

pcap_set_buffer_size = pcap.pcap_set_buffer_size
pcap_set_buffer_size.argtypes = [pcap_t, ctypes.c_int]

pcap_set_snaplen = pcap.pcap_set_snaplen
pcap_set_snaplen.argtypes = [pcap_t, ctypes.c_int]

pcap_set_promisc = pcap.pcap_set_promisc
pcap_set_promisc.argtypes = [pcap_t, ctypes.c_int]

pcap_set_timeout = pcap.pcap_set_timeout
pcap_set_timeout.argtypes = [pcap_t, ctypes.c_int]

pcap_activate = pcap.pcap_activate
pcap_activate.argtypes = [pcap_t]
pcap_activate.restype = ctypes.c_int

pcap_datalink = pcap.pcap_datalink
pcap_datalink.argtypes = [pcap_t]
pcap_datalink.restype = ctypes.c_int

pcap_geterr = pcap.pcap_geterr
pcap_geterr.argtypes = [pcap_t]
pcap_geterr.restype = ctypes.c_char_p

# Proper argtypes using pcap_pkthdr avoids unsafe c_ubyte cast
pcap_next_ex = pcap.pcap_next_ex
pcap_next_ex.argtypes = [
    pcap_t,
    ctypes.POINTER(ctypes.POINTER(pcap_pkthdr)),
    ctypes.POINTER(ctypes.POINTER(ctypes.c_ubyte)),
]
pcap_next_ex.restype = ctypes.c_int

pcap_close = pcap.pcap_close
pcap_close.argtypes = [pcap_t]

pcap_compile = pcap.pcap_compile
pcap_compile.argtypes = [pcap_t, ctypes.POINTER(bpf_program), ctypes.c_char_p,
                         ctypes.c_int, ctypes.c_uint32]
pcap_compile.restype = ctypes.c_int

pcap_setfilter = pcap.pcap_setfilter
pcap_setfilter.argtypes = [pcap_t, ctypes.POINTER(bpf_program)]
pcap_setfilter.restype = ctypes.c_int

pcap_freecode = pcap.pcap_freecode
pcap_freecode.argtypes = [ctypes.POINTER(bpf_program)]

try:
    pcap_set_immediate_mode = pcap.pcap_set_immediate_mode
    pcap_set_immediate_mode.argtypes = [pcap_t, ctypes.c_int]
except AttributeError:
    pcap_set_immediate_mode = None


def _err(pc):
    """Return a human-readable error string from a pcap handle."""
    return (pcap_geterr(pc) or b"unknown").decode("utf-8", "replace")


def _connect_with_retry(sock_path: str,
                        retries: int = 20,
                        delay: float = 0.5) -> "socket.socket":
    """
    Connect a Unix datagram socket to sock_path, retrying until the socket
    file appears.

    Dispatcher creates the socket shortly after its process starts.  Because
    the capture unit starts immediately after systemd considers dispatcher
    active (Type=simple), there is a small window where the socket file does
    not yet exist.  Rather than failing hard and relying on systemd's restart
    loop, we wait here so the two services converge cleanly on every start and
    on every dispatcher restart.

    Args:
        sock_path: Filesystem path of the dispatcher's Unix datagram socket.
        retries:   Maximum number of attempts (default 20 → up to 10 seconds).
        delay:     Seconds to wait between attempts (default 0.5 s).

    Returns:
        A connected AF_UNIX SOCK_DGRAM socket.

    Raises:
        FileNotFoundError: If the socket is still absent after all retries.
    """
    import socket
    for attempt in range(1, retries + 1):
        try:
            s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
            s.connect(sock_path)
            if attempt > 1:
                logging.info("capture: connected to dispatcher socket after "
                             "%d attempt(s)", attempt)
            return s
        except FileNotFoundError:
            if attempt == retries:
                logging.error("capture: dispatcher socket %s not found after "
                              "%d attempts — giving up", sock_path, retries)
                raise
            logging.debug("capture: socket %s not ready (attempt %d/%d), "
                          "retrying in %.1fs", sock_path, attempt, retries, delay)
            time.sleep(delay)


def _build_port_filter(cfg: Config) -> str:
    """
    Build a BPF filter expression restricting capture to the TCP ports any
    protocol detector actually looks at.

    Without this, capture forwards 100% of traffic on the interface to the
    dispatcher for full parsing, even on a SPAN/mirror port carrying mostly
    irrelevant traffic (bulk HTTPS, video, etc.) that no detector will ever
    match. Filtering at the pcap/kernel layer means that traffic never
    reaches userspace at all, rather than being parsed and then discarded.

    Args:
        cfg: Loaded Config object.

    Returns:
        A BPF filter expression string, e.g. "tcp and (port 21 or port 25)".
    """
    ports = set()
    for port_set in (cfg.http_ports, cfg.ftp_ports, cfg.smtp_ports,
                     cfg.imap_ports, cfg.pop3_ports, cfg.telnet_ports,
                     cfg.ldap_ports, cfg.redis_ports):
        ports.update(port_set)
    terms = " or ".join(f"port {p}" for p in sorted(ports))
    return f"tcp and ({terms})"


def capture_into_unix_dgram(iface: str, sock_path: str,
                             buf_bytes: int = 32 * 1024 * 1024,
                             snaplen: int = 65535,
                             immediate: bool = True,
                             bpf_filter: str = None):
    """
    Capture packets from a network interface and forward them to the dispatcher.

    Opens the specified interface with libpcap in promiscuous mode and sends
    each captured packet — prefixed with a metadata header — to the dispatcher
    via a connected Unix datagram socket.

    Waits up to 10 seconds for the dispatcher socket to appear before giving
    up, tolerating the startup race between the two services.

    The socket is set non-blocking so that a slow or stalled dispatcher cannot
    block the capture loop.  If the dispatcher's receive buffer is full
    (BlockingIOError), the packet is dropped and counted.  If the socket
    itself is broken (OSError), a reconnect is attempted automatically so
    capture survives a dispatcher restart without losing the pcap session.

    caplen values outside the range (0, snaplen] are skipped to guard
    against malformed or corrupt pcap headers.

    The packet header format is:
        struct { uint32 sec; uint32 usec; uint32 caplen; uint16 l2type; uint16 pad; }

    Args:
        iface:      Network interface name to capture from (e.g. "eth1").
        sock_path:  Path to the dispatcher's Unix datagram socket.
        buf_bytes:  Kernel capture buffer size in bytes (default: 32MB).
        snaplen:    Maximum bytes to capture per packet (default: 65535).
        immediate:  If True, enable immediate mode for low-latency capture.
                    Falls back to 1ms timeout if immediate mode is unavailable.
        bpf_filter: BPF filter expression (tcpdump/pcap-filter syntax) applied
                    in-kernel so non-matching packets never reach userspace.
                    None skips filtering entirely (capture everything); an
                    empty string "" also matches everything but goes through
                    the same compile/setfilter path. See
                    config.bpf_filter / capture._build_port_filter for how
                    the caller normally derives this from configured ports.
    """
    import struct
    HDR = struct.Struct("!IIIHH")  # sec, usec, caplen, l2type, pad

    s = _connect_with_retry(sock_path)
    # Non-blocking so a stalled dispatcher cannot pause the capture loop.
    s.setblocking(False)

    errbuf = ctypes.create_string_buffer(PCAP_ERRBUF_SIZE)
    pc = pcap_create(iface.encode(), errbuf)
    if not pc:
        s.close()
        print(f"pcap_create failed: {errbuf.value.decode()}", file=sys.stderr)
        os._exit(2)

    if buf_bytes:
        pcap_set_buffer_size(pc, int(buf_bytes))
    pcap_set_snaplen(pc, snaplen)
    pcap_set_promisc(pc, 1)

    # Use timeout=0 only when immediate mode is active to avoid busy-looping
    if immediate and pcap_set_immediate_mode:
        pcap_set_immediate_mode(pc, 1)
        pcap_set_timeout(pc, 0)
    else:
        pcap_set_timeout(pc, 1)

    r = pcap_activate(pc)
    if r != 0:
        msg = _err(pc)
        pcap_close(pc)
        s.close()
        print(f"pcap_activate: {msg}", file=sys.stderr)
        os._exit(3)

    if bpf_filter is not None:
        prog = bpf_program()
        if pcap_compile(pc, ctypes.byref(prog), bpf_filter.encode(),
                        1, PCAP_NETMASK_UNKNOWN) != 0:
            msg = _err(pc)
            pcap_close(pc)
            s.close()
            print(f"pcap_compile({bpf_filter!r}): {msg}", file=sys.stderr)
            os._exit(4)
        if pcap_setfilter(pc, ctypes.byref(prog)) != 0:
            msg = _err(pc)
            pcap_freecode(ctypes.byref(prog))
            pcap_close(pc)
            s.close()
            print(f"pcap_setfilter({bpf_filter!r}): {msg}", file=sys.stderr)
            os._exit(4)
        # Safe to free immediately after pcap_setfilter() succeeds -- it
        # copies the compiled program in, it doesn't hold onto bf_insns.
        pcap_freecode(ctypes.byref(prog))
        logging.info("capture: BPF filter active: %s", bpf_filter)

    dlt = pcap_datalink(pc)
    hdr_ptr = ctypes.POINTER(pcap_pkthdr)()
    data_ptr = ctypes.POINTER(ctypes.c_ubyte)()
    # Running total of packets dropped due to dispatcher backpressure.
    drop_count = 0

    try:
        while True:
            rc = pcap_next_ex(pc, ctypes.byref(hdr_ptr), ctypes.byref(data_ptr))
            if rc == 1:
                hdr = hdr_ptr.contents
                caplen = int(hdr.caplen)
                # Guard against corrupt or malformed pcap headers.
                if caplen == 0 or caplen > snaplen:
                    continue
                sec = int(hdr.ts.tv_sec)
                usec = int(hdr.ts.tv_usec)
                pkt = ctypes.string_at(data_ptr, caplen)
                try:
                    s.send(HDR.pack(sec, usec, caplen, dlt, 0) + pkt)
                except BlockingIOError:
                    # Dispatcher receive buffer is full; drop this packet rather
                    # than blocking the capture loop.  Log every 1000 drops so
                    # sustained backpressure is visible without flooding the log.
                    drop_count += 1
                    if drop_count % 1000 == 1:
                        logging.warning(
                            "capture: %d packet(s) dropped — dispatcher backpressure",
                            drop_count)
                except OSError as exc:
                    # Socket is broken (dispatcher restarted, etc.).  Reconnect
                    # so capture can resume without restarting the pcap session.
                    logging.error("capture: send error (%s), reconnecting", exc)
                    try:
                        s.close()
                    except OSError:
                        pass
                    s = _connect_with_retry(sock_path)
                    s.setblocking(False)
            elif rc == 0:   # timeout — no packet available yet
                continue
            elif rc == -2:  # pcap_breakloop() called
                break
            else:           # rc == -1: error; keep running
                continue
    finally:
        try:
            pcap_close(pc)
        except Exception as exc:
            logging.warning("capture: pcap_close failed: %s", exc)


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(levelname)s %(message)s",
    )
    try:
        cfg = Config()
    except ValueError as exc:
        logging.critical("tscan-capture: configuration error — %s", exc)
        raise SystemExit(1)
    # cfg.bpf_filter unset (None) -> auto-build from configured protocol
    # ports. Explicitly set (including "") -> use verbatim, letting an
    # empty string disable filtering (capture everything) for troubleshooting.
    bpf_filter = cfg.bpf_filter
    if bpf_filter is None:
        bpf_filter = _build_port_filter(cfg)
    capture_into_unix_dgram(
        iface=cfg.iface,
        sock_path=cfg.socket_path,
        buf_bytes=cfg.buffer_bytes,
        snaplen=cfg.snaplen,
        immediate=not cfg.no_immediate,
        bpf_filter=bpf_filter,
    )
