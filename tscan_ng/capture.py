"""
capture.py - libpcap bindings for tscan-ng.

Imported purely as a library by pipeline.py (tscan-pipeline.service's
deployed entry point): pcap_open_dead()/pcap_compile()/pcap_freecode()/
pcap_close() compile a BPF program against an unactivated ("dead") pcap
handle -- no interface, no capture, no CAP_NET_RAW needed -- then attach
the resulting bytecode directly to pipeline.py's own raw AF_PACKET socket
via SO_ATTACH_FILTER. _build_port_filter() derives that BPF expression from
the configured detector ports. See pipeline.py's module docstring for the
fan-out architecture this serves.

This module used to also hold a complete standalone capture process
(capture_into_unix_dgram(), opening a network interface in promiscuous mode
via libpcap and forwarding each packet -- prefixed with a fixed-size header
-- to a dispatcher process over a Unix datagram socket) plus a `python -m
tscan_ng.capture` entry point, paired with tscan-capture.service. That was
half of the original two-process design (see tscan_ng/run.py's module
docstring for the dispatcher/worker half); pipeline.py's fan-out processes
superseded it, and the standalone capture code was removed as dead weight
once nothing still ran it -- see git history if it's ever needed for
reference.

This module loads no configuration itself; it only receives a Config
(see tscan_ng/config.py) as an argument to _build_port_filter(). Importing
it raises RuntimeError if libpcap cannot be found. Only the bindings
pipeline.py uses are declared; the leftovers from the removed live-capture
code (pcap_create, pcap_activate, pcap_next_ex, ...) were deleted in
TODO.md #55.
"""

import ctypes, ctypes.util
from tscan_ng.config import Config

libpcap_path = ctypes.util.find_library('pcap')
if not libpcap_path:
    # Required, not optional: pipeline.py compiles its BPF filter with
    # libpcap, so there is no capture without it.
    raise RuntimeError("libpcap not found")
pcap = ctypes.CDLL(libpcap_path)

# Opaque handle type for a C `pcap_t *`; never dereferenced from Python.
pcap_t = ctypes.c_void_p


class bpf_program(ctypes.Structure):
    """
    Maps to C struct bpf_program (bf_len, bf_insns).

    bf_insns is populated by pcap_compile() with a pointer to a
    libpcap-allocated instruction array. pipeline._attach_filter() casts it
    to its own sock_filter array to build the SO_ATTACH_FILTER argument,
    then releases it with pcap_freecode().
    """
    _fields_ = [("bf_len", ctypes.c_uint), ("bf_insns", ctypes.c_void_p)]


# Passed to pcap_compile() when the capture device's network mask is
# unknown/unavailable, which is always true for us (no netmask-relative
# filter terms like "net"/"broadcast" are used).
PCAP_NETMASK_UNKNOWN = 0xffffffff


# libpcap function bindings (argtypes/restype declarations; without them
# ctypes would default every argument and return to a C int, which truncates
# 64-bit pointers). Only what pipeline._attach_filter() uses; the bindings
# for the removed live-capture path went in TODO.md #55.

# Returns a pcap_t that exists only to compile filters against a given
# datalink type -- no interface, no capture, no CAP_NET_RAW required.
# Used by pipeline.py to compile a BPF filter for a raw AF_PACKET socket
# without needing an activated (and therefore privileged) capture handle.
pcap_open_dead = pcap.pcap_open_dead
pcap_open_dead.argtypes = [ctypes.c_int, ctypes.c_int]
pcap_open_dead.restype = pcap_t

pcap_compile = pcap.pcap_compile
pcap_compile.argtypes = [pcap_t, ctypes.POINTER(bpf_program), ctypes.c_char_p,
                         ctypes.c_int, ctypes.c_uint32]
pcap_compile.restype = ctypes.c_int

pcap_freecode = pcap.pcap_freecode
pcap_freecode.argtypes = [ctypes.POINTER(bpf_program)]

pcap_geterr = pcap.pcap_geterr
pcap_geterr.argtypes = [pcap_t]
pcap_geterr.restype = ctypes.c_char_p

pcap_close = pcap.pcap_close
pcap_close.argtypes = [pcap_t]

def _err(pc):
    """
    Return the last error message recorded on a pcap handle.

    Args:
        pc: A pcap_t handle (e.g. the dead handle from pcap_open_dead).

    Returns:
        The message decoded as UTF-8 (undecodable bytes replaced), or
        "unknown" if libpcap has no message.
    """
    return (pcap_geterr(pc) or b"unknown").decode("utf-8", "replace")


def _build_port_filter(cfg: Config) -> str:
    """
    Build a BPF filter expression restricting capture to the ports any
    protocol detector actually looks at.

    Without this, capture forwards 100% of traffic on the interface to the
    pipeline for full parsing, even on a SPAN/mirror port carrying mostly
    irrelevant traffic (bulk HTTPS, video, etc.) that no detector will ever
    match. Filtering at the pcap/kernel layer means that traffic never
    reaches userspace at all, rather than being parsed and then discarded.

    Every detector here is TCP-based except snmp.py, which is UDP (SNMP is
    virtually always deployed over UDP in practice) -- so cfg.snmp_ports
    feeds a separate "udp and (...)" clause rather than joining the TCP
    port union. If snmp_ports is somehow empty, the udp clause is omitted
    entirely rather than emitting an invalid empty "udp and ()" (defensive:
    Config._getports falls back to defaults on an empty list, so this is
    not normally reachable). The TCP clause has no such guard, but the
    same fallback guarantees it is non-empty.

    Args:
        cfg: Loaded Config object.

    Returns:
        A BPF filter expression string, e.g.
        "(tcp and (port 21 or port 25)) or (udp and (port 161))", or just
        "tcp and (port 21 or port 25)" if no UDP ports are configured.
    """
    tcp_ports = set()
    for port_set in (cfg.http_ports, cfg.ftp_ports, cfg.smtp_ports,
                     cfg.imap_ports, cfg.pop3_ports, cfg.telnet_ports,
                     cfg.ldap_ports, cfg.redis_ports, cfg.smb_ports,
                     cfg.irc_ports, cfg.postgres_ports):
        tcp_ports.update(port_set)
    tcp_terms = " or ".join(f"port {p}" for p in sorted(tcp_ports))
    tcp_clause = f"tcp and ({tcp_terms})"

    udp_ports = set(cfg.snmp_ports)
    if not udp_ports:
        return tcp_clause
    udp_terms = " or ".join(f"port {p}" for p in sorted(udp_ports))
    udp_clause = f"udp and ({udp_terms})"
    return f"({tcp_clause}) or ({udp_clause})"
