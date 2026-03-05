"""
parsing/net.py - Layer 2/3/4 packet parser for tscan-ng.

Parses raw packet bytes into a normalized dict suitable for use by detectors.
Supports Ethernet (DLT_EN10MB), raw IP (DLT_RAW), and Linux cooked capture
(DLT_LINUX_SLL) link layer types.

Returned dict fields:
    src     (str)   - Source IP address (v4 or v6)
    dst     (str)   - Destination IP address (v4 or v6)
    tcp     (bool)  - True if transport layer is TCP
    udp     (bool)  - True if transport layer is UDP
    sport   (int)   - Source port
    dport   (int)   - Destination port
    payload (bytes) - Transport layer payload
"""

import socket
import dpkt

DLT_EN10MB    = 1    # Standard Ethernet
DLT_RAW       = 12   # Raw IP
DLT_LINUX_SLL = 113  # Linux cooked capture


def _ip_str(raw: bytes) -> str:
    """
    Convert raw IP address bytes to a human-readable string.
    Handles both IPv4 (4 bytes) and IPv6 (16 bytes).
    Args:
        raw: Raw IP address bytes from a dpkt IP/IP6 header.
    Returns:
        Dotted-decimal (IPv4) or colon-hex (IPv6) string, or empty string on error.
    """
    try:
        if len(raw) == 4:
            return socket.inet_ntop(socket.AF_INET, raw)
        elif len(raw) == 16:
            return socket.inet_ntop(socket.AF_INET6, raw)
    except Exception:
        pass
    return ""


def parse_basic(l2type: int, data: bytes) -> dict | None:
    try:
        ...existing code...
        return {
            ...
        }
    except Exception as e:
        import sys
        print(f"parse_basic exception: {e} l2type={l2type} len={len(data)}", file=sys.stderr)
        return None
    """
    Parse a raw packet into a normalized dict for detector consumption.

    Walks the packet from Layer 2 through Layer 4. Returns None if the packet
    is not IPv4/IPv6, not TCP/UDP, or cannot be parsed.

    Args:
        l2type: libpcap datalink type (e.g. DLT_EN10MB, DLT_RAW, DLT_LINUX_SLL).
        data:   Raw packet bytes as captured by libpcap.

    Returns:
        A dict with keys: src, dst, tcp, udp, sport, dport, payload.
        Returns None if the packet is not parseable or not of interest.
    """
    try:
        if l2type == DLT_EN10MB:
            eth = dpkt.ethernet.Ethernet(data)
            ip = eth.data
        elif l2type == DLT_RAW:
            ip = dpkt.ip.IP(data)
        elif l2type == DLT_LINUX_SLL:
            sll = dpkt.sll.SLL(data)
            ip = sll.data
        else:
            return None

        if not isinstance(ip, (dpkt.ip.IP, dpkt.ip6.IP6)):
            return None

        l4 = ip.data
        if not isinstance(l4, (dpkt.tcp.TCP, dpkt.udp.UDP)):
            return None

        return {
            "src":     _ip_str(ip.src),
            "dst":     _ip_str(ip.dst),
            "tcp":     isinstance(l4, dpkt.tcp.TCP),
            "udp":     isinstance(l4, dpkt.udp.UDP),
            "sport":   l4.sport,
            "dport":   l4.dport,
            "payload": bytes(l4.data) if l4.data else b"",
        }

    except Exception:
        return None
