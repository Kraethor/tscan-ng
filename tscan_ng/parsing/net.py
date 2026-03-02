import socket
import dpkt

DLT_EN10MB   = 1
DLT_RAW      = 12
DLT_LINUX_SLL = 113

def _ip_str(raw: bytes) -> str:
    """Convert raw IP bytes to a readable string (v4 or v6)."""
    try:
        if len(raw) == 4:
            return socket.inet_ntop(socket.AF_INET, raw)
        elif len(raw) == 16:
            return socket.inet_ntop(socket.AF_INET6, raw)
    except Exception:
        pass
    return ""

def parse_basic(l2type: int, data: bytes):
    """ETH/RAW/SLL -> (IPv4/IPv6) -> TCP/UDP. Return a small dict or None."""
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
