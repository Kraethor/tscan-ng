import dpkt

def parse_basic(l2type: int, data: bytes):
    """ETH -> (IPv4/IPv6) -> TCP/UDP. Return a small dict or None."""
    try:
        eth = dpkt.ethernet.Ethernet(data)
        ip = eth.data
        if not isinstance(ip, (dpkt.ip.IP, dpkt.ip6.IP6)):
            return None
        l4 = ip.data
        return {
            "tcp": isinstance(l4, dpkt.tcp.TCP),
            "udp": isinstance(l4, dpkt.udp.UDP),
            "payload": bytes(getattr(l4, "data", b"")),
            "sport": getattr(l4, "sport", None),
            "dport": getattr(l4, "dport", None),
        }
    except Exception:
        return None
