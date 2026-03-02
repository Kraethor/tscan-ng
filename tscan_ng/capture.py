import os, sys, ctypes, ctypes.util, multiprocessing as mp

PCAP_ERRBUF_SIZE = 256
libpcap_path = ctypes.util.find_library('pcap')
if not libpcap_path:
    raise RuntimeError("libpcap not found")
pcap = ctypes.CDLL(libpcap_path)

pcap_t = ctypes.c_void_p

class timeval(ctypes.Structure):
    _fields_ = [("tv_sec", ctypes.c_long), ("tv_usec", ctypes.c_long)]
class pcap_pkthdr(ctypes.Structure):
    _fields_ = [("ts", timeval), ("caplen", ctypes.c_uint32), ("len", ctypes.c_uint32)]

pcap_create = pcap.pcap_create; pcap_create.argtypes=[ctypes.c_char_p, ctypes.c_char_p]; pcap_create.restype=pcap_t
pcap_set_buffer_size = pcap.pcap_set_buffer_size; pcap_set_buffer_size.argtypes=[pcap_t, ctypes.c_int]
pcap_set_snaplen = pcap.pcap_set_snaplen; pcap_set_snaplen.argtypes=[pcap_t, ctypes.c_int]
pcap_set_promisc = pcap.pcap_set_promisc; pcap_set_promisc.argtypes=[pcap_t, ctypes.c_int]
pcap_set_timeout = pcap.pcap_set_timeout; pcap_set_timeout.argtypes=[pcap_t, ctypes.c_int]
pcap_activate = pcap.pcap_activate; pcap_activate.argtypes=[pcap_t]; pcap_activate.restype=ctypes.c_int
pcap_datalink = pcap.pcap_datalink; pcap_datalink.argtypes=[pcap_t]; pcap_datalink.restype=ctypes.c_int
pcap_geterr = pcap.pcap_geterr; pcap_geterr.argtypes=[pcap_t]; pcap_geterr.restype=ctypes.c_char_p

# Change 1: proper argtypes using pcap_pkthdr instead of unsafe c_ubyte cast
pcap_next_ex = pcap.pcap_next_ex
pcap_next_ex.argtypes = [
    pcap_t,
    ctypes.POINTER(ctypes.POINTER(pcap_pkthdr)),
    ctypes.POINTER(ctypes.POINTER(ctypes.c_ubyte)),
]
pcap_next_ex.restype = ctypes.c_int

try:
    pcap_set_immediate_mode = pcap.pcap_set_immediate_mode
    pcap_set_immediate_mode.argtypes = [pcap_t, ctypes.c_int]
except AttributeError:
    pcap_set_immediate_mode = None

def _err(pc):
    return (pcap_geterr(pc) or b"unknown").decode("utf-8","ignore")

def capture_into_unix_dgram(iface: str, sock_path: str, buf_bytes=32*1024*1024, snaplen=65535, immediate=True):
    import struct, socket
    HDR = struct.Struct("!IIIHH")  # sec,usec,caplen,l2type,pad
    s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    s.connect(sock_path)

    errbuf = ctypes.create_string_buffer(PCAP_ERRBUF_SIZE)
    pc = pcap_create(iface.encode(), errbuf)
    if not pc:
        print(f"pcap_create failed: {errbuf.value.decode()}", file=sys.stderr); os._exit(2)
    if buf_bytes: pcap_set_buffer_size(pc, int(buf_bytes))
    pcap_set_snaplen(pc, snaplen)
    pcap_set_promisc(pc, 1)

    # Change 2: use timeout=1 as fallback if immediate mode unavailable to avoid busy-loop
    if immediate and pcap_set_immediate_mode:
        pcap_set_immediate_mode(pc, 1)
        pcap_set_timeout(pc, 0)
    else:
        pcap_set_timeout(pc, 1)

    r = pcap_activate(pc)
    if r != 0:
        print(f"pcap_activate: {_err(pc)}", file=sys.stderr); os._exit(3)

    dlt = pcap_datalink(pc)

    # Change 1: clean call without manual cast
    hdr_ptr = ctypes.POINTER(pcap_pkthdr)()
    data_ptr = ctypes.POINTER(ctypes.c_ubyte)()

    try:
        while True:
            rc = pcap_next_ex(pc, ctypes.byref(hdr_ptr), ctypes.byref(data_ptr))
            if rc == 1:
                hdr = hdr_ptr.contents
                caplen = int(hdr.caplen)
                sec = int(hdr.ts.tv_sec); usec = int(hdr.ts.tv_usec)
                pkt = ctypes.string_at(data_ptr, caplen)
                s.send(HDR.pack(sec, usec, caplen, dlt, 0) + pkt)
            elif rc == 0:   # timeout
                continue
            elif rc == -2:  # breakloop
                break
            else:
                continue
    finally:
        try:
            pcap_close = pcap.pcap_close; pcap_close.argtypes=[pcap_t]; pcap_close(pc)
        except Exception:
            pass

if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("-i","--iface", required=True)
    ap.add_argument("-s","--socket", required=True)
    ap.add_argument("-B","--buffer-bytes", type=int, default=32*1024*1024)
    ap.add_argument("--snaplen", type=int, default=65535)
    ap.add_argument("--no-immediate", action="store_true")
    args = ap.parse_args()
    capture_into_unix_dgram(args.iface, args.socket, args.buffer_bytes, args.snaplen, immediate=not args.no_immediate)
