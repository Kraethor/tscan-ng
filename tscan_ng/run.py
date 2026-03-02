import argparse, os, struct, socket, multiprocessing as mp
from tscan_ng.parsing.net import parse_basic
from tscan_ng.detectors import DETECTORS
from tscan_ng.sinks.jsonl import JSONLSink

HDR = struct.Struct("!IIIHH")  # sec,usec,caplen,l2type,pad
DETECTORS = [
    http_basic.detect,
    ftp.detect,
    pop3.detect,
    imap.detect,
    smtp.detect,
]

def worker_main(pipe, out_path):
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

def dispatcher(socket_path: str, nworkers: int, out_path: str|None):
    # workers
    parents, procs = [], []
    for _ in range(nworkers):
        p_end, c_end = mp.Pipe()
        p = mp.Process(target=worker_main, args=(c_end, out_path), daemon=True)
        p.start(); c_end.close()
        parents.append(p_end); procs.append(p)
    # bind UNIX dgram to receive from capture
    if os.path.exists(socket_path):
        os.unlink(socket_path)
    s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    s.bind(socket_path)
    os.chmod(socket_path, 0o660)
    rr = 0
    try:
        while True:
            buf = s.recv(65536 + HDR.size)
            if len(buf) < HDR.size: continue
            sec, usec, caplen, l2type, _ = HDR.unpack_from(buf, 0)
            payload = memoryview(buf)[HDR.size:HDR.size+caplen].tobytes()
            ts = sec + usec / 1_000_000.0
            parents[rr % len(parents)].send((ts, l2type, payload))
            rr += 1
    except KeyboardInterrupt:
        pass
    finally:
        for pe in parents:
            try: pe.send(None)
            except BrokenPipeError: pass
        for p in procs:
            p.join(timeout=1)

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--socket", required=True)
    ap.add_argument("--workers", type=int, default=max(1, os.cpu_count() or 1))
    ap.add_argument("--out", default="/var/log/tscan/results.jsonl")
    args = ap.parse_args()
    dispatcher(args.socket, args.workers, args.out or None)
