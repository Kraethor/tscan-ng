#!/usr/bin/env python3
"""
scripts/fake_smtp.py - Plaintext ESMTP test server for tscan_ng.detectors.smtp.

Implements just enough of RFC 5321 (EHLO/HELO, AUTH PLAIN/LOGIN, MAIL FROM,
RCPT TO, DATA, QUIT) to generate real cleartext credential traffic for the
SMTP detector to capture. No TLS. Valid creds: testuser / hunter2 --
everything else gets a 535 authentication-failure response. See
docs/test_reference.md for how this fits into the manual test workflow.

Usage:
    python3 /opt/tscan/scripts/fake_smtp.py

    No arguments or environment variables. Listens on 0.0.0.0:2525 (TCP,
    threaded: one daemon thread per connection, SO_REUSEADDR set) and logs
    every line sent/received, with a timestamp and client address, to stdout.
    HOST, PORT, VALID_USER and VALID_PASS are module constants to edit in the
    source. The service is intentionally not installed as a systemd unit; run
    it by hand on the test host that generates traffic for the capture NIC to
    see (traffic originating on the capture host itself is NOT visible to a
    SPAN port on that same host, see docs/REBUILD.md).

Privileges:
    None -- the port is above 1024. Do not run as root.

Exit codes:
    The server loop has no shutdown path of its own and, unlike the other
    scripts here, runs at import time (there is no `if __name__` guard), so
    do not import this module. Stop it with Ctrl-C/SIGTERM. A bind failure
    (port already in use) raises OSError and exits 1 with a traceback.

Security: accepts any client on every interface and prints attempted
passwords in the clear to stdout -- test use only, never expose to an
untrusted network.
"""

import socket, base64, threading, datetime

HOST = "0.0.0.0"   # listen on all interfaces
PORT = 2525

VALID_USER = "testuser"
VALID_PASS = "hunter2"

def log(addr, msg):
    """Print a timestamped, per-client log line to stdout."""
    ts = datetime.datetime.now().strftime("%H:%M:%S")
    print(f"[{ts}] {addr[0]}:{addr[1]} | {msg}")

def check(user, pw, addr):
    """Return True and log success if (user, pw) match VALID_USER/VALID_PASS."""
    if user == VALID_USER and pw == VALID_PASS:
        log(addr, f"*** AUTH SUCCESS user={user!r}")
        return True
    log(addr, f"*** AUTH FAILED user={user!r} pass={pw!r}")
    return False

def handle(conn, addr):
    """Drive one client connection through the SMTP command loop."""
    def send(line):
        """Log and write one CRLF-terminated response line to the client."""
        log(addr, f">>> {line}")
        conn.sendall((line + "\r\n").encode())

    def recv():
        """Block until a newline-terminated line arrives, log it, and
        return it stripped of line endings."""
        data = b""
        while not data.endswith(b"\n"):
            chunk = conn.recv(4096)
            if not chunk:
                break
            data += chunk
        line = data.decode(errors="replace").strip()
        log(addr, f"<<< {line}")
        return line

    try:
        send("220 fakemail.local ESMTP FakeSMTP")
        while True:
            line = recv()
            if not line:
                break
            cmd = line.upper()

            if cmd.startswith("EHLO") or cmd.startswith("HELO"):
                send("250-fakemail.local Hello")
                send("250-AUTH PLAIN LOGIN")
                send("250 OK")

            elif cmd.startswith("AUTH PLAIN"):
                parts = line.split(" ", 2)
                if len(parts) == 3:
                    try:
                        decoded = base64.b64decode(parts[2]).decode(errors="replace")
                        fields = decoded.split("\x00")
                        user, pw = fields[1], fields[2]
                    except Exception as e:
                        log(addr, f"*** AUTH PLAIN decode error: {e}")
                        send("501 malformed auth input")
                        continue
                else:
                    send("334 ")
                    b64 = recv()
                    try:
                        decoded = base64.b64decode(b64).decode(errors="replace")
                        fields = decoded.split("\x00")
                        user, pw = fields[1], fields[2]
                    except Exception as e:
                        log(addr, f"*** AUTH PLAIN decode error: {e}")
                        send("501 malformed auth input")
                        continue
                if check(user, pw, addr):
                    send("235 Authentication successful")
                else:
                    send("535 5.7.8 Authentication credentials invalid")

            elif cmd.startswith("AUTH LOGIN"):
                send("334 VXNlcm5hbWU6")  # base64("Username:")
                user_b64 = recv()
                user = base64.b64decode(user_b64).decode(errors="replace")
                log(addr, f"*** AUTH LOGIN user={user!r}")
                send("334 UGFzc3dvcmQ6")  # base64("Password:")
                pass_b64 = recv()
                pw = base64.b64decode(pass_b64).decode(errors="replace")
                if check(user, pw, addr):
                    send("235 Authentication successful")
                else:
                    send("535 5.7.8 Authentication credentials invalid")

            elif cmd.startswith("MAIL FROM"):
                send("250 OK")
            elif cmd.startswith("RCPT TO"):
                send("250 OK")
            elif cmd.startswith("DATA"):
                send("354 End data with <CR><LF>.<CR><LF>")
                while True:
                    l = recv()
                    if l == ".":
                        break
                send("250 OK: message queued")
            elif cmd in ("QUIT", ""):
                send("221 Bye")
                break
            else:
                send("500 Unrecognized command")

    except Exception as e:
        log(addr, f"ERROR: {e}")
    finally:
        conn.close()

# Accept loop (runs at import time): one handler thread per client so a slow
# or stuck connection never blocks the next.
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((HOST, PORT))
    s.listen(10)
    print(f"Fake SMTP listening on {HOST}:{PORT}")
    while True:
        conn, addr = s.accept()
        threading.Thread(target=handle, args=(conn, addr), daemon=True).start()
