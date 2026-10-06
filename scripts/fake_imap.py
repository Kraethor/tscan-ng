#!/usr/bin/env python3
# Copyright (C) 2026 Kraethor
#
# This file is part of tscan-ng.
#
# tscan-ng is free software: you can redistribute it and/or modify it under
# the terms of the GNU General Public License as published by the Free
# Software Foundation, version 3.
#
# tscan-ng is distributed in the hope that it will be useful, but WITHOUT ANY
# WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along with
# tscan-ng. If not, see <https://www.gnu.org/licenses/>.
#
# Additional term under GPLv3 section 7(b): if you convey this work or a
# modified version of it, you must preserve the attribution "Based on tscan-ng
# by Kraethor (https://github.com/Kraethor/tscan-ng)" in the source and in any
# user-facing output or accompanying documentation.
#
# SPDX-License-Identifier: GPL-3.0-only

"""
scripts/fake_imap.py - Plaintext IMAP4rev1 test server for
tscan_ng.detectors.imap.

Implements just enough of RFC 3501 (CAPABILITY, LOGIN, AUTHENTICATE
PLAIN/LOGIN, SELECT, LIST, NOOP, LOGOUT) to generate real cleartext
credential traffic for the IMAP detector to capture. No TLS. Valid creds:
testuser / hunter2 -- everything else gets a tagged NO response. See
docs/test_reference.md for how this fits into the manual test workflow.

Usage:
    python3 /opt/tscan/scripts/fake_imap.py

    No arguments or environment variables. Listens on 0.0.0.0:1430 (TCP,
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
PORT = 1430

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
    """Drive one client connection through the IMAP command loop."""
    tag = "*"

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
        send("* OK [CAPABILITY IMAP4rev1 AUTH=PLAIN AUTH=LOGIN] fakemail.local FakeIMAP ready")

        while True:
            line = recv()
            if not line:
                break

            parts = line.split(" ", 2)
            if len(parts) < 2:
                continue

            tag = parts[0]
            cmd = parts[1].upper()
            arg = parts[2] if len(parts) > 2 else ""

            if cmd == "CAPABILITY":
                send("* CAPABILITY IMAP4rev1 AUTH=PLAIN AUTH=LOGIN")
                send(f"{tag} OK CAPABILITY completed")

            elif cmd == "NOOP":
                send(f"{tag} OK NOOP completed")

            elif cmd == "LOGOUT":
                send("* BYE FakeIMAP logging out")
                send(f"{tag} OK LOGOUT completed")
                break

            elif cmd == "LOGIN":
                creds = arg.split(" ", 1)
                user = creds[0].strip('"') if len(creds) > 0 else ""
                pw   = creds[1].strip('"') if len(creds) > 1 else ""
                if check(user, pw, addr):
                    send(f"{tag} OK LOGIN completed")
                else:
                    send(f"{tag} NO [AUTHENTICATIONFAILED] Invalid credentials")

            elif cmd == "AUTHENTICATE":
                mech = arg.upper()

                if mech == "PLAIN":
                    send("+ ")
                    b64 = recv()
                    try:
                        decoded = base64.b64decode(b64).decode(errors="replace")
                        fields = decoded.split("\x00")
                        user, pw = fields[1], fields[2]
                    except Exception as e:
                        log(addr, f"*** AUTH PLAIN decode error: {e} raw={b64!r}")
                        send(f"{tag} BAD invalid encoding")
                        continue
                    if check(user, pw, addr):
                        send(f"{tag} OK AUTHENTICATE completed")
                    else:
                        send(f"{tag} NO [AUTHENTICATIONFAILED] Invalid credentials")

                elif mech == "LOGIN":
                    send("+ VXNlcm5hbWU6")  # base64("Username:")
                    user_b64 = recv()
                    user = base64.b64decode(user_b64).decode(errors="replace")
                    log(addr, f"*** AUTH LOGIN user={user!r}")
                    send("+ UGFzc3dvcmQ6")  # base64("Password:")
                    pass_b64 = recv()
                    pw = base64.b64decode(pass_b64).decode(errors="replace")
                    if check(user, pw, addr):
                        send(f"{tag} OK AUTHENTICATE completed")
                    else:
                        send(f"{tag} NO [AUTHENTICATIONFAILED] Invalid credentials")

                else:
                    send(f"{tag} NO AUTHENTICATE mechanism not supported")

            elif cmd == "SELECT":
                send(f"* 3 EXISTS")
                send(f"* 0 RECENT")
                send(f"* OK [UNSEEN 1] first unseen message")
                send(f"* FLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft)")
                send(f"{tag} OK [READ-WRITE] SELECT completed")

            elif cmd == "LIST":
                send('* LIST (\\HasNoChildren) "/" "INBOX"')
                send(f"{tag} OK LIST completed")

            else:
                send(f"{tag} BAD command unrecognized")

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
    print(f"Fake IMAP listening on {HOST}:{PORT}")
    while True:
        conn, addr = s.accept()
        threading.Thread(target=handle, args=(conn, addr), daemon=True).start()
