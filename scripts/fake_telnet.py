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
scripts/fake_telnet.py - Plaintext telnet test server for tscan_ng.detectors.telnet.

Speaks just enough real telnet (IAC WILL/DO negotiation, a login/Password
prompt, and a tiny fake shell) to generate real cleartext credential traffic
for the telnet detector to capture. No encryption. Valid creds: testuser /
hunter2 -- everything else is rejected after 3 attempts. See
docs/test_reference.md for how this fits into the manual test workflow.

Usage:
    python3 /opt/tscan/scripts/fake_telnet.py

    No arguments or environment variables. Listens on 0.0.0.0:2323 (TCP,
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

import socket, threading, datetime

HOST = "0.0.0.0"   # listen on all interfaces
PORT = 2323  # avoid 23 which needs root

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
    """Drive one client connection through the login prompt and fake shell."""
    def send(text):
        """Log and write raw text to the client verbatim (caller supplies
        any line endings)."""
        log(addr, f">>> {text.strip()}")
        conn.sendall(text.encode())

    def recv_line():
        """Read byte-by-byte until CR/LF, stripping telnet IAC negotiation
        sequences inline, and return the decoded line."""
        data = b""
        while True:
            ch = conn.recv(1)
            if not ch:
                break
            # Strip telnet IAC negotiation bytes if a real telnet client connects
            if ch == b'\xff':
                conn.recv(2)  # skip option bytes
                continue
            if ch in (b'\r', b'\n'):
                if data:
                    break
                continue
            data += ch
        line = data.decode(errors="replace").strip()
        log(addr, f"<<< {line!r}")
        return line

    try:
        # Telnet negotiation — suppress go ahead, echo off
        # These are standard IAC sequences a real telnet client expects
        conn.sendall(bytes([
            0xff, 0xfb, 0x03,  # IAC WILL SUPPRESS-GO-AHEAD
            0xff, 0xfb, 0x01,  # IAC WILL ECHO
            0xff, 0xfd, 0x03,  # IAC DO SUPPRESS-GO-AHEAD
        ]))

        send("\r\nWelcome to fakemail.local\r\n")
        send("Unauthorized access is prohibited.\r\n\r\n")

        for attempt in range(3):
            send("login: ")
            user = recv_line()
            log(addr, f"*** USER {user!r}")

            send("Password: ")
            pw = recv_line()

            if check(user, pw, addr):
                send(f"\r\nLast login: Mon Jan  1 00:00:00 2025 from 127.0.0.1\r\n")
                send(f"fakemail:~$ ")
                # Accept a few commands then disconnect
                while True:
                    cmd = recv_line()
                    if not cmd:
                        break
                    if cmd.lower() in ("exit", "logout", "quit"):
                        send("logout\r\n")
                        break
                    elif cmd.startswith("ls"):
                        send("mail  logs  tmp\r\n")
                        send("fakemail:~$ ")
                    elif cmd.startswith("whoami"):
                        send(f"{user}\r\n")
                        send("fakemail:~$ ")
                    elif cmd.startswith("pwd"):
                        send(f"/home/{user}\r\n")
                        send("fakemail:~$ ")
                    else:
                        send(f"-bash: {cmd}: command not found\r\n")
                        send("fakemail:~$ ")
                break
            else:
                if attempt < 2:
                    send("\r\nLogin incorrect\r\n\r\n")
                else:
                    send("\r\nLogin incorrect\r\n")
                    send("Maximum login attempts exceeded. Goodbye.\r\n")

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
    print(f"Fake Telnet listening on {HOST}:{PORT}")
    while True:
        conn, addr = s.accept()
        threading.Thread(target=handle, args=(conn, addr), daemon=True).start()
