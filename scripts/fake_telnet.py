#!/usr/bin/env python3
"""
scripts/fake_telnet.py - Plaintext telnet test server for tscan_ng.detectors.telnet.

Speaks just enough real telnet (IAC WILL/DO negotiation, a login/Password
prompt, and a tiny fake shell) to generate real cleartext credential traffic
for the telnet detector to capture. No encryption. Valid creds: testuser /
hunter2 -- everything else is rejected after 3 attempts. See
docs/test_reference.md for how this fits into the manual test workflow.
"""

import socket, threading, datetime

HOST = "0.0.0.0"
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

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((HOST, PORT))
    s.listen(10)
    print(f"Fake Telnet listening on {HOST}:{PORT}")
    while True:
        conn, addr = s.accept()
        threading.Thread(target=handle, args=(conn, addr), daemon=True).start()
