#!/usr/bin/env python3
# fake_smtp.py — plaintext AUTH PLAIN/LOGIN server, no TLS
# Valid creds: testuser / hunter2  — everything else fails

import socket, base64, threading, datetime

HOST = "0.0.0.0"
PORT = 2525

VALID_USER = "testuser"
VALID_PASS = "hunter2"

def log(addr, msg):
    ts = datetime.datetime.now().strftime("%H:%M:%S")
    print(f"[{ts}] {addr[0]}:{addr[1]} | {msg}")

def check(user, pw, addr):
    if user == VALID_USER and pw == VALID_PASS:
        log(addr, f"*** AUTH SUCCESS user={user!r}")
        return True
    log(addr, f"*** AUTH FAILED user={user!r} pass={pw!r}")
    return False

def handle(conn, addr):
    def send(line):
        log(addr, f">>> {line}")
        conn.sendall((line + "\r\n").encode())

    def recv():
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

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((HOST, PORT))
    s.listen(10)
    print(f"Fake SMTP listening on {HOST}:{PORT}")
    while True:
        conn, addr = s.accept()
        threading.Thread(target=handle, args=(conn, addr), daemon=True).start()
