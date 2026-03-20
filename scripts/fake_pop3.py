#!/usr/bin/env python3
# fake_pop3.py — plaintext USER/PASS and AUTH PLAIN server, no TLS
# Valid creds: testuser / hunter2  — everything else fails

import socket, base64, threading, datetime

HOST = "0.0.0.0"
PORT = 1100  # avoid 110 which needs root; use 1100 for testing

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
    pending_user = None

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
        send("+OK FakePOP3 server ready <fake@fakemail.local>")

        while True:
            line = recv()
            if not line:
                break

            parts = line.split(" ", 1)
            cmd = parts[0].upper()
            arg = parts[1] if len(parts) > 1 else ""

            if cmd == "CAPA":
                send("+OK Capabilities follow")
                send("USER")
                send("AUTH PLAIN")
                send("UIDL")
                send("TOP")
                send(".")

            elif cmd == "USER":
                pending_user = arg.strip()
                log(addr, f"*** USER {pending_user!r}")
                send("+OK send PASS")

            elif cmd == "PASS":
                pw = arg.strip()
                if pending_user is None:
                    send("-ERR USER command required first")
                else:
                    if check(pending_user, pw, addr):
                        send("+OK mailbox locked and ready")
                    else:
                        send("-ERR [AUTH] Invalid credentials")
                    pending_user = None

            elif cmd == "AUTH":
                mech = arg.upper()

                if mech == "PLAIN":
                    send("+ ")  # challenge
                    b64 = recv()
                    try:
                        decoded = base64.b64decode(b64).decode(errors="replace")
                        fields = decoded.split("\x00")
                        user, pw = fields[1], fields[2]
                    except Exception as e:
                        log(addr, f"*** AUTH PLAIN decode error: {e} raw={b64!r}")
                        send("-ERR malformed auth input")
                        continue
                    if check(user, pw, addr):
                        send("+OK authentication successful")
                    else:
                        send("-ERR [AUTH] Invalid credentials")

                elif mech == "":
                    send("+OK supported mechanisms:")
                    send("PLAIN")
                    send(".")

                else:
                    send("-ERR unsupported AUTH mechanism")

            elif cmd == "STAT":
                send("+OK 3 4096")

            elif cmd == "LIST":
                if arg:
                    send(f"+OK {arg} 1024")
                else:
                    send("+OK 3 messages")
                    send("1 1024")
                    send("2 2048")
                    send("3 1024")
                    send(".")

            elif cmd == "UIDL":
                if arg:
                    send(f"+OK {arg} fake-uid-{arg}00000")
                else:
                    send("+OK unique-id listing follows")
                    send("1 fake-uid-100000")
                    send("2 fake-uid-200000")
                    send("3 fake-uid-300000")
                    send(".")

            elif cmd == "RETR":
                send("+OK 512 octets")
                send("From: sender@fakemail.local")
                send("To: testuser@fakemail.local")
                send("Subject: Test message")
                send("")
                send("This is a fake message body.")
                send(".")

            elif cmd == "TOP":
                send("+OK top of message follows")
                send("From: sender@fakemail.local")
                send("To: testuser@fakemail.local")
                send("Subject: Test message")
                send(".")

            elif cmd == "DELE":
                send(f"+OK message {arg} deleted")

            elif cmd == "NOOP":
                send("+OK")

            elif cmd == "RSET":
                pending_user = None
                send("+OK")

            elif cmd == "QUIT":
                send("+OK FakePOP3 server signing off")
                break

            else:
                send("-ERR unknown command")

    except Exception as e:
        log(addr, f"ERROR: {e}")
    finally:
        conn.close()

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((HOST, PORT))
    s.listen(10)
    print(f"Fake POP3 listening on {HOST}:{PORT}")
    while True:
        conn, addr = s.accept()
        threading.Thread(target=handle, args=(conn, addr), daemon=True).start()
