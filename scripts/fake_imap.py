#!/usr/bin/env python3
# fake_imap.py — plaintext AUTH PLAIN/LOGIN server, no TLS
# Valid creds: testuser / hunter2  — everything else fails

import socket, base64, threading, datetime

HOST = "0.0.0.0"
PORT = 1430

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
    tag = "*"

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

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((HOST, PORT))
    s.listen(10)
    print(f"Fake IMAP listening on {HOST}:{PORT}")
    while True:
        conn, addr = s.accept()
        threading.Thread(target=handle, args=(conn, addr), daemon=True).start()
