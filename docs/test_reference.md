# tscan-ng Protocol Test Reference

**Test server:** cloud.sisypheansecurity.com
**Valid credentials:** `testuser` / `hunter2` — any other credentials will fail

---

## Base64 Quick Reference

`AUTH PLAIN` encodes as `\x00username\x00password` in base64.

| Test | Command | Expected result |
|------|---------|-----------------|
| AUTH PLAIN — good | `printf '\x00testuser\x00hunter2' \| base64` | `AHRlc3R1c2VyAGh1bnRlcjI=` |
| AUTH PLAIN — bad | `printf '\x00baduser\x00wrongpass' \| base64` | `AGJhZHVzZXIAd3JvbmdwYXNz` |
| AUTH LOGIN user — good | `printf 'testuser' \| base64` | `dGVzdHVzZXI=` |
| AUTH LOGIN pass — good | `printf 'hunter2' \| base64` | `aHVudGVyMg==` |
| AUTH LOGIN user — bad | `printf 'baduser' \| base64` | `YmFkdXNlcg==` |
| AUTH LOGIN pass — bad | `printf 'wrongpass' \| base64` | `d3JvbmdwYXNz` |

---

## SMTP — Port 2525

Fake SMTP server running on the test host. Supports `AUTH PLAIN` and `AUTH LOGIN` with no TLS.

### curl commands

| Test | Command | Expected result |
|------|---------|-----------------|
| AUTH PLAIN — good | `curl -v --url "smtp://cloud.sisypheansecurity.com:2525" --mail-from "from@test.com" --mail-rcpt "to@test.com" --user "testuser:hunter2" --no-ssl` | `235 Authentication successful` |
| AUTH PLAIN — bad | `curl -v --url "smtp://cloud.sisypheansecurity.com:2525" --mail-from "from@test.com" --mail-rcpt "to@test.com" --user "baduser:wrongpass" --no-ssl` | `535 5.7.8 Authentication credentials invalid` |

### nc manual session

Connect with: `nc cloud.sisypheansecurity.com 2525`

| Step | You type | Server replies |
|------|----------|----------------|
| 1 | `EHLO test` | `250-AUTH PLAIN LOGIN` / `250 OK` |
| 2a | `AUTH PLAIN AHRlc3R1c2VyAGh1bnRlcjI=` | `235 Authentication successful` |
| 2b | `AUTH PLAIN AGJhZHVzZXIAd3JvbmdwYXNz` | `535 5.7.8 ... invalid` |
| 3a | `AUTH LOGIN` | `334 VXNlcm5hbWU6` (Username:) |
| 3b | `dGVzdHVzZXI=` then `aHVudGVyMg==` | `235 Authentication successful` |
| 3c | `YmFkdXNlcg==` then `d3JvbmdwYXNz` | `535 5.7.8 ... invalid` |
| 4 | `QUIT` | `221 Bye` |

---

## IMAP — Port 1430

Fake IMAP server. Supports `LOGIN` command, `AUTHENTICATE PLAIN`, and `AUTHENTICATE LOGIN` with no TLS.

### curl commands

| Test | Command | Expected result |
|------|---------|-----------------|
| LOGIN — good | `curl -v "imap://cloud.sisypheansecurity.com:1430/INBOX" --user "testuser:hunter2" --no-ssl` | `OK LOGIN completed` |
| LOGIN — bad | `curl -v "imap://cloud.sisypheansecurity.com:1430/INBOX" --user "baduser:wrongpass" --no-ssl` | `NO [AUTHENTICATIONFAILED]` |

### nc manual session

Connect with: `nc cloud.sisypheansecurity.com 1430`

| Step | You type | Server replies |
|------|----------|----------------|
| 1 | (connect) | `* OK ... FakeIMAP ready` |
| 2a | `A001 LOGIN testuser hunter2` | `A001 OK LOGIN completed` |
| 2b | `A001 LOGIN baduser wrongpass` | `A001 NO [AUTHENTICATIONFAILED]` |
| 3a | `A002 AUTHENTICATE PLAIN` | `+` (challenge) |
| 3b | `AHRlc3R1c2VyAGh1bnRlcjI=` | `A002 OK AUTHENTICATE completed` |
| 3c | `AGJhZHVzZXIAd3JvbmdwYXNz` | `A002 NO [AUTHENTICATIONFAILED]` |
| 4a | `A003 AUTHENTICATE LOGIN` | `+ VXNlcm5hbWU6` (Username:) |
| 4b | `dGVzdHVzZXI=` then `aHVudGVyMg==` | `A003 OK AUTHENTICATE completed` |
| 4c | `YmFkdXNlcg==` then `d3JvbmdwYXNz` | `A003 NO [AUTHENTICATIONFAILED]` |
| 5 | `A004 LOGOUT` | `* BYE` / `A004 OK LOGOUT completed` |

---

## POP3 — Port 1100

Fake POP3 server. Supports `USER`/`PASS` (fully plaintext, no encoding) and `AUTH PLAIN`. `USER`/`PASS` is the most interesting for tscan-ng as credentials appear completely raw on the wire.

### curl commands

| Test | Command | Expected result |
|------|---------|-----------------|
| USER/PASS — good | `curl -v "pop3://cloud.sisypheansecurity.com:1100" --user "testuser:hunter2" --no-ssl` | `+OK mailbox locked and ready` |
| USER/PASS — bad | `curl -v "pop3://cloud.sisypheansecurity.com:1100" --user "baduser:wrongpass" --no-ssl` | `-ERR [AUTH] Invalid credentials` |

### nc manual session

Connect with: `nc cloud.sisypheansecurity.com 1100`

| Step | You type | Server replies |
|------|----------|----------------|
| 1 | (connect) | `+OK FakePOP3 server ready` |
| 2 | `CAPA` | `+OK` / `USER` / `AUTH PLAIN` / `.` |
| 3a | `USER testuser` | `+OK send PASS` |
| 3b | `PASS hunter2` | `+OK mailbox locked and ready` |
| 4a | `USER baduser` | `+OK send PASS` |
| 4b | `PASS wrongpass` | `-ERR [AUTH] Invalid credentials` |
| 5a | `AUTH PLAIN` | `+` (challenge) |
| 5b | `AHRlc3R1c2VyAGh1bnRlcjI=` | `+OK authentication successful` |
| 5c | `AGJhZHVzZXIAd3JvbmdwYXNz` | `-ERR [AUTH] Invalid credentials` |
| 6 | `QUIT` | `+OK FakePOP3 signing off` |

---

## FTP — ftp.freebsd.org (public server)

Uses the FreeBSD public FTP server for real plaintext FTP auth traffic. Anonymous login sends credentials in the clear.

| Test | Command | Expected result |
|------|---------|-----------------|
| Anonymous login | `curl -v ftp://ftp.freebsd.org/ --user anonymous:test@test.com` | `230 Login successful` |
| List directory | `curl -v ftp://ftp.freebsd.org/pub/ --user anonymous:test@test.com` | Directory listing |
| Bad anon pass | `curl -v ftp://ftp.freebsd.org/ --user anonymous:notanemail` | May reject or accept (server-dependent) |
| nc banner grab | `nc ftp.freebsd.org 21` | `220 FTP server ready` |

### nc manual session

Connect with: `nc ftp.freebsd.org 21`

| Step | You type | Server replies |
|------|----------|----------------|
| 1 | (connect) | `220 FTP server ready` |
| 2 | `USER anonymous` | `331 Please specify the password` |
| 3 | `PASS test@test.com` | `230 Login successful` |
| 4 | `PWD` | `257 "/" is current directory` |
| 5 | `QUIT` | `221 Goodbye` |

---

## HTTP Basic Auth — neverssl.com

Uses neverssl.com to generate plaintext HTTP traffic. The `Authorization` header carries base64-encoded credentials with no encryption.

> **Note:** neverssl.com does not validate credentials — the goal is to generate the header on the wire for tscan-ng to see.

| Test | Command | Expected result |
|------|---------|-----------------|
| Basic auth — good creds | `curl -v http://neverssl.com/ -H "Authorization: Basic dGVzdHVzZXI6aHVudGVyMg=="` | `200 OK` (header visible in capture) |
| Basic auth — bad creds | `curl -v http://neverssl.com/ -H "Authorization: Basic YmFkdXNlcjp3cm9uZ3Bhc3M="` | `200 OK` (header visible in capture) |
| Verbose with creds | `curl -v http://neverssl.com/ --user "testuser:hunter2"` | `200 OK` — curl sends Basic auth header |
| Bad creds verbose | `curl -v http://neverssl.com/ --user "baduser:wrongpass"` | `200 OK` — header still captured |

Base64 breakdown:
`dGVzdHVzZXI6aHVudGVyMg==` = `testuser:hunter2`
`YmFkdXNlcjp3cm9uZ3Bhc3M=` = `baduser:wrongpass`

### Verify encoding

| Test | Command | Expected result |
|------|---------|-----------------|
| Encode good creds | `printf 'testuser:hunter2' \| base64` | `dGVzdHVzZXI6aHVudGVyMg==` |
| Encode bad creds | `printf 'baduser:wrongpass' \| base64` | `YmFkdXNlcjp3cm9uZ3Bhc3M=` |
| Decode to verify | `echo 'dGVzdHVzZXI6aHVudGVyMg==' \| base64 -d` | `testuser:hunter2` |

---

## Telnet — Port 2323

Fake Telnet server running on the test host. Telnet sends all data including credentials completely in the clear.

| Test | Command | Expected result |
|------|---------|-----------------|
| Connect | `telnet cloud.sisypheansecurity.com 2323` | Login prompt |
| nc connect | `nc cloud.sisypheansecurity.com 2323` | Type username/password at prompts — fully plaintext |

### nc manual session

Connect with: `nc cloud.sisypheansecurity.com 2323`

| Step | You type | Server replies |
|------|----------|----------------|
| 1 | (connect) | `Welcome to fakemail.local` / `login:` |
| 2a | `testuser` (at login:) | `Password:` |
| 2b | `hunter2` (at Password:) | `Last login: ...` / `fakemail:~$` |
| 3a | `baduser` (at login:) | `Password:` |
| 3b | `wrongpass` (at Password:) | `Login incorrect` |
| 4 | `exit` (after login) | `logout` |

Telnet has no AUTH mechanism — username and password are sent as raw ASCII during the login sequence, making them trivially visible in any packet capture.

---

## LDAP — Port 389 / 3268

LDAP simple-bind sends the Distinguished Name and password in plaintext inside a BER-encoded LDAPMessage. Use a local test instance (e.g. OpenLDAP in Docker) or any cleartext LDAP service.

> **Note:** Port 636 (LDAPS) and 3269 (GC+TLS) are TLS-wrapped and are not captured by tscan-ng.

### ldapsearch commands

| Test | Command | Expected result |
|------|---------|-----------------|
| Simple bind — good | `ldapsearch -H ldap://<host>:389 -D "cn=admin,dc=example,dc=com" -w hunter2 -b "dc=example,dc=com"` | Search results |
| Simple bind — bad | `ldapsearch -H ldap://<host>:389 -D "cn=admin,dc=example,dc=com" -w wrongpass -b "dc=example,dc=com"` | `Invalid credentials (49)` |
| Anonymous bind | `ldapsearch -H ldap://<host>:389 -x -b "dc=example,dc=com"` | Results (no credential captured — anonymous) |

> LDAP is a binary (BER) protocol. Raw nc sessions are not practical for manual testing; use `ldapsearch` or a GUI tool such as Apache Directory Studio. Wireshark will decode BindRequest / BindResponse clearly.

---

## Redis — Port 6379 / 6380

Redis `AUTH` sends the password (and optionally a username in Redis 6+) as a plaintext RESP array.

### redis-cli commands

| Test | Command | Expected result |
|------|---------|-----------------|
| AUTH — good | `redis-cli -h <host> -p 6379 -a hunter2 PING` | `PONG` |
| AUTH — bad | `redis-cli -h <host> -p 6379 -a wrongpass PING` | `WRONGPASS invalid username-password pair` |
| ACL AUTH — good (Redis 6+) | `redis-cli -h <host> -p 6379 --user testuser -a hunter2 PING` | `PONG` |
| ACL AUTH — bad (Redis 6+) | `redis-cli -h <host> -p 6379 --user baduser -a wrongpass PING` | `WRONGPASS invalid username-password pair` |

### nc manual session

Connect with: `nc <host> 6379`

| Step | You type | Server replies |
|------|----------|----------------|
| 1 | (connect) | (no banner) |
| 2a | `AUTH hunter2` | `+OK` |
| 2b | `AUTH wrongpass` | `-WRONGPASS invalid username-password pair or user is disabled.` |
| 3 | `QUIT` | `+OK` |

---

## Protocol Summary

| Protocol | Port | Auth method | Encoding | Server | Notes |
|----------|------|-------------|----------|--------|-------|
| SMTP | 2525 | AUTH PLAIN / LOGIN | base64 | cloud.sisypheansecurity.com | Fake server |
| IMAP | 1430 | LOGIN / AUTHENTICATE | base64 | cloud.sisypheansecurity.com | Fake server |
| POP3 | 1100 | USER/PASS / AUTH PLAIN | Plaintext / base64 | cloud.sisypheansecurity.com | Fake server |
| FTP | 21 | USER / PASS | Plaintext | ftp.freebsd.org | Public server |
| HTTP | 80 | Basic Auth | base64 | neverssl.com | No TLS guaranteed |
| Telnet | 2323 | Login prompt | Plaintext | cloud.sisypheansecurity.com | Raw ASCII on wire |
| LDAP | 389, 3268 | Simple bind | Plaintext BER | Local test instance | 636/3269 are TLS — not captured |
| Redis | 6379, 6380 | AUTH command | Plaintext RESP | Local test instance | Redis 6+ supports ACL username |
