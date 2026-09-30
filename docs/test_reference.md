# tscan-ng Protocol Test Reference

**Test server:** cloud.sisypheansecurity.com
**Valid credentials:** `testuser` / `hunter2` — any other credentials will fail

---

## How testing works

tscan-ng is passive: it only sees traffic mirrored to its capture NIC (SPAN
port), so run the clients below from a machine whose traffic is mirrored, not
from the tscan host itself. The fake servers referenced in this document
(`scripts/fake_smtp.py` on 2525, `fake_imap.py` on 1430, `fake_pop3.py` on
1100, `fake_telnet.py` on 2323) are plain Python scripts started by hand on
the test host, e.g. `python3 /opt/tscan/scripts/fake_smtp.py`; they need no
root, log every exchange to stdout, and accept only `testuser` / `hunter2`.

Where to look for results:

- `python3 /opt/tscan/scripts/watch.py` — live view, new findings only, and
  only those with `outcome == "success"`.
- `sudo tail -f /var/log/tscan/results.jsonl` — every finding of every
  outcome (`success`, `failed`, `redirect`, `server_error`, `no_response`,
  `unknown`).
- Discord (if configured) — every outcome except `pending` and `failed`, and except `no_response` on `snmp_creds` findings (unanswered SNMP probes are logged but not alerted).

**Repeat-finding cooldown:** a finding with the same destination IP, destination
port and credentials as one already emitted within the last
`[dedup] finding_cooldown_sec` (default 1800 s = 30 min) is dropped before it
reaches either the JSONL file or Discord. When re-running a test with the
same `user:pass` against the same server and nothing new shows up, that is
why. Vary the credentials or target, temporarily set `finding_cooldown_sec = 0`
(restart `tscan-pipeline`), or fully stop and start the service to clear the
markers in `/run/tscan/finding_cooldown/`.

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

> **Detector coverage:** `tscan_ng/detectors/imap.py` recognises the `LOGIN`
> command and `AUTHENTICATE PLAIN` (inline and split forms). The fake server
> also speaks `AUTHENTICATE LOGIN` (steps 4a–4c) for completeness, but the
> detector does not parse that mechanism, so steps 4a–4c are not expected to
> produce a finding.

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
| 6 | `QUIT` | `+OK FakePOP3 server signing off` |

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

## SMB — Port 445 / 139

SMB2/3 NTLM authentication never puts a plaintext password on the wire — it's
a challenge/response handshake. tscan-ng captures the NTLMv2 CHALLENGE +
AUTHENTICATE exchange in the exact format `hashcat -m 5600` /
`john --format=netntlmv2` expect for offline cracking, not a password. See
`tscan_ng/detectors/smb.py` for the full protocol correlation. Requires a
real SMB server (or a local Samba instance) that completes SMB2 NTLM auth —
a Kerberos-only environment won't produce this exchange.

### smbclient commands

| Test | Command | Expected result |
|------|---------|-----------------|
| Auth attempt (any outcome) | `smbclient //<host>/<share> -U testuser%hunter2` | NTLMv2 challenge/response visible in capture regardless of whether login succeeds |
| Bad credentials | `smbclient //<host>/<share> -U baduser%wrongpass` | `NT_STATUS_LOGON_FAILURE`; the NTLMv2 hash is still captured — a captured hash is equally crackable whether or not the logon succeeded |

> **Note:** The finding is always written to `results.jsonl`. For the
> bad-credentials case the final SESSION_SETUP status maps to
> `outcome: "failed"`, which is not sent to Discord (only `failed` and
> `pending` are suppressed), even though the captured hash is useful
> regardless of outcome. An unrecognised non-success status maps to
> `server_error`, which does alert. `watch.py` only displays `success`.

---

## SNMP — Port 161 (UDP)

The only UDP-carried detector in tscan-ng (see `capture._build_port_filter`
for the BPF change this required). Captures the community string, which is
present in *every* SNMPv1/v2c message, request or response — there is no
separate auth handshake. SNMPv3 (USM, not a plaintext community string) is
out of scope. See `tscan_ng/detectors/snmp.py` for why "outcome" is a much
weaker signal here than elsewhere: a rejected community string is often
silently dropped rather than answered.

### snmpget / snmpwalk commands

| Test | Command | Expected result |
|------|---------|-----------------|
| GetRequest — community `public` | `snmpget -v2c -c public <host> 1.3.6.1.2.1.1.1.0` | Response-PDU with sysDescr, or a timeout if `public` isn't a valid community on the target |
| Walk — community `public` | `snmpwalk -v2c -c public <host> 1.3.6.1.2.1.1` | Multiple Response-PDUs, all carrying the same community string |
| Bad community | `snmpget -v2c -c wrongcommunity <host> 1.3.6.1.2.1.1.1.0` | Typically a silent timeout (no Response-PDU) — expected per the module's "weak outcome signal" note above |

> **Known quirk:** the `filter` string in an SNMP finding is generated by the
> shared TCP-oriented helper (`host A and host B and tcp port X and tcp port
> Y`); replace `tcp` with `udp` before using it against a pcap.

---

## IRC — Ports 6667 / 6666 / 6668 / 6669

IRC itself has no login concept — the credential tscan-ng targets is the one
sent to a network's NickServ services bot as an ordinary chat message. See
`tscan_ng/detectors/irc.py` for the exact matched patterns and why SASL
PLAIN authentication is explicitly out of scope.

### nc manual session (against a server running NickServ, e.g. Atheme/Anope)

Connect with: `nc <host> 6667`

| Step | You type | Server replies |
|------|----------|-----------------|
| 1 | `NICK mynick` / `USER mynick 0 * :Test User` | Standard connection registration numerics |
| 2a | `PRIVMSG NickServ :IDENTIFY hunter2` | `:NickServ!NickServ@services... NOTICE mynick :Password accepted - you are now recognized.` |
| 2b | `PRIVMSG NickServ :IDENTIFY wrongpass` | `:NickServ!NickServ@services... NOTICE mynick :Password incorrect.` |
| 2c (short alias) | `PRIVMSG NickServ :ID hunter2` | Same as 2a — `ID` is a common alias for `IDENTIFY` |

> **Note:** Exact NOTICE wording is services-daemon-specific (Atheme, Anope,
> etc.) and not standardized by any IRC RFC. A NOTICE that doesn't match a
> recognized phrasing is skipped rather than treated as a failure.

---

## PostgreSQL — Port 5432

Captures the PostgreSQL wire protocol's `PasswordMessage` — a genuine
cleartext password — but only when the server is configured for `password`
auth in `pg_hba.conf`. The modern default, SCRAM-SHA-256, is explicitly out
of scope (see `tscan_ng/detectors/postgres.py`): it's designed so the
plaintext password never crosses the wire at all. `md5` auth is also out of
scope for the same reason (it sends a salted hash, not a password).

### psql commands

Requires a test server/database with `pg_hba.conf` set to `password` (not
`scram-sha-256` or `md5`) for the relevant host/user entry.

| Test | Command | Expected result |
|------|---------|-----------------|
| Cleartext auth — good | `PGSSLMODE=disable psql "host=<host> user=testuser password=hunter2 dbname=postgres"` | Connects; `PasswordMessage` visible in capture |
| Cleartext auth — bad | `PGSSLMODE=disable psql "host=<host> user=testuser password=wrongpass dbname=postgres"` | `FATAL: password authentication failed for user "testuser"` — `PasswordMessage` still captured |

> **Important:** `PGSSLMODE=disable` (or an equivalent client setting) is
> required — TLS-wrapped connections are not captured by tscan-ng, same as
> LDAPS/SMTPS elsewhere in this reference.

---

## Protocol Summary

| Protocol | Port | Auth method | Encoding | Server | Notes |
|----------|------|-------------|----------|--------|-------|
| SMTP | 2525 | AUTH PLAIN / LOGIN | base64 | cloud.sisypheansecurity.com | Fake server |
| IMAP | 1430 | LOGIN / AUTHENTICATE PLAIN | plaintext (LOGIN) / base64 (PLAIN) | cloud.sisypheansecurity.com | Fake server |
| POP3 | 1100 | USER/PASS / AUTH PLAIN | Plaintext / base64 | cloud.sisypheansecurity.com | Fake server |
| FTP | 21 | USER / PASS | Plaintext | ftp.freebsd.org | Public server |
| HTTP | 80 | Basic Auth | base64 | neverssl.com | No TLS guaranteed |
| Telnet | 2323 | Login prompt | Plaintext | cloud.sisypheansecurity.com | Raw ASCII on wire |
| LDAP | 389, 3268 | Simple bind | Plaintext BER | Local test instance | 636/3269 are TLS — not captured |
| Redis | 6379, 6380 | AUTH command | Plaintext RESP | Local test instance | Redis 6+ supports ACL username |
| SMB | 445, 139 | NTLM SESSION_SETUP | NTLMv2 challenge/response (hashcat -m 5600) | Real SMB server / local Samba | Captures a crackable hash, not a password |
| SNMP | 161 (UDP) | Community string | Plaintext BER | Any SNMPv1/v2c agent | Only UDP detector; SNMPv3 (USM) not captured |
| IRC | 6667, 6666, 6668, 6669 | NickServ IDENTIFY | Plaintext PRIVMSG | Server running NickServ (Atheme/Anope) | SASL PLAIN auth out of scope |
| PostgreSQL | 5432 | PasswordMessage | Plaintext | Local test instance | Requires `password` auth in pg_hba.conf; SCRAM/md5 not captured |
