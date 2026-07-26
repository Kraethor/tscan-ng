# tscan-ng

`tscan-ng` is a line-speed network traffic scanner designed for passive
monitoring via SPAN / mirror ports.

## Repository layout
- `tscan_ng/` – Python capture pipeline, detectors, and output sinks
- `scripts/` – operational scripts (live viewer, health check, deploy/update)
- `systemd/` – systemd service/timer units
- `logrotate/` – log rotation configuration
- `docs/` – rebuild and deployment documentation

## Architecture

A single systemd service, **tscan-pipeline**, does the whole job. It spawns
`workers` (default: one per CPU) self-contained processes, each opening its
own raw `AF_PACKET` socket joined to a shared kernel `PACKET_FANOUT_HASH`
group on the capture interface. The kernel guarantees every packet of a
given flow lands on the same worker, so each process independently does
its own capture → TCP stream reassembly (`SessionTable`) → protocol
detection → output, with no coordination needed between workers.

Every finding is written to a shared JSONL file (`tscan_ng/sinks/jsonl.py`,
`flock()`-safe for concurrent writers) and, for successful credential
captures, to a Discord webhook (`tscan_ng/sinks/discord.py`) — both fire
from inside the pipeline itself, independent of whether anything is
watching. A worker that dies abnormally (e.g. the capture interface going
down) exits non-zero so systemd's `Restart=on-failure` actually restarts
the service, and fires its own Discord alert. A separate
`tscan-pipeline-healthcheck` timer polls the service's status every 2
minutes from outside the Python process entirely, as a second layer that
also catches failures the in-process code can't see (OOM-kill, startup
failure). See "Alerting & health monitoring" below.

## Detectors

| Protocol | Detection method            | Default ports                          |
|----------|------------------------------|------------------------------------------|
| HTTP     | Basic Auth header scan      | 80, 3128, 8000, 8008, 8080, 8081, 8888  |
| FTP      | USER/PASS command scan      | 21, 2121                                |
| SMTP     | AUTH credential scan        | 25, 465, 587, 2525                      |
| IMAP     | LOGIN command scan          | 143, 993, 1430                          |
| POP3     | USER/PASS command scan      | 110, 995, 1100                          |
| Telnet   | Login/Password prompt scan  | 23, 2323                                |
| LDAP       | Simple-bind BindRequest     | 389, 3268                               |
| Redis      | AUTH command scan          | 6379, 6380                              |
| SMB        | NTLMv2 challenge/response   | 445, 139                                |
| SNMP       | v1/v2c community string    | 161 (UDP)                               |
| IRC        | NickServ IDENTIFY scan     | 6667, 6666, 6668, 6669                  |
| PostgreSQL | Cleartext PasswordMessage  | 5432                                    |

Every detector, including HTTP, is gated on its configured port list — a
session whose ports don't appear in the relevant `[ports]` entry is
skipped by that detector, and a BPF filter compiled from the union of all
configured ports is attached at the capture socket so non-matching traffic
never reaches userspace at all.

SMB is a deliberate exception to "credential" meaning "plaintext
password" — NTLM authentication is a challenge/response handshake, so what
gets captured is the NTLMv2 hash itself, formatted ready for `hashcat -m
5600` / `john --format=netntlmv2` (the same technique tools like Responder
use), not a password. See `tscan_ng/detectors/smb.py` for the full
protocol-correlation details and the resulting alerting tradeoff (a
captured hash is equally crackable whether or not that specific logon
attempt succeeded, but Discord alerting is still gated on the SMB session
actually succeeding, for consistency with every other detector).

SNMP is the other exception, in the other direction: it's the first and
only UDP-carried detector (every other protocol here is TCP), and its
"outcome" is a much weaker signal than elsewhere — SNMPv1/v2c has no
"authentication failed" response; a rejected community string typically
just gets silently dropped by the agent rather than answered. See
`tscan_ng/detectors/snmp.py` for the full reasoning.

## Configuration

Runtime settings live in `tscan_ng/config/tscan_ng.conf` (gitignored — it's
host-specific and may hold a Discord webhook secret). The minimum required
setting is `capture.iface`. All other values have safe defaults; see the
config file itself and `tscan_ng/config.py` for full documentation of
every setting, including `[capture]` (interface, snaplen, buffer size),
`[dispatcher]` (worker count, output path), and `[sessions]` (timeouts,
buffer/session limits).

Port lists for each protocol detector are configured under `[ports]` and
can be extended without touching source code:

```ini
[ports]
http   = 80, 8080, 8000, 8008, 8081, 8888, 3128
ftp    = 21, 2121
smtp   = 25, 465, 587, 2525
imap   = 143, 993, 1430
pop3   = 110, 995, 1100
telnet = 23, 2323
ldap   = 389, 3268
redis  = 6379, 6380
smb    = 445, 139
snmp   = 161
irc    = 6667, 6666, 6668, 6669
postgres = 5432
```

After editing the config, restart the pipeline:
```bash
sudo systemctl restart tscan-pipeline
```

## Alerting & health monitoring

Discord alerting is always on — it lives inside `tscan-pipeline.service`,
not in any viewer, so there is nothing to remember to turn on. Add a
`[discord]` section to `tscan_ng.conf` to enable it:

```ini
[discord]
discord_webhook = https://discord.com/api/webhooks/...

# Minimum seconds between operational alerts (pipeline_worker exiting
# abnormally). Credential-finding alerts are never rate-limited.
notify_cooldown_sec = 300
```

Leave `discord_webhook` blank or omit the section to disable alerting
entirely. Three kinds of alert share the one webhook:

- **Credential finding** — fired for every successful capture. Only the
  finding `type`, the username portion of `creds`, and `session_id` are
  sent; no passwords or packet payloads leave the host.
- **Pipeline failure** (in-process) — fired when a worker process exits
  abnormally (e.g. the capture interface going down). Rate-limited by
  `notify_cooldown_sec` so a sustained outage sends one alert per cooldown
  window, not one per crash-loop cycle.
- **Service down / recovered** (external) — `tscan-pipeline-healthcheck.timer`
  runs a check every 2 minutes, entirely outside the Python process, and
  alerts once on each up/down transition. This is the layer that catches
  failures the in-process code structurally can't see, such as an
  OOM-kill or a startup failure before configuration even loads.

## Live monitor

`scripts/watch.py` tails the results file and displays colour-coded
findings in real time. It's a read-only viewer — logging and alerting both
already happen inside `tscan-pipeline.service` regardless of whether this
is running, so closing it never turns anything off. No root required:

```bash
python3 /opt/tscan/scripts/watch.py
```

## Deployment
See `docs/REBUILD.md` for full rebuild instructions.

## Notes
- Designed to run with a non-login service account
- Capture NIC is RX-only (no default route)
- Management NIC handles SSH, Git, and admin
