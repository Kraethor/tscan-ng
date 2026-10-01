# tscan-ng

`tscan-ng` is a line-speed network traffic scanner designed for passive
monitoring via SPAN / mirror ports.

## Repository layout
- `tscan_ng/` – Python capture pipeline, detectors, and output sinks
- `scripts/` – operational scripts (live viewer, dashboard, status snapshot,
  health check, deploy/update/push) and the fake protocol servers used for
  manual testing; see "Scripts" below
- `systemd/` – systemd service/timer units, plus a template
  systemd-networkd config for the capture NIC
- `logrotate/` – log rotation configuration
- `tests/` – unit tests for detector parsing (stdlib `unittest`, no network
  or root needed); see "Deployment" below for how to run them
- `docs/` – rebuild and deployment documentation (`REBUILD.md`) and the
  manual protocol test reference (`test_reference.md`)
- `requirements.txt` – pinned Python dependencies (`dpkt`, `orjson`,
  `requests`); libpcap (`libpcap0.8`) is a system package, not a pip one

## Architecture

A single systemd service, **tscan-pipeline**, does the whole job. It spawns
`workers` (default: one per CPU) self-contained processes, each opening its
own raw `AF_PACKET` socket joined to a shared kernel `PACKET_FANOUT_HASH`
group on the capture interface. The kernel guarantees every packet of a
given flow lands on the same worker, so each process independently does
its own capture → TCP stream reassembly (`SessionTable`) → protocol
detection → output, with no coordination needed between workers.

Every finding is written to a shared JSONL file (`tscan_ng/sinks/jsonl.py`,
`flock()`-safe for concurrent writers) and, for any finding whose outcome
isn't "failed" (see `DiscordSink._SUPPRESSED_OUTCOMES`) and isn't
an SNMP `no_response` (unanswered internet scans of UDP 161; see
`DiscordSink._SUPPRESSED_TYPE_OUTCOMES`), to a
Discord webhook (`tscan_ng/sinks/discord.py`) — both fire from inside the
pipeline itself, independent of whether anything is watching. Both sinks sit
behind one shared repeat-finding cooldown in `pipeline.py`'s `_emit()`: a
finding with the same `(dst, dport, creds, outcome)` as one already emitted within
`[dedup] finding_cooldown_sec` (default 1800 s) is dropped before *either*
sink sees it, so a scanner replaying the same credentials at the same
service produces one log line and one alert per window, not one per packet.
A worker that dies abnormally (e.g. the capture interface going
down) exits non-zero so systemd's `Restart=on-failure` actually restarts
the service, and fires its own Discord alert. A separate
`tscan-pipeline-healthcheck` timer polls the service's status every 2
minutes from outside the Python process entirely, as a second layer that
also catches failures the in-process code can't see (OOM-kill, startup
failure). See "Alerting & health monitoring" below.

Workers are started with `multiprocessing`'s `spawn` method (pinned in
`pipeline.main()`). On `systemctl stop`/`restart` (SIGTERM) each worker stops
its capture loop, flushes its sessions — credentials seen but not yet answered
are written as `no_response` instead of being lost — and exits; a stop or
restart normally takes about a second.

## Detectors

| Protocol | Detection method            | Default ports                          |
|----------|------------------------------|------------------------------------------|
| HTTP     | Basic Auth header scan      | 80, 3128, 8000, 8008, 8080, 8081, 8888  |
| FTP      | USER/PASS command scan      | 21, 2121                                |
| SMTP     | AUTH PLAIN / AUTH LOGIN scan | 25, 465, 587, 2525                      |
| IMAP     | LOGIN and AUTHENTICATE PLAIN scan | 143, 993, 1430                    |
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
attempt succeeded, but a failed SMB logon still maps to outcome="failed"
and so still won't alert, for consistency with every other detector —
only outcome="failed" is suppressed; a non-success,
non-failed SMB status maps to "server_error", which does alert).

SNMP is the other exception, in the other direction: it's the first and
only UDP-carried detector (every other protocol here is TCP), and its
"outcome" is a much weaker signal than elsewhere — SNMPv1/v2c has no
"authentication failed" response; a rejected community string typically
just gets silently dropped by the agent rather than answered. See
`tscan_ng/detectors/snmp.py` for the full reasoning. Because unanswered
scans of UDP 161 are constant, an SNMP `no_response` is logged to the JSONL
file but does not alert on Discord; an SNMP finding that got a reply still does.

## Configuration

Runtime settings live in `tscan_ng/config/tscan_ng.conf` (gitignored — it's
host-specific and may hold a Discord webhook secret); start from the tracked,
secret-free template `tscan_ng.conf.example`. The minimum required
setting is `capture.iface`. All other values have safe defaults; see the
config file itself and `tscan_ng/config.py` for full documentation of
every setting, including `[capture]` (interface, snaplen, buffer size),
`[dispatcher]` (worker count, output path), `[sessions]` (timeouts,
buffer/session limits), `[logging]` (worker log level, default INFO), `[discord]`
(webhook, operational-alert cooldown) and
`[dedup]` (repeat-finding cooldown). The config file is read once at startup,
so restart the service after editing it. Note that `[dispatcher] socket` is a
leftover from the retired dispatcher architecture: it is still validated by
`config.py` (must be an absolute path) but nothing opens it any more.

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
# abnormally). Does NOT apply to credential findings -- see [dedup].
notify_cooldown_sec = 300

[dedup]
# Minimum seconds between findings sharing the same (dst, dport, creds, outcome).
# Applied once in pipeline.py's _emit(), i.e. BEFORE both results.jsonl and
# Discord, so it also thins out what watch.py and the dashboard show.
# 0 disables it (every finding is emitted). Default 1800 (30 minutes).
finding_cooldown_sec = 1800
```

Leave `discord_webhook` blank or omit the section to disable alerting
entirely. Three kinds of alert share the one webhook:

- **Credential finding** — fired for every finding whose outcome is not
  `failed` (so `success`, `redirect`, `server_error`,
  `no_response` and `unknown` all alert — e.g. an HTTP Basic request answered
  with a 403 usually means the credentials were accepted), except an SNMP
  `no_response` (unanswered internet scans of UDP 161 — logged, not alerted).
  Only the finding `type`, the username portion of `creds`, the `outcome` and
  `session_id` are sent; no passwords or packet payloads leave the host. SNMP
  findings have no username part (the community string is the secret), so
  their alerts show a placeholder instead of the community string. Repeats of the same
  `(dst, dport, creds, outcome)` within `[dedup] finding_cooldown_sec` are suppressed
  before this point (see Architecture).
- **Pipeline failure** (in-process) — fired when a worker process exits
  abnormally (e.g. the capture interface going down). Rate-limited by
  `notify_cooldown_sec` so a sustained outage sends one alert per cooldown
  window, not one per crash-loop cycle.
- **Service down / recovered** (external) — `tscan-pipeline-healthcheck.timer`
  runs a check every 2 minutes, entirely outside the Python process, and
  alerts once on each up/down transition. This is the layer that catches
  failures the in-process code structurally can't see, such as an
  OOM-kill or a startup failure before configuration even loads.

## Monitoring & status

Three read-only tools:

- `scripts/watch.py` — tails the results file and displays colour-coded
  credential findings in real time. Shows only new findings with
  `outcome == "success"` (other outcomes are in the JSONL and may still
  alert on Discord, but are not displayed). Reads only the results JSONL, so
  it needs membership in the `tscan` group (or `sudo`): `/var/log/tscan` is
  `0750`. Control characters in captured fields (an attacker can put ANSI
  escapes in a password or URL) are shown as `\xNN` escapes rather than
  sent to your terminal.
- `scripts/dashboard.py` — live full-screen status dashboard (service
  state, monitor/admin interface health, capture throughput, recent
  findings — again counting only `outcome == "success"` — and worker/load
  info), refreshing once a second. Interface names and the worker count are
  constants at the top of the script, not read from the config. Everything it
  reads (systemd unit properties, `/sys/class/net` statistics) is
  world-readable except the results JSONL, which needs `tscan` group
  membership like `watch.py`; without it the findings panel stays at zero.
- `scripts/status.sh` — a quick, non-interactive snapshot of the same
  service/interface/log state for a single glance or piping elsewhere,
  including the main PID and the number of worker processes. Unlike the two
  above, it runs `journalctl` via `sudo` — passwordless (NOPASSWD, see
  `/etc/sudoers.d/`) so it needs no interactive root login, but that one
  call genuinely runs as root. `systemctl` and `ip` run as the invoking user.

None of these affect logging or alerting — both already happen inside
`tscan-pipeline.service` regardless of whether any viewer is running, so
closing them never turns anything off.

```bash
python3 /opt/tscan/scripts/watch.py
python3 /opt/tscan/scripts/dashboard.py
bash /opt/tscan/scripts/status.sh
```

## Scripts

| Script | Run as | Purpose |
|--------|--------|---------|
| `scripts/watch.py [file]` | `tscan` group | Live coloured viewer of successful findings (see above) |
| `scripts/dashboard.py` | any user | Full-screen curses status dashboard (see above) |
| `scripts/status.sh` | any user with the NOPASSWD sudo grants | One-shot text status snapshot |
| `scripts/pipeline_healthcheck.py` | `tscan`, via `tscan-pipeline-healthcheck.service` | Out-of-process up/down check; alerts on Discord on each transition |
| `scripts/update.sh` | root | `git pull --ff-only`, pip install, pre-flight (tests + config), install changed systemd units, restart, verify it stays up; rolls back to the previous commit if anything fails (exit 0 up, 2 nothing changed, 3 rolled back, 4 down). Does **not** install `logrotate/tscan` or the networkd file |
| `scripts/push.sh "msg" [file ...]` | root | Stage, commit and push as the `tscan` user |
| `scripts/fake_smtp.py`, `fake_imap.py`, `fake_pop3.py`, `fake_telnet.py` | any non-root user, on a test host | Cleartext fake servers on TCP 2525 / 1430 / 1100 / 2323 that accept `testuser` / `hunter2` and reject everything else; used to generate traffic for the detectors (see `docs/test_reference.md`) |

Each script has a header documenting its arguments, environment, required
privileges and exit codes.

## systemd, logrotate and networking

- `systemd/tscan-pipeline.service` — the pipeline (`Restart=on-failure`,
  `RestartSec=5`, `StartLimitIntervalSec=0`, ambient `CAP_NET_RAW` +
  `CAP_NET_ADMIN`, `MemoryHigh=6G` / `MemoryMax=8G` / `MemorySwapMax=512M`,
  `RuntimeDirectory=tscan`).
- `systemd/tscan-pipeline-healthcheck.service` / `.timer` — oneshot check run
  every 2 minutes (`OnBootSec=2min`, `OnUnitActiveSec=2min`); state lives in
  `/var/lib/tscan-healthcheck` (`StateDirectory=`).
- `logrotate/tscan` — daily, keep 14, compressed, `copytruncate` and
  `su tscan tscan` (both required; see the comments in the file).
- `systemd/tscan-monitor.network.example` — template
  systemd-networkd match for the capture NIC. Without a `.network` file
  matching its MAC, nothing brings that NIC up after boot or USB
  re-enumeration and the pipeline crash-loops. The live host uses
  `/etc/systemd/network/70-tscan-monitor.network`.
- Runtime scratch: `/run/tscan/` (created by `RuntimeDirectory=tscan`) holds
  the Discord operational-alert cooldown marker and, under
  `/run/tscan/finding_cooldown/`, one marker file per `(dst, dport, creds, outcome)`
  key for the finding cooldown. The directory is emptied when the service
  stops, so the finding cooldown resets on every full stop/start (it survives
  `Restart=on-failure` cycles). Markers older than the cooldown are deleted
  by worker 0 every `expiry_interval_sec`, so the directory holds at most
  one window's worth of keys.

## Deployment
See `docs/REBUILD.md` for full rebuild instructions. `scripts/push.sh
"commit message" [file ...]` stages, commits, and pushes local changes as
the `tscan` service user (the repo at `/opt/tscan` is owned by `tscan`, not
whichever admin is running the script). Never run bare `git` as another
user in `/opt/tscan`: it leaves root/operator-owned objects that the
`tscan` user can no longer write.

Unit tests (detector parsing regressions; no network, root or config file
needed) run from `/opt/tscan` with the project venv, which has `dpkt`:

    PYTHONDONTWRITEBYTECODE=1 venv/bin/python -m unittest discover -s tests -t . -v

`PYTHONDONTWRITEBYTECODE=1` is there because `__pycache__` is not writable
for the operator account. Testing detectors against live traffic by hand:
see `docs/test_reference.md`.

## Notes
- Designed to run with a non-login service account
- Capture NIC is RX-only (no default route)
- Management NIC handles SSH, Git, and admin
