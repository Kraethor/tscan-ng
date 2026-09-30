# REBUILD.md
**tscan-ng – Rebuild & Deployment Guide**
**Applies to any tscan-ng deployment (e.g. U01, ser8)**

## Purpose

This document describes how to rebuild a `tscan-ng` capture node from scratch
(e.g., hardware loss, OS reinstall, disaster recovery).

The goal is that **this repo alone** is sufficient to rebuild a working system.

---

## System Overview

- **Host role:** Passive network traffic capture + analysis
- **Traffic source:** Switch SPAN / mirror port
- **Execution model:** One systemd service (`tscan-pipeline`) plus a
  timer/oneshot pair for external health monitoring
  (`tscan-pipeline-healthcheck`)
- **Language:** Python (raw `AF_PACKET` sockets; libpcap via ctypes for BPF
  filter compilation only)
- **Security model:**
  - Non-login service account
  - No group sharing
  - No interactive access for service user

---

## Network Design

### Interfaces

| Interface      | Purpose              | Notes                        |
|-----------------|-----------------------|--------------------------------|
| Management NIC | SSH, Git, admin      | Has default route + DNS      |
| Capture NIC    | SPAN destination     | RX-only, no gateway          |

**Important:**
Traffic generated *on this host* will **not** be seen by the capture NIC.

**Bringing the capture NIC up automatically:**
Nothing does this by default. Netplan on a typical install only manages
the admin NIC (matched by its own MAC address), NetworkManager is usually
not installed, and a udev rule reacting to the capture NIC appearing
(e.g. for ethtool ring-buffer tuning) does not itself set the link
state. Left unconfigured, the capture NIC stays admin-down after every
boot or USB re-enumeration, and `tscan-pipeline.service` crash-loops
waiting for it (see "Pipeline restarts continuously" below).

Fix by adding a systemd-networkd match for the capture NIC's MAC address.
A template is at `systemd/tscan-monitor.network.example`:
```bash
sudo cp /opt/tscan/systemd/tscan-monitor.network.example \
  /etc/systemd/network/70-tscan-monitor.network
sudo sed -i 's/00:11:22:33:44:55/<capture-nic-mac-address>/' \
  /etc/systemd/network/70-tscan-monitor.network
sudo systemctl restart systemd-networkd
```
No DHCP/addressing — it's a passive SPAN/mirror interface and never
needs an IP.

---

## Filesystem Layout

| Path                                       | Purpose                                              |
|----------------------------------------------|---------------------------------------------------------|
| `/opt/tscan`                               | Application root                                     |
| `/opt/tscan/tscan_ng`                      | Python source                                        |
| `/opt/tscan/tscan_ng/config/tscan_ng.conf` | Runtime configuration (gitignored, host-specific)    |
| `/opt/tscan/scripts`                       | Operational scripts                                  |
| `/opt/tscan/systemd`                       | systemd unit files, plus `tscan-monitor.network.example` (template for the capture NIC's networkd config) |
| `/opt/tscan/logrotate`                     | logrotate config                                     |
| `/opt/tscan/docs`                          | Documentation (this file, `test_reference.md`)       |
| `/opt/tscan/requirements.txt`              | Pinned pip dependencies (`dpkt`, `orjson`, `requests`) |
| `/opt/tscan/venv`                          | Python virtualenv                                    |
| `/opt/tscan/.ssh`                          | GitHub deploy key (mode 700, `tscan`-owned)          |
| `/var/log/tscan`                           | Runtime logs                                         |
| `/run/tscan`                               | tmpfs, created by `RuntimeDirectory=tscan` on the pipeline unit. Holds the cross-process Discord operational-alert cooldown marker (`discord_notify_last`) and the per-key repeat-finding cooldown markers (`finding_cooldown/<sha256>`, see "Repeat-finding cooldown" below) — not a socket (the old dispatcher's Unix socket no longer exists in the fan-out architecture, and the `[dispatcher] socket` config key is vestigial). Contents are lost whenever the service is stopped (a full stop/start resets the cooldowns). |
| `/var/lib/tscan-healthcheck`               | Persistent state for the healthcheck timer (`down` up/down transition marker and `discord_marker`), created via `StateDirectory=` on that unit |
| `/etc/systemd/network/70-tscan-monitor.network` | Capture NIC networkd config (installed by hand from the `.example` template) |
| `/etc/logrotate.d/tscan`                   | Installed by hand from `logrotate/tscan` (`update.sh` does not touch it) |

---

## Prerequisites (Ubuntu)
```bash
sudo apt update
sudo apt install -y \
  python3 \
  python3-venv \
  python3-pip \
  git \
  libpcap0.8 \
  logrotate
```
`libpcap0.8` is loaded at import time via `ctypes` (`capture.py` raises
`RuntimeError("libpcap not found")` without it). Python 3.11 or newer is
required (`scripts/dashboard.py` uses `datetime.UTC`, and the live host runs
3.14).

---

## Create Service Account

Create a **non-login** service user:
```bash
sudo useradd \
  --system \
  --no-create-home \
  --shell /usr/sbin/nologin \
  tscan
```

Verify:
```bash
getent passwd tscan
```
**Note:**
This is a non-login service account with no home directory. It has no
interactive access and exists solely to own and run the tscan-ng service.

---

## Deploy Code

```bash
sudo mkdir -p /opt/tscan
sudo chown -R tscan:tscan /opt/tscan
sudo chmod 755 /opt/tscan
```

The repo is private and cloned over SSH using a deploy key scoped to this
repo, not a GitHub PAT. Provision the key **before** cloning, since the
clone step needs it:

```bash
sudo -u tscan -H mkdir -p -m 700 /opt/tscan/.ssh
# Copy in the existing deploy key pair (id_ed25519_tscan_ng /
# id_ed25519_tscan_ng.pub) from wherever it's backed up, or generate a new
# one and register its public half as a GitHub deploy key on
# Kraethor/tscan-ng (read access is enough; write access is only needed if
# this host will also push):
sudo -u tscan -H ssh-keygen -t ed25519 -f /opt/tscan/.ssh/id_ed25519_tscan_ng -N ""
sudo -u tscan -H chmod 600 /opt/tscan/.ssh/id_ed25519_tscan_ng
```

Clone the repo **as the service user**, over SSH, pinned to this key:
```bash
sudo -u tscan -H env GIT_SSH_COMMAND="ssh -i /opt/tscan/.ssh/id_ed25519_tscan_ng -o IdentitiesOnly=yes -o UserKnownHostsFile=/opt/tscan/.ssh/known_hosts -o StrictHostKeyChecking=accept-new" \
  git clone git@github.com:Kraethor/tscan-ng.git /opt/tscan
```

Once cloned, pin the same SSH command in the repo's own config so future
`git` operations (including the `sudo -u tscan git ...` pattern used
elsewhere in this doc and by `scripts/update.sh`) use it automatically
without needing `GIT_SSH_COMMAND` set every time:
```bash
sudo -u tscan -H git -C /opt/tscan config core.sshCommand \
  "ssh -i /opt/tscan/.ssh/id_ed25519_tscan_ng -o IdentitiesOnly=yes -o UserKnownHostsFile=/opt/tscan/.ssh/known_hosts -o StrictHostKeyChecking=accept-new"
sudo -u tscan -H git -C /opt/tscan config user.name "<git identity>"
sudo -u tscan -H git -C /opt/tscan config user.email "<git identity email>"
```

---

## Python Virtual Environment
```bash
sudo -u tscan -H bash -lc '
  cd /opt/tscan
  python3 -m venv venv
  source venv/bin/activate
  pip install --upgrade pip
  pip install -r requirements.txt
  deactivate
'
```

## Grant Capture Capabilities

The `tscan-pipeline.service` unit grants `CAP_NET_RAW` and `CAP_NET_ADMIN`
directly to the pipeline process via systemd's `AmbientCapabilities`
directive. No `setcap` on the Python binary is required — the unit file
handles this automatically, and Python's `multiprocessing.Process` (used to
fork off each worker) preserves ambient capabilities across `fork()`, so
every worker inherits them without a re-exec step.

---

## Configuration

Set ownership and permissions on the config file:
```bash
sudo chown tscan:tscan /opt/tscan/tscan_ng/config/tscan_ng.conf
sudo chmod 640 /opt/tscan/tscan_ng/config/tscan_ng.conf
```

`640` (owner + group readable, not world-readable) is sufficient: every
process that reads this file — `tscan-pipeline.service` and
`tscan-pipeline-healthcheck.service` — runs as `tscan`. Unlike the old
architecture, `scripts/watch.py` no longer reads this file at all (it just
tails the results JSONL by path), so there is no longer a reason to make
it world-readable. The file may still contain a Discord webhook URL, which
should be treated as a secret.

Create it from the tracked template (`cp /opt/tscan/tscan_ng.conf.example /opt/tscan/tscan_ng/config/tscan_ng.conf`,
then fix ownership/mode as above) and set at minimum:
```ini
[capture]
iface = <your capture interface name>
```

All other values have safe defaults. See the config file itself and
`tscan_ng/config.py` for documentation of every setting. Sections:
`[capture]` (iface, snaplen, buffer_bytes, bpf_filter; `no_immediate` is a
leftover from the libpcap capture path and is not read by any code now),
`[dispatcher]` (workers, out; `socket` is vestigial — validated but unused),
`[sessions]` (timeout_seconds, max_buf_bytes, expiry_interval_sec,
pending_max_age_sec, max_sessions), `[ports]`, `[discord]` and `[dedup]`.
The file is read once at startup; `config.py` validates it and the service
exits with a "Invalid configuration" error (status 1) on bad values,
including a `capture.iface` that is not present in `/sys/class/net`.

### Protocol detector ports

The `[ports]` section controls which ports each protocol detector will
scan — this now includes HTTP, which used to run port-agnostic on every
port and no longer does. A session whose src and dst port are both absent
from a protocol's list is skipped by that detector, and a BPF filter
compiled from every configured port is attached directly to each worker's
capture socket, so non-matching traffic never reaches userspace in the
first place. All of these are TCP ports except `snmp`, which is UDP —
capture.py's `_build_port_filter` gives it its own `udp and (...)` BPF
clause rather than folding it into the TCP port union. Defaults:

```ini
[ports]
http     = 80, 8080, 8000, 8008, 8081, 8888, 3128
ftp      = 21, 2121
smtp     = 25, 465, 587, 2525
imap     = 143, 993, 1430
pop3     = 110, 995, 1100
telnet   = 23, 2323
ldap     = 389, 3268
redis    = 6379, 6380
smb      = 445, 139
snmp     = 161
irc      = 6667, 6666, 6668, 6669
postgres = 5432
```

Add non-standard ports by appending to the comma-separated list. No
source code changes are required — just edit the config and restart the
service.

### Discord alerting

To enable Discord alerts, add a `[discord]` section to the config:

```ini
[discord]
discord_webhook = https://discord.com/api/webhooks/...
notify_cooldown_sec = 300
```

Leave `discord_webhook` blank or omit the section to disable alerting.
Alerting is built into `tscan-pipeline.service` itself — it does not
depend on `watch.py` or any other viewer running. Three kinds of alert
share the one webhook:

- **Credential finding**, fired for every finding whose outcome is not
  `pending` or `failed` (`success`, `redirect`, `server_error`,
  `no_response` and `unknown` all alert). Only `type`, the username
  portion of `creds`, the `outcome` and `session_id` are sent — no
  password material or packet payloads leave the host.
- **Pipeline failure** (in-process), fired when a worker exits abnormally
  (e.g. the capture interface dropping). `notify_cooldown_sec` rate-limits
  this so a sustained outage doesn't send one alert per restart cycle.
- **Service down / recovered** (external), fired by
  `tscan-pipeline-healthcheck.timer` — see its own section below.

### Repeat-finding cooldown

```ini
[dedup]
finding_cooldown_sec = 1800
```

Findings that share the same `(dst, dport, creds)` — the same credentials
sent to the same service, regardless of source or protocol type — are
emitted at most once per `finding_cooldown_sec` (default 1800 s = 30
minutes; `0` disables the cooldown). The check happens once in
`pipeline.py`'s `_emit()`, **upstream of both** `results.jsonl` and Discord,
so `watch.py` and the dashboard (which read that file) are thinned out the
same way. Distinct targets or distinct credentials are still emitted
immediately. State is kept as marker files under `/run/tscan/finding_cooldown/`,
so it is shared by all workers and is reset by a full service stop/start
(not by a `Restart=on-failure` cycle). If the marker directory cannot be
used, the check fails open (findings are logged, just not deduplicated).
Not to be confused with `[discord] notify_cooldown_sec`, which only rate-limits
operational (non-finding) alerts.

**Important:**
After editing `tscan_ng.conf`, the service must be restarted:
```bash
sudo systemctl restart tscan-pipeline
```

---

## Logging Directory
```bash
sudo mkdir -p /var/log/tscan
sudo chown -R tscan:tscan /var/log/tscan
sudo chmod 750 /var/log/tscan
```
`750` means only `tscan` (and its group) can read the findings log, in which
case `watch.py` and `dashboard.py` need `sudo` (or membership in the `tscan`
group). Their documented "runs as any user" behaviour requires the
directory to be world-searchable and the file world-readable (the live host
uses `775` on the directory; the service creates `results.jsonl` as `644`).
Choose according to how sensitive the captured credentials are — the JSONL
contains them in the clear.

---

## Install systemd Units
```bash
sudo cp /opt/tscan/systemd/tscan-pipeline.service /etc/systemd/system/
sudo cp /opt/tscan/systemd/tscan-pipeline-healthcheck.service /etc/systemd/system/
sudo cp /opt/tscan/systemd/tscan-pipeline-healthcheck.timer /etc/systemd/system/
```

Reload and enable:
```bash
sudo systemctl daemon-reload
sudo systemctl enable --now tscan-pipeline
sudo systemctl enable --now tscan-pipeline-healthcheck.timer
```

Verify:
```bash
sudo systemctl status tscan-pipeline --no-pager
sudo systemctl list-timers tscan-pipeline-healthcheck.timer --no-pager
```

`tscan-pipeline.service` sets `StartLimitIntervalSec=0`, so it will keep
retrying forever on failure (e.g. while the capture interface is down)
rather than exhausting systemd's default start-limit and landing
permanently in `failed`. `tscan-pipeline-healthcheck.timer` runs every 2
minutes and is the independent, out-of-process check that this doesn't
silently stop working.

---

## Install logrotate Configuration
```bash
sudo cp /opt/tscan/logrotate/tscan /etc/logrotate.d/tscan
```

Test:
```bash
sudo logrotate -v /etc/logrotate.d/tscan
```

**Important:**
The logrotate config must include:
```
su tscan tscan
```

---

## Update Script

For subsequent updates after initial deployment, use the update script:
```bash
sudo /opt/tscan/scripts/update.sh
```

The script will:
- Stop `tscan-pipeline`
- Pull the latest code from the repository (as `tscan`, over the deploy key)
- Run `pip install --upgrade -r requirements.txt` in the venv (whenever the
  file exists and `/opt/tscan/venv` exists; it does not check whether the
  file changed)
- Reinstall systemd units if they changed (`tscan-pipeline.service` and
  the healthcheck `.service`/`.timer` pair)
- Reload systemd if needed
- Start `tscan-pipeline` and ensure the healthcheck timer is enabled
- Report final status

It does **not** install `logrotate/tscan` or the capture-NIC networkd file;
repeat those steps by hand if they change. The script uses `set -e`, and the
service is stopped first, so a failure in the pull/pip/unit-copy steps leaves
the pipeline **stopped** — fix the cause and re-run, or
`sudo systemctl start tscan-pipeline`.

**Important:**
The update script must be run as root. It handles stop/start ordering
automatically.

`scripts/push.sh "commit message" [file ...]` (root) is the counterpart for
sending local changes upstream; it runs every git command as `tscan`.

---

## Runtime Verification

### Pipeline process
```bash
sudo systemctl status tscan-pipeline --no-pager
```
Should show `active (running)` with `workers`-many `pipeline_worker`
child processes under the main PID.

### Capture NIC
```bash
sudo tcpdump -ni <capture-interface> -c 10
```

### Detection Output
```bash
sudo tail -f /var/log/tscan/results.jsonl
```

### Live Monitor
```bash
python3 /opt/tscan/scripts/watch.py
```

Displays colour-coded findings in real time. It starts at the end of the
file, so only new findings appear, and it shows only `outcome == "success"`
(other outcomes are in the JSONL and may still alert on Discord). Read-only —
logging and Discord alerting already happen inside `tscan-pipeline.service`
regardless of whether this is running. Needs only read access to
`/var/log/tscan/results.jsonl` (see "Logging Directory" above); no root
required on the current host.

### Live Status Dashboard
```bash
python3 /opt/tscan/scripts/dashboard.py
```

Full-screen, auto-refreshing view of service state, monitor/admin
interface health, capture throughput, recent findings, and worker/load
info (findings count only `outcome == "success"`; the worker count shown is
a constant in the script, not read from the config). Everything it reads (systemd unit properties, `/sys/class/net`
statistics, the results JSONL) is world-readable, so this also runs as any
user — no root required. Press `q` or Ctrl-C to quit.

### Quick Status Snapshot
```bash
bash /opt/tscan/scripts/status.sh
```

A non-interactive, one-shot version of the same status information —
useful for a quick check or piping into something else. Uses the
NOPASSWD sudo grants for `systemctl`/`journalctl`/`ip` (see
`/etc/sudoers.d/`) rather than requiring a root login.

### Fake protocol servers (generating test traffic)
```bash
python3 /opt/tscan/scripts/fake_smtp.py    # TCP 2525
python3 /opt/tscan/scripts/fake_imap.py    # TCP 1430
python3 /opt/tscan/scripts/fake_pop3.py    # TCP 1100
python3 /opt/tscan/scripts/fake_telnet.py  # TCP 2323
```
Run on a separate test host (traffic originating on the capture host
itself never appears on its SPAN-fed capture NIC), then use the commands in
`docs/test_reference.md` from a machine whose traffic is mirrored to the
capture NIC. Valid credentials are `testuser` / `hunter2`. Remember the
repeat-finding cooldown: re-sending the identical credentials to the same
server within 30 minutes will not produce a second `results.jsonl` line.

### Health check timer
```bash
sudo systemctl list-timers tscan-pipeline-healthcheck.timer --no-pager
sudo systemctl status tscan-pipeline-healthcheck.service --no-pager
```
The service's last run should be `code=exited, status=0/SUCCESS` — a
non-zero exit here means the healthcheck script itself broke, not
necessarily that the pipeline is down. The script reads only the Discord
webhook, without config validation, so a missing capture NIC or an invalid or
unreadable config file does not stop it: it still checks the unit and sends
the DOWN alert (with an unreadable config there is no webhook, so no Discord
message, but the marker file is still written).
To reset its state, remove `/var/lib/tscan-healthcheck/down` (this makes it
treat the pipeline as "up"; it will alert DOWN again on the next tick if the
service is still not active).

---

## Permissions Model (Intentional)

| Item                                       | Owner      | Mode  | Rationale                                         |
|-----------------------------------------------|--------------|---------|------------------------------------------------------|
| `/opt/tscan`                               | `tscan`    | `755` | Service integrity                                 |
| `/opt/tscan/tscan_ng/config/tscan_ng.conf` | `tscan`    | `640` | May hold a Discord webhook secret; only `tscan`-run processes need to read it |
| `/opt/tscan/.ssh`                          | `tscan`    | `700` | Deploy key must not be readable by other users    |
| `/opt/tscan/scripts/update.sh`             | `tscan`    | —     | Ops script ownership                              |
| `/var/log/tscan`                           | `tscan`    | `750` | Log directory                                     |
| `/run/tscan`                               | `tscan`    | `755` | Created by `RuntimeDirectory=tscan`; ephemeral, torn down on service stop |
| `/var/lib/tscan-healthcheck`               | `tscan`    | `755` | Created by `StateDirectory=`; persists across reboots |
| Git operations                             | via `sudo -u tscan` | — | Deploy key and git identity live in the repo's own `.git/config`, not any user's home |
| No login for `tscan`                       | enforced   | —     | Attack surface reduction                          |

---

## Common Failure Modes

### Pipeline fails with `CHDIR`
- `/opt/tscan` not accessible by the service user
- Fix: `chmod 755 /opt/tscan`

### Pipeline exits immediately, no findings ever appear
- Check `capture.iface` is set correctly in `tscan_ng.conf` and exists:
  `ip -br link show`
- Verify the capture NIC is receiving traffic:
```bash
sudo tcpdump -ni <capture-interface> -c 10
```

### Pipeline restarts continuously (crash-loop)
- This is now the *expected*, self-healing behavior when the capture
  interface is down — `tscan-pipeline.service` has
  `StartLimitIntervalSec=0` and `Restart=on-failure`, so it retries
  forever rather than giving up. Bring the interface back up
  (`sudo ip link set <iface> up`) and the next restart attempt will
  succeed on its own; no manual service restart needed.
- If this keeps recurring after every reboot or USB re-enumeration, the
  capture NIC likely has no systemd-networkd config keeping it up — check
  `ls /etc/systemd/network/` for a match on its MAC address and see
  "Bringing the capture NIC up automatically" under Network Design above.
  Without it, `ip link set <iface> up` is a one-time fix that won't
  survive the next boot.
- You should have received a Discord "pipeline[N] ... exiting" alert
  (rate-limited to one per `notify_cooldown_sec`) and, within 2 minutes, a
  "tscan-pipeline.service is DOWN" alert from the healthcheck timer. If
  you didn't and the interface really was down, check `discord_webhook`
  is set in `tscan_ng.conf` and check `journalctl -u tscan-pipeline` /
  `journalctl -u tscan-pipeline-healthcheck` for delivery errors.

### Logs stop updating after rotation
- logrotate missing `su tscan tscan`
- Fix ownership and rerun logrotate

### Repeated test credentials produce no new finding / alert
- This is the `[dedup] finding_cooldown_sec` cooldown working as designed
  (same `dst`, `dport` and `creds` within 30 minutes). Use different
  credentials or a different target, set `finding_cooldown_sec = 0` while
  testing, or stop and start the service (which clears
  `/run/tscan/finding_cooldown/`).

### Findings appear in results.jsonl but not in watch.py / dashboard
- Both viewers count/display only `outcome == "success"`. Check the line's
  `outcome` field (e.g. `server_error`, `no_response`, `unknown`). Also
  check they can read the file (see "Logging Directory").

### Config changes have no effect
- The service must be restarted after editing `tscan_ng.conf`:
```bash
sudo systemctl restart tscan-pipeline
```

### Detector not firing for a known protocol
- The session's port may not be in the `[ports]` list for that protocol
  — this now applies to HTTP too (it is no longer port-agnostic)
- Add the port to the relevant entry in `tscan_ng.conf` and restart the
  service

### Pipeline fails with `Operation not permitted`
- The service unit is missing `AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN`
- This is already set in the repo's `systemd/tscan-pipeline.service`
- Fix: reinstall the unit and restart:
```bash
sudo cp /opt/tscan/systemd/tscan-pipeline.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl restart tscan-pipeline
```

### Update script fails on git pull
- The deploy key at `/opt/tscan/.ssh/id_ed25519_tscan_ng` may be missing,
  wrong, or its public half may have been removed as a GitHub deploy key
  on `Kraethor/tscan-ng`
- Verify: `sudo -u tscan -H git -C /opt/tscan fetch` and read the error
- This repo does not use a PAT-in-URL for cloning/pulling

---

## Rebuild Checklist

- [ ] OS installed
- [ ] Service account created
- [ ] Deploy key provisioned at `/opt/tscan/.ssh/id_ed25519_tscan_ng` and
      registered on GitHub
- [ ] Repo cloned over SSH, `core.sshCommand`/`user.name`/`user.email` set
- [ ] Virtualenv created
- [ ] `tscan_ng.conf` permissions set and `iface` configured
- [ ] systemd units installed and enabled: `tscan-pipeline`,
      `tscan-pipeline-healthcheck.service`/`.timer`
- [ ] logrotate installed
- [ ] Capture NIC mirrored correctly
- [ ] Capture NIC has a systemd-networkd config
      (`/etc/systemd/network/70-tscan-monitor.network`, from
      `systemd/tscan-monitor.network.example`) so it comes up
      automatically after reboot/USB re-enumeration
- [ ] Runtime verification complete (pipeline status, NIC, output)
- [ ] Update script tested: `sudo /opt/tscan/scripts/update.sh`
- [ ] Discord webhook configured in `[discord]` section (optional) and a
      test finding/failure confirmed to arrive; `[dedup]
      finding_cooldown_sec` reviewed (default 1800)
- [ ] Optional: fake test servers (`scripts/fake_*.py`) exercised per
      `docs/test_reference.md`
- [ ] Live monitor tested: `python3 /opt/tscan/scripts/watch.py`
- [ ] Live dashboard tested: `python3 /opt/tscan/scripts/dashboard.py`
- [ ] Quick status snapshot tested: `bash /opt/tscan/scripts/status.sh`
- [ ] Healthcheck timer confirmed running:
      `systemctl list-timers tscan-pipeline-healthcheck.timer`
