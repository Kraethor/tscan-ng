# REBUILD.md
**tscan-ng – Rebuild & Deployment Guide**
**Host: U01**

## Purpose

This document describes how to rebuild a `tscan-ng` capture node from scratch  
(e.g., hardware loss, OS reinstall, disaster recovery).

The goal is that **this repo alone** is sufficient to rebuild a working system.

---

## System Overview

- **Host role:** Passive network traffic capture + analysis
- **Traffic source:** Switch SPAN / mirror port
- **Execution model:** systemd services
- **Language:** Python (libpcap via ctypes)
- **Security model:**
  - Non-login service account
  - No group sharing
  - No interactive access for service user

---

## Network Design

### Interfaces

| Interface      | Purpose              | Notes                        |
|----------------|----------------------|------------------------------|
| Management NIC | SSH, Git, admin      | Has default route + DNS      |
| Capture NIC    | SPAN destination     | RX-only, no gateway          |

**Important:**  
Traffic generated *on this host* will **not** be seen by the capture NIC.

---

## Filesystem Layout

| Path                                      | Purpose                        |
|-------------------------------------------|--------------------------------|
| `/opt/tscan`                              | Application root               |
| `/opt/tscan/tscan_ng`                     | Python source                  |
| `/opt/tscan/tscan_ng/config/tscan_ng.conf`| Runtime configuration          |
| `/opt/tscan/scripts`                      | Operational scripts            |
| `/opt/tscan/systemd`                      | systemd unit files             |
| `/opt/tscan/logrotate`                    | logrotate config               |
| `/opt/tscan/docs`                         | Documentation                  |
| `/opt/tscan/venv`                         | Python virtualenv              |
| `/var/log/tscan`                          | Runtime logs                   |
| `/run/tscan`                              | Runtime socket (tmpfs)         |

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
interactive access and exists solely to own and run the tscan-ng services.

---

## Deploy Code
```bash
sudo mkdir -p /opt/tscan
sudo chown -R tscan:tscan /opt/tscan
sudo chmod 755 /opt/tscan
```

Clone the repo **as the service user**:
```bash
sudo -u tscan -H git clone https://github.com/Kraethor/tscan-ng.git /opt/tscan
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

The `tscan-capture.service` unit grants `CAP_NET_RAW` and `CAP_NET_ADMIN`
directly to the capture process via systemd's `AmbientCapabilities`
directive. No `setcap` on the Python binary is required — the unit file
handles this automatically.

---

## Configuration

Set ownership and permissions on the config file:
```bash
sudo chown tscan:tscan /opt/tscan/tscan_ng/config/tscan_ng.conf
sudo chmod 644 /opt/tscan/tscan_ng/config/tscan_ng.conf
```

`644` (world-readable) is required so that `watch.py`, run as a regular
user, can read the Discord webhook URL from the config. The file contains
no credentials other than the optional webhook URL.

Edit `/opt/tscan/tscan_ng/config/tscan_ng.conf` and set at minimum:
```ini
[capture]
iface = <your capture interface name>
```

All other values have safe defaults. See the config file itself for
documentation of every setting.

### Protocol detector ports

The `[ports]` section controls which TCP ports each protocol detector
will scan. Sessions whose src and dst port are both absent from a
protocol's list are skipped by that detector, saving CPU at high line
speeds. The defaults match standard well-known ports:

```ini
[ports]
ftp    = 21, 2121
smtp   = 25, 465, 587, 2525
imap   = 143, 993, 1430
pop3   = 110, 995, 1100
telnet = 23, 2323
ldap   = 389, 3268
redis  = 6379, 6380
```

Add non-standard ports by appending to the comma-separated list. No
source code changes are required — just edit the config and restart
both services.

### Discord alerting

To enable Discord alerts on confirmed credential findings, add a
`[discord]` section to the config:

```ini
[discord]
discord_webhook = https://discord.com/api/webhooks/...
```

Leave blank or omit the section to disable alerting. The webhook URL
is the only value in this section. Alerts are fired by `watch.py` and
send only a generic "Credential found" notification — no credential
material is transmitted.

**Important:**  
After editing `tscan_ng.conf`, both services must be restarted:
```bash
sudo systemctl restart tscan-dispatcher tscan-capture
```

---

## Logging Directory
```bash
sudo mkdir -p /var/log/tscan
sudo chown -R tscan:tscan /var/log/tscan
sudo chmod 750 /var/log/tscan
```

---

## Install systemd Units
```bash
sudo cp /opt/tscan/systemd/tscan-dispatcher.service /etc/systemd/system/
sudo cp /opt/tscan/systemd/tscan-capture.service /etc/systemd/system/
```

Reload and enable:
```bash
sudo systemctl daemon-reload
sudo systemctl enable tscan-dispatcher tscan-capture
sudo systemctl start tscan-dispatcher tscan-capture
```

Verify:
```bash
sudo systemctl status tscan-dispatcher tscan-capture --no-pager
```

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
- Stop both services in the correct order
- Pull the latest code from the repository
- Update Python dependencies if `requirements.txt` changed
- Reinstall systemd units if they changed
- Reload systemd if needed
- Start both services in the correct order
- Report final service status

**Important:**  
The update script must be run as root. It handles the correct service
stop/start ordering automatically.

---

## Runtime Verification

### Socket
```bash
ls -l /run/tscan/tscan.sock
```

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

Displays colour-coded findings in real time and fires Discord alerts on
each confirmed credential capture. Run as any user — no root required.

---

## Permissions Model (Intentional)

| Item                                       | Owner      | Mode  | Rationale                           |
|--------------------------------------------|------------|-------|-------------------------------------|
| `/opt/tscan`                               | `tscan`    | `755` | Service integrity                   |
| `/opt/tscan/tscan_ng/config/tscan_ng.conf` | `tscan`    | `644` | World-readable for watch.py         |
| `/opt/tscan/scripts/update.sh`             | `tscan`    | —     | Ops script ownership                |
| `/var/log/tscan`                           | `tscan`    | `750` | Log directory                       |
| Git operations                             | `thoward`  | —     | Developer access                    |
| No login for `tscan`                       | enforced   | —     | Attack surface reduction            |

---

## Common Failure Modes

### Capture service fails with `CHDIR`
- `/opt/tscan` not accessible by service user
- Fix: `chmod 755 /opt/tscan`

### Capture fails to connect to socket
- Dispatcher not running
- Restart dispatcher first, then capture:
```bash
sudo systemctl restart tscan-dispatcher tscan-capture
```

### Logs stop updating after rotation
- logrotate missing `su tscan tscan`
- Fix ownership and rerun logrotate

### Service starts but no output appears
- Check `iface` is set correctly in `tscan_ng.conf`
- Verify the capture NIC is receiving traffic:
```bash
sudo tcpdump -ni <capture-interface> -c 10
```

### Config changes have no effect
- Both services must be restarted after editing `tscan_ng.conf`:
```bash
sudo systemctl restart tscan-dispatcher tscan-capture
```

### Detector not firing for a known protocol
- The session's port may not be in the `[ports]` list for that protocol
- Add the port to the relevant entry in `tscan_ng.conf` and restart both services
- Note: the HTTP detector is port-agnostic and always runs regardless of port

### Capture fails with `Operation not permitted`
- The service unit is missing `AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN`
- This is already set in the repo's `systemd/tscan-capture.service`
- Fix: reinstall the unit and restart:
```bash
sudo cp /opt/tscan/systemd/tscan-capture.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl restart tscan-capture
```

### Update script fails on git pull
- GitHub credentials may have expired
- Re-enter credentials when prompted, or configure SSH key auth for the `tscan` user

---

## Rebuild Checklist

- [ ] OS installed
- [ ] Service account created
- [ ] Repo cloned
- [ ] Virtualenv created
- [ ] `tscan_ng.conf` permissions set and `iface` configured
- [ ] systemd units installed and enabled
- [ ] logrotate installed
- [ ] Capture NIC mirrored correctly
- [ ] Runtime verification complete (socket, NIC, output)
- [ ] Update script tested: `sudo /opt/tscan/scripts/update.sh`
- [ ] Discord webhook configured in `[discord]` section (optional)
- [ ] Live monitor tested: `python3 /opt/tscan/scripts/watch.py`
