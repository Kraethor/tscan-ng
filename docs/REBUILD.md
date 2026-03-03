# REBUILD.md
**tscan-ng – Rebuild & Deployment Guide (U02)**

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

| Path                          | Purpose                        |
|-------------------------------|--------------------------------|
| `/opt/tscan`                  | Application root               |
| `/opt/tscan/tscan_ng`         | Python source                  |
| `/opt/tscan/tscan-ng.conf`    | Runtime configuration          |
| `/opt/tscan/systemd`          | systemd unit files             |
| `/opt/tscan/logrotate`        | logrotate config               |
| `/opt/tscan/docs`             | Documentation                  |
| `/opt/tscan/venv`             | Python virtualenv              |
| `/var/log/tscan`              | Runtime logs                   |
| `/run/tscan`                  | Runtime socket (tmpfs)         |

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
  --create-home \
  --home-dir /home/tscan \
  --shell /usr/sbin/nologin \
  tscan
```

Verify:
```bash
getent passwd tscan
```

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
  pip install dpkt orjson
  deactivate
'
```

---

## Configuration

Copy the example config and set ownership:
```bash
sudo cp /opt/tscan/tscan-ng.conf /opt/tscan/tscan-ng.conf
sudo chown tscan:tscan /opt/tscan/tscan-ng.conf
sudo chmod 640 /opt/tscan/tscan-ng.conf
```

Edit `/opt/tscan/tscan-ng.conf` and set at minimum:
```ini
[capture]
iface = <your capture interface name>
```

All other values have safe defaults. See the config file itself for
documentation of every setting.

**Important:**  
After editing `tscan-ng.conf`, both services must be restarted:
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

---

## Permissions Model (Intentional)

| Item                  | Owner      | Rationale                  |
|-----------------------|------------|----------------------------|
| `/opt/tscan`          | `tscan`    | Service integrity          |
| `tscan-ng.conf`       | `tscan`    | Config security            |
| Git operations        | `thoward`  | Developer access           |
| No group sharing      | enforced   | Least privilege            |
| No login for `tscan`  | enforced   | Attack surface reduction   |

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
- Check `iface` is set correctly in `tscan-ng.conf`
- Verify the capture NIC is receiving traffic:
```bash
  sudo tcpdump -ni <capture-interface> -c 10
```

### Config changes have no effect
- Both services must be restarted after editing `tscan-ng.conf`:
```bash
  sudo systemctl restart tscan-dispatcher tscan-capture
```

---

## Rebuild Checklist

- [ ] OS installed
- [ ] Service account created
- [ ] Repo cloned
- [ ] Virtualenv created
- [ ] `tscan-ng.conf` deployed and `iface` set correctly
- [ ] systemd units installed
- [ ] logrotate installed
- [ ] Capture NIC mirrored correctly
- [ ] Logs updating
