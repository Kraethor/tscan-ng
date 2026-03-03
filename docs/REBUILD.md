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
