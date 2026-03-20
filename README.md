# tscan-ng

`tscan-ng` is a line-speed network traffic scanner designed for passive
monitoring via SPAN / mirror ports.

## Repository layout
- `tscan_ng/` – Python capture + dispatcher + detectors
- `systemd/` – systemd service units
- `logrotate/` – log rotation configuration
- `docs/` – rebuild and deployment documentation

## Architecture

Two systemd services work together:

- **tscan-capture** — reads raw packets from the SPAN NIC via libpcap and
  forwards them over a Unix datagram socket.
- **tscan-dispatcher** — receives packets, routes them to worker processes
  by flow affinity, reassembles TCP streams, runs detectors, and writes
  findings to a JSONL file.

## Detectors

| Protocol | Detection method       | Default ports             |
|----------|------------------------|---------------------------|
| HTTP     | Basic Auth header scan | All ports (port-agnostic) |
| FTP      | USER/PASS command scan | 21, 2121                  |
| SMTP     | AUTH credential scan   | 25, 465, 587, 2525        |
| IMAP     | LOGIN command scan     | 143, 993, 1430            |
| POP3     | USER/PASS command scan | 110, 995, 1100            |

## Configuration

Runtime settings live in `tscan_ng/config/tscan_ng.conf`. The minimum
required setting is `capture.iface`. All other values have safe defaults.

Port lists for each protocol detector are configured under `[ports]` and
can be extended without touching source code:

```ini
[ports]
ftp   = 21, 2121
smtp  = 25, 465, 587, 2525
imap  = 143, 993, 1430
pop3  = 110, 995, 1100
```

After editing the config, restart both services:
```bash
sudo systemctl restart tscan-dispatcher tscan-capture
```

## Deployment
See `docs/REBUILD.md` for full rebuild instructions.

## Notes
- Designed to run with a non-login service account
- Capture NIC is RX-only (no default route)
- Management NIC handles SSH, Git, and admin
