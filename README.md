# tscan-ng

`tscan-ng` is a line-speed network traffic scanner designed for passive
monitoring via SPAN / mirror ports.

## Repository layout
- `tscan_ng/` – Python capture + dispatcher + detectors
- `systemd/` – systemd service units
- `logrotate/` – log rotation configuration
- `docs/` – rebuild and deployment documentation

## Deployment
See `docs/REBUILD.md` for full rebuild instructions.

## Notes
- Designed to run with a non-login service account
- Capture NIC is RX-only (no default route)
- Management NIC handles SSH, Git, and admin
