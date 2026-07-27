#!/opt/tscan/venv/bin/python
"""
scripts/pipeline_healthcheck.py - External health check for tscan-pipeline.service.

Runs periodically via tscan-pipeline-healthcheck.timer. Checks the unit's
state directly through systemctl, entirely outside the tscan-ng Python
process, so it can catch failures the in-process Discord alerting
(tscan_ng/sinks/discord.py) structurally cannot see: an OOM-kill (SIGKILL,
no code runs to send an alert), a startup failure before Config() even
succeeds, or any other way the process could vanish without a chance to
alert on its own way out.

Alerts once per state transition (up -> down, down -> up), not once per
timer tick, using a marker file in StateDirectory=tscan-healthcheck
(/var/lib/tscan-healthcheck, persists across reboots so a state change
during a reboot is still reported correctly afterwards).

"Recovered" is only declared once the unit has been continuously active
for at least MIN_UP_SECONDS. Without this debounce, a tick landing in the
middle of a crash-loop (a real outage cycles through non-"active" states
for a few seconds every RestartSec, then briefly reports "active" right
before crashing again) would clear the down-alert and then immediately
re-alert "down" on the very next tick -- the same one-message-per-crash
spam the in-process cooldown (tscan_ng/sinks/discord.py) exists to avoid,
just relocated here.
"""

import os
import subprocess
import sys
import time

sys.path.insert(0, "/opt/tscan")

from tscan_ng.config import Config
from tscan_ng.sinks.discord import DiscordSink

UNIT = "tscan-pipeline.service"
STATE_DIR = "/var/lib/tscan-healthcheck"
DOWN_MARKER = os.path.join(STATE_DIR, "down")
MIN_UP_SECONDS = 30
_SYSTEMCTL_TIMEOUT = 10


def _is_active() -> bool:
    """True if systemctl reports UNIT as active right now."""
    result = subprocess.run(
        ["systemctl", "is-active", UNIT],
        capture_output=True, text=True, timeout=_SYSTEMCTL_TIMEOUT)
    return result.stdout.strip() == "active"


def _active_duration() -> float:
    """Seconds since UNIT last entered the active state, or 0 if unknown."""
    result = subprocess.run(
        ["systemctl", "show", UNIT, "-p", "ActiveEnterTimestampMonotonic", "--value"],
        capture_output=True, text=True, timeout=_SYSTEMCTL_TIMEOUT)
    try:
        entered_usec = int(result.stdout.strip())
    except ValueError:
        return 0.0
    now_usec = time.clock_gettime(time.CLOCK_MONOTONIC) * 1_000_000
    return max(0.0, (now_usec - entered_usec) / 1_000_000)


def main() -> None:
    """Check tscan-pipeline.service's current state against the persisted
    down-marker and alert exactly once on each up<->down transition (see
    module docstring for the debounce and cooldown rationale)."""
    try:
        os.makedirs(STATE_DIR, exist_ok=True)
    except OSError:
        pass  # systemd's StateDirectory= already created this under normal operation.

    cfg = Config()
    # cooldown_sec=0: this module already dedupes on state transition, so
    # notify() should always send when we decide to call it. A separate
    # cooldown_path keeps this independent of pipeline_worker's own
    # operational-alert cooldown -- a confirmed full outage is worth
    # reporting even if an individual worker's crash alert was recently
    # suppressed.
    discord = DiscordSink(
        cfg.discord_webhook,
        cooldown_path=os.path.join(STATE_DIR, "discord_marker"),
        cooldown_sec=0,
    )

    was_down = os.path.exists(DOWN_MARKER)
    active = _is_active()

    if not active:
        if not was_down:
            open(DOWN_MARKER, "w").close()
            t = discord.notify(f"{UNIT} is DOWN (systemctl is-active: not active)")
            if t:
                t.join(timeout=5)
        return

    if was_down:
        up_for = _active_duration()
        if up_for >= MIN_UP_SECONDS:
            os.remove(DOWN_MARKER)
            t = discord.notify(f"{UNIT} has RECOVERED (active for {up_for:.0f}s)")
            if t:
                t.join(timeout=5)
        # else: still inside a crash-loop's restart window -- wait for the
        # next tick before declaring recovery.


if __name__ == "__main__":
    main()
