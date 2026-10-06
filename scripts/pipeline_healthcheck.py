#!/opt/tscan/venv/bin/python
# Copyright (C) 2026 Kraethor
#
# This file is part of tscan-ng.
#
# tscan-ng is free software: you can redistribute it and/or modify it under
# the terms of the GNU General Public License as published by the Free
# Software Foundation, version 3.
#
# tscan-ng is distributed in the hope that it will be useful, but WITHOUT ANY
# WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along with
# tscan-ng. If not, see <https://www.gnu.org/licenses/>.
#
# Additional term under GPLv3 section 7(b): if you convey this work or a
# modified version of it, you must preserve the attribution "Based on tscan-ng
# by Kraethor (https://github.com/Kraethor/tscan-ng)" in the source and in any
# user-facing output or accompanying documentation.
#
# SPDX-License-Identifier: GPL-3.0-only

"""
scripts/pipeline_healthcheck.py - External health check for tscan-pipeline.service.

Runs periodically via tscan-pipeline-healthcheck.timer. Checks the unit's
state directly through systemctl, entirely outside the tscan-ng Python
process, so it can catch failures the in-process Discord alerting
(tscan_ng/sinks/discord.py) structurally cannot see: an OOM-kill (SIGKILL,
no code runs to send an alert), a startup failure before Config() even
succeeds (for example the capture NIC being absent), or any other way the process could vanish without a chance to
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

Decision table (one run = one systemd timer tick; every path exits 0):
    unit not active, no marker -> create DOWN_MARKER, send "is DOWN" alert
    unit not active, marker    -> nothing (already alerted)
    unit active,     no marker -> nothing (healthy)
    unit active,     marker    -> if active >= MIN_UP_SECONDS: remove marker
                                  and send "has RECOVERED"; else wait for the
                                  next tick.
Note that "active" here is literally `systemctl is-active` == "active":
"activating" (systemd's state during the RestartSec delay and startup) and
"failed" both count as down.

Usage:
    Normally started by tscan-pipeline-healthcheck.service (Type=oneshot,
    User=tscan, StateDirectory=tscan-healthcheck), which is triggered every
    2 minutes by tscan-pipeline-healthcheck.timer (OnBootSec=2min,
    OnUnitActiveSec=2min). Manual run (same user and interpreter as the unit):

        sudo -u tscan /opt/tscan/venv/bin/python /opt/tscan/scripts/pipeline_healthcheck.py

    No command-line arguments.

Environment / configuration:
    No environment variables. Reads the Discord webhook via
    tscan_ng.config.Config() from /opt/tscan/tscan_ng/config/tscan_ng.conf
    ([discord] discord_webhook; empty => alerting silently disabled, but the
    marker file is still maintained). The config is loaded with
    Config(validate=False) on purpose: the full validation (capture.iface
    must exist in /sys/class/net, ...) fails exactly when the capture NIC has
    been unplugged, which is the documented main outage, and a watchdog that
    dies with the thing it watches alerts nobody (TODO.md #4). If the config
    cannot even be parsed, the webhook is treated as empty (no Discord alert
    can be sent) but the systemctl check and the marker file still run.
    Shebang points at the venv interpreter (/opt/tscan/venv/bin/python)
    because `requests` (imported by tscan_ng.sinks.discord) lives only there.

Privileges:
    Runs as the tscan service user. Needs: `systemctl is-active` / `show`
    (unprivileged, read-only), read access to the config file, and write
    access to /var/lib/tscan-healthcheck (STATE_DIR) for DOWN_MARKER and
    discord_marker. No capabilities, no root.

State files (in STATE_DIR = /var/lib/tscan-healthcheck):
    down            existence == "we have already alerted DOWN"; persists
                    across reboots.
    discord_marker  the DiscordSink cooldown marker, kept separate from the
                    pipeline's own /run/tscan/discord_notify_last.

Exit codes:
    0  every normal path above, including "alert could not be delivered"
       (Discord failures are swallowed inside DiscordSink).
    1  unhandled exception (Python traceback in the journal):
       subprocess.TimeoutExpired from systemctl, OSError creating/removing
       the marker. (An invalid or unreadable config no longer raises.) The unit then shows
       status=1/FAILURE, which per docs/REBUILD.md means "the healthcheck
       itself broke", not necessarily that the pipeline is down.
"""

import os
import subprocess
import sys
import time

sys.path.insert(0, "/opt/tscan")

from tscan_ng.config import Config, DEFAULT_CONFIG_PATH
from tscan_ng.sinks.discord import DiscordSink

UNIT = "tscan-pipeline.service"      # unit being watched
CONFIG_PATH = DEFAULT_CONFIG_PATH    # where the Discord webhook is read from
STATE_DIR = "/var/lib/tscan-healthcheck"
DOWN_MARKER = os.path.join(STATE_DIR, "down")
MIN_UP_SECONDS = 30   # continuous-active time required before declaring recovery (debounce)
_SYSTEMCTL_TIMEOUT = 10   # seconds; subprocess.run() raises TimeoutExpired past this


def _is_active() -> bool:
    """True if systemctl reports UNIT as active right now."""
    result = subprocess.run(
        ["systemctl", "is-active", UNIT],
        capture_output=True, text=True, timeout=_SYSTEMCTL_TIMEOUT)
    return result.stdout.strip() == "active"


def _active_duration() -> float:
    """Seconds since UNIT last entered the active state, or 0 if unknown.

    Uses ActiveEnterTimestampMonotonic (microseconds on CLOCK_MONOTONIC,
    which is the same clock as systemd's) so the result is immune to
    wall-clock changes. systemd reports 0 for a unit that never activated,
    which would yield an uptime equal to the whole system uptime; callers
    only invoke this after _is_active() was true, so that case is not
    expected. A non-integer reply returns 0.0."""
    result = subprocess.run(
        ["systemctl", "show", UNIT, "-p", "ActiveEnterTimestampMonotonic", "--value"],
        capture_output=True, text=True, timeout=_SYSTEMCTL_TIMEOUT)
    try:
        entered_usec = int(result.stdout.strip())
    except ValueError:
        return 0.0
    now_usec = time.clock_gettime(time.CLOCK_MONOTONIC) * 1_000_000
    return max(0.0, (now_usec - entered_usec) / 1_000_000)


def _load_webhook() -> str:
    """Return the configured Discord webhook URL, or "" if it can't be read.

    Loads Config without validation (see the module docstring): the watchdog
    must work while the capture NIC is missing or the config is otherwise
    invalid. Any failure to read the config yields "" (alerting disabled)
    instead of an exception, so the down-marker logic below still runs."""
    try:
        return Config(CONFIG_PATH, validate=False).discord_webhook
    except Exception:
        return ""


def main() -> None:
    """Check tscan-pipeline.service's current state against the persisted
    down-marker and alert exactly once on each up<->down transition (see
    module docstring for the debounce and cooldown rationale)."""
    try:
        os.makedirs(STATE_DIR, exist_ok=True)
    except OSError:
        pass  # systemd's StateDirectory= already created this under normal operation.

    # cooldown_sec=0: this module already dedupes on state transition, so
    # notify() should always send when we decide to call it. A separate
    # cooldown_path keeps this independent of pipeline_worker's own
    # operational-alert cooldown -- a confirmed full outage is worth
    # reporting even if an individual worker's crash alert was recently
    # suppressed.
    discord = DiscordSink(
        _load_webhook(),
        cooldown_path=os.path.join(STATE_DIR, "discord_marker"),
        cooldown_sec=0,
    )

    # Read the marker before querying systemd so the decision below is based
    # on one consistent (previous-state, current-state) pair.
    was_down = os.path.exists(DOWN_MARKER)
    active = _is_active()

    if not active:
        if not was_down:
            # Create the marker *before* alerting so a crash mid-notify
            # cannot cause a duplicate DOWN alert on the next tick.
            open(DOWN_MARKER, "w").close()
            t = discord.notify(f"{UNIT} is DOWN (systemctl is-active: not active)")
            if t:
                # notify() posts on a daemon thread; join so it can finish
                # before this short-lived process exits.
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
