#!/usr/bin/env python3
"""
scripts/dashboard.py - Live full-screen status dashboard for tscan-ng.

Purpose:
    A curses UI, refreshed once a second (REFRESH_SEC), showing at a glance:
      * SERVICE     - tscan-pipeline.service state/substate, uptime (from
                      ActiveEnterTimestamp), MemoryCurrent/MemoryMax, restart
                      count (NRestarts); tscan-pipeline-healthcheck.timer
                      state, time since its last trigger, and whether the
                      external healthcheck currently considers the pipeline
                      down (presence of DOWN_MARKER).
      * INTERFACES  - operstate, rx/tx bit rate and (for the capture NIC) packet
                      rate and per-interval rx_dropped delta for the SPAN
                      capture NIC (MONITOR_IFACE) and the management NIC
                      (ADMIN_IFACE, plus its IPv4 address).
      * THROUGHPUT - sparkline of the capture NIC's packets/sec over the last
                      SPARK_WIDTH samples, current/peak rate, and since-boot
                      totals.
      * FINDINGS    - count, last one, and per-type breakdown of findings in
                      RESULTS_PATH since the last log rotation. NOTE: only
                      findings with outcome == "success" are counted here,
                      unlike Discord alerting (every outcome except
                      "failed") and the JSONL log itself (all
                      outcomes), so this number is expected to be lower than
                      the line count of results.jsonl.
      * WORKERS     - the hard-coded WORKERS_CONFIGURED value (NOT read from
                      the config file; keep in sync with [dispatcher] workers
                      in tscan_ng.conf) and the 1/5/15-minute load average.

Usage:
    python3 /opt/tscan/scripts/dashboard.py

    Press q, Q or Esc to quit (Ctrl-C also works; it is caught in __main__
    and exits silently). No arguments and no command-line options.

Environment / configuration:
    None read from the environment. The interface names, unit names, paths and
    worker count are module-level constants (see below) that must be edited in
    the source when the host changes. Requires Python >= 3.11 (datetime.UTC)
    and a terminal that supports curses colour.

Privileges:
    No sudo, no root. Read-only. Everything it reads is world-readable
    (`systemctl show` properties, /sys/class/net/*/statistics and operstate,
    `ip -4 -brief addr show`, /var/lib/tscan-healthcheck/down existence)
    except /var/log/tscan/results.jsonl: that directory is 0750 tscan:tscan
    (set by the unit's LogsDirectoryMode=, TODO.md #6), so the user needs
    to be in the tscan group. If access is denied the FINDINGS panel
    silently stays at zero rather than erroring (see FindingsTailer).

Exit codes:
    0  normal quit (q/Esc/Ctrl-C).
    1  stdout is not a TTY (message on stderr); curses is never started.
    Any other unhandled exception is re-raised by curses.wrapper() after the
    terminal has been restored, giving Python's usual exit status 1 and a
    traceback.
"""

import curses
import datetime
import json
import os
import subprocess
import sys
import time

# Unit names and paths below must match the units in systemd/ and
# scripts/pipeline_healthcheck.py (DOWN_MARKER is the same path written there).
PIPELINE_UNIT = "tscan-pipeline.service"
HEALTHCHECK_TIMER = "tscan-pipeline-healthcheck.timer"
DOWN_MARKER = "/var/lib/tscan-healthcheck/down"

MONITOR_IFACE = "enx00242788e34c"   # SPAN/mirror capture interface
ADMIN_IFACE = "enp2s0"              # management/SSH interface

RESULTS_PATH = "/var/log/tscan/results.jsonl"
# Display-only: NOT read from tscan_ng.conf. Update by hand if [dispatcher]
# workers changes.
WORKERS_CONFIGURED = 12

REFRESH_SEC = 1.0          # redraw period; also the curses getch() timeout
# Eight block heights, lowest to highest, used by sparkline().
SPARK_CHARS = "▁▂▃▄▅▆▇█"
SPARK_WIDTH = 40           # number of pps samples kept/shown (= seconds of history)


# ── systemd helpers ───────────────────────────────────────────────────────────

def systemctl_show(unit: str, props: list[str]) -> dict:
    """Return {property: value} for *unit*, empty string for missing props."""
    try:
        out = subprocess.run(
            ["systemctl", "show", unit, "--property=" + ",".join(props)],
            capture_output=True, text=True, timeout=5,
        ).stdout
    except (subprocess.SubprocessError, OSError):
        return {p: "" for p in props}
    result = {}
    for line in out.splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            result[k] = v
    return {p: result.get(p, "") for p in props}


def parse_mem_value(v: str):
    """Parse a systemd memory property (e.g. MemoryCurrent/MemoryMax) to bytes.

    Returns None for values systemd reports as unset/unlimited: '[not set]',
    'infinity', or the raw uint64 sentinel (18446744073709551615)."""
    try:
        n = float(v)
    except (TypeError, ValueError):
        return None
    return None if n >= 18446744073709551615 else n


def human_bytes(n: float) -> str:
    """Format a byte count as a short human-readable string, e.g. '318.4M'."""
    for unit in ("B", "K", "M", "G", "T"):
        if abs(n) < 1024:
            return f"{n:.1f}{unit}"
        n /= 1024
    return f"{n:.1f}P"


def human_bits_per_sec(bytes_per_sec: float) -> str:
    """Convert a bytes/sec rate to a short human-readable bits/sec string,
    e.g. '65.1Mbps' -- network throughput is conventionally reported in bits."""
    bits = bytes_per_sec * 8
    for unit in ("bps", "Kbps", "Mbps", "Gbps"):
        if abs(bits) < 1000:
            return f"{bits:.1f}{unit}"
        bits /= 1000
    return f"{bits:.1f}Tbps"


def fmt_duration(delta: datetime.timedelta) -> str:
    """Format a timedelta as a short 'Xd Yh', 'Yh Zm', 'Zm Ws', or 'Ws' string,
    dropping to '0s' for a negative delta (e.g. a clock-skewed timestamp)."""
    secs = int(delta.total_seconds())
    if secs < 0:
        return "0s"
    days, secs = divmod(secs, 86400)
    hours, secs = divmod(secs, 3600)
    mins, secs = divmod(secs, 60)
    if days:
        return f"{days}d {hours}h {mins}m"
    if hours:
        return f"{hours}h {mins}m"
    if mins:
        return f"{mins}m {secs}s"
    return f"{secs}s"


def parse_systemd_timestamp(ts: str):
    """Parse systemd's 'Mon 2026-07-27 00:45:02 UTC' timestamps into a naive
    datetime (the timezone name is discarded, so the result is only comparable
    to another UTC-naive datetime -- run() compares against naive UTC 'now').

    Returns None for empty/'n/a'/'0' values (unit never activated) or anything
    that does not parse."""
    if not ts or ts in ("n/a", "0"):
        return None
    try:
        parts = ts.split(None, 1)[1]  # drop leading weekday
        parts = parts.rsplit(None, 1)[0]  # drop trailing tz name
        return datetime.datetime.strptime(parts, "%Y-%m-%d %H:%M:%S")
    except (ValueError, IndexError):
        return None


# ── interface stats ───────────────────────────────────────────────────────────

def read_iface_stat(iface: str, stat: str) -> int:
    """Read one integer counter from /sys/class/net/{iface}/statistics/{stat},
    e.g. stat="rx_bytes". Returns 0 if the interface or file is unavailable."""
    try:
        with open(f"/sys/class/net/{iface}/statistics/{stat}") as f:
            return int(f.read().strip())
    except (OSError, ValueError):
        return 0


def read_operstate(iface: str) -> str:
    """Return iface's kernel link state ('up', 'down', ...), or 'unknown'
    if /sys/class/net/{iface}/operstate can't be read."""
    try:
        with open(f"/sys/class/net/{iface}/operstate") as f:
            return f.read().strip()
    except OSError:
        return "unknown"


def read_iface_ipv4(iface: str) -> str:
    """Return iface's first IPv4 address in CIDR form (e.g. '192.168.20.216/24'),
    or '-' if it has none or `ip` fails. Shells out rather than parsing
    /sys/class/net since the kernel exposes no sysfs file for IP addresses."""
    try:
        out = subprocess.run(
            ["ip", "-4", "-brief", "addr", "show", iface],
            capture_output=True, text=True, timeout=5,
        ).stdout.split()
        for tok in out:
            if "/" in tok:
                return tok
    except (subprocess.SubprocessError, OSError):
        pass
    return "-"


# Counters from /sys/class/net/<iface>/statistics/ that snapshot_iface() reads.
IFACE_STATS = ("rx_bytes", "rx_packets", "rx_dropped", "rx_errors",
               "tx_bytes", "tx_packets")


def snapshot_iface(iface: str) -> dict:
    """Read all of IFACE_STATS for iface at once, for throughput-delta math
    between two points in time."""
    return {s: read_iface_stat(iface, s) for s in IFACE_STATS}


# ── findings tailer ───────────────────────────────────────────────────────────

class FindingsTailer:
    """Tracks success-finding count/last-seen in RESULTS_PATH, tailing new
    lines each poll. Keeps the file open so a rotation loses nothing
    (TODO.md #47): when logrotate renames the file and creates a new one,
    the rest of the old file is read first, then the new one from its
    start; a file truncated in place is re-read from its start. Counters
    are reset by neither rotation nor truncation: they keep accumulating for
    the life of the dashboard process, so "since last log rotation" is
    accurate only for a dashboard started after the most recent rotation.

    Attributes:
        path:       Path of the JSONL file being tailed.
        total:      Number of outcome == "success" findings consumed so far.
        by_proto:   {finding "type": count} for those findings.
        last_line:  The most recent successful finding dict, or None.
    """

    def __init__(self, path: str):
        """Create the tailer and immediately prime counters from *path* if
        it already exists (so startup shows totals since the last rotation,
        not zero)."""
        self.path = path
        self.total = 0
        self.by_proto: dict[str, int] = {}
        self.last_line = None
        self._fh = None
        self._ino = None
        self._open_and_read()

    def _open_and_read(self):
        """Open *path*, consume every line in it, and keep it open for the
        next poll(). Leaves the tailer closed if the file cannot be opened."""
        try:
            self._fh = open(self.path, "r", encoding="utf-8", errors="replace")
            self._ino = os.fstat(self._fh.fileno()).st_ino
        except OSError:
            self._fh = self._ino = None
            return
        self._read_new()

    def _read_new(self):
        """Consume the lines appended to the open file since the last read."""
        for raw in iter(self._fh.readline, ""):
            self._consume(raw)

    def _consume(self, raw: str):
        """Parse one JSONL line and fold it into total/by_proto/last_line if
        it's a successful finding; silently skip anything else (in-progress
        writes, malformed JSON, non-success outcomes)."""
        raw = raw.strip()
        if not raw:
            return
        try:
            finding = json.loads(raw)
        except (json.JSONDecodeError, ValueError):
            return
        if finding.get("outcome") != "success":
            return
        self.total += 1
        ftype = finding.get("type", "unknown")
        self.by_proto[ftype] = self.by_proto.get(ftype, 0) + 1
        self.last_line = finding

    def poll(self):
        """Consume any lines appended to *path* since the last poll/prime,
        following a rotation (new file at the path) or an in-place truncation
        without skipping lines."""
        try:
            if self._fh is None:
                self._open_and_read()
                return
            self._read_new()
            st = os.stat(self.path)
            if st.st_ino != self._ino:
                # Rotated: the old file was finished just above; switch.
                self._fh.close()
                self._open_and_read()
            elif st.st_size < self._fh.tell():
                # Truncated in place: read again from the start.
                self._fh.seek(0)
                self._read_new()
        except OSError:
            pass


def sparkline(values: list[float]) -> str:
    """Render *values* as a one-line block-character sparkline, scaled so
    the largest value in the window maps to the tallest bar."""
    if not values:
        return ""
    vmax = max(values) or 1.0
    return "".join(
        SPARK_CHARS[min(len(SPARK_CHARS) - 1, int(v / vmax * (len(SPARK_CHARS) - 1)))]
        for v in values
    )


# ── main draw loop ────────────────────────────────────────────────────────────

def run(stdscr):
    """Curses main loop: set up color pairs and refresh timing, then repeatedly
    sample service/interface/findings state and redraw the full screen until
    the user presses q/Q/Esc. Called via curses.wrapper() from main() so the
    terminal is always restored on exit, including on an unhandled exception.

    Args:
        stdscr: The curses standard screen window passed in by curses.wrapper().
    """
    curses.curs_set(0)
    curses.start_color()
    curses.use_default_colors()
    curses.init_pair(1, curses.COLOR_GREEN, -1)
    curses.init_pair(2, curses.COLOR_RED, -1)
    curses.init_pair(3, curses.COLOR_YELLOW, -1)
    curses.init_pair(4, curses.COLOR_CYAN, -1)
    curses.init_pair(5, curses.COLOR_WHITE, -1)
    GREEN, RED, YELLOW, CYAN, WHITE = (curses.color_pair(i) for i in (1, 2, 3, 4, 5))
    BOLD = curses.A_BOLD
    DIM = curses.A_DIM

    stdscr.timeout(int(REFRESH_SEC * 1000))

    tailer = FindingsTailer(RESULTS_PATH)
    prev_monitor = snapshot_iface(MONITOR_IFACE)
    prev_admin = snapshot_iface(ADMIN_IFACE)
    prev_time = time.monotonic()
    pps_history: list[float] = []

    while True:
        now = time.monotonic()
        dt = max(1e-6, now - prev_time)

        cur_monitor = snapshot_iface(MONITOR_IFACE)
        cur_admin = snapshot_iface(ADMIN_IFACE)
        mon_rx_bps = (cur_monitor["rx_bytes"] - prev_monitor["rx_bytes"]) / dt
        mon_rx_pps = (cur_monitor["rx_packets"] - prev_monitor["rx_packets"]) / dt
        mon_dropped = cur_monitor["rx_dropped"] - prev_monitor["rx_dropped"]
        adm_rx_bps = (cur_admin["rx_bytes"] - prev_admin["rx_bytes"]) / dt
        adm_tx_bps = (cur_admin["tx_bytes"] - prev_admin["tx_bytes"]) / dt

        pps_history.append(mon_rx_pps)
        if len(pps_history) > SPARK_WIDTH:
            pps_history.pop(0)

        prev_monitor, prev_admin, prev_time = cur_monitor, cur_admin, now
        tailer.poll()

        svc = systemctl_show(PIPELINE_UNIT, [
            "ActiveState", "SubState", "ActiveEnterTimestamp",
            "MemoryCurrent", "MemoryMax", "NRestarts",
        ])
        timer = systemctl_show(HEALTHCHECK_TIMER, ["ActiveState", "LastTriggerUSec"])
        down_flagged = os.path.exists(DOWN_MARKER)
        # Naive UTC, to be comparable with parse_systemd_timestamp()'s naive
        # results (systemd is assumed to print timestamps in UTC on this host).
        now_utc = datetime.datetime.now(datetime.UTC).replace(tzinfo=None)

        # ── render ──
        stdscr.erase()
        h, w = stdscr.getmaxyx()
        row = 0

        def line(text="", attr=0, col=0):
            """Write one single-attribute row and advance to the next row,
            silently truncating if the terminal is narrower than the text
            or if row has scrolled past the bottom of the screen."""
            nonlocal row
            if row < h - 1:
                try:
                    stdscr.addnstr(row, col, text, max(0, w - col - 1), attr)
                except curses.error:
                    pass
            row += 1

        def mline(segments):
            """Write (text, attr) segments left-to-right on one row, each
            starting where the previous one actually ended -- avoids
            hardcoding column offsets that break when label widths change."""
            nonlocal row
            if row < h - 1:
                col = 0
                for text, attr in segments:
                    try:
                        stdscr.addnstr(row, col, text, max(0, w - col - 1), attr)
                    except curses.error:
                        pass
                    col += len(text)
            row += 1

        now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        line(f" tscan-ng dashboard — {os.uname().nodename} — {now_str}  (q to quit)", BOLD | CYAN)
        line()

        # Service
        active = svc["ActiveState"] == "active"
        state_attr = GREEN | BOLD if active else RED | BOLD
        entered = parse_systemd_timestamp(svc["ActiveEnterTimestamp"])
        uptime = fmt_duration(now_utc - entered) if entered else "?"
        mem_cur_val = parse_mem_value(svc["MemoryCurrent"])
        mem_max_val = parse_mem_value(svc["MemoryMax"])
        mem_cur = human_bytes(mem_cur_val) if mem_cur_val is not None else "n/a"
        mem_max = human_bytes(mem_max_val) if mem_max_val is not None else "n/a"
        line(" SERVICE", BOLD)
        mline([
            (f"   {PIPELINE_UNIT:<34}", 0),
            (f"{svc['ActiveState']}/{svc['SubState']}", state_attr),
        ])
        line(f"     uptime {uptime}   mem {mem_cur}/{mem_max}   restarts {svc['NRestarts'] or 0}", DIM)

        timer_active = timer["ActiveState"] == "active"
        last_trigger = parse_systemd_timestamp(timer["LastTriggerUSec"])
        ago = fmt_duration(now_utc - last_trigger) if last_trigger else "?"
        health_attr = RED | BOLD if down_flagged else GREEN | BOLD
        health_text = "DOWN (alerted)" if down_flagged else "healthy"
        mline([
            (f"   {HEALTHCHECK_TIMER:<34}", 0),
            (timer["ActiveState"] or "?", GREEN if timer_active else RED),
        ])
        mline([
            (f"     last check {ago} ago   pipeline health: ", DIM),
            (health_text, health_attr),
        ])
        line()

        # Interfaces
        line(" INTERFACES", BOLD)
        mon_state = read_operstate(MONITOR_IFACE)
        mon_attr = GREEN | BOLD if mon_state == "up" else RED | BOLD
        mline([
            (f"   monitor  {MONITOR_IFACE:<20}", 0),
            (mon_state.upper(), mon_attr),
        ])
        line(f"     rx {human_bits_per_sec(mon_rx_bps):>10}   {mon_rx_pps:8.1f} pkt/s   dropped(Δ) {mon_dropped}", DIM)

        adm_state = read_operstate(ADMIN_IFACE)
        adm_attr = GREEN | BOLD if adm_state == "up" else RED | BOLD
        adm_ip = read_iface_ipv4(ADMIN_IFACE)
        mline([
            (f"   admin    {ADMIN_IFACE:<20}", 0),
            (adm_state.upper(), adm_attr),
        ])
        line(f"     {adm_ip:<18}  rx {human_bits_per_sec(adm_rx_bps):>10}   tx {human_bits_per_sec(adm_tx_bps):>10}", DIM)
        line()

        # Throughput
        line(" MONITOR THROUGHPUT (packets/sec)", BOLD)
        line(f"   {sparkline(pps_history)}", YELLOW | BOLD)
        line(f"   now {mon_rx_pps:8.1f} pkt/s   peak {max(pps_history, default=0):8.1f} pkt/s"
             f"   total since boot {cur_monitor['rx_packets']:,} pkts / {human_bytes(cur_monitor['rx_bytes'])}", DIM)
        line()

        # Findings
        line(" FINDINGS (since last log rotation)", BOLD)
        line(f"   total: {tailer.total}", 0)
        if tailer.last_line:
            f_ = tailer.last_line
            ts = f_.get("ts_start") or f_.get("ts") or 0
            ts_str = datetime.datetime.fromtimestamp(ts).strftime("%H:%M:%S") if ts else "?"
            line(f"   last:  {ts_str}  {f_.get('type', '?')}  {f_.get('src', '?')} -> {f_.get('dst', '?')}", DIM)
        top = sorted(tailer.by_proto.items(), key=lambda kv: -kv[1])[:6]
        if top:
            line("   by protocol: " + "  ".join(f"{k}={v}" for k, v in top), DIM)
        line()

        # Workers / load
        line(" WORKERS / LOAD", BOLD)
        load1, load5, load15 = os.getloadavg()
        line(f"   workers configured: {WORKERS_CONFIGURED}   load avg: {load1:.2f} {load5:.2f} {load15:.2f}", DIM)

        stdscr.refresh()

        # getch() blocks for at most REFRESH_SEC (stdscr.timeout above), which
        # doubles as the loop's sleep; -1 (timeout) falls through and redraws.
        ch = stdscr.getch()
        if ch in (ord("q"), ord("Q"), 27):
            break


def main():
    """Entry point: refuse to run outside a terminal (curses needs a real
    tty), then hand off to curses.wrapper(run)."""
    if not sys.stdout.isatty():
        print("This is a full-screen dashboard; run it in a terminal.", file=sys.stderr)
        sys.exit(1)
    curses.wrapper(run)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
