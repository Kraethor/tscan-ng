#!/usr/bin/env python3
"""
scripts/watch.py - Live display of successful tscan-ng credential findings.

Tails the JSONL results file and prints a human-readable, coloured summary
for each finding whose outcome is "success".  All other outcomes are silently
skipped.  Log rotation is handled transparently — the file is reopened
automatically when it is truncated or replaced by a new inode.

Usage:
    sudo python3 /opt/tscan/scripts/watch.py [results_file]

Default results file: /var/log/tscan/results.jsonl

Colour coding:
    Protocol label   — unique colour per protocol for instant identification
    Source / dest    — white
    Credentials      — bold bright-red   (the primary artefact)
    Filter string    — bold bright-yellow (designed for easy selection/copy)
    Outcome          — bold bright-green

The filter string on each finding is a Wireshark/tcpdump-compatible BPF
expression that isolates the exact session.  Highlight and copy it directly
into Wireshark or:

    sudo tcpdump -r capture.pcap '<filter>'
"""

import json
import os
import sys
import time
from datetime import datetime
from discord_alert import send_alert

# ── ANSI helpers ──────────────────────────────────────────────────────────────

RESET  = "\033[0m"
BOLD   = "\033[1m"
DIM    = "\033[2m"

# Standard foreground colours
WHITE   = "\033[37m"

# Bright foreground colours
BRIGHT_RED     = "\033[91m"
BRIGHT_GREEN   = "\033[92m"
BRIGHT_YELLOW  = "\033[93m"
BRIGHT_BLUE    = "\033[94m"
BRIGHT_MAGENTA = "\033[95m"
BRIGHT_CYAN    = "\033[96m"
BRIGHT_WHITE   = "\033[97m"

# Per-protocol colour + label --------------------------------------------------
# Each entry is (ansi_colour_string, display_label).
_PROTO = {
    "http_basic":    (BOLD + BRIGHT_CYAN,    "HTTP Basic"),
    "ftp_creds":     (BOLD + BRIGHT_BLUE,    "FTP"),
    "ftp_anonymous": (BOLD + BRIGHT_BLUE,    "FTP (anon)"),
    "smtp_creds":    (BOLD + BRIGHT_YELLOW,  "SMTP"),
    "imap_creds":    (BOLD + BRIGHT_GREEN,   "IMAP"),
    "pop3_creds":    (BOLD + BRIGHT_MAGENTA, "POP3"),
    "telnet_creds":  (BOLD + BRIGHT_RED,     "Telnet"),
    "ldap_creds":    (BOLD + BRIGHT_WHITE,   "LDAP"),
    "redis_creds":   (BOLD + BRIGHT_CYAN,    "Redis"),
}

DEFAULT_RESULTS = "/var/log/tscan/results.jsonl"


# ── Layout helpers ────────────────────────────────────────────────────────────

def _term_width() -> int:
    """Return the current terminal width, defaulting to 80 if unavailable."""
    try:
        return os.get_terminal_size().columns
    except OSError:
        return 80


def _header(proto_color: str, label: str, ts_str: str) -> str:
    """
    Build a full-width coloured separator line.

    Example:
        ━━━ HTTP Basic ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 2026-03-20 14:23:11 ━

    Args:
        proto_color: ANSI colour string for this protocol.
        label:       Protocol label text, e.g. "HTTP Basic".
        ts_str:      Formatted timestamp string.

    Returns:
        A fully coloured separator string (no trailing newline).
    """
    width     = _term_width()
    left_seg  = "━" * 3
    mid_seg   = f" {label} "
    right_seg = f" {ts_str} ━"
    fill_len  = max(0, width - len(left_seg) - len(mid_seg) - len(right_seg))
    fill      = "━" * fill_len
    return proto_color + left_seg + mid_seg + fill + right_seg + RESET


# ── Finding formatter ─────────────────────────────────────────────────────────

def _format(finding: dict) -> str | None:
    """
    Format a single finding dict into a coloured, multi-line display string.

    Returns None if the finding should not be displayed (outcome != "success").

    Layout per finding:

        ━━━ PROTO ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ YYYY-MM-DD HH:MM:SS ━
          src_ip:sport  →  dst_ip:dport  [protocol extras if any]
          Credentials:  user:password
          Status:       <code>  success
          Filter:       host … and tcp port … and tcp port …
        <blank line>

    The filter line is rendered in bold bright-yellow so it stands out as the
    "copy this" element.

    Args:
        finding: Parsed JSONL finding dict from tscan-ng.

    Returns:
        Formatted string ready for print(), or None to skip.
    """
    if finding.get("outcome") != "success":
        return None

    ftype = finding.get("type", "unknown")
    proto_color, label = _PROTO.get(ftype, (BOLD + BRIGHT_WHITE, ftype.upper()))

    # Timestamp
    ts_raw = finding.get("ts_start") or finding.get("ts") or 0
    ts_str = datetime.fromtimestamp(ts_raw).strftime("%Y-%m-%d %H:%M:%S")

    lines = [_header(proto_color, label, ts_str)]

    # ── Flow line: src:sport → dst:dport [extras] ──────────────────────────
    src   = finding.get("src",   "?")
    dst   = finding.get("dst",   "?")
    sport = finding.get("sport", "?")
    dport = finding.get("dport", "?")

    flow = (
        f"  {BOLD}{BRIGHT_WHITE}{src}:{sport}{RESET}"
        f"  →  "
        f"{BOLD}{BRIGHT_WHITE}{dst}:{dport}{RESET}"
    )

    # Protocol-specific extras appended to the flow line
    if ftype == "http_basic":
        host   = finding.get("host",   "")
        method = finding.get("method", "")
        uri    = finding.get("uri",    "")
        if host:
            flow += f"  {DIM}host: {host}{RESET}"
        if method or uri:
            flow += f"  {DIM}{method} {uri}{RESET}"
    elif ftype == "smtp_creds":
        mech = finding.get("mechanism", "")
        if mech:
            flow += f"  {DIM}AUTH {mech}{RESET}"

    lines.append(flow)

    # ── Credentials ────────────────────────────────────────────────────────
    creds = finding.get("creds", "")
    lines.append(f"  {DIM}Credentials:{RESET}  {BOLD}{BRIGHT_RED}{creds}{RESET}")

    # ── Status + outcome ───────────────────────────────────────────────────
    status  = finding.get("status",  "")
    outcome = finding.get("outcome", "")
    status_str = str(status)
    if ftype == "http_basic":
        status_text = finding.get("status_text", "")
        status_str  = f"{status} {status_text}".strip()
    # Only show status separately if it adds information beyond the outcome.
    if status_str and status_str != outcome:
        lines.append(
            f"  {DIM}Status:{RESET}       {BRIGHT_WHITE}{status_str}{RESET}"
            f"  {BOLD}{BRIGHT_GREEN}{outcome}{RESET}"
        )
    else:
        lines.append(
            f"  {DIM}Status:{RESET}       {BOLD}{BRIGHT_GREEN}{outcome}{RESET}"
        )

    # ── Filter — bold yellow so it reads as "copy this" ────────────────────
    filt = finding.get("filter", "")
    if filt:
        lines.append(
            f"  {DIM}Filter:{RESET}       {BOLD}{BRIGHT_YELLOW}{filt}{RESET}"
        )

    lines.append("")  # blank spacer between findings
    return "\n".join(lines)


# ── File tailer ───────────────────────────────────────────────────────────────

def _tail(path: str):
    """
    Tail *path* from its current end and yield new lines as they arrive.

    Handles log rotation transparently: if the file's inode changes (logrotate
    replaced it) or its size shrinks (truncation), the file is reopened from
    the beginning of the new file so no lines are missed.

    Args:
        path: Path to the file to tail.

    Yields:
        Raw text lines (including the trailing newline) as they are written.
    """
    def _open():
        """Open *path*, seek to end, return (filehandle, inode)."""
        fh = open(path, "r", encoding="utf-8", errors="replace")
        fh.seek(0, 2)
        return fh, os.fstat(fh.fileno()).st_ino

    fh, inode = _open()
    try:
        while True:
            line = fh.readline()
            if line:
                yield line
                continue

            # No new data — pause then check for rotation.
            time.sleep(0.1)
            try:
                st = os.stat(path)
            except FileNotFoundError:
                # File temporarily absent (mid-rotation); wait and retry.
                time.sleep(1)
                continue

            if st.st_ino != inode or st.st_size < fh.tell():
                # Inode changed or file was truncated — reopen.
                fh.close()
                fh, inode = _open()
    finally:
        fh.close()


# ── Entry point ───────────────────────────────────────────────────────────────

def main():
    """
    Main entry point.

    Waits for the results file to appear if it does not yet exist, prints a
    startup banner, then tails the file and prints formatted findings for every
    successful credential capture.
    """
    path = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_RESULTS

    if not os.path.exists(path):
        print(f"Waiting for {path} …", flush=True)
        while not os.path.exists(path):
            time.sleep(1)

    print(
        f"\n{BOLD}tscan-ng live monitor{RESET}"
        f"  {DIM}—  successful sessions only  —  {path}{RESET}\n",
        flush=True,
    )

    for raw_line in _tail(path):
        raw_line = raw_line.strip()
        if not raw_line:
            continue
        try:
            finding = json.loads(raw_line)
        except (json.JSONDecodeError, ValueError):
            continue
        output = _format(finding)
        if output:
            print(output, flush=True)
            send_alert(finding)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{DIM}Monitor stopped.{RESET}\n")
