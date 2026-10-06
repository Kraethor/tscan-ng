#!/usr/bin/env python3
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
scripts/watch.py - Live display of successful tscan-ng credential findings.

Purpose:
    Tails the JSONL results file written by tscan-pipeline.service
    (tscan_ng/sinks/jsonl.py) and prints a human-readable, coloured summary
    for each *new* finding whose outcome is "success". Findings with any
    other outcome (failed, no_response, server_error, redirect,
    unknown, ...) are silently skipped by this viewer, even though they are
    present in the JSONL file and (except "failed") still trigger
    Discord alerts -- read the file directly (or with jq) to see them.

    The viewer starts at the *end* of the file, so it shows only findings
    written after it was launched, never history. Because pipeline.py's
    _emit() applies the [dedup] finding_cooldown_sec cooldown before writing
    to the JSONL file, repeat submissions of the same credentials to the
    same (dst, dport) inside the cooldown window (default 1800 s) never
    reach this display either.

    Log rotation is handled transparently: when the file at the path is a
    new one (logrotate renames results.jsonl and creates a new file, see
    logrotate/tscan), the rest of the old file is read first and the new
    one is then read from its start; a file truncated in place is re-read
    from its start (TODO.md #47).

    This is a read-only viewer. Logging and Discord alerting both happen inside
    tscan-pipeline.service itself (see tscan_ng/sinks/jsonl.py and
    tscan_ng/sinks/discord.py) regardless of whether this script is running, so
    closing this terminal never turns alerting off.

Usage:
    python3 /opt/tscan/scripts/watch.py [results_file]

    results_file   optional path to a JSONL findings file
                   (default: /var/log/tscan/results.jsonl). If it does not
                   exist yet the script prints "Waiting for <path> ..." and
                   polls once a second until it appears.

Environment:
    None read. Output uses ANSI escape codes unconditionally (no isatty()
    check, no NO_COLOR support), so piping to a file embeds escape sequences.

Privileges:
    Read access to the results file. /var/log/tscan is 0750 tscan:tscan and
    the service creates files 0640 (LogsDirectoryMode= and UMask= in
    tscan-pipeline.service, TODO.md #6), so the user must be in the tscan
    group or use `sudo`.

Untrusted input:
    Nearly every field of a finding comes from captured traffic. Control and
    format characters in string fields are printed as \\xNN / \\uNNNN escapes
    (see _escape()), so a hostile client cannot send ANSI/OSC sequences to the
    operator's terminal. The exact bytes remain in results.jsonl.

Exit codes:
    0  Ctrl-C (prints "Monitor stopped." and exits cleanly).
    1  any unhandled exception (e.g. PermissionError opening the file);
       Python prints a traceback. There is no other explicit exit path.

Colour coding:
    Protocol label   - unique colour per protocol for instant identification
    Source / dest    - white
    Credentials      - bold bright-red   (the primary artefact)
    Filter string    - bold bright-yellow (designed for easy selection/copy)
    Outcome          - bold bright-green

The filter string on each finding is a tcpdump/pcap-filter (BPF) expression
that isolates the exact session; Wireshark accepts it as a capture filter.
Highlight and copy it directly into Wireshark or:

    sudo tcpdump -r capture.pcap '<filter>'

Known limitation: the filter text is built by tscan_ng.session._make_filter(),
which always emits "tcp port ... and tcp port ...", including for snmp_creds
findings whose transport is UDP. For SNMP, change "tcp" to "udp" by hand before
using the filter, or it will match nothing.
"""

import json
import os
import sys
import time
import unicodedata
from datetime import datetime

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
# Keyed by the finding's "type" field (one per detector; ftp has two types).
# Each entry is (ansi_colour_string, display_label). A type missing from this
# table (e.g. a newly added detector) still displays, in bold bright white,
# with ftype.upper() as its label -- see _format().
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
    "smb_creds":     (BOLD + WHITE,          "SMB"),
    "snmp_creds":    (BOLD + BRIGHT_YELLOW,  "SNMP"),
    "irc_creds":     (BOLD + BRIGHT_GREEN,   "IRC"),
    "postgres_creds": (BOLD + BRIGHT_BLUE,   "PostgreSQL"),
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


# ── Escaping of untrusted fields ──────────────────────────────────────────────

# Unicode categories that can change what the terminal does rather than just
# print a glyph: Cc = C0/C1 controls and DEL (ESC starts ANSI/OSC sequences,
# 0x9B is a one-byte CSI), Cf = format characters (bidi overrides such as
# U+202E, zero-width characters), Zl/Zp = line/paragraph separators.
_UNSAFE_CATEGORIES = frozenset({"Cc", "Cf", "Zl", "Zp"})


def _is_unsafe(ch: str) -> bool:
    """Return True if *ch* must not be written raw to the terminal."""
    return unicodedata.category(ch) in _UNSAFE_CATEGORIES


def _escape(text: str) -> str:
    """
    Replace unsafe characters in *text* with visible \\xNN / \\uNNNN escapes.

    Almost every field of a finding (creds, host, uri, user, ...) is copied
    from network traffic, so it is attacker-controlled; JSON decoding turns
    \\u001b in results.jsonl back into a real ESC. Printed raw, it could clear
    the screen, rewrite earlier findings or set the window title.

    Backslashes are left as they are so ordinary credentials display exactly;
    a password that literally contains the text "\\x1b" therefore looks the
    same as an escaped ESC. results.jsonl holds the exact value.
    """
    if not any(_is_unsafe(ch) for ch in text):
        return text
    return "".join(
        (f"\\x{ord(ch):02x}" if ord(ch) < 0x100 else f"\\u{ord(ch):04x}")
        if _is_unsafe(ch) else ch
        for ch in text
    )


def _escape_finding(finding: dict) -> dict:
    """Return a copy of *finding* with every top-level string value escaped.

    Non-string values (ts, ports, status codes) are left alone. A nested
    list/dict would be printed via its repr(), which already escapes control
    characters."""
    return {k: _escape(v) if isinstance(v, str) else v for k, v in finding.items()}


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

    Every string field is passed through _escape_finding() first, so control
    characters from the captured traffic are shown as \\xNN escapes instead of
    being interpreted by the terminal.

    Args:
        finding: Parsed JSONL finding dict from tscan-ng.

    Returns:
        Formatted string ready for print(), or None to skip.
    """
    if finding.get("outcome") != "success":
        return None
    finding = _escape_finding(finding)

    ftype = finding.get("type", "unknown")
    proto_color, label = _PROTO.get(ftype, (BOLD + BRIGHT_WHITE, ftype.upper()))

    # Timestamp
    ts_raw = finding.get("ts_start") or finding.get("ts") or 0  # epoch seconds; 0 -> 1970 if neither key is present
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
    elif ftype == "smb_creds":
        domain = finding.get("domain", "")
        workstation = finding.get("workstation", "")
        if domain:
            flow += f"  {DIM}domain: {domain}{RESET}"
        if workstation:
            flow += f"  {DIM}from: {workstation}{RESET}"
    elif ftype == "snmp_creds":
        version  = finding.get("version",  "")
        pdu_type = finding.get("pdu_type", "")
        if version or pdu_type:
            flow += f"  {DIM}{version} {pdu_type}{RESET}"
    elif ftype == "postgres_creds":
        user = finding.get("user", "")
        if user:
            flow += f"  {DIM}user: {user}{RESET}"

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

    Handles log rotation without losing lines (TODO.md #47): if the path now
    names a different file (logrotate renamed the old one and created a new
    one), the lines still unread in the old file are yielded first and the
    new file is then read from its start; if the same file shrank below the
    read position (truncated in place), it is re-read from its start. Only
    the first open seeks to the end, so lines written before the viewer
    started are not replayed.

    Args:
        path: Path to the file to tail.

    Yields:
        Raw text lines (including the trailing newline) as they are written.
    """
    def _open(at_end: bool):
        """Open *path* (at its end if *at_end*), return (filehandle, inode)."""
        fh = open(path, "r", encoding="utf-8", errors="replace")
        if at_end:
            fh.seek(0, 2)
        return fh, os.fstat(fh.fileno()).st_ino

    fh, inode = _open(at_end=True)
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

            if st.st_ino != inode:
                # Rotated: finish the old file (a worker may have written to
                # it after the last read), then read the new one from its start.
                for line in iter(fh.readline, ""):
                    yield line
                fh.close()
                fh, inode = _open(at_end=False)
            elif st.st_size < fh.tell():
                # Truncated in place: read again from the start.
                fh.seek(0)
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


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{DIM}Monitor stopped.{RESET}\n")
