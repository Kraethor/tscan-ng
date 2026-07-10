"""
config.py - Configuration loader for tscan-ng.

Loads runtime configuration from a single INI-style config file at a
well-known path. Provides typed accessors for all configuration values
with safe defaults for every setting.

Default config path: /opt/tscan/tscan_ng/config/tscan_ng.conf

All sections and keys are optional — missing values fall back to defaults
so the service can start with a minimal or empty config file.

Config file format:

    [capture]
    iface               = eth1
    snaplen             = 65535
    buffer_bytes        = 33554432
    no_immediate        = false
    bpf_filter          = tcp and (port 21 or port 25)

    [dispatcher]
    workers             = 4
    socket              = /run/tscan/tscan.sock
    out                 = /var/log/tscan/results.jsonl

    [sessions]
    timeout_seconds     = 60
    max_buf_bytes       = 4194304
    expiry_interval_sec = 30
    pending_max_age_sec = 45
    max_sessions        = 2048

    [ports]
    # Comma-separated port numbers for each protocol detector.
    # Sessions whose src or dst port is not in this list are skipped.
    http   = 80, 8080, 8000, 8008, 8081, 8888, 3128
    ftp    = 21, 2121
    smtp   = 25, 465, 587, 2525
    imap   = 143, 993, 1430
    pop3   = 110, 995, 1100
    telnet = 23, 2323
    ldap   = 389, 3268
    redis  = 6379, 6380
"""

import configparser
import logging
import os

DEFAULT_CONFIG_PATH = "/opt/tscan/tscan_ng/config/tscan_ng.conf"


class Config:
    """
    Typed configuration accessor for tscan_ng.

    Reads from an INI-style config file. All values have safe defaults
    so the service starts correctly even with a minimal config.

    Args:
        path: Path to the config file. Defaults to /opt/tscan/tscan_ng/config/tscan_ng.conf.
    """

    def __init__(self, path: str = DEFAULT_CONFIG_PATH):
        """
        Load configuration from the given path.

        Missing files or sections are silently ignored — all values
        fall back to their defaults.

        Args:
            path: Filesystem path to the INI config file.
        """
        self._cfg = configparser.ConfigParser()
        if os.path.exists(path):
            self._cfg.read(path)
        self._path = path
        self._validate()

    def _get(self, section: str, key: str, fallback):
        """
        Retrieve a raw string value from the config with a fallback.

        Args:
            section:  INI section name.
            key:      INI key name.
            fallback: Value to return if section/key is missing.

        Returns:
            String value from config or fallback.
        """
        return self._cfg.get(section, key, fallback=fallback)

    def _getint(self, section: str, key: str, fallback: int) -> int:
        """
        Retrieve an integer value from the config with a fallback.

        Args:
            section:  INI section name.
            key:      INI key name.
            fallback: Integer to return if section/key is missing.

        Returns:
            Integer value from config or fallback.
        """
        return self._cfg.getint(section, key, fallback=fallback)

    def _getbool(self, section: str, key: str, fallback: bool) -> bool:
        """
        Retrieve a boolean value from the config with a fallback.

        Accepts true/false, yes/no, on/off, 1/0 (case-insensitive).

        Args:
            section:  INI section name.
            key:      INI key name.
            fallback: Boolean to return if section/key is missing.

        Returns:
            Boolean value from config or fallback.
        """
        return self._cfg.getboolean(section, key, fallback=fallback)

    def _getports(self, section: str, key: str, fallback: frozenset) -> frozenset:
        """
        Retrieve a frozenset of port numbers from a comma-separated config value.

        Each token is stripped of whitespace and parsed as an integer. Tokens
        that are empty or non-numeric are silently skipped.  If the key is
        absent the fallback frozenset is returned unchanged.

        Args:
            section:  INI section name.
            key:      INI key name.
            fallback: frozenset to return if the section/key is missing.

        Returns:
            frozenset[int] of port numbers parsed from the config value.
        """
        raw = self._cfg.get(section, key, fallback=None)
        if raw is None:
            return fallback
        ports = set()
        for token in raw.split(","):
            token = token.strip()
            if token.isdigit():
                ports.add(int(token))
        return frozenset(ports) if ports else fallback

    # -------------------------------------------------------------------------
    # [capture]
    # -------------------------------------------------------------------------

    @property
    def iface(self) -> str:
        """Network interface to capture from (e.g. eth1)."""
        return self._get("capture", "iface", fallback="")

    @property
    def snaplen(self) -> int:
        """Maximum bytes to capture per packet."""
        return self._getint("capture", "snaplen", fallback=65535)

    @property
    def buffer_bytes(self) -> int:
        """Kernel capture ring buffer size in bytes."""
        return self._getint("capture", "buffer_bytes", fallback=32 * 1024 * 1024)

    @property
    def no_immediate(self) -> bool:
        """If True, disable immediate mode and use 1ms timeout instead."""
        return self._getbool("capture", "no_immediate", fallback=False)

    @property
    def bpf_filter(self) -> str | None:
        """
        Explicit BPF filter override for pcap capture, or None if unset.

        None (key absent) means: auto-build a filter from every protocol
        detector's configured ports (see capture._build_port_filter), which
        is the right default -- it keeps traffic no detector will ever look
        at from reaching userspace at all. Set explicitly to override:
        an empty string disables filtering entirely (capture everything,
        e.g. for troubleshooting); any other value is used verbatim as a
        tcpdump/pcap-filter expression.
        """
        return self._get("capture", "bpf_filter", fallback=None)

    # -------------------------------------------------------------------------
    # [dispatcher]
    # -------------------------------------------------------------------------

    @property
    def workers(self) -> int:
        """Number of worker processes to spawn."""
        return self._getint("dispatcher", "workers",
                            fallback=max(1, os.cpu_count() or 1))

    @property
    def socket_path(self) -> str:
        """Filesystem path for the Unix datagram socket."""
        return self._get("dispatcher", "socket",
                         fallback="/run/tscan/tscan.sock")

    @property
    def out_path(self) -> str:
        """Output JSONL file path."""
        return self._get("dispatcher", "out",
                         fallback="/var/log/tscan/results.jsonl")

    # -------------------------------------------------------------------------
    # [sessions]
    # -------------------------------------------------------------------------

    @property
    def session_timeout(self) -> float:
        """Idle session timeout in seconds before expiry."""
        return float(self._getint("sessions", "timeout_seconds", fallback=60))

    @property
    def session_max_buf(self) -> int:
        """Maximum bytes buffered per directional stream per session."""
        return self._getint("sessions", "max_buf_bytes",
                            fallback=4 * 1024 * 1024)

    @property
    def expiry_interval(self) -> float:
        """How often (in seconds) each worker runs session expiry."""
        return float(self._getint("sessions", "expiry_interval_sec",
                                  fallback=30))

    @property
    def pending_max_age(self) -> float:
        """
        Maximum age (seconds) of an unresolved pending finding before it is
        force-closed as no_response.

        A pending finding's server_buf_floor blocks server_buf trimming from
        cutting past it (see Session.add_pending), so a finding that never
        correlates with a response holds that floor in place indefinitely.
        On a busy, continuously-active session this alone lets server_buf
        grow past max_buf_bytes without bound. Aging out stale pending
        findings clears the floor so normal trimming can resume.
        """
        return float(self._getint("sessions", "pending_max_age_sec",
                                  fallback=45))

    @property
    def max_sessions(self) -> int:
        """
        Maximum number of concurrent sessions tracked per worker.

        Per-session buffers are already bounded by max_buf_bytes, but
        nothing previously bounded the *number* of concurrent sessions —
        a burst of many concurrent flows could still grow total memory
        without limit even with per-session buffers capped. This caps it
        the way libnids's n_tcp_streams does for dsniff: a hard ceiling,
        evicting the oldest/least-valuable session to make room for a new
        one once it's hit (see SessionTable._evict_one).

        This is a second, independent layer of defense alongside
        max_buf_bytes and the service's cgroup MemoryMax — it does not
        mathematically guarantee staying under MemoryMax in the absolute
        worst case (every session simultaneously pegged at max_buf_bytes
        in both directions: 2048 * 2 * 4MiB would be ~16GB), since real
        traffic essentially never pegs every concurrent session at once.
        Its job is bounding the more common failure mode — a connection-
        count explosion — that MemoryMax alone can't distinguish from
        legitimate load until memory is already gone. Tune down if
        MemoryHigh pressure shows up in practice, or up if legitimate
        traffic gets evicted too aggressively.
        """
        return self._getint("sessions", "max_sessions", fallback=2048)

    # -------------------------------------------------------------------------
    # [ports]
    # -------------------------------------------------------------------------

    @property
    def http_ports(self) -> frozenset:
        """Frozenset of TCP ports to scan for HTTP Basic Auth credentials."""
        return self._getports("ports", "http",
                              fallback=frozenset({80, 8080, 8000, 8008, 8081, 8888, 3128}))

    @property
    def ftp_ports(self) -> frozenset:
        """Frozenset of TCP ports to scan for FTP credentials."""
        return self._getports("ports", "ftp", fallback=frozenset({21, 2121}))

    @property
    def smtp_ports(self) -> frozenset:
        """Frozenset of TCP ports to scan for SMTP credentials."""
        return self._getports("ports", "smtp", fallback=frozenset({25, 465, 587, 2525}))

    @property
    def imap_ports(self) -> frozenset:
        """Frozenset of TCP ports to scan for IMAP credentials."""
        return self._getports("ports", "imap", fallback=frozenset({143, 993, 1430}))

    @property
    def pop3_ports(self) -> frozenset:
        """Frozenset of TCP ports to scan for POP3 credentials."""
        return self._getports("ports", "pop3", fallback=frozenset({110, 995, 1100}))

    @property
    def telnet_ports(self) -> frozenset:
        """Frozenset of TCP ports to scan for Telnet credentials."""
        return self._getports("ports", "telnet", fallback=frozenset({23, 2323}))

    @property
    def ldap_ports(self) -> frozenset:
        """Frozenset of TCP ports to scan for LDAP simple-bind credentials."""
        return self._getports("ports", "ldap", fallback=frozenset({389, 3268}))

    @property
    def redis_ports(self) -> frozenset:
        """Frozenset of TCP ports to scan for Redis AUTH credentials."""
        return self._getports("ports", "redis", fallback=frozenset({6379, 6380}))

    # -------------------------------------------------------------------------
    # [discord]
    # -------------------------------------------------------------------------

    @property
    def discord_webhook(self) -> str:
        """Discord webhook URL for credential alerts. Empty string if unset."""
        return self._get("discord", "discord_webhook", fallback="").strip()

    def _validate(self):
        """
        Validate configuration values and raise ValueError for any that
        would cause undefined behaviour or silent failures at runtime.

        Checks performed:
          - capture.iface is set and exists in /sys/class/net
          - capture.snaplen and buffer_bytes are within sane bounds
          - dispatcher.workers is at least 1
          - dispatcher.socket is an absolute path; its parent directory is
            checked for world-writable permissions (warning only — the
            directory may not exist yet when running outside systemd)
          - dispatcher.out directory exists and is writable by the current
            process (silent failures here are very hard to diagnose)
          - sessions values are positive
        """
        errors = []

        # --- capture ---------------------------------------------------------

        if not self.iface:
            errors.append("capture.iface must be set")
        else:
            # Validate against the kernel's interface list so misconfigured
            # interface names fail at startup rather than at pcap_create().
            try:
                available = sorted(os.listdir("/sys/class/net"))
                if self.iface not in available:
                    errors.append(
                        f"capture.iface '{self.iface}' not found "
                        f"(available: {', '.join(available)})"
                    )
            except OSError:
                pass  # Non-Linux host or unusual environment — skip the check

        if self.snaplen < 64:
            errors.append(f"capture.snaplen must be >= 64 (got {self.snaplen})")
        if self.buffer_bytes <= 0:
            errors.append(f"capture.buffer_bytes must be > 0 (got {self.buffer_bytes})")

        # --- dispatcher ------------------------------------------------------

        if self.workers < 1:
            errors.append(f"dispatcher.workers must be >= 1 (got {self.workers})")

        if not self.socket_path:
            errors.append("dispatcher.socket must be set")
        elif not os.path.isabs(self.socket_path):
            errors.append(
                f"dispatcher.socket must be an absolute path "
                f"(got {self.socket_path!r})"
            )
        else:
            sock_dir = os.path.dirname(os.path.normpath(self.socket_path))
            if os.path.isdir(sock_dir):
                try:
                    if os.stat(sock_dir).st_mode & 0o002:
                        # World-writable socket directory allows any local user
                        # to delete and replace the socket, intercepting packets.
                        logging.warning(
                            "config: dispatcher.socket parent directory '%s' is "
                            "world-writable — any local user can replace the socket",
                            sock_dir)
                except OSError:
                    pass

        if self.out_path:
            out_dir = os.path.dirname(self.out_path) or "."
            if not os.path.isdir(out_dir):
                errors.append(
                    f"dispatcher.out directory '{out_dir}' does not exist — "
                    "create it and grant write permission to the service user"
                )
            elif not os.access(out_dir, os.W_OK):
                errors.append(
                    f"dispatcher.out directory '{out_dir}' is not writable "
                    "by the current user"
                )

        # --- sessions --------------------------------------------------------

        if self.session_timeout <= 0:
            errors.append(
                f"sessions.timeout_seconds must be > 0 (got {self.session_timeout})")
        if self.session_max_buf < 1024:
            errors.append(
                f"sessions.max_buf_bytes must be >= 1024 (got {self.session_max_buf})")
        if self.expiry_interval <= 0:
            errors.append(
                f"sessions.expiry_interval_sec must be > 0 (got {self.expiry_interval})")
        if self.pending_max_age <= 0:
            errors.append(
                f"sessions.pending_max_age_sec must be > 0 (got {self.pending_max_age})")
        if self.max_sessions < 1:
            errors.append(
                f"sessions.max_sessions must be >= 1 (got {self.max_sessions})")

        # --- ports -----------------------------------------------------------

        for proto, ports in [
            ("http",   self.http_ports),
            ("ftp",    self.ftp_ports),
            ("smtp",   self.smtp_ports),
            ("imap",   self.imap_ports),
            ("pop3",   self.pop3_ports),
            ("telnet", self.telnet_ports),
            ("ldap",   self.ldap_ports),
            ("redis",  self.redis_ports),
        ]:
            bad = [p for p in ports if not (0 < p < 65536)]
            if bad:
                errors.append(
                    f"ports.{proto} contains out-of-range port numbers: "
                    + ", ".join(str(p) for p in sorted(bad))
                )

        if errors:
            raise ValueError(
                "Invalid configuration:\n" + "\n".join(f"  - {e}" for e in errors))

    def __repr__(self) -> str:
        return (
            f"Config(path={self._path!r}, "
            f"iface={self.iface!r}, "
            f"workers={self.workers}, "
            f"socket={self.socket_path!r}, "
            f"session_timeout={self.session_timeout}s, "
            f"expiry_interval={self.expiry_interval}s, "
            f"ftp_ports={sorted(self.ftp_ports)}, "
            f"smtp_ports={sorted(self.smtp_ports)}, "
            f"imap_ports={sorted(self.imap_ports)}, "
            f"pop3_ports={sorted(self.pop3_ports)}, "
            f"telnet_ports={sorted(self.telnet_ports)}, "
            f"ldap_ports={sorted(self.ldap_ports)}, "
            f"redis_ports={sorted(self.redis_ports)})"
        )
