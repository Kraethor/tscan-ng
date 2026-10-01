"""
config.py - Configuration loader for tscan-ng.

Loads runtime configuration from a single INI-style config file at a
well-known path. Provides typed accessors for all configuration values
with safe defaults for every setting.

Default config path: /opt/tscan/tscan_ng/config/tscan_ng.conf

The [ports] accessors are driven by the protocol registry in
tscan_ng.protocols (TODO.md #58): Config.ports(name) and each
Config.<name>_ports attribute cover exactly the protocols listed there.

Nearly every section and key is optional — missing values fall back to
defaults. The one exception is capture.iface, which has no usable default:
Config() raises ValueError (see Config._validate) if it is unset or names
an interface that does not exist, so a truly empty config file does not
start. Values are re-read from the parsed file on every property access
(nothing is cached); the file itself is parsed once, in Config.__init__.

Retired keys: dispatcher.socket and capture.no_immediate (from the old
capture.py -> run.py dispatcher design) were removed in TODO.md #55.
Unknown keys are ignored, so an old config that still sets them loads
unchanged.

Config file format:

    [capture]
    iface               = eth1
    snaplen             = 65535
    buffer_bytes        = 268435456
    bpf_filter          = tcp and (port 21 or port 25)

    [dispatcher]
    workers             = 4
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
    smb    = 445, 139
    snmp   = 161
    irc    = 6667, 6666, 6668, 6669
    postgres = 5432

    [discord]
    discord_webhook      = https://discord.com/api/webhooks/...
    notify_cooldown_sec  = 300

    [dedup]
    finding_cooldown_sec = 1800
"""

import configparser
import os

from tscan_ng import protocols

DEFAULT_CONFIG_PATH = "/opt/tscan/tscan_ng/config/tscan_ng.conf"


class Config:
    """
    Typed configuration accessor for tscan_ng.

    Reads from an INI-style config file. All values have safe defaults
    except capture.iface, which must be set (see _validate).

    Args:
        path: Path to the config file. Defaults to /opt/tscan/tscan_ng/config/tscan_ng.conf.

    Raises:
        ValueError: From __init__, if validation fails (all problems are
            reported together in one message). Individual property reads
            can also raise ValueError if a value is not parseable as the
            expected type (e.g. a non-integer timeout_seconds), and that
            surfaces through _validate as well.
    """

    def __init__(self, path: str = DEFAULT_CONFIG_PATH, validate: bool = True):
        """
        Load configuration from the given path.

        Missing files or sections are silently ignored — all values
        fall back to their defaults — but the result is then validated
        (see _validate), which rejects a missing capture.iface and other
        unusable values. The path is remembered only for __repr__.

        Args:
            path:     Filesystem path to the INI config file.
            validate: If False, skip _validate. For callers that only need to
                      read a few raw settings and must keep working when the
                      full config is unusable at the moment -- the external
                      health check (scripts/pipeline_healthcheck.py) reads the
                      Discord webhook this way so it can still alert when the
                      capture NIC has vanished and validation would fail. The
                      pipeline itself always validates.

        Raises:
            ValueError: If validate is true and _validate finds any invalid
                        setting.
        """
        self._cfg = configparser.ConfigParser()
        if os.path.exists(path):
            self._cfg.read(path)
        self._path = path
        if validate:
            self._validate()

    def _get(self, section: str, key: str, fallback):
        """
        Retrieve a raw string value from the config with a fallback.

        Args:
            section:  INI section name.
            key:      INI key name.
            fallback: Value to return if section/key is missing.

        Returns:
            String value from config or fallback. Note the fallback is
            returned as-is (it may be None), not coerced to str.
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

        Raises:
            ValueError: If the configured value is not a valid integer
                (configparser.getint; floats such as "0.5" are rejected).
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

        Raises:
            ValueError: If the configured value is not a recognised boolean.
        """
        return self._cfg.getboolean(section, key, fallback=fallback)

    def _getports(self, section: str, key: str, fallback: frozenset) -> frozenset:
        """
        Retrieve a frozenset of port numbers from a comma-separated config value.

        Each token is stripped of whitespace and parsed as an integer. Tokens
        that are empty or non-numeric (including ranges like "80-90") are
        silently skipped.  If the key is absent -- or present but yields no
        valid ports at all (e.g. an empty value) -- the fallback frozenset
        is returned, so a detector cannot be disabled by emptying its list.
        Range checking (1-65535) is left to _validate.

        Args:
            section:  INI section name.
            key:      INI key name.
            fallback: frozenset to return if the section/key is missing.

        Returns:
            frozenset[int] of port numbers parsed from the config value,
            or the fallback.
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
        """
        Maximum bytes to capture per packet.

        Used as the recv() size in pipeline.pipeline_worker (longer frames
        are truncated in userspace) and as the snaplen the BPF filter is
        compiled against; the kernel socket filter itself does not truncate.
        """
        return self._getint("capture", "snaplen", fallback=65535)

    @property
    def buffer_bytes(self) -> int:
        """
        Kernel socket receive buffer size in bytes, per pipeline process.

        Set via SO_RCVBUFFORCE on each pipeline's AF_PACKET socket (see
        pipeline._open_fanout_socket) -- a ceiling, not a pre-allocation, so
        oversizing this costs nothing while idle. It only matters during a
        burst, and the ultimate backstop regardless of how large a burst
        gets is this service's cgroup MemoryMax, the same protection
        session buffers already rely on. 256MB (raised from an original
        32MB used by the old libpcap-based capture.py) was sized against a
        live replay-load test: the worst single 30-second window saw
        ~63,000 kernel-level drops on one pipeline before this increase,
        and 256MB leaves headroom for roughly double that while keeping
        worst-case total memory (all dispatcher.workers sockets + typical
        session buffer load) comfortably under MemoryHigh -- pushing right up against
        MemoryHigh risks throttling/reclaim pressure that could itself slow
        packet processing and cause more drops, not fewer.
        """
        return self._getint("capture", "buffer_bytes", fallback=256 * 1024 * 1024)

    @property
    def bpf_filter(self) -> str | None:
        """
        Explicit BPF filter override (attached to each pipeline's AF_PACKET
        socket via SO_ATTACH_FILTER), or None if unset.

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
        """
        Number of pipeline processes to spawn (one per PACKET_FANOUT
        member). Defaults to the CPU count.
        """
        return self._getint("dispatcher", "workers",
                            fallback=max(1, os.cpu_count() or 1))

    @property
    def out_path(self) -> str:
        """Output JSONL file path. Empty string means write to stdout."""
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
        """
        Maximum bytes buffered per directional stream per session.

        server_buf may temporarily exceed this while a pending finding holds
        a trim floor (see session.SessionTable.add_packet).
        """
        return self._getint("sessions", "max_buf_bytes",
                            fallback=4 * 1024 * 1024)

    @property
    def expiry_interval(self) -> float:
        """
        Minimum seconds between periodic runs in each pipeline process
        (session expiry plus the kernel packet-drop check; see
        pipeline._maybe_run_periodic).
        """
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

    def ports(self, name: str) -> frozenset:
        """
        Frozenset of ports to scan for protocol *name* (a tscan_ng.protocols
        name, e.g. "http", "snmp").

        Read from [ports] in the config file, falling back to the protocol's
        default_ports in the registry. SNMP's are UDP ports; every other
        protocol's are TCP (see tscan_ng.protocols and
        capture._build_port_filter).

        Args:
            name: Protocol name from tscan_ng.protocols.BY_NAME.

        Returns:
            frozenset[int].

        Raises:
            KeyError: if *name* is not a known protocol.
        """
        proto = protocols.BY_NAME[name]
        return self._getports("ports", proto.name, fallback=proto.default_ports)

    def __getattr__(self, attr: str) -> frozenset:
        """
        Expose each protocol's ports as cfg.<name>_ports.

        Only <name>_ports attributes are served here; anything else raises
        AttributeError as usual. __getattr__ runs only for attributes not
        found normally, so it never shadows a real method or property.
        """
        if attr.endswith("_ports"):
            name = attr[:-len("_ports")]
            if name in protocols.BY_NAME:
                return self.ports(name)
        raise AttributeError(
            f"{type(self).__name__!r} object has no attribute {attr!r}")

    # -------------------------------------------------------------------------
    # [discord]
    # -------------------------------------------------------------------------

    @property
    def discord_webhook(self) -> str:
        """Discord webhook URL for credential alerts. Empty string if unset."""
        return self._get("discord", "discord_webhook", fallback="").strip()

    @property
    def discord_notify_cooldown(self) -> float:
        """
        Minimum seconds between operational (non-finding) Discord alerts,
        e.g. a pipeline_worker exiting abnormally.

        Distinct from credential-finding alerts (DiscordSink.write()), which
        aren't cooldown-limited on the Discord side at all -- see
        finding_cooldown below, which suppresses repeat findings upstream of
        every sink (JSONL included), before either one ever sees them.
        Operational alerts need their own cooldown because a sustained
        failure (e.g. the capture interface staying down) makes every
        pipeline_worker process re-raise and re-alert on every RestartSec
        cycle; without a cooldown that's one Discord message every few
        seconds for as long as the outage lasts.
        """
        return float(self._getint("discord", "notify_cooldown_sec", fallback=300))

    # -------------------------------------------------------------------------
    # [dedup]
    # -------------------------------------------------------------------------

    @property
    def finding_cooldown(self) -> float:
        """
        Minimum seconds between findings that share the same
        (dst, dport, creds, outcome) key -- i.e. the same credentials
        submitted to the same service with the same result -- before pipeline.py's _emit() will write another
        one to *any* sink (JSONLSink and DiscordSink alike). 0 disables the
        cooldown (every finding is emitted).

        Exists so a spammer (or scanner) that keeps replaying the same bad
        credentials at the same service doesn't turn into one results.jsonl
        line (and one Discord message) per packet; each distinct
        (target, credential) pair still gets its own first emission
        immediately, and starts alerting again on its own once
        finding_cooldown_sec has passed since the last one.
        """
        return float(self._getint("dedup", "finding_cooldown_sec", fallback=1800))

    @property
    def log_level(self) -> str:
        """
        Root log level for the pipeline worker processes, from [logging]
        level (default INFO). Upper-cased; must be one of DEBUG, INFO,
        WARNING, ERROR, CRITICAL (checked in _validate). A blank value falls
        back to INFO.

        Workers used to be hardwired to DEBUG, which made parsing.net log a
        traceback for every malformed packet and turned on DEBUG output from
        every library; set this to DEBUG only while troubleshooting
        (TODO.md #18).
        """
        return self._get("logging", "level", fallback="INFO").strip().upper() or "INFO"

    @property
    def server_ports(self) -> frozenset:
        """
        Union of every detector's configured ports (TCP and UDP): the set of
        ports on which the other end of a flow is the server.

        Used by session.SessionTable to decide which side of a flow is the
        client when the first packet seen came from the server (capture
        started mid-flow, or the server spoke first). Derived from [ports]
        rather than hardcoded so every detector's ports, and any non-default
        configured port, are covered (TODO.md #12).
        """
        ports = set()
        for proto in protocols.PROTOCOLS:
            ports.update(self.ports(proto.name))
        return frozenset(ports)

    def _validate(self):
        """
        Validate configuration values and raise ValueError for any that
        would cause undefined behaviour or silent failures at runtime.

        Checks performed:
          - capture.iface is set and exists in /sys/class/net
          - capture.snaplen and buffer_bytes are within sane bounds
          - dispatcher.workers is at least 1
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
            # interface names fail at startup with a clear message rather
            # than later at socket bind() in each pipeline process.
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

        # --- logging ---------------------------------------------------------

        if self.log_level not in ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"):
            errors.append(
                f"logging.level must be DEBUG, INFO, WARNING, ERROR or CRITICAL "
                f"(got {self.log_level!r})")

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

        for proto in protocols.PROTOCOLS:
            bad = [p for p in self.ports(proto.name) if not (0 < p < 65536)]
            if bad:
                errors.append(
                    f"ports.{proto.name} contains out-of-range port numbers: "
                    + ", ".join(str(p) for p in sorted(bad))
                )

        if errors:
            raise ValueError(
                "Invalid configuration:\n" + "\n".join(f"  - {e}" for e in errors))

    def __repr__(self) -> str:
        """Summarise the main settings (not the webhook URL, which is a secret)."""
        return (
            f"Config(path={self._path!r}, "
            f"iface={self.iface!r}, "
            f"workers={self.workers}, "
            f"session_timeout={self.session_timeout}s, "
            f"expiry_interval={self.expiry_interval}s, "
            + "".join(f"{p.name}_ports={sorted(self.ports(p.name))}, "
                       for p in protocols.PROTOCOLS).rstrip(", ")
            + ")"
        )
