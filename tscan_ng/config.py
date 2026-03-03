"""
config.py - Configuration loader for tscan-ng.

Loads runtime configuration from a single INI-style config file at a
well-known path. Provides typed accessors for all configuration values
with safe defaults for every setting.

Default config path: /opt/tscan/tscan.conf

All sections and keys are optional — missing values fall back to defaults
so the service can start with a minimal or empty config file.

Config file format:

    [capture]
    iface               = eth1
    snaplen             = 65535
    buffer_bytes        = 33554432
    no_immediate        = false

    [dispatcher]
    workers             = 4
    socket              = /run/tscan/tscan.sock
    out                 = /var/log/tscan/results.jsonl

    [sessions]
    timeout_seconds     = 60
    max_buf_bytes       = 1048576
    expiry_interval_sec = 30
"""

import configparser
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
                            fallback=1 * 1024 * 1024)

    @property
    def expiry_interval(self) -> float:
        """How often (in seconds) each worker runs session expiry."""
        return float(self._getint("sessions", "expiry_interval_sec",
                                  fallback=30))

    def __repr__(self) -> str:
        return (
            f"Config(path={self._path!r}, "
            f"iface={self.iface!r}, "
            f"workers={self.workers}, "
            f"socket={self.socket_path!r}, "
            f"session_timeout={self.session_timeout}s, "
            f"expiry_interval={self.expiry_interval}s)"
        )
