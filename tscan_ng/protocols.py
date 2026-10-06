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
protocols.py - The one table of protocols tscan-ng knows about (TODO.md #58).

Each protocol used to be spelled out separately in detectors/__init__.py
(imports, module list, configure_all), config.py (one property each, the
validation list, __repr__, server_ports), capture.py (port filter) and
session.py (default server ports). A protocol missing from one of those
failed silently. PROTOCOLS below is now the single list:

    config.py              Config.ports(name), the <name>_ports attributes,
                           server_ports, validation and __repr__ loop over it.
    detectors/__init__.py  DETECTOR_MODULES is imported from it, in this
                           order, and configure_all() loops over it.
    session.py             the default server-port set is the union of the
                           default ports here.

Places that still name protocols themselves are checked against this table
by tests/test_protocol_registry.py: capture._build_port_filter(),
scripts/watch.py's label table and tscan_ng.conf.example.

Module-level state: constants only. Imports nothing from tscan_ng, so any
module can import it without a cycle.
"""

from typing import NamedTuple


class Protocol(NamedTuple):
    """
    One protocol the pipeline handles.

    Attributes:
        name:          Key under [ports] in the config file; also the prefix
                       of Config.<name>_ports.
        module:        Detector module name under tscan_ng.detectors.
        transport:     "tcp" or "udp".
        default_ports: Ports used when the config file does not list any.
                       Must equal the detector module's own default port set
                       (checked by tests/test_protocol_registry.py).
    """
    name:          str
    module:        str
    transport:     str
    default_ports: frozenset


# Order is the order detectors run in (it has no functional significance:
# each detector gates on its own ports).
PROTOCOLS: tuple = (
    Protocol("http",     "http_basic", "tcp", frozenset({80, 8080, 8000, 8008, 8081, 8888, 3128})),
    Protocol("imap",     "imap",       "tcp", frozenset({143, 993, 1430})),
    Protocol("ftp",      "ftp",        "tcp", frozenset({21, 2121})),
    Protocol("smtp",     "smtp",       "tcp", frozenset({25, 465, 587, 2525})),
    Protocol("pop3",     "pop3",       "tcp", frozenset({110, 995, 1100})),
    Protocol("telnet",   "telnet",     "tcp", frozenset({23, 2323})),
    Protocol("ldap",     "ldap",       "tcp", frozenset({389, 3268})),
    Protocol("redis",    "redis",      "tcp", frozenset({6379, 6380})),
    Protocol("smb",      "smb",        "tcp", frozenset({445, 139})),
    Protocol("snmp",     "snmp",       "udp", frozenset({161})),
    Protocol("irc",      "irc",        "tcp", frozenset({6667, 6666, 6668, 6669})),
    Protocol("postgres", "postgres",   "tcp", frozenset({5432})),
)

BY_NAME: dict = {p.name: p for p in PROTOCOLS}


def ports_attr(protocol: Protocol) -> str:
    """
    Name of the module-level port set in the protocol's detector module.

    Args:
        protocol: Entry from PROTOCOLS.

    Returns:
        e.g. "_HTTP_PORTS" for http (in detectors/http_basic.py). This is the
        global detectors.configure_all() rebinds from the config.
    """
    return f"_{protocol.name.upper()}_PORTS"
