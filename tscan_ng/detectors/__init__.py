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
detectors/__init__.py - Detector registry for tscan-ng.

Exports DETECTOR_MODULES (one module per protocol), STREAM_DETECTORS (their
detect_stream functions) and run_detectors(), which calls them with
per-detector exception isolation, consumed by each pipeline_worker() process in
pipeline.py, the deployed tscan-pipeline.service path. tscan_ng.resolve
builds its resolver registry from DETECTOR_MODULES. Every protocol here needs stream reassembly to correlate a credential
with its server response (see e.g. detectors/ftp.py's module docstring), so
all 12 are stream-aware; there is no per-packet detector mechanism.

Each detector module provides:
    FINDING_TYPES = ("<proto>_creds", ...)       # types it emits
    def detect_stream(session, ts) -> list        # finds credentials; always []
    def resolve(p, session) -> tuple | None       # matches the server's reply
detect_stream() never judges the outcome: it parks each credential with
session.add_pending() and consumes the client bytes it used. resolve()
returns ({"status", "outcome", ...}, bytes_to_consume) once the reply is
in server_buf, else None; tscan_ng.resolve consumes the bytes and shifts
the other pending findings' floors. It must not modify server_buf itself.

Conventions every detector follows (TODO.md #61; tests/test_conventions.py):
    - Bytes are decoded with errors="replace", never "ignore": a credential
      containing a non-UTF-8 byte shows U+FFFD in its place rather than
      silently losing the byte.
    - "status" in resolve()'s fields is always a str: the protocol's own
      reply code where it has one ("230", "401", "49", "OK", a SQLSTATE),
      otherwise the outcome word (irc, redis, telnet).
    - The per-call scan windows are module constants named _MAX_SCAN_CLIENT
      (client_buf) and, where server_buf is windowed too, _MAX_SCAN_SERVER.

Call configure_all(cfg) once in each worker process after loading Config to
apply the port sets from the config file to every protocol detector.

How detectors are driven (pipeline.py pipeline_worker(), per captured packet):
    1. SessionTable.add_packet() appends the payload to the flow's
       client_buf/server_buf and returns the Session.
    2. run_detectors() calls every function in STREAM_DETECTORS with
       (session, ts), in list order. Order has no functional significance:
       each detector gates on its own port set, so at most one does real
       work for a given flow. Credentials are parked with
       session.add_pending(). Each call is isolated (TODO.md #59): a
       detector that raises is logged and skipped for the rest of that
       flow, and the others still run.
    3. tscan_ng.resolve.resolve_pending() offers every pending finding to the
       resolve() of the module that emitted its "type". A reply that is
       already buffered is therefore matched on the same packet. Each
       protocol's response parsing lives only in its resolve() (TODO.md #56).

Registration checklist for a NEW detector (TODO.md #58 collapsed most of
the old list into one registry; tests/test_protocol_registry.py fails if a
place below is missed):
    1. detectors/<proto>.py: module-level `_<PROTO>_PORTS` frozenset (the
       name configure_all() rebinds), FINDING_TYPES, `detect_stream(session,
       ts)` and `resolve(p, session)` as described above. Use the shared
       helpers in detectors/common.py (on_ports(), base_finding(), the
       decoders) rather than copying them (TODO.md #57).
    2. tscan_ng/protocols.py: one Protocol(...) row in PROTOCOLS (config
       name, module, transport, default ports). This alone wires up
       DETECTOR_MODULES, configure_all() (below), every Config.<name>_ports
       accessor, Config.server_ports, config validation and __repr__, the
       capture.py BPF port filter and session.py's default server ports.
    3. config/tscan_ng.conf and tscan_ng.conf.example: a `<proto> = ...`
       line under [ports] (optional; the registry default is used if absent).
    4. scripts/watch.py: a colour/label entry in _PROTO (and a display branch
       if the finding carries protocol-specific fields); docs (README.md,
       docs/REBUILD.md, docs/test_reference.md) and tests.
    Also check whether DiscordSink._SUPPRESSED_OUTCOMES (and
    _SUPPRESSED_TYPE_OUTCOMES) give the new outcome values the alerting
    behaviour you want.

"""

import logging

import importlib

from tscan_ng import protocols

# One module per protocol, in tscan_ng.protocols.PROTOCOLS order. Imported
# from the registry so adding a protocol there is enough (TODO.md #58); the
# names still resolve to tscan_ng.detectors.<module>.
DETECTOR_MODULES = [
    importlib.import_module(f"tscan_ng.detectors.{p.module}") for p in protocols.PROTOCOLS
]

STREAM_DETECTORS = [mod.detect_stream for mod in DETECTOR_MODULES]


def run_detectors(session, ts: float) -> list[dict]:
    """
    Offer *session* to every detector in STREAM_DETECTORS, isolating each one.

    A detector that raises is logged once (with traceback, detector module
    and session id) and added to session.failed_detectors, so it is not
    called for that flow again: nothing was consumed from the buffer, so it
    would raise on every later packet of the flow. The remaining detectors
    still run, and the failure does not count as a packet-processing failure
    in pipeline._capture_loop() (TODO.md #59).

    Args:
        session: Session the current packet was added to.
        ts:      Unix timestamp of the current packet.

    Returns:
        The findings the detectors returned (none today: they park
        credentials with session.add_pending() instead).
    """
    findings = []
    for det in STREAM_DETECTORS:
        if det in session.failed_detectors:
            continue
        try:
            findings.extend(det(session, ts))
        except Exception:
            session.failed_detectors.add(det)
            logging.exception(
                "detector %s raised on session %s (%s:%d -> %s:%d); "
                "skipping it for the rest of this flow",
                getattr(det, "__module__", det), session.session_id,
                session.src, session.sport, session.dst, session.dport)
    return findings


def configure_all(cfg) -> None:
    """
    Apply per-protocol port sets from *cfg* to each detector module.

    Each protocol detector gates on a module-level frozenset of ports. This
    function replaces those frozensets with the values loaded from the config
    file, allowing port lists to be changed without editing source code.
    The detectors look the frozenset up as a module global at call time, so
    rebinding it here takes effect immediately. The hard-coded frozensets in
    each module are only the defaults used when configure_all() is never
    called (e.g. in unit tests). Only port gating is configurable; the
    per-detector _MAX_* scan limits are not.

    Must be called once per worker process before the packet processing loop.

    Args:
        cfg: Loaded Config object (tscan_ng.config.Config).
    """
    for proto, mod in zip(protocols.PROTOCOLS, DETECTOR_MODULES):
        setattr(mod, protocols.ports_attr(proto), cfg.ports(proto.name))
