"""
Tests for flow-direction detection using the configured detector ports
(TODO.md #12).

session._SERVER_PORTS used to be a hardcoded list that omitted the ports of
several detectors (postgres 5432, redis 6379, ldap 389, smb 445, snmp 161, ...)
and any non-default configured port. A flow first seen from the server side
(capture started mid-flow, or the server spoke first) was then stored with
client and server swapped, and the detectors found nothing.

Run from /opt/tscan:
    PYTHONDONTWRITEBYTECODE=1 venv/bin/python -m unittest discover -s tests -t . -v
"""

import os
import tempfile
import unittest

from tscan_ng.config import Config
from tscan_ng.session import SessionTable
from tscan_ng.detectors import postgres
from tests.test_detectors import (pg_startup, pg_password, PG_AUTH_CLEARTEXT,
                                  PG_AUTH_OK, PG_STARTUP_P)

CLIENT, SERVER = "10.0.0.2", "10.0.0.9"


def pkt(from_server: bool, sport_server: int, payload: bytes) -> dict:
    """A parsed-packet dict travelling in the given direction."""
    if from_server:
        return {"src": SERVER, "dst": CLIENT, "sport": sport_server,
                "dport": 50000, "payload": payload}
    return {"src": CLIENT, "dst": SERVER, "sport": 50000,
            "dport": sport_server, "payload": payload}


def conf_with(extra: str) -> Config:
    """Config from a temp file using iface 'lo', a temp output file and *extra* INI text."""
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "t.conf")
        with open(path, "w") as f:
            # Output goes to the temp dir: validation requires a writable output
            # directory, and /var/log/tscan is not writable by non-tscan users (#6).
            f.write("[capture]\niface = lo\n"
                    f"[dispatcher]\nout = {os.path.join(d, 'results.jsonl')}\n" + extra)
        return Config(path)


class ConfigServerPortsTests(unittest.TestCase):
    def test_defaults_include_every_detector_port(self):
        ports = conf_with("").server_ports
        for p in (21, 25, 80, 110, 143, 389, 445, 5432, 6379, 6667, 161, 3128):
            self.assertIn(p, ports)

    def test_custom_port_is_included(self):
        self.assertIn(15432, conf_with("[ports]\npostgres = 15432\n").server_ports)


class DirectionTests(unittest.TestCase):
    def test_server_first_flow_on_postgres_port_is_oriented_correctly(self):
        table = SessionTable(server_ports=conf_with("").server_ports)
        s, _ = table.add_packet(pkt(True, 5432, PG_AUTH_CLEARTEXT), 1.0)
        self.assertEqual((s.src, s.dport), (CLIENT, 5432))

    def test_server_first_flow_on_custom_port(self):
        cfg = conf_with("[ports]\npostgres = 15432\n")
        table = SessionTable(server_ports=cfg.server_ports)
        s, _ = table.add_packet(pkt(True, 15432, b"x"), 1.0)
        self.assertEqual((s.src, s.dport), (CLIENT, 15432))

    def test_udp_snmp_response_first(self):
        table = SessionTable(server_ports=conf_with("").server_ports)
        s, _ = table.add_packet(pkt(True, 161, b"x"), 1.0)
        self.assertEqual((s.src, s.dport), (CLIENT, 161))

    def test_default_table_keeps_old_behaviour(self):
        table = SessionTable()
        s, _ = table.add_packet(pkt(True, 21, b"220 hi\r\n"), 1.0)
        self.assertEqual((s.src, s.dport), (CLIENT, 21))

    def test_client_first_flow_unchanged(self):
        table = SessionTable(server_ports=conf_with("").server_ports)
        s, _ = table.add_packet(pkt(False, 5432, b"x"), 1.0)
        self.assertEqual((s.src, s.dport), (CLIENT, 5432))

    def test_postgres_credentials_found_when_server_spoke_first(self):
        """End to end: the first packet seen is the server's auth request."""
        table = SessionTable(server_ports=conf_with("").server_ports)
        session, _ = table.add_packet(pkt(True, 5432, PG_AUTH_CLEARTEXT), 1.0)
        table.add_packet(pkt(False, 5432, PG_STARTUP_P + pg_password(b"s3cret")), 2.0)
        table.add_packet(pkt(True, 5432, PG_AUTH_OK), 3.0)
        found = postgres.detect_stream(session, 3.0)
        self.assertEqual([f["creds"] for f in found], ["postgres:s3cret"])


if __name__ == "__main__":
    unittest.main()
