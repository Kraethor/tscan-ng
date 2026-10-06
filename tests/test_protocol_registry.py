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
Tests for TODO.md #58: one table of protocols, and a check that every place
which has to know about each protocol agrees with it.

tscan_ng/protocols.py lists each protocol once (config key, detector module,
transport, default ports). config.py and detectors/__init__.py are driven by
it. The places that still name protocols themselves (capture.py's port
filter, scripts/watch.py's label table, the example config) are compared
against it here, so a protocol missing from one of them fails a test instead
of failing silently in production.

Run from /opt/tscan:
    PYTHONDONTWRITEBYTECODE=1 venv/bin/python -m unittest discover -s tests -t . -v
"""

import configparser
import importlib.util
import os
import re
import tempfile
import unittest

from tscan_ng import detectors, protocols, resolve, session
from tscan_ng.capture import _build_port_filter
from tscan_ng.config import Config

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def conf(extra: str = "") -> Config:
    """Config from a temp file using iface 'lo', a temp output file and *extra* INI text."""
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "t.conf")
        with open(path, "w") as f:
            f.write("[capture]\niface = lo\n"
                    f"[dispatcher]\nout = {os.path.join(d, 'results.jsonl')}\n" + extra)
        return Config(path)


def unique_ports() -> dict:
    """One distinct, non-default port per protocol: {name: port}."""
    return {p.name: 40001 + i for i, p in enumerate(protocols.PROTOCOLS)}


def conf_with_unique_ports() -> Config:
    lines = "".join(f"{name} = {port}\n" for name, port in unique_ports().items())
    return conf("[ports]\n" + lines)


class RegistryShapeTests(unittest.TestCase):
    def test_twelve_protocols_with_unique_names_and_modules(self):
        names = [p.name for p in protocols.PROTOCOLS]
        modules = [p.module for p in protocols.PROTOCOLS]
        self.assertEqual(len(names), 12)
        self.assertEqual(len(set(names)), 12)
        self.assertEqual(len(set(modules)), 12)
        for p in protocols.PROTOCOLS:
            with self.subTest(protocol=p.name):
                self.assertIn(p.transport, ("tcp", "udp"))
                self.assertTrue(p.default_ports)

    def test_only_snmp_is_udp(self):
        self.assertEqual([p.name for p in protocols.PROTOCOLS if p.transport == "udp"],
                         ["snmp"])


class DetectorTests(unittest.TestCase):
    def test_detector_modules_come_from_the_registry(self):
        self.assertEqual([m.__name__ for m in detectors.DETECTOR_MODULES],
                         [f"tscan_ng.detectors.{p.module}" for p in protocols.PROTOCOLS])

    def test_module_defaults_match_the_registry(self):
        for p, mod in zip(protocols.PROTOCOLS, detectors.DETECTOR_MODULES):
            with self.subTest(protocol=p.name):
                self.assertEqual(getattr(mod, protocols.ports_attr(p)), p.default_ports)

    def test_every_finding_type_has_a_resolver(self):
        for mod in detectors.DETECTOR_MODULES:
            for ftype in mod.FINDING_TYPES:
                with self.subTest(type=ftype):
                    self.assertIs(resolve.RESOLVERS.get(ftype), mod.resolve)

    def test_configure_all_reaches_every_module(self):
        cfg = conf_with_unique_ports()
        saved = [getattr(m, protocols.ports_attr(p))
                 for p, m in zip(protocols.PROTOCOLS, detectors.DETECTOR_MODULES)]
        try:
            detectors.configure_all(cfg)
            for p, mod in zip(protocols.PROTOCOLS, detectors.DETECTOR_MODULES):
                with self.subTest(protocol=p.name):
                    self.assertEqual(getattr(mod, protocols.ports_attr(p)),
                                     frozenset({unique_ports()[p.name]}))
        finally:
            for p, mod, ports in zip(protocols.PROTOCOLS, detectors.DETECTOR_MODULES, saved):
                setattr(mod, protocols.ports_attr(p), ports)


class ConfigTests(unittest.TestCase):
    def test_defaults_come_from_the_registry(self):
        cfg = conf()
        for p in protocols.PROTOCOLS:
            with self.subTest(protocol=p.name):
                self.assertEqual(cfg.ports(p.name), p.default_ports)
                self.assertEqual(getattr(cfg, f"{p.name}_ports"), p.default_ports)

    def test_configured_ports_and_server_ports(self):
        cfg = conf_with_unique_ports()
        for name, port in unique_ports().items():
            with self.subTest(protocol=name):
                self.assertEqual(cfg.ports(name), frozenset({port}))
        self.assertEqual(cfg.server_ports, frozenset(unique_ports().values()))

    def test_unknown_protocol_is_an_error(self):
        cfg = conf()
        with self.assertRaises(KeyError):
            cfg.ports("gopher")
        with self.assertRaises(AttributeError):
            cfg.gopher_ports

    def test_out_of_range_port_is_reported_for_any_protocol(self):
        for p in protocols.PROTOCOLS:
            with self.subTest(protocol=p.name):
                with self.assertRaisesRegex(ValueError, rf"ports\.{p.name} "):
                    conf(f"[ports]\n{p.name} = 70000\n")

    def test_repr_lists_every_protocol(self):
        text = repr(conf())
        for p in protocols.PROTOCOLS:
            with self.subTest(protocol=p.name):
                self.assertIn(f"{p.name}_ports=", text)

    def test_session_default_server_ports_are_the_registry_defaults(self):
        expected = frozenset().union(*(p.default_ports for p in protocols.PROTOCOLS))
        self.assertEqual(session._SERVER_PORTS, expected)


class OtherPlacesAgreeTests(unittest.TestCase):
    """Places that still spell the protocols out themselves."""

    def test_capture_filter_admits_every_protocol_on_its_transport(self):
        text = _build_port_filter(conf_with_unique_ports())
        clauses = {t: set(map(int, re.findall(r"port (\d+)", body)))
                   for t, body in re.findall(r"(tcp|udp) and \(([^)]*)\)", text)}
        for p in protocols.PROTOCOLS:
            port = unique_ports()[p.name]
            other = "udp" if p.transport == "tcp" else "tcp"
            with self.subTest(protocol=p.name):
                self.assertIn(port, clauses.get(p.transport, set()))
                self.assertNotIn(port, clauses.get(other, set()))

    def test_watch_has_a_label_for_every_finding_type(self):
        spec = importlib.util.spec_from_file_location(
            "watch_for_registry_test", os.path.join(REPO, "scripts", "watch.py"))
        watch = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(watch)
        for ftype in resolve.RESOLVERS:
            with self.subTest(type=ftype):
                self.assertIn(ftype, watch._PROTO)

    def test_example_config_lists_every_protocol(self):
        parser = configparser.ConfigParser()
        parser.read(os.path.join(REPO, "tscan_ng.conf.example"))
        self.assertEqual(set(parser["ports"]), {p.name for p in protocols.PROTOCOLS})
        for p in protocols.PROTOCOLS:
            with self.subTest(protocol=p.name):
                listed = {int(t) for t in parser["ports"][p.name].split(",")}
                self.assertEqual(listed, set(p.default_ports))


if __name__ == "__main__":
    unittest.main()
