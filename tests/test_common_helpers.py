"""
Tests for TODO.md #57: helpers every detector needs live once, in
detectors/common.py, instead of being copied into each module.

    decode_sasl_plain()  was _decode_plain in smtp.py and imap.py
    parse_ber_len/_tlv() were _parse_ber_len/_tlv in ldap.py and snmp.py
    base_finding()       the type/session/endpoint/creds/filter dict (15 copies)
    on_ports()           the "is this flow on my ports" gate (12 copies)

Run from /opt/tscan:
    PYTHONDONTWRITEBYTECODE=1 venv/bin/python -m unittest discover -s tests -t . -v
"""

import base64
import inspect
import re
import unittest

from tscan_ng.detectors import DETECTOR_MODULES, common, ftp, imap, ldap, smtp, snmp
from tscan_ng.session import Session, _make_filter

TS = 1000.0


def make_session(dport: int) -> Session:
    """A client 10.0.0.2:50000 talking to server 10.0.0.9:<dport>."""
    s = Session("10.0.0.2", "10.0.0.9", 50000, dport)
    s.last_ts = TS
    return s


class SaslPlainTests(unittest.TestCase):
    def test_two_and_three_field_forms(self):
        self.assertEqual(common.decode_sasl_plain(base64.b64encode(b"\0bob\0pw1")),
                         ("bob", "pw1"))
        self.assertEqual(common.decode_sasl_plain(base64.b64encode(b"admin\0bob\0pw1")),
                         ("bob", "pw1"))

    def test_bad_input_is_none(self):
        self.assertIsNone(common.decode_sasl_plain(b"!!!not base64!!!"))
        self.assertIsNone(common.decode_sasl_plain(base64.b64encode(b"no-nul-here")))


class BerTests(unittest.TestCase):
    def test_len_short_and_long_form(self):
        self.assertEqual(common.parse_ber_len(b"\x05", 0), (5, 1))
        self.assertEqual(common.parse_ber_len(b"\x82\x01\x00", 0), (256, 3))

    def test_len_errors(self):
        self.assertEqual(common.parse_ber_len(b"", 0), (None, None))
        self.assertEqual(common.parse_ber_len(b"\x80", 0), (None, None))      # indefinite
        self.assertEqual(common.parse_ber_len(b"\x82\x01", 0), (None, None))  # truncated

    def test_tlv(self):
        self.assertEqual(common.parse_ber_tlv(b"\x04\x03abcXY", 0), (0x04, b"abc", 5))
        self.assertEqual(common.parse_ber_tlv(b"\x04\x03ab", 0), (None, None, None))


class BaseFindingTests(unittest.TestCase):
    def test_fields_and_order(self):
        s = make_session(21)
        f = common.base_finding(s, "x_creds", "bob:pw1", nick="bob", tag="a1")
        self.assertEqual(list(f), ["type", "session_id", "src", "dst", "sport", "dport",
                                   "nick", "tag", "creds", "filter"])
        self.assertEqual(f, {
            "type": "x_creds", "session_id": s.session_id,
            "src": "10.0.0.2", "dst": "10.0.0.9", "sport": 50000, "dport": 21,
            "nick": "bob", "tag": "a1", "creds": "bob:pw1",
            "filter": _make_filter("10.0.0.2", "10.0.0.9", 50000, 21),
        })

    def test_ftp_finding_is_unchanged(self):
        s = make_session(21)
        s.client_buf.extend(b"USER bob\r\nPASS pw1\r\n")
        ftp.detect_stream(s, TS)
        self.assertEqual(s.pending[0].finding,
                         common.base_finding(s, "ftp_creds", "bob:pw1"))

    def test_smtp_finding_keeps_mechanism(self):
        s = make_session(25)
        s.client_buf.extend(b"AUTH PLAIN " + base64.b64encode(b"\0bob\0pw1") + b"\r\n")
        smtp.detect_stream(s, TS)
        self.assertEqual(s.pending[0].finding,
                         common.base_finding(s, "smtp_creds", "bob:pw1", mechanism="PLAIN"))


class OnPortsTests(unittest.TestCase):
    def test_either_endpoint_counts(self):
        self.assertTrue(common.on_ports(make_session(21), frozenset({21})))
        s = Session("10.0.0.9", "10.0.0.2", 21, 50000)   # stored server-first
        self.assertTrue(common.on_ports(s, frozenset({21})))
        self.assertFalse(common.on_ports(make_session(22), frozenset({21})))


class NoCopiesLeftTests(unittest.TestCase):
    def test_duplicated_helpers_are_gone(self):
        for mod, names in ((smtp, ["_decode_plain"]), (imap, ["_decode_plain"]),
                           (ldap, ["_parse_ber_len", "_parse_ber_tlv"]),
                           (snmp, ["_parse_ber_len", "_parse_ber_tlv"])):
            for name in names:
                with self.subTest(module=mod.__name__, name=name):
                    self.assertFalse(hasattr(mod, name))

    def test_no_detector_builds_the_base_dict_or_port_gate_itself(self):
        own_dict = re.compile(r'"session_id":|_make_filter\(')
        own_gate = re.compile(r"session\.[sd]port\s+not\s+in\s+_\w+_PORTS")
        for mod in DETECTOR_MODULES:
            source = inspect.getsource(mod)
            with self.subTest(module=mod.__name__):
                self.assertIsNone(own_dict.search(source))
                self.assertIsNone(own_gate.search(source))
                self.assertIn("on_ports(session, ", source)


if __name__ == "__main__":
    unittest.main()
