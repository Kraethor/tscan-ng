"""
Tests for TODO.md #25: SMB pairs each AUTHENTICATE with the right CHALLENGE.

The CHALLENGE response, the AUTHENTICATE request and the final response of
one NTLM exchange all carry the same SMB2 header SessionId (the server
assigns it in the CHALLENGE and the client echoes it). The detector used
the first CHALLENGE in server_buf and the first non-MORE_PROCESSING final
status, so a second authentication over the same connection paired its
AUTHENTICATE with the first exchange's ServerChallenge -- an uncrackable
hash -- and could read the wrong final status. It now matches by SessionId
(and MessageId for the final status).

These build minimal SMB2 SESSION_SETUP messages; no live SMB server.

Run from /opt/tscan:
    PYTHONDONTWRITEBYTECODE=1 venv/bin/python -m unittest discover -s tests -t . -v
"""

import struct
import unittest

from tscan_ng.detectors import smb
from tscan_ng.session import Session

TS = 1000.0
_SEC_OFF_RESP = 64 + 8    # token after the 8-byte response structure
_SEC_OFF_REQ = 64 + 24    # token after the 24-byte request structure


def smb2(command, is_response, message_id, session_id, status, structure):
    hdr = bytearray(64)
    hdr[0:4] = b"\xfeSMB"
    struct.pack_into("<I", hdr, 8, status)
    struct.pack_into("<H", hdr, 12, command)
    struct.pack_into("<I", hdr, 16, 0x1 if is_response else 0x0)  # SERVER_TO_REDIR
    struct.pack_into("<Q", hdr, 24, message_id)
    struct.pack_into("<Q", hdr, 40, session_id)
    return bytes(hdr) + structure


def session_setup_response(token):
    s = bytearray(8)
    struct.pack_into("<H", s, 0, 9)                 # StructureSize
    struct.pack_into("<H", s, 4, _SEC_OFF_RESP)     # SecurityBufferOffset
    struct.pack_into("<H", s, 6, len(token))        # SecurityBufferLength
    return bytes(s) + token


def session_setup_request(token):
    s = bytearray(24)
    struct.pack_into("<H", s, 0, 25)                # StructureSize
    struct.pack_into("<H", s, 12, _SEC_OFF_REQ)     # SecurityBufferOffset
    struct.pack_into("<H", s, 14, len(token))       # SecurityBufferLength
    return bytes(s) + token


def ntlm_challenge(server_challenge: bytes) -> bytes:
    msg = bytearray(32)
    msg[0:8] = b"NTLMSSP\x00"
    struct.pack_into("<I", msg, 8, 2)               # CHALLENGE
    msg[24:32] = server_challenge
    return bytes(msg)


def ntlm_authenticate(domain, user, workstation, nt_response, unicode=True) -> bytes:
    enc = "utf-16-le" if unicode else "latin-1"
    dom, usr, ws = domain.encode(enc), user.encode(enc), workstation.encode(enc)
    payload = bytearray()

    def place(b):
        off = 64 + len(payload)
        payload.extend(b)
        return off

    nt_off = place(nt_response)
    dom_off = place(dom)
    usr_off = place(usr)
    ws_off = place(ws)
    msg = bytearray(64)
    msg[0:8] = b"NTLMSSP\x00"
    struct.pack_into("<I", msg, 8, 3)               # AUTHENTICATE

    def field(pos, b, off):
        struct.pack_into("<H", msg, pos, len(b))
        struct.pack_into("<H", msg, pos + 2, len(b))
        struct.pack_into("<I", msg, pos + 4, off)

    field(12, b"", 64)                              # LmChallengeResponse (unused)
    field(20, nt_response, nt_off)
    field(28, dom, dom_off)
    field(36, usr, usr_off)
    field(44, ws, ws_off)
    field(52, b"", 64)                              # EncryptedRandomSessionKey
    struct.pack_into("<I", msg, 60, 0x1 if unicode else 0)   # NegotiateFlags: UNICODE
    return bytes(msg) + bytes(payload)


# A 16-byte NTProofStr + an 8-byte blob stand-in (len > 24, as the detector needs).
NT_RESPONSE = bytes(range(24)) + b"\xaa\xbb\xcc\xdd"


class FindChallengeTests(unittest.TestCase):
    def test_matches_the_requested_session_id(self):
        buf = (smb2(1, True, 0, 0x1111, smb._STATUS_MORE_PROCESSING_REQUIRED,
                    session_setup_response(ntlm_challenge(b"AAAAAAAA")))
               + smb2(1, True, 0, 0x2222, smb._STATUS_MORE_PROCESSING_REQUIRED,
                      session_setup_response(ntlm_challenge(b"BBBBBBBB"))))
        self.assertEqual(smb._find_ntlm_challenge(buf, 0x2222), b"BBBBBBBB")
        self.assertEqual(smb._find_ntlm_challenge(buf, 0x1111), b"AAAAAAAA")
        self.assertIsNone(smb._find_ntlm_challenge(buf, 0x9999))


class ReauthPairingTests(unittest.TestCase):
    def make_session(self):
        s = Session("10.0.0.2", "10.0.0.9", 50000, 445)
        s.last_ts = TS
        return s

    def test_authenticate_pairs_with_its_own_sessions_challenge(self):
        s = self.make_session()
        # Two CHALLENGEs already buffered; the client's AUTHENTICATE is for
        # the SECOND session. The old code used the first challenge (AAAA).
        s.server_buf.extend(
            smb2(1, True, 0, 0x1111, smb._STATUS_MORE_PROCESSING_REQUIRED,
                 session_setup_response(ntlm_challenge(b"AAAAAAAA")))
            + smb2(1, True, 0, 0x2222, smb._STATUS_MORE_PROCESSING_REQUIRED,
                   session_setup_response(ntlm_challenge(b"BBBBBBBB"))))
        s.client_buf.extend(
            smb2(1, False, 5, 0x2222, 0,
                 session_setup_request(ntlm_authenticate("CORP", "alice", "WS", NT_RESPONSE))))
        smb.detect_stream(s, TS)
        self.assertEqual(len(s.pending), 1)
        creds = s.pending[0].finding["creds"]
        self.assertIn(b"BBBBBBBB".hex(), creds)         # the matching challenge
        self.assertNotIn(b"AAAAAAAA".hex(), creds)
        self.assertTrue(creds.startswith("alice::CORP:"))

    def test_final_status_matched_by_session_and_message_id(self):
        s = self.make_session()
        s.server_buf.extend(
            smb2(1, True, 5, 0x2222, smb._STATUS_MORE_PROCESSING_REQUIRED,
                 session_setup_response(ntlm_challenge(b"BBBBBBBB"))))
        s.client_buf.extend(
            smb2(1, False, 5, 0x2222, 0,
                 session_setup_request(ntlm_authenticate("CORP", "alice", "WS", NT_RESPONSE))))
        smb.detect_stream(s, TS)
        self.assertEqual(len(s.pending), 1)
        # A final status for a DIFFERENT session must not resolve it; the
        # one for this session (0x2222 / message 5) must.
        s.server_buf.extend(smb2(1, True, 7, 0x3333, smb._STATUS_SUCCESS,
                                 session_setup_response(b"\x00")))
        from tscan_ng import resolve as resolve_mod
        self.assertEqual(resolve_mod.resolve_pending(s, TS + 1), [])
        s.server_buf.extend(smb2(1, True, 5, 0x2222, smb._STATUS_SUCCESS,
                                 session_setup_response(b"\x00")))
        done = resolve_mod.resolve_pending(s, TS + 2)
        self.assertEqual([f["outcome"] for f in done], ["success"])


if __name__ == "__main__":
    unittest.main()
