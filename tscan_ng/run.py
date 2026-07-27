"""
run.py - Shared response-correlation logic for tscan-ng.

_try_resolve() below is imported directly by pipeline.py and runs in every
pipeline_worker process -- it is the shared response-correlation logic
(matching a pending finding like "credentials seen, no server reply yet"
against newly arrived server_buf data) for every protocol detector. See
pipeline_worker()'s docstring in pipeline.py, which calls out that its own
detector/session/pending-resolution loop is "architecturally identical to
run.py's old worker_main()".

This module used to also hold the original two-process design's dispatcher
and worker pool (dispatcher() receiving raw packets from capture.py's
capture_into_unix_dgram() over a Unix datagram socket and routing them by
flow-affinity hash to worker_main() processes over bounded multiprocessing
Queues) plus a `python -m tscan_ng.run` standalone entry point, paired with
tscan-dispatcher.service. pipeline.py's N self-contained fan-out processes
superseded that design (see pipeline.py's module docstring for why), and
the dispatcher/worker code was removed as dead weight once nothing still
ran it -- see git history if it's ever needed for reference.

Configuration is loaded from /opt/tscan/tscan_ng/config/tscan_ng.conf at
startup. See tscan_ng/config.py for all available settings and their defaults.

Pending findings (credentials seen but no server response yet) are
registered on the session by each stream detector and resolved here when
the response arrives, or closed out as no_response elsewhere (session
expiry or shutdown, in session.py).
"""

from tscan_ng.detectors.http_basic import _parse_response, _outcome
from tscan_ng.detectors.imap import (_IMAP_RESPONSE_BYTES_RE,
                                      _outcome as _imap_outcome)
from tscan_ng.detectors.ftp import _FTP_RESPONSE_RE, _outcome as _ftp_outcome
from tscan_ng.detectors.smtp import (
    _SMTP_RESPONSE_RE, _outcome as _smtp_outcome
)
from tscan_ng.detectors.pop3 import _POP3_RESPONSE_RE, _outcome as _pop3_outcome
from tscan_ng.detectors.telnet import _outcome as _telnet_outcome
from tscan_ng.detectors.ldap import _find_bind_response, _outcome as _ldap_outcome
from tscan_ng.detectors.redis import _find_auth_response
from tscan_ng.detectors.smb import _find_final_status, _outcome as _smb_outcome
from tscan_ng.detectors.snmp import _find_snmp_response, _outcome as _snmp_outcome
from tscan_ng.detectors.irc import _find_identify_response, _outcome as _irc_outcome
from tscan_ng.detectors.postgres import _find_auth_outcome


def _try_resolve(p, session, ts: float) -> dict | None:
    """
    Attempt to resolve a pending finding against available server buffer data.

    Dispatches to the appropriate resolver based on the finding type.
    Returns a completed finding dict if resolved, or None if still pending.

    Private fields prefixed with '_' are stripped from the final emitted
    finding.

    Args:
        p:       PendingFinding object from the session.
        session: Session object containing server_buf and client_buf.
        ts:      Unix timestamp of the current packet.

    Returns:
        Completed finding dict if resolved, None otherwise.
    """
    finding_type = p.finding.get("type", "")
    clean_finding = {k: v for k, v in p.finding.items() if not k.startswith("_")}

    if finding_type == "http_basic":
        response = _parse_response(session.server_buf)
        if response:
            status, status_text, rsp_end = response
            # Consume the response line from server_buf so that subsequent
            # requests on the same keep-alive connection are not incorrectly
            # correlated with this (now-stale) response.
            del session.server_buf[:rsp_end]
            session.shift_pending_floors(rsp_end)
            return {
                **clean_finding,
                "ts":          p.ts_start,
                "ts_start":    p.ts_start,
                "ts_end":      ts,
                "status":      status,
                "status_text": status_text,
                "outcome":     _outcome(status),
            }

    elif finding_type == "imap_creds":
        tag = p.finding.get("tag", "")
        tag_bytes = tag.upper().encode("utf-8", "ignore")
        # Search server_buf as bytes so resp_match.end() is a byte offset,
        # not a character offset.  Decoding with errors="ignore" drops bytes
        # and shifts character positions, causing incorrect buffer trimming.
        server_bytes_imap = bytes(session.server_buf)
        for resp_match in _IMAP_RESPONSE_BYTES_RE.finditer(server_bytes_imap):
            if resp_match.group(1).upper() == tag_bytes:
                status = resp_match.group(2).upper().decode("utf-8", "ignore")
                # Consume up to and including this tagged response so it
                # cannot be matched again by a subsequent pending finding.
                del session.server_buf[:resp_match.end()]
                session.shift_pending_floors(resp_match.end())
                return {
                    **clean_finding,
                    "ts_start":    p.ts_start,
                    "ts_end":      ts,
                    "status":      status,
                    "outcome":     _imap_outcome(status),
                }

    elif finding_type in ("ftp_creds", "ftp_anonymous"):
        response = _FTP_RESPONSE_RE.search(bytes(session.server_buf))
        if response:
            code = response.group(1)
            # Consume the matched response line to prevent re-correlation
            # with a later credential exchange on the same session.
            del session.server_buf[:response.end()]
            session.shift_pending_floors(response.end())
            return {
                **clean_finding,
                "ts_start":    p.ts_start,
                "ts_end":      ts,
                "status":      code.decode("utf-8", "ignore"),
                "outcome":     _ftp_outcome(code),
            }

    elif finding_type == "smtp_creds":
        response = _SMTP_RESPONSE_RE.search(bytes(session.server_buf))
        if response:
            code = response.group(1)
            # Consume the matched response line to prevent re-correlation
            # with a later credential exchange on the same session.
            del session.server_buf[:response.end()]
            session.shift_pending_floors(response.end())
            return {
                **clean_finding,
                "ts_start":    p.ts_start,
                "ts_end":      ts,
                "status":      code.decode("utf-8", "ignore"),
                "outcome":     _smtp_outcome(code),
            }

    elif finding_type == "pop3_creds":
        responses = list(_POP3_RESPONSE_RE.finditer(bytes(session.server_buf)))
        # Mirror pop3.detect_stream: -ERR is unambiguous at any position;
        # success requires all three responses (banner, USER reply, PASS reply)
        # because two +OK lines are ambiguous (banner + USER, PASS still pending).
        err_response = next(
            (r for r in responses if r.group(1).upper() == b"-ERR"), None
        )
        if err_response:
            code = err_response.group(1)
            del session.server_buf[:err_response.end()]
            session.shift_pending_floors(err_response.end())
            return {
                **clean_finding,
                "ts_start":    p.ts_start,
                "ts_end":      ts,
                "status":      code.decode("utf-8", "ignore"),
                "outcome":     _pop3_outcome(code),
            }
        elif len(responses) >= 3:
            # responses[0]=banner, responses[1]=USER reply, responses[2]=PASS reply
            code = responses[2].group(1)
            del session.server_buf[:responses[2].end()]
            session.shift_pending_floors(responses[2].end())
            return {
                **clean_finding,
                "ts_start":    p.ts_start,
                "ts_end":      ts,
                "status":      code.decode("utf-8", "ignore"),
                "outcome":     _pop3_outcome(code),
            }

    elif finding_type == "telnet_creds":
        result = _telnet_outcome(session.server_buf)
        if result:
            return {
                **clean_finding,
                "ts_start": p.ts_start,
                "ts_end":   ts,
                "status":   result,
                "outcome":  result,
            }

    elif finding_type == "ldap_creds":
        result_code, rsp_end = _find_bind_response(bytes(session.server_buf))
        if result_code is not None:
            # Consume the BindResponse so it cannot be matched again.
            del session.server_buf[:rsp_end]
            session.shift_pending_floors(rsp_end)
            return {
                **clean_finding,
                "ts_start": p.ts_start,
                "ts_end":   ts,
                "status":   str(result_code),
                "outcome":  _ldap_outcome(result_code),
            }

    elif finding_type == "redis_creds":
        outcome, rsp_end = _find_auth_response(bytes(session.server_buf))
        if outcome is not None:
            # Consume the AUTH response so it cannot be matched again.
            del session.server_buf[:rsp_end]
            session.shift_pending_floors(rsp_end)
            return {
                **clean_finding,
                "ts_start": p.ts_start,
                "ts_end":   ts,
                "status":   outcome,
                "outcome":  outcome,
            }

    elif finding_type == "smb_creds":
        status, rsp_end = _find_final_status(bytes(session.server_buf))
        if status is not None:
            # Consume the SESSION_SETUP response so it cannot be matched again.
            del session.server_buf[:rsp_end]
            session.shift_pending_floors(rsp_end)
            return {
                **clean_finding,
                "ts_start": p.ts_start,
                "ts_end":   ts,
                "status":   str(status),
                "outcome":  _smb_outcome(status),
            }

    elif finding_type == "snmp_creds":
        # _request_id is only on the uncleaned p.finding (see
        # detectors/snmp.py's add_pending call) -- clean_finding has it
        # stripped since it's not meant to appear in the emitted finding.
        request_id = p.finding.get("_request_id")
        error_status, rsp_end = _find_snmp_response(bytes(session.server_buf), request_id)
        if error_status is not None:
            # Consume the Response-PDU so it cannot be matched again.
            del session.server_buf[:rsp_end]
            session.shift_pending_floors(rsp_end)
            return {
                **clean_finding,
                "ts_start": p.ts_start,
                "ts_end":   ts,
                "status":   str(error_status),
                "outcome":  _snmp_outcome(error_status),
            }

    elif finding_type == "irc_creds":
        outcome, rsp_end = _find_identify_response(bytes(session.server_buf))
        if outcome is not None:
            # Consume the NickServ NOTICE so it cannot be matched again.
            del session.server_buf[:rsp_end]
            session.shift_pending_floors(rsp_end)
            return {
                **clean_finding,
                "ts_start": p.ts_start,
                "ts_end":   ts,
                "status":   outcome,
                "outcome":  _irc_outcome(outcome),
            }

    elif finding_type == "postgres_creds":
        outcome, status, rsp_end = _find_auth_outcome(bytes(session.server_buf))
        if outcome is not None:
            # Consume the AuthenticationOk/ErrorResponse so it cannot be
            # matched again.
            del session.server_buf[:rsp_end]
            session.shift_pending_floors(rsp_end)
            return {
                **clean_finding,
                "ts_start": p.ts_start,
                "ts_end":   ts,
                "status":   status,
                "outcome":  outcome,
            }

    return None
