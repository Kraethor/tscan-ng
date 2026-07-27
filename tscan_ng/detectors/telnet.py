"""
detectors/telnet.py - Telnet credential detector for tscan-ng.

Stream-aware detector that operates on reassembled TCP streams rather than
individual packets. Extracts plaintext credentials from Telnet login sessions
by correlating server prompts with client responses.

Handles the standard interactive Telnet login flow:
    SERVER: ... (banner + IAC negotiation)
    SERVER: login: (or Username:)
    CLIENT: username\r\n
    SERVER: Password:
    CLIENT: password\r\n
    SERVER: ...  (shell prompt on success, or "Login incorrect" on failure)

IAC negotiation:
    The Telnet protocol embeds binary option negotiation sequences (IAC
    sequences) in both client and server streams. These are stripped from
    the client stream before credential extraction so that negotiation bytes
    do not corrupt the extracted username or password.

Port handling:
    The detector gates on _TELNET_PORTS. Sessions where neither endpoint is
    in the set are skipped immediately. The scan is bounded to _MAX_CMD_SCAN
    bytes to keep per-packet work O(1).

Credential extraction:
    The detector waits until the server buffer shows both a login prompt
    and a password prompt before extracting credentials. This prevents false
    positives from non-login Telnet sessions. The first two non-empty lines
    from the (IAC-stripped) client buffer are taken as username and password.

    Once credentials are extracted, the scanned portion of client_buf is
    consumed to prevent re-detection on subsequent packets.

Finding outcomes:
    success      - Server showed a shell prompt or "Last login:" after auth
    failed       - Server showed "Login incorrect" or equivalent
    no_response  - Session expired before outcome could be determined
                   (emitted by SessionTable.expire())
"""

import re
import logging
from tscan_ng.session import _make_filter

# Standard and common alternate Telnet ports.
# Sessions where neither endpoint is in this set are skipped immediately.
_TELNET_PORTS: frozenset = frozenset({
    23,    # Standard Telnet (RFC 854)
    2323,  # Common alternate Telnet port
})

# Maximum bytes of each buffer to scan per call.
# Telnet login exchanges are short; 4 KB is well above any realistic auth
# exchange including banner and IAC negotiation overhead.
_MAX_CMD_SCAN = 4096

# ── Telnet IAC constants (RFC 854) ────────────────────────────────────────────

_IAC  = 0xFF  # Interpret As Command
_WILL = 0xFB  # Sender wants to enable option
_WONT = 0xFC  # Sender refuses to enable option
_DO   = 0xFD  # Sender wants receiver to enable option
_DONT = 0xFE  # Sender wants receiver to disable option
_SB   = 0xFA  # Subnegotiation begin
_SE   = 0xF0  # Subnegotiation end

# ── Server-side patterns ──────────────────────────────────────────────────────

# Matches common login prompts sent by the server.
# Must appear in server_buf before we attempt credential extraction.
_LOGIN_PROMPT_RE = re.compile(
    rb'(?:login|username)\s*:\s*',
    re.IGNORECASE,
)

# Matches password prompts sent by the server.
# Must appear in server_buf after the login prompt.
_PASS_PROMPT_RE = re.compile(
    rb'[Pp]assword\s*:\s*',
    re.IGNORECASE,
)

# Matches common success indicators in the server stream after authentication.
# Shell prompts ($, #, >) and "Last login:" are reliable success signals.
_SUCCESS_RE = re.compile(
    rb'(?:'
    rb'Last\s+login'           # Linux/Unix last-login line
    rb'|Welcome\s+to'          # Some systems show a welcome banner
    rb'|[\$#>]\s*\r?\n'        # Shell prompt at end of a line
    rb')',
    re.IGNORECASE,
)

# Matches common failure indicators in the server stream.
_FAIL_RE = re.compile(
    rb'(?:'
    rb'Login\s+incorrect'      # Linux PAM / getty
    rb'|Authentication\s+failed'
    rb'|Login\s+failed'
    rb'|Invalid\s+(?:login|password|username)'
    rb'|Bad\s+password'
    rb'|Access\s+denied'
    rb')',
    re.IGNORECASE,
)


# ── IAC stripping ─────────────────────────────────────────────────────────────

def _strip_iac(data: bytes) -> bytes:
    """
    Remove Telnet IAC option negotiation sequences from a byte string.

    Handles:
      - 3-byte sequences: IAC WILL/WONT/DO/DONT <option>
      - Subnegotiation:   IAC SB ... IAC SE
      - 2-byte sequences: IAC <other-cmd>

    Non-IAC bytes are passed through unchanged so that the resulting
    byte string contains only application-layer data (typed text).

    Args:
        data: Raw bytes from the Telnet client or server stream.

    Returns:
        Bytes with all IAC sequences removed.
    """
    result = bytearray()
    i = 0
    while i < len(data):
        b = data[i]
        if b != _IAC:
            result.append(b)
            i += 1
            continue

        # IAC sequence — determine length and skip.
        if i + 1 >= len(data):
            # Incomplete IAC at end of buffer — discard and stop.
            break

        cmd = data[i + 1]

        if cmd == _SB:
            # Subnegotiation: skip everything until IAC SE.
            i += 2
            while i < len(data) - 1:
                if data[i] == _IAC and data[i + 1] == _SE:
                    i += 2
                    break
                i += 1
        elif cmd in (_WILL, _WONT, _DO, _DONT):
            # 3-byte option negotiation: IAC <cmd> <option>.
            i += 3
        else:
            # 2-byte sequence: IAC <cmd> with no option byte.
            i += 2

    return bytes(result)


# ── Line extraction ───────────────────────────────────────────────────────────

def _extract_lines(data: bytes) -> list:
    """
    Split IAC-stripped Telnet data into non-empty lines.

    Handles both standard Telnet line endings (\r\n) and NVT binary-mode
    endings (\r\0). Empty lines and whitespace-only lines are discarded.

    Args:
        data: IAC-stripped bytes from the client stream.

    Returns:
        List of non-empty stripped byte strings, one per line.
    """
    # Normalise \r\0 (NVT binary-mode line end) and \r\n to plain \n.
    data = data.replace(b'\r\0', b'\n').replace(b'\r\n', b'\n')
    return [line.strip() for line in data.split(b'\n') if line.strip()]


# ── Outcome determination ─────────────────────────────────────────────────────

def _outcome(server_buf: bytearray) -> str | None:
    """
    Determine the authentication outcome from the server buffer.

    Searches for success or failure indicators in the server stream.
    Returns None if neither has appeared yet — the caller should
    register a pending finding and retry on the next packet.

    Args:
        server_buf: Reassembled server-direction byte stream.

    Returns:
        'success', 'failed', or None if outcome is not yet determinable.
    """
    server_bytes = bytes(server_buf)
    if _FAIL_RE.search(server_bytes):
        return "failed"
    if _SUCCESS_RE.search(server_bytes):
        return "success"
    return None


# ── Stream detector ───────────────────────────────────────────────────────────

def detect_stream(session, ts: float) -> list:
    """
    Stream-aware Telnet credential detector.

    Waits until the server has sent both a login prompt and a password
    prompt, then extracts the first two non-empty lines from the
    (IAC-stripped) client buffer as username and password.

    Emits a finding immediately if an outcome is already visible in the
    server buffer, or registers a pending finding for later resolution
    when the outcome arrives. Consumes the inspected portion of client_buf
    to prevent re-detection on subsequent packets.

    Args:
        session: Session object from session.SessionTable.
        ts:      Unix timestamp of the current packet.

    Returns:
        List of resolved finding dicts. Pending findings are registered on
        the session and not returned until resolved.
    """
    # Gate: only scan sessions on known Telnet ports.
    if session.dport not in _TELNET_PORTS and session.sport not in _TELNET_PORTS:
        return []

    # Need data in both directions to detect a login exchange.
    client_bytes = bytes(session.client_buf[:_MAX_CMD_SCAN])
    server_bytes = bytes(session.server_buf[:_MAX_CMD_SCAN])

    if not client_bytes or not server_bytes:
        return []

    # Require the server to have sent both a login prompt and a password
    # prompt before extracting credentials. This confirms we are in an
    # interactive authentication exchange rather than some other Telnet use.
    if not _LOGIN_PROMPT_RE.search(server_bytes):
        return []
    if not _PASS_PROMPT_RE.search(server_bytes):
        return []

    # Strip IAC negotiation sequences and split into typed lines.
    stripped = _strip_iac(client_bytes)
    lines    = _extract_lines(stripped)

    if len(lines) < 2:
        # Username and/or password not yet in the buffer — wait.
        return []

    user   = lines[0].decode("utf-8", "ignore")
    passwd = lines[1].decode("utf-8", "ignore")

    if not user or not passwd:
        logging.debug(
            "telnet: session %s: credential lines present but decoded empty",
            session.session_id)
        del session.client_buf[:len(client_bytes)]
        return []

    # Consume the scanned window from client_buf to prevent re-detection
    # if more client data arrives before the session expires.
    del session.client_buf[:len(client_bytes)]

    base = {
        "type":       "telnet_creds",
        "session_id": session.session_id,
        "src":        session.src,
        "dst":        session.dst,
        "sport":      session.sport,
        "dport":      session.dport,
        "creds":      f"{user}:{passwd}",
        "filter":     _make_filter(session.src, session.dst,
                                   session.sport, session.dport),
    }

    result = _outcome(session.server_buf)
    if result:
        return [{
            **base,
            "ts_start": ts,
            "ts_end":   session.last_ts,
            "status":   result,
            "outcome":  result,
        }]

    # Outcome not yet visible — register as pending for later resolution.
    session.add_pending(base, ts_start=ts)
    return []
