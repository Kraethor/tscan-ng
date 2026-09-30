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

Outcome determination is heuristic (text matching, no protocol status code):
    _find_outcome() searches the server stream for login-failure text or
    success text ("Last login", "Welcome to", or a line ending in a $ # >
    prompt character), failure patterns first, but ONLY in the bytes after the
    password prompt that preceded the password being sent. So a "Welcome to
    ..." banner before the login prompt no longer counts as success
    (TODO.md #15). When a verdict is found, the server stream up to and
    including the matched text is consumed (and pending floors shifted), so a
    retry after a failed login is judged on its own response instead of the
    previous attempt's leftover text. Text that never appears leaves the
    finding pending until it expires as no_response.

Known limitations:
    - "Welcome to" after the password is still treated as success, which is a
      weak signal (a server could print it on a failed login); "Login
      incorrect"-style failure text is checked first and wins.
    - Only the first two non-empty client lines are used, and only the first
      4 KB of each buffer is examined for the prompts, so a long banner can
      hide the prompts. Backspace/DEL editing is not interpreted, so a mistyped
      and corrected character sequence is reported literally.
    - Server-side echo is ignored (only client_buf is parsed) and the server
      stream is not IAC-stripped before the regexes run.
    - Only one credential pair is extracted per call; a retry after a
      failed login is picked up by later calls only because the previous
      window was consumed.
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

# Matches common login prompts sent by the server ("login:", "Username:",
# "Last login:" also matches, being a substring hit on "login" + ":").
# Must appear in server_buf before we attempt credential extraction.
_LOGIN_PROMPT_RE = re.compile(
    rb'(?:login|username)\s*:\s*',
    re.IGNORECASE,
)

# Matches password prompts sent by the server.
# Must appear in server_buf (detect_stream only checks that it is present
# somewhere in the first _MAX_CMD_SCAN bytes; it does NOT verify the ordering
# relative to the login prompt). IGNORECASE makes the [Pp] class redundant.
_PASS_PROMPT_RE = re.compile(
    rb'[Pp]assword\s*:\s*',
    re.IGNORECASE,
)

# Matches common success indicators in the server stream after authentication.
# Shell prompts ($, #, >) and "Last login:" are reliable success signals.
# Note "Welcome to" is weaker: many devices print it in the pre-login banner,
# and this regex is run over the whole server buffer (see _outcome).
_SUCCESS_RE = re.compile(
    rb'(?:'
    rb'Last\s+login'           # Linux/Unix last-login line
    rb'|Welcome\s+to'          # Some systems show a welcome banner
    rb'|[\$#>]\s*\r?\n'        # Shell prompt at end of a line
    rb')',
    re.IGNORECASE,
)

# Matches common failure indicators in the server stream. Checked before
# _SUCCESS_RE in _outcome(), so a failure message anywhere in the buffer wins.
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

    Edge cases: an escaped literal 0xFF (IAC IAC) is treated as an ordinary
    2-byte command and dropped rather than emitted as one 0xFF data byte. An
    IAC as the very last byte, or an IAC SB with no terminating IAC SE in the
    data, is truncated/incomplete: the trailing partial sequence is discarded
    (in the unterminated-SB case the buffer's final byte is then re-read as
    ordinary data). Because callers strip a whole window at a time, an IAC
    sequence split across two segments can leave its tail bytes in the text.

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
        # (RFC 854: option negotiation is IAC + verb + option-code; IAC SB
        # starts a variable-length subnegotiation closed by IAC SE; every
        # other command such as NOP/GA/AYT is IAC + one byte.)
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

    Handles both standard Telnet line endings (CR LF) and NVT binary-mode
    endings (CR NUL). Empty lines and whitespace-only lines are discarded.
    A bare CR (or LF) on its own is not special: a lone LF still splits a line,
    a lone CR does not.

    Args:
        data: IAC-stripped bytes from the client stream.

    Returns:
        List of non-empty stripped byte strings, one per line.
    """
    # Normalise \r\0 (NVT binary-mode line end) and \r\n to plain \n.
    data = data.replace(b'\r\0', b'\n').replace(b'\r\n', b'\n')
    return [line.strip() for line in data.split(b'\n') if line.strip()]


# ── Outcome determination ─────────────────────────────────────────────────────

def _find_outcome(server_bytes: bytes, start: int = 0):
    """
    Determine the authentication outcome from the server stream.

    Searches server_bytes[start:] for failure indicators first, then success
    indicators. Returns (None, None) if neither has appeared yet -- the
    caller should register a pending finding and retry on the next packet.

    Only the bytes from *start* onward are considered, so text the server
    sent before the password was typed (banners, earlier attempts) cannot
    decide the outcome. Also imported by run.py's _try_resolve() for pending
    findings (which passes the finding's server_buf_floor as *start*).

    Args:
        server_bytes: Reassembled server-direction byte stream.
        start:        Offset in server_bytes where the response to the
                      password can begin (the end of the password prompt, or
                      the pending finding's floor).

    Returns:
        (outcome, end_offset): outcome is 'success' or 'failed' and
        end_offset is the absolute offset just past the matched text, for the
        caller to consume; (None, None) if not yet determinable.
    """
    m = _FAIL_RE.search(server_bytes, start)
    if m:
        return "failed", m.end()
    m = _SUCCESS_RE.search(server_bytes, start)
    if m:
        return "success", m.end()
    return None, None


# ── Stream detector ───────────────────────────────────────────────────────────

def detect_stream(session, ts: float) -> list:
    """
    Stream-aware Telnet credential detector.

    Waits until the server has sent both a login prompt and a password
    prompt (both within the first _MAX_CMD_SCAN bytes of server_buf, in either
    order), then extracts the first two non-empty lines from the
    (IAC-stripped) client buffer as username and password. Sessions where
    either buffer is empty are skipped.

    Emits a finding immediately if an outcome is already visible in the
    server buffer, or registers a pending finding for later resolution
    when the outcome arrives. Consumes the inspected portion of client_buf
    (the whole scanned window, including anything typed after the password)
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
    pass_prompt = _PASS_PROMPT_RE.search(server_bytes)
    if not pass_prompt:
        return []

    # Strip IAC negotiation sequences and split into typed lines.
    stripped = _strip_iac(client_bytes)
    lines    = _extract_lines(stripped)

    if len(lines) < 2:
        # Username and/or password not yet in the buffer — wait.
        return []

    user   = lines[0].decode("utf-8", "ignore")
    passwd = lines[1].decode("utf-8", "ignore")

    # Defensive: _extract_lines() drops empty lines, so both values are
    # normally non-empty; this only fires if a line decodes to nothing.
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

    # "status" mirrors "outcome" (there is no protocol status code to report).
    # Only text after the password prompt can answer the password; the matched
    # response is consumed so the next attempt starts clean.
    full_server = bytes(session.server_buf)
    result, rsp_end = _find_outcome(full_server, pass_prompt.end())
    if result:
        del session.server_buf[:rsp_end]
        session.shift_pending_floors(rsp_end)
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
