"""
resolve.py - Response correlation for pending findings (TODO.md #56).

Every detector reports credentials by parking them on the session with
session.add_pending(); nothing is emitted by the detectors themselves. This
module is the only place a pending finding meets its server response:
resolve_pending() runs straight after the detectors on every packet
(pipeline.py), so a reply that is already buffered is matched on the same
packet, and a later reply on the packet that brings it.

Each detector module provides resolve(p, session), which parses its own
protocol's reply out of session.server_buf and returns

    (fields, consumed)   fields: "status" and "outcome" (http_basic also
                         "status_text"); consumed: bytes from the front of
                         server_buf that belong to this reply, or
    None                 no reply yet.

A resolver never modifies server_buf. try_resolve() deletes the consumed
bytes and shifts the remaining pending findings' floors, so one reply can
never answer two findings and floors stay valid. RESOLVERS maps every
finding type to its module's resolve(), built from
detectors.DETECTOR_MODULES and their FINDING_TYPES.

Replaces run.py's _try_resolve(), an 11-branch if/elif that duplicated each
detector's own immediate-resolve parser.

Pending findings that never get a reply are closed as no_response elsewhere
(age limit, session expiry, eviction or shutdown; see session.py).
"""

from tscan_ng.detectors import DETECTOR_MODULES

RESOLVERS = {ftype: mod.resolve for mod in DETECTOR_MODULES for ftype in mod.FINDING_TYPES}


def try_resolve(p, session, ts: float) -> dict | None:
    """
    Try to resolve one pending finding against session.server_buf.

    Args:
        p:       PendingFinding from session.pending.
        session: Session holding the server_buf to search.
        ts:      Unix timestamp of the current packet (becomes ts_end).

    Returns:
        The completed finding (private "_" fields stripped, ts_start/ts_end
        set, the resolver's fields merged in), or None if there is no reply
        yet or the finding's type has no resolver. On success the reply is
        consumed from server_buf and pending floors are shifted.
    """
    resolver = RESOLVERS.get(p.finding.get("type", ""))
    result = resolver(p, session) if resolver else None
    if result is None:
        return None
    fields, consumed = result
    del session.server_buf[:consumed]
    session.shift_pending_floors(consumed)
    clean = {k: v for k, v in p.finding.items() if not k.startswith("_")}
    return {**clean, "ts_start": p.ts_start, "ts_end": ts, **fields}


def resolve_pending(session, ts: float) -> list[dict]:
    """
    Offer every pending finding on *session* to its resolver, oldest first.

    Resolved findings are removed from session.pending and returned; the
    rest stay pending. Oldest first matters for the positional protocols:
    the first unanswered credential gets the first reply.

    Args:
        session: Session whose pending findings are checked.
        ts:      Unix timestamp of the current packet.

    Returns:
        List of completed finding dicts (without a "ts" field; pipeline.py
        adds it via _stamp_resolved()).
    """
    resolved, still_pending = [], []
    for p in session.pending:
        done = try_resolve(p, session, ts)
        if done is None:
            still_pending.append(p)
        else:
            resolved.append(done)
    session.pending = still_pending
    return resolved
