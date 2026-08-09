"""
sinks/discord.py - Discord webhook alerting for tscan-ng.

Two kinds of alert, both posted to the same webhook:
  - write(finding):  a credential-finding alert, fired for every finding
    whose outcome isn't in DiscordSink._SUPPRESSED_OUTCOMES (currently
    "pending" and "failed" -- see that constant for why). Exposes the same
    write(finding) interface as JSONLSink so pipeline.py can treat both
    sinks identically at each finding call site.
  - notify(message): a free-text operational alert -- pipeline_worker exit,
    kernel packet drops, etc. -- for the "is the pipeline itself healthy"
    channel of alerting, distinct from "did we catch a credential".

Repeat-spam suppression (the same credentials replayed at the same service
over and over) is handled once, upstream, in pipeline.py's _emit() -- it
gates JSONLSink and DiscordSink identically via sinks/cooldown.py, rather
than each sink deduping separately.

This replaces the old scripts/discord_alert.py, which only alerted while a
human had watch.py open on a terminal. Living inside tscan-pipeline.service
itself means alerting no longer depends on anyone watching -- it is always
on, the same as the JSONL log.

Design goals (carried over from scripts/discord_alert.py):
  - Never block packet processing: pipeline_worker's hot loop can't afford
    to stall on a Discord outage or slow network the way a detached
    terminal viewer could, so the actual HTTP POST runs on a throwaway
    daemon thread.
  - Never expose credentials to Discord: only `type`, the username portion
    of `creds`, and `session_id` are sent for findings.
  - Never raise back into the caller: exceptions from the network call are
    swallowed inside the background thread.
  - Never leak the webhook URL itself into logs: the URL's path *is* the
    secret (anyone who has it can post to the channel), and it's the POST
    target of every call in this module. requests delegates the actual
    HTTP exchange to urllib3, whose connectionpool logger emits the full
    request URL at DEBUG level -- and pipeline_worker (see pipeline.py)
    runs with the root logger at DEBUG for its own operational logging.
    Silencing urllib3 specifically, below, keeps that useful DEBUG output
    everywhere else while stopping this module from being the reason the
    webhook secret ends up in `journalctl -u tscan-pipeline`. Fixed here
    rather than at each caller so it holds regardless of what log level
    any future caller configures.
"""

import logging
import threading

import requests

from tscan_ng.sinks.cooldown import claim_slot

# See "Never leak the webhook URL itself into logs" above.
logging.getLogger("urllib3").setLevel(logging.WARNING)

# Default marker file for notify()'s cooldown. Every pipeline_worker process
# constructs its own DiscordSink independently (there is no shared memory
# between them), so the cooldown has to live on disk to actually coordinate
# across processes -- otherwise a single event that takes down every worker
# at once (e.g. the capture interface dropping) fires one alert per worker
# instead of one alert total. /run/tscan is created by tscan-pipeline.service
# via RuntimeDirectory=tscan, so it exists whenever a pipeline_worker could
# plausibly call notify().
_DEFAULT_COOLDOWN_PATH = "/run/tscan/discord_notify_last"


class DiscordSink:
    """
    Sends Discord webhook alerts for tscan-ng: credential findings and
    operational events.

    Args:
        webhook_url:   Discord webhook URL, or "" to disable alerting
            entirely (write()/notify() become no-ops).
        cooldown_path: Marker file used to rate-limit notify() across
            processes. See sinks/cooldown.py's claim_slot().
        cooldown_sec:  Minimum seconds between notify() alerts sharing
            cooldown_path. 0 disables the cooldown (every notify() call
            sends), which is correct for a caller that already does its own
            edge-triggered dedup (e.g. the external healthcheck, which only
            calls notify() on an up/down state transition).
    """

    def __init__(self, webhook_url: str,
                 cooldown_path: str = _DEFAULT_COOLDOWN_PATH,
                 cooldown_sec: float = 300):
        """Store webhook config. See the class docstring for Args."""
        self._webhook_url = webhook_url
        self._cooldown_path = cooldown_path
        self._cooldown_sec = cooldown_sec

    # Outcomes not worth an alert: "pending" never reaches write() (it isn't
    # a terminal state — see pipeline.py's resolution loop), and "failed"
    # means the server rejected the credentials (401), so there's nothing
    # actionable to page on. Every other terminal outcome (success, redirect,
    # server_error, no_response, and the catch-all "unknown" for status
    # codes _outcome() doesn't otherwise classify -- e.g. 403, which for
    # Basic Auth usually means the credentials *were* accepted and something
    # else blocked the request) is alert-worthy: each represents credentials
    # that were actually submitted and merits a human look.
    _SUPPRESSED_OUTCOMES = frozenset({"pending", "failed"})

    def write(self, finding: dict) -> None:
        """
        Fire a background alert for *finding* if alerting is enabled and the
        finding's outcome isn't in _SUPPRESSED_OUTCOMES. No-op otherwise.

        Args:
            finding: Finding dict, same shape as written to the JSONL sink.
        """
        if not self._webhook_url or finding.get("outcome") in self._SUPPRESSED_OUTCOMES:
            return
        threading.Thread(
            target=_send_finding, args=(self._webhook_url, finding), daemon=True
        ).start()

    def notify(self, message: str) -> "threading.Thread | None":
        """
        Fire a background operational alert with free-text *message*, e.g.
        "pipeline[2] pid=1234 exiting: recv() error (iface down?)". No-op if
        alerting is disabled, or if another alert already claimed this
        cooldown window (see claim_slot).

        Returns the (already-started) daemon thread doing the POST, or None
        if no alert was sent (disabled, or suppressed by the cooldown).
        Fire-and-forget callers can ignore the return value; a caller about
        to exit the process right after calling notify() should join() it
        (with a timeout) first -- otherwise the process can exit before the
        background thread gets a chance to actually send the alert, since
        daemon threads are not waited on at interpreter shutdown.

        Args:
            message: Plain-text message to post to the webhook.
        """
        if not self._webhook_url:
            return None
        if not claim_slot(self._cooldown_path, self._cooldown_sec):
            return None
        t = threading.Thread(
            target=_post,
            args=(self._webhook_url, {"content": message, "allowed_mentions": {"parse": []}}),
            daemon=True,
        )
        t.start()
        return t


def _send_finding(webhook_url: str, finding: dict) -> None:
    """
    Build and POST the Discord payload for one successful credential
    finding. Runs on a background thread.

    Because the username comes directly from captured network traffic, it
    is attacker-controlled input. `allowed_mentions: {"parse": []}` stops a
    crafted username (e.g. containing "@everyone") from triggering a
    mention in the target channel.

    Args:
        webhook_url: Discord webhook URL.
        finding: Finding dict for one credential capture (any outcome not
                 in DiscordSink._SUPPRESSED_OUTCOMES).
    """
    ftype = finding.get("type", "unknown")
    username = finding.get("creds", "").split(":", 1)[0] or "unknown"
    session_id = finding.get("session_id", "unknown")
    outcome = finding.get("outcome", "unknown")

    payload = {
        "content": f"Credential found — type: `{ftype}`  user: `{username}`  "
                    f"outcome: `{outcome}`  session: `{session_id}`",
        "allowed_mentions": {"parse": []},
    }
    _post(webhook_url, payload)


def _post(webhook_url: str, payload: dict) -> None:
    """
    POST *payload* to the Discord webhook. All exceptions are intentionally
    suppressed so a Discord outage or network failure can never affect the
    capture pipeline (this always runs on a background thread; there is no
    caller left to usefully report an exception to).

    Args:
        webhook_url: Discord webhook URL.
        payload: JSON-serializable Discord webhook payload.
    """
    try:
        requests.post(webhook_url, json=payload, timeout=5)
    except Exception:
        pass
