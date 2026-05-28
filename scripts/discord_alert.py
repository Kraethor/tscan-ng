#!/usr/bin/env python3
"""
discord_alert.py

Minimal Discord webhook notification support for tscan-ng.

Purpose
-------
This module provides a deliberately minimal and isolated notification
mechanism for confirmed credential discoveries detected by watch.py.

Design Goals
------------
- Do NOT block packet processing or watch loops.
- Do NOT expose credentials to Discord.
- Do NOT raise exceptions back into watch.py.
- Keep the implementation intentionally simple for initial testing.
- Allow future expansion (cooldowns, embeds, dedupe, masking, queues).

Security Notes
--------------
This module intentionally sends ONLY a generic notification message:

    "Credential found"

No usernames, passwords, tokens, packet payloads, or stream metadata
are transmitted to Discord.

The local JSONL results remain the authoritative evidence source.

Configuration
-------------
Environment Variables:

TS_DISCORD_WEBHOOK
    Discord webhook URL used for alert delivery.

Example:

export TS_DISCORD_WEBHOOK="https://discord.com/api/webhooks/..."

Usage
-----
from discord_alert import send_alert

send_alert()
"""

import os
import requests


# Discord webhook URL loaded from environment or tscan_ng.conf.
# If undefined, alerting is silently disabled.
# WEBHOOK_URL = os.getenv("TS_DISCORD_WEBHOOK")
WEBHOOK_URL = config.get("discord_webhook", "").strip()

def send_alert() -> None:
    """
    Send a minimal Discord alert.

    This function intentionally sends only a generic notification
    message to validate webhook functionality without exposing
    credential material.

    Failure Behavior
    ----------------
    All exceptions are intentionally suppressed to prevent
    Discord outages or network failures from impacting the
    tscan-ng monitoring pipeline.
    """

    # If no webhook is configured, do nothing.
    if not WEBHOOK_URL:
        return

    payload = {
        "content": "Credential found"
    }

    try:
        requests.post(
            WEBHOOK_URL,
            json=payload,
            timeout=5
        )

    except Exception:
        # Intentionally suppress all exceptions.
        #
        # Alerting failures must never impact watch.py
        # or the credential processing pipeline.
        pass
