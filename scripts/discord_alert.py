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
import sys

# Ensure tscan_ng package is importable when running from scripts/
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import requests

from tscan_ng.config import Config

# Load the global tscan-ng configuration.
config = Config()

# Discord webhook URL loaded from tscan_ng.conf [discord] section.
# If undefined, alerting is silently disabled.
WEBHOOK_URL = config.discord_webhook

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
